// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"compress/gzip"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vx6/vx6/internal/dht"
)

type routingMapWriter struct {
	file *os.File
	zip  *gzip.Writer
	csv  *csv.Writer
}

type routingMapEntry struct {
	owner    string
	ownerID  string
	space    string
	peerID   string
	peerName string
	peerHash string
	actual   int
	expected int
	distance *big.Int
	valid    bool
}

func newRoutingMapWriter(root, label string) (*routingMapWriter, error) {
	dir := filepath.Join(root, "routing-map")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, label+".csv.gz"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	z := gzip.NewWriter(f)
	w := csv.NewWriter(z)
	if err := w.Write([]string{"capture", "owner_name", "owner_node_id", "index", "actual_bucket", "expected_bucket", "local_xor_rank", "xor_distance_hex", "peer_name", "peer_node_id", "peer_name_hash", "placement_ok"}); err != nil {
		_ = z.Close()
		_ = f.Close()
		return nil, err
	}
	return &routingMapWriter{file: f, zip: z, csv: w}, nil
}

func (w *routingMapWriter) add(capture string, diag NodeDiagnostics) (checks, failures int, err error) {
	table := diag.DHT.Table
	if table.SelfID == "" || table.SelfNameHash == "" {
		return 0, 1, fmt.Errorf("%s: missing self XOR coordinate", diag.Name)
	}
	if table.SelfID != diag.NodeID || table.SelfNameHash != dht.NodeNameHash(diag.Name) {
		return 0, 1, fmt.Errorf("%s: diagnostic self identity does not match its XOR coordinates", diag.Name)
	}
	entries := make([]routingMapEntry, 0, table.IDIndex.Entries+table.NameIndex.Entries)
	for _, bucket := range table.IDIndex.Buckets {
		for _, peer := range bucket.Peers {
			distance, expected, ok := xorBucket(table.SelfID, peer.NodeID)
			valid := ok && expected == bucket.Index && peer.NodeID != table.SelfID &&
				strings.HasPrefix(table.SelfID, "vx6_") && strings.HasPrefix(peer.NodeID, "vx6_") &&
				peer.Name != "" && peer.NameHash == dht.NodeNameHash(peer.Name)
			entries = append(entries, routingMapEntry{owner: diag.Name, ownerID: table.SelfID, space: "node_id",
				peerID: peer.NodeID, peerName: peer.Name, peerHash: peer.NameHash, actual: bucket.Index,
				expected: expected, distance: distance, valid: valid})
			checks++
			if !valid {
				failures++
			}
		}
	}
	for _, bucket := range table.NameIndex.Buckets {
		for _, peer := range bucket.Peers {
			distance, expected, ok := xorBucket(table.SelfNameHash, peer.NameHash)
			nameHashOK := peer.Name != "" && peer.NameHash == dht.NodeNameHash(peer.Name)
			valid := ok && expected == bucket.Index && nameHashOK && strings.HasPrefix(peer.NodeID, "vx6_")
			entries = append(entries, routingMapEntry{owner: diag.Name, ownerID: table.SelfID, space: "name_hash",
				peerID: peer.NodeID, peerName: peer.Name, peerHash: peer.NameHash, actual: bucket.Index,
				expected: expected, distance: distance, valid: valid})
			checks++
			if !valid {
				failures++
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].owner != entries[j].owner {
			return entries[i].owner < entries[j].owner
		}
		if entries[i].space != entries[j].space {
			return entries[i].space < entries[j].space
		}
		if cmp := entries[i].distance.Cmp(entries[j].distance); cmp != 0 {
			return cmp < 0
		}
		return entries[i].peerID < entries[j].peerID
	})
	var rank int
	lastOwner, lastSpace := "", ""
	for _, entry := range entries {
		if entry.owner != lastOwner || entry.space != lastSpace {
			rank = 1
			lastOwner, lastSpace = entry.owner, entry.space
		} else {
			rank++
		}
		row := []string{capture, entry.owner, entry.ownerID, entry.space, fmt.Sprint(entry.actual), fmt.Sprint(entry.expected),
			fmt.Sprint(rank), fmt.Sprintf("%064x", entry.distance), entry.peerName, entry.peerID, entry.peerHash, fmt.Sprint(entry.valid)}
		if err := w.csv.Write(row); err != nil {
			return checks, failures, err
		}
	}
	w.csv.Flush()
	return checks, failures, w.csv.Error()
}

func (w *routingMapWriter) close() error {
	w.csv.Flush()
	if err := w.csv.Error(); err != nil {
		_ = w.zip.Close()
		_ = w.file.Close()
		return err
	}
	if err := w.zip.Close(); err != nil {
		_ = w.file.Close()
		return err
	}
	return w.file.Close()
}

func xorBucket(a, b string) (*big.Int, int, bool) {
	a = strings.TrimPrefix(a, "vx6_")
	b = strings.TrimPrefix(b, "vx6_")
	left, err := hex.DecodeString(a)
	if err != nil || len(left) != 32 || hex.EncodeToString(left) != a {
		return new(big.Int), -1, false
	}
	right, err := hex.DecodeString(b)
	if err != nil || len(right) != 32 || hex.EncodeToString(right) != b {
		return new(big.Int), -1, false
	}
	x := new(big.Int).SetBytes(left)
	x.Xor(x, new(big.Int).SetBytes(right))
	if x.Sign() == 0 {
		return x, -1, false
	}
	return x, x.BitLen() - 1, true
}
