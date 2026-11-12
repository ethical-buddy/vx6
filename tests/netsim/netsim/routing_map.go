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
	owner, ownerID, space                   string
	peerID, peerName, peerHash              string
	actual, expected, localRank, globalRank int
	distance                                *big.Int
	inTable, wanted                         bool
	placement                               string
}

type routingMapAudit struct {
	Checks, Failures          int
	IDExpected, IDPresent     int
	NameExpected, NamePresent int
}

type censusPeer struct {
	name, id, nameHash string
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
	if err := w.Write([]string{"capture", "census_nodes", "owner_name", "owner_node_id", "index", "local_bucket", "expected_bucket", "global_bucket_rank", "local_bucket_rank", "xor_distance_hex", "peer_name", "peer_node_id", "peer_name_hash", "global_nearest_k", "in_local_table", "placement"}); err != nil {
		_ = z.Close()
		_ = f.Close()
		return nil, err
	}
	return &routingMapWriter{file: f, zip: z, csv: w}, nil
}

// addCapture compares each captured local table with a test-only census. The
// nearest-K comparison is diagnostic: K is a referral target, not a hard cap.
func (w *routingMapWriter) addCapture(capture string, diagnostics []NodeDiagnostics) (map[string]routingMapAudit, error) {
	census := make([]censusPeer, 0, len(diagnostics))
	for _, diag := range diagnostics {
		t := diag.DHT.Table
		if t.SelfID == "" || t.SelfID != diag.NodeID || t.SelfNameHash != dht.NodeNameHash(diag.Name) {
			continue
		}
		census = append(census, censusPeer{name: diag.Name, id: t.SelfID, nameHash: t.SelfNameHash})
	}
	audits := make(map[string]routingMapAudit, len(diagnostics))
	for _, diag := range diagnostics {
		audit, err := w.addNode(capture, len(census), diag, census)
		audits[diag.Name] = audit
		if err != nil {
			return audits, err
		}
	}
	w.csv.Flush()
	return audits, w.csv.Error()
}

func (w *routingMapWriter) addNode(capture string, censusSize int, diag NodeDiagnostics, census []censusPeer) (routingMapAudit, error) {
	var audit routingMapAudit
	table := diag.DHT.Table
	if table.SelfID == "" || table.SelfNameHash == "" || table.SelfID != diag.NodeID || table.SelfNameHash != dht.NodeNameHash(diag.Name) {
		return audit, fmt.Errorf("%s: missing or inconsistent self XOR coordinates", diag.Name)
	}
	entries := make([]routingMapEntry, 0, table.IDIndex.Entries+table.NameIndex.Entries)
	for _, space := range []string{"node_id", "name_hash"} {
		selfCoordinate, buckets := table.SelfID, table.IDIndex.Buckets
		if space == "name_hash" {
			selfCoordinate, buckets = table.SelfNameHash, table.NameIndex.Buckets
		}
		global := make([]routingMapEntry, 0, len(census))
		for _, peer := range census {
			if peer.id == table.SelfID {
				continue
			}
			coordinate := peer.id
			if space == "name_hash" {
				coordinate = peer.nameHash
			}
			distance, bucket, ok := xorBucket(selfCoordinate, coordinate)
			if !ok {
				continue
			}
			global = append(global, routingMapEntry{owner: diag.Name, ownerID: table.SelfID, space: space,
				peerID: peer.id, peerName: peer.name, peerHash: peer.nameHash, expected: bucket, distance: distance})
		}
		sort.Slice(global, func(i, j int) bool {
			if global[i].expected != global[j].expected {
				return global[i].expected < global[j].expected
			}
			if cmp := global[i].distance.Cmp(global[j].distance); cmp != 0 {
				return cmp < 0
			}
			return global[i].peerID < global[j].peerID
		})
		globalByID := make(map[string]routingMapEntry, len(global))
		globalBucketRank := make(map[int]int)
		wanted := make(map[string]bool)
		for _, entry := range global {
			globalBucketRank[entry.expected]++
			entry.globalRank = globalBucketRank[entry.expected]
			entry.wanted = entry.globalRank <= dht.K
			globalByID[entry.peerID] = entry
			if entry.wanted {
				if space == "node_id" {
					audit.IDExpected++
				} else {
					audit.NameExpected++
				}
				wanted[entry.peerID] = true
			}
		}

		localByID := make(map[string]routingMapEntry)
		for _, bucket := range buckets {
			for _, peer := range bucket.Peers {
				coordinate := peer.NodeID
				if space == "name_hash" {
					coordinate = peer.NameHash
				}
				distance, expected, ok := xorBucket(selfCoordinate, coordinate)
				valid := ok && expected == bucket.Index && peer.NodeID != table.SelfID &&
					strings.HasPrefix(peer.NodeID, "vx6_") && peer.Name != "" && peer.NameHash == dht.NodeNameHash(peer.Name)
				entry := routingMapEntry{owner: diag.Name, ownerID: table.SelfID, space: space,
					peerID: peer.NodeID, peerName: peer.Name, peerHash: peer.NameHash, actual: bucket.Index,
					expected: expected, distance: distance, inTable: true, placement: "correct"}
				if !valid {
					entry.placement = "wrong_bucket_or_identity"
					audit.Failures++
				}
				audit.Checks++
				localByID[peer.NodeID] = entry
			}
		}
		stored := make([]routingMapEntry, 0, len(localByID))
		for _, entry := range localByID {
			stored = append(stored, entry)
		}
		sort.Slice(stored, func(i, j int) bool {
			if stored[i].actual != stored[j].actual {
				return stored[i].actual < stored[j].actual
			}
			if cmp := stored[i].distance.Cmp(stored[j].distance); cmp != 0 {
				return cmp < 0
			}
			return stored[i].peerID < stored[j].peerID
		})
		localBucketRank := make(map[int]int)
		for _, entry := range stored {
			localBucketRank[entry.actual]++
			entry.localRank = localBucketRank[entry.actual]
			if censusEntry, ok := globalByID[entry.peerID]; ok {
				entry.globalRank, entry.wanted = censusEntry.globalRank, censusEntry.wanted
			}
			localByID[entry.peerID] = entry
			entries = append(entries, entry)
		}
		for id := range wanted {
			if _, present := localByID[id]; present {
				if space == "node_id" {
					audit.IDPresent++
				} else {
					audit.NamePresent++
				}
				continue
			}
			entry := globalByID[id]
			entry.placement = "missing_global_nearest_k"
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].space != entries[j].space {
			return entries[i].space < entries[j].space
		}
		if entries[i].expected != entries[j].expected {
			return entries[i].expected < entries[j].expected
		}
		if cmp := entries[i].distance.Cmp(entries[j].distance); cmp != 0 {
			return cmp < 0
		}
		return entries[i].peerID < entries[j].peerID
	})
	for _, entry := range entries {
		localBucket, localRank := "", ""
		if entry.inTable {
			localBucket, localRank = fmt.Sprint(entry.actual), fmt.Sprint(entry.localRank)
		}
		row := []string{capture, fmt.Sprint(censusSize), entry.owner, entry.ownerID, entry.space, localBucket,
			fmt.Sprint(entry.expected), fmt.Sprint(entry.globalRank), localRank, fmt.Sprintf("%064x", entry.distance),
			entry.peerName, entry.peerID, entry.peerHash, fmt.Sprint(entry.wanted), fmt.Sprint(entry.inTable), entry.placement}
		if err := w.csv.Write(row); err != nil {
			return audit, err
		}
	}
	return audit, nil
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
		return x, 0, true
	}
	return x, x.BitLen() - 1, true
}
