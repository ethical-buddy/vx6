// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"compress/gzip"
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/vx6/vx6/internal/dht"
)

func TestXorBucketMatchesRoutingTableBitRange(t *testing.T) {
	zero := "0000000000000000000000000000000000000000000000000000000000000000"
	peer := "8000000000000000000000000000000000000000000000000000000000000000"
	distance, bucket, ok := xorBucket(zero, peer)
	if !ok || bucket != 255 || distance.Text(16) != peer {
		t.Fatalf("bucket=%d distance=%x ok=%t", bucket, distance, ok)
	}
	if distance, bucket, ok := xorBucket(zero, zero); !ok || bucket != 0 || distance.Sign() != 0 {
		t.Fatalf("zero name-hash distance must use bucket zero: bucket=%d distance=%x ok=%t", bucket, distance, ok)
	}
	if _, _, ok := xorBucket("VX6_"+zero, peer); ok {
		t.Fatal("non-canonical uppercase coordinate must be rejected")
	}
}

func TestRoutingMapReportsMissingGlobalNearestPeers(t *testing.T) {
	selfID := "vx6_0000000000000000000000000000000000000000000000000000000000000000"
	peerID := "vx6_8000000000000000000000000000000000000000000000000000000000000000"
	self := NodeDiagnostics{Name: "SELF", NodeID: selfID}
	self.DHT.Table.SelfID = selfID
	self.DHT.Table.SelfNameHash = dht.NodeNameHash("SELF")
	peer := NodeDiagnostics{Name: "PEER", NodeID: peerID}
	peer.DHT.Table.SelfID = peerID
	peer.DHT.Table.SelfNameHash = dht.NodeNameHash("PEER")

	dir := t.TempDir()
	writer, err := newRoutingMapWriter(dir, "idle")
	if err != nil {
		t.Fatal(err)
	}
	audits, err := writer.addCapture("idle", []NodeDiagnostics{self, peer})
	closeErr := writer.close()
	if err != nil || closeErr != nil {
		t.Fatalf("write census map: add=%v close=%v", err, closeErr)
	}
	if got := audits["SELF"]; got.IDExpected != 1 || got.IDPresent != 0 || got.NameExpected != 1 || got.NamePresent != 0 {
		t.Fatalf("missing global contacts not reported: %+v", got)
	}

	f, err := os.Open(filepath.Join(dir, "routing-map", "idle.csv.gz"))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(zr).ReadAll()
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	_ = zr.Close()
	_ = f.Close()
	missingRows := 0
	for _, row := range rows[1:] {
		if row[len(row)-1] == "missing_global_nearest_k" {
			missingRows++
		}
	}
	if missingRows != 4 {
		t.Fatalf("map has %d missing-contact rows, want 4", missingRows)
	}
}

func TestRoutingMapAuditsBothIndexesAndRejectsMisplacedPeer(t *testing.T) {
	selfID := "vx6_0000000000000000000000000000000000000000000000000000000000000000"
	peerID := "vx6_8000000000000000000000000000000000000000000000000000000000000000"
	nameHash := dht.NodeNameHash("PEER")
	selfNameHash := dht.NodeNameHash("SELF")
	_, idBucket, ok := xorBucket(selfID, peerID)
	if !ok {
		t.Fatal("test fixture has invalid ID coordinates")
	}
	_, nameBucket, ok := xorBucket(selfNameHash, nameHash)
	if !ok {
		t.Fatal("test fixture has invalid name coordinates")
	}

	makeDiagnostics := func(actualNameBucket int) NodeDiagnostics {
		var diag NodeDiagnostics
		diag.Name, diag.NodeID = "SELF", selfID
		diag.DHT.Table.SelfID = selfID
		diag.DHT.Table.SelfNameHash = selfNameHash
		diag.DHT.Table.IDIndex.Buckets = []DiagnosticBucketHead{{Index: idBucket, Peers: []DiagnosticPeerHead{{Name: "PEER", NodeID: peerID, NameHash: nameHash}}}}
		diag.DHT.Table.NameIndex.Buckets = []DiagnosticBucketHead{{Index: actualNameBucket, Peers: []DiagnosticPeerHead{{Name: "PEER", NodeID: peerID, NameHash: nameHash}}}}
		return diag
	}

	self := makeDiagnostics(nameBucket)
	peer := NodeDiagnostics{Name: "PEER", NodeID: peerID}
	peer.DHT.Table.SelfID = peerID
	peer.DHT.Table.SelfNameHash = nameHash
	writer, err := newRoutingMapWriter(t.TempDir(), "audit")
	if err != nil {
		t.Fatal(err)
	}
	audits, err := writer.addCapture("settle-0", []NodeDiagnostics{self, peer})
	closeErr := writer.close()
	if err != nil || closeErr != nil {
		t.Fatalf("valid placements: add=%v close=%v", err, closeErr)
	}
	if got := audits["SELF"]; got.Checks != 2 || got.Failures != 0 || got.IDExpected != 1 || got.IDPresent != 1 || got.NameExpected != 1 || got.NamePresent != 1 {
		t.Fatalf("valid local/global audit: %+v", got)
	}

	writer, err = newRoutingMapWriter(t.TempDir(), "bad-audit")
	if err != nil {
		t.Fatal(err)
	}
	wrongBucket := (nameBucket + 1) % 256
	audits, err = writer.addCapture("settle-0", []NodeDiagnostics{makeDiagnostics(wrongBucket), peer})
	closeErr = writer.close()
	if err != nil || closeErr != nil {
		t.Fatalf("misplaced name entry: add=%v close=%v", err, closeErr)
	}
	if got := audits["SELF"]; got.Checks != 2 || got.Failures != 1 || got.NameExpected != 1 || got.NamePresent != 1 {
		t.Fatalf("misplaced local bucket audit: %+v", got)
	}
}
