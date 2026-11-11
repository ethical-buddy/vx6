// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
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
	if _, _, ok := xorBucket(zero, zero); ok {
		t.Fatal("zero distance must not map to a peer bucket")
	}
	if _, _, ok := xorBucket("VX6_"+zero, peer); ok {
		t.Fatal("non-canonical uppercase coordinate must be rejected")
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

	writer, err := newRoutingMapWriter(t.TempDir(), "audit")
	if err != nil {
		t.Fatal(err)
	}
	checks, failures, err := writer.add("settle-0", makeDiagnostics(nameBucket))
	closeErr := writer.close()
	if err != nil || closeErr != nil || checks != 2 || failures != 0 {
		t.Fatalf("valid placements: checks=%d failures=%d add=%v close=%v", checks, failures, err, closeErr)
	}

	writer, err = newRoutingMapWriter(t.TempDir(), "bad-audit")
	if err != nil {
		t.Fatal(err)
	}
	wrongBucket := (nameBucket + 1) % 256
	checks, failures, err = writer.add("settle-0", makeDiagnostics(wrongBucket))
	closeErr = writer.close()
	if err != nil || closeErr != nil || checks != 2 || failures != 1 {
		t.Fatalf("misplaced name entry: checks=%d failures=%d add=%v close=%v", checks, failures, err, closeErr)
	}
}
