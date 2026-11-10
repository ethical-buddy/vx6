// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAnnotatePeersAddsASNAndPrefix(t *testing.T) {
	var doc any
	raw := `{"dht":{"table":{"node_id_index":{"buckets":[{"index":3,"peers":[
		{"node_id":"vx6_a","addr":"[2001:db8:300:1::11]:4242"},
		{"node_id":"vx6_b","addr":"[2001:db8:900:1::11]:4242"}]}]}}}}`
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	annotatePeers(doc, map[string]uint32{"2001:db8:300:1::11": 64514})
	peers := doc.(map[string]any)["dht"].(map[string]any)["table"].(map[string]any)["node_id_index"].(map[string]any)["buckets"].([]any)[0].(map[string]any)["peers"].([]any)
	first, second := peers[0].(map[string]any), peers[1].(map[string]any)
	if first["asn"] != uint32(64514) || first["prefix_48"] != "2001:db8:300::/48" {
		t.Fatalf("first peer not annotated: %v", first)
	}
	if _, ok := second["asn"]; ok || second["prefix_48"] != "2001:db8:900::/48" {
		t.Fatalf("unknown address must get a prefix but no ASN: %v", second)
	}
}

func TestSummarizeDiagnosticsCountsBothIndexesAndStore(t *testing.T) {
	raw := `{"name":"N1","node_id":"vx6_1","rss_kb":2048,"dht":{
		"table":{"active":2,"offline":1,"pending":3,
			"node_id_index":{"entries":2,"non_empty_buckets":2,"buckets":[{"peers":[{"in_probation":true}]},{"peers":[{"in_probation":false}]}]},
			"name_hash_index":{"entries":2,"non_empty_buckets":1},
			"capacity_policy":{"k":20,"max_pending_candidates":512,"warm_start_candidates":50},
			"offline_peers":[{"in_probation":true}]},
		"store":{"peer_rows":3,"categories":{"active":["a","b"],"inactive":["c"],"probation":["a"],"closest-id":["a"],"closest-name":["b"]},
			"values":[{"valid":true},{"valid":false}]},
		"cached_values":4}}`
	var diag NodeDiagnostics
	if err := json.Unmarshal([]byte(raw), &diag); err != nil {
		t.Fatal(err)
	}
	got := summarizeDiagnostics("settle-0", diag)
	want := NodeRoundSummary{Name: "N1", Label: "settle-0", Active: 2, Offline: 1, Pending: 3, InProbation: 2,
		IDBuckets: 2, NameBuckets: 1, StoreRows: 3, StoreActive: 2, StoreInactive: 1, StoreProbation: 1,
		StoreClosestID: 1, StoreClosestName: 1, StoreValues: 2, StoreValidValues: 1, CachedValues: 4, RSSKB: 2048}
	got.capacity, got.capacityCaptured = CapacityPolicy{}, false
	if got != want {
		t.Fatalf("summary\n got %+v\nwant %+v", got, want)
	}
}

func TestAttachSourceStatsSeparatesOutcomes(t *testing.T) {
	nodes := []NodeRoundSummary{{Name: "A"}, {Name: "B"}}
	attachSourceStats(nodes, []LookupReport{
		{Source: "A", Found: true, Outcome: "found_verified"},
		{Source: "A", Outcome: "incomplete", Error: "dht lookup incomplete"},
		{Source: "A", Outcome: "not_found_reachable"},
		{Source: "B", Outcome: "admin_error", Error: "socket"},
		{Source: "Z", Found: true},
	})
	if a := nodes[0]; a.LookupsAsSource != 3 || a.FoundAsSource != 1 || a.IncompleteAsSource != 1 || a.NotFoundAsSource != 1 {
		t.Fatalf("A: %+v", a)
	}
	if b := nodes[1]; b.LookupsAsSource != 1 || b.IncompleteAsSource != 1 {
		t.Fatalf("B: %+v", b)
	}
}

func TestIdleSampleAggregates(t *testing.T) {
	sample := idleSample("idle-01", time.Minute, []NodeRoundSummary{
		{Name: "A", Active: 3, Offline: 1, Pending: 2, InProbation: 1, StoreRows: 4, StoreInactive: 1},
		{Name: "B", Active: 1, StoreRows: 2},
		{Name: "C", CaptureError: "gone"},
	})
	if sample.TotalActive != 4 || sample.MinActive != 1 || sample.MaxActive != 3 || sample.TotalOffline != 1 ||
		sample.TotalPending != 2 || sample.TotalProbation != 1 || sample.StoreRows != 6 || sample.StoreInactive != 1 ||
		sample.CaptureErrors != 1 || sample.ElapsedSec != 60 {
		t.Fatalf("idle sample: %+v", sample)
	}
}

func TestMeasurementOptionsAndLookupMode(t *testing.T) {
	if err := validateMeasurementOptions("auto", 15*time.Minute, time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		mode         string
		idle, period time.Duration
	}{{"all", 0, time.Minute}, {"auto", -time.Second, time.Minute}, {"auto", time.Minute, time.Second}, {"auto", time.Minute, 2 * time.Minute}} {
		if err := validateMeasurementOptions(bad.mode, bad.idle, bad.period); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	small := &SimRun{t: &Topology{Nodes: make([]Node, 10)}, lookupMode: LookupModeAuto}
	large := &SimRun{t: &Topology{Nodes: make([]Node, 11)}, lookupMode: LookupModeAuto}
	forced := &SimRun{t: &Topology{Nodes: make([]Node, 3)}, lookupMode: LookupModeSample}
	if small.effectiveLookupMode() != LookupModeExhaustive || large.effectiveLookupMode() != LookupModeSample || forced.effectiveLookupMode() != LookupModeSample {
		t.Fatal("auto lookup mode must be exhaustive up to 10 nodes and sample above; explicit modes are kept")
	}
}
