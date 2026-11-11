// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestSelectOffTableProbesUsesEachXORIndex(t *testing.T) {
	nodes := []Node{{Name: "A"}, {Name: "B"}, {Name: "C"}}
	targets := map[string]offTableTarget{
		"A": {NodeID: "id-a", NameHash: "hash-a", Name: "A"},
		"B": {NodeID: "id-b", NameHash: "hash-b", Name: "B"},
		"C": {NodeID: "id-c", NameHash: "hash-c", Name: "C"},
	}
	var a NodeDiagnostics
	a.DHT.Table.IDIndex.Buckets = []DiagnosticBucketHead{{Peers: []DiagnosticPeerHead{{NodeID: "id-b"}}}}
	a.DHT.Table.NameIndex.Buckets = []DiagnosticBucketHead{{Peers: []DiagnosticPeerHead{{NameHash: "hash-c"}}}}
	var b NodeDiagnostics
	b.DHT.Table.IDIndex.Buckets = []DiagnosticBucketHead{{Peers: []DiagnosticPeerHead{{NodeID: "id-a"}}}}
	b.DHT.Table.NameIndex.Buckets = []DiagnosticBucketHead{{Peers: []DiagnosticPeerHead{{NameHash: "hash-a"}}}}
	selected := selectOffTableProbes(nodes, targets, map[string]NodeDiagnostics{"A": a, "B": b})
	if len(selected) != 4 {
		t.Fatalf("selected %d off-table queries, want 4: %+v", len(selected), selected)
	}
	want := map[string]bool{"A/id/C": true, "A/name/B": true, "B/id/C": true, "B/name/C": true}
	for _, probe := range selected {
		key := probe.Source.Name + "/" + probe.Type + "/" + probe.Target.Name
		if !want[key] {
			t.Errorf("unexpected off-table query %q", key)
		}
		delete(want, key)
	}
	for key := range want {
		t.Errorf("missing off-table query %q", key)
	}
}

func TestOffTableCountsAppearInJSONAndMarkdown(t *testing.T) {
	dir := t.TempDir()
	report := &Report{OffTableLookups: true, LookupMode: LookupModeSample,
		Rounds: []RoundReport{{Label: "settle-0", OffTableQueriesAvailable: 17,
			OffTableQueriesSelected: 8, OffTableStatusErrors: 1, OffTableDiagnosticErrors: 2}}}
	if err := writeReportFiles(dir, report); err != nil {
		t.Fatal(err)
	}
	jsonData, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"off_table_lookups": true`, `"off_table_queries_available": 17`, `"off_table_queries_selected": 8`} {
		if !strings.Contains(string(jsonData), field) {
			t.Errorf("report.json missing %s", field)
		}
	}
	markdown, err := os.ReadFile(filepath.Join(dir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(markdown), "8/17") || !strings.Contains(string(markdown), "1/2") {
		t.Fatalf("Markdown report does not show off-table denominators and preflight errors:\n%s", markdown)
	}
}

func TestCoverageDoesNotClaimOffTableLookupWithoutEligibleQueries(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selected int
		want     string
	}{{"none eligible", 0, "NOT EXERCISED"}, {"queries selected", 3, "EXERCISED"}} {
		t.Run(tc.name, func(t *testing.T) {
			items := coverage(&Report{OffTableLookups: true, Rounds: []RoundReport{{OffTableQueriesSelected: tc.selected}}})
			for _, item := range items {
				if item.name == "Lookup of targets absent from the corresponding local XOR index" {
					if item.status != tc.want {
						t.Fatalf("status %q, want %q", item.status, tc.want)
					}
					return
				}
			}
			t.Fatal("off-table coverage row missing")
		})
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
