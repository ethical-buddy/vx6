package main

import (
	"strings"
	"testing"

	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/proto"
)

func TestIndependentXOROracleUsesFull256BitDistance(t *testing.T) {
	peers := []*peer{
		{info: proto.NodeInfo{ID: "vx6_" + strings.Repeat("0", 63) + "1", Name: "NODE-1", NameHash: strings.Repeat("0", 63) + "1"}},
		{info: proto.NodeInfo{ID: "vx6_" + strings.Repeat("0", 63) + "2", Name: "NODE-2", NameHash: strings.Repeat("0", 63) + "2"}},
		{info: proto.NodeInfo{ID: "vx6_" + strings.Repeat("0", 63) + "3", Name: "NODE-3", NameHash: strings.Repeat("0", 63) + "3"}},
	}
	got := independentTop(peers, strings.Repeat("0", 63)+"2", false, 3)
	if got[0].ID != peers[1].info.ID || got[1].ID != peers[2].info.ID || got[2].ID != peers[0].info.ID {
		t.Fatalf("ID XOR order = %v; expected exact full-hash order", []string{got[0].ID, got[1].ID, got[2].ID})
	}
	nameGot := independentTop(peers, strings.Repeat("0", 63)+"1", true, 3)
	if nameGot[0].ID != peers[0].info.ID {
		t.Fatalf("name-hash XOR nearest = %s, want %s", nameGot[0].ID, peers[0].info.ID)
	}
}

func TestBucketPlacementAuditDetectsWrongBucket(t *testing.T) {
	self := "vx6_" + strings.Repeat("0", 63) + "1"
	peerID := "vx6_" + strings.Repeat("0", 63) + "3"
	correct := dht.DiagnosticIndex{Space: "node_id", Buckets: []dht.DiagnosticBucket{{Index: 1, Peers: []dht.DiagnosticPeer{{NodeID: peerID}}}}}
	if got := bucketPlacementErrors(correct, self); got != 0 {
		t.Fatalf("correct bucket reported %d errors", got)
	}
	correct.Buckets[0].Index = 0
	if got := bucketPlacementErrors(correct, self); got != 1 {
		t.Fatalf("misplaced peer reported %d errors, want one", got)
	}
}

func TestTopRecallCountsOverlapAgainstOracle(t *testing.T) {
	want := []proto.NodeInfo{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
	got := []proto.NodeInfo{{ID: "a"}, {ID: "c"}, {ID: "x"}}
	if score := topRecall(got, want); score != 50 {
		t.Fatalf("recall = %.1f%%, want 50%%", score)
	}
}

func TestDetailedArtifactsAreRecognizedForAbsoluteAndRelativePaths(t *testing.T) {
	for _, path := range []string{
		"/tmp/vx6-run/lookups/000001.json",
		"/tmp/vx6-run/join/000001.json",
		"/tmp/vx6-run/snapshots/all-nodes.json",
		"lookups/index.json",
	} {
		if !detailedArtifactPath(path) {
			t.Errorf("detailed artifact path not recognized: %s", path)
		}
	}
	for _, path := range []string{"report.json", "/tmp/vx6-run/host.json"} {
		if detailedArtifactPath(path) {
			t.Errorf("summary artifact should remain uncompressed: %s", path)
		}
	}
}

func TestSummarySeparatesIncompleteMatchesFromNegativeControls(t *testing.T) {
	rows := []lookupSample{
		{Space: "node_id", FoundTarget: true, Outcome: string(dht.LookupFound)},
		{Space: "name_hash", FoundTarget: true, Outcome: string(dht.LookupIncomplete)},
		{Space: "node_id", NegativeTarget: true, Outcome: string(dht.LookupNotFound)},
	}
	m := summarize(3, rows, nil, 0, 0, 0)
	if m.Found != 2 || m.FoundComplete != 1 || m.FoundIncomplete != 1 {
		t.Fatalf("positive summary = found %d complete %d incomplete %d", m.Found, m.FoundComplete, m.FoundIncomplete)
	}
	if m.NegativeLookups != 1 || m.NegativeNotFound != 1 || m.NegativeFalsePositive != 0 {
		t.Fatalf("negative-control summary = %+v", m)
	}
	if m.IDLookupCompleteFound != 1 || m.NameLookupCompleteFound != 0 {
		t.Fatalf("per-coordinate complete-found summary = ID %d, name %d", m.IDLookupCompleteFound, m.NameLookupCompleteFound)
	}
}
