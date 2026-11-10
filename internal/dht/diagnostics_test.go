package dht

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
)

func TestLookupTraceRecordsRoundsWithoutChangingResult(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	const seedCount, branch = 3, 3
	const peerCount = seedCount + seedCount*branch
	infos := make([]proto.NodeInfo, peerCount)
	servers := make([]*Server, peerCount)
	now := time.Now().UTC()
	for i := range servers {
		id, err := identity.Generate()
		if err != nil {
			t.Fatal(err)
		}
		servers[i] = newTestServerWithIdentity(id)
		addr := startDHTListener(t, ctx, servers[i])
		rec, err := record.NewEndpointRecordV2(id, fmt.Sprintf("TRACE-%02d", i), addr, 1, time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		infos[i] = NodeInfoFromEndpointRecord(rec)
	}
	for i := 0; i < seedCount; i++ {
		for j := 0; j < branch; j++ {
			servers[i].RT.AddNode(infos[seedCount+i*branch+j])
		}
	}
	target := "node/id/" + infos[peerCount-1].ID

	plainClient := newTestServer("plain-client")
	tracedClient := newTestServer("traced-client")
	for i := 0; i < seedCount; i++ {
		plainClient.RT.AddNode(infos[i])
		tracedClient.RT.AddNode(infos[i])
	}
	plain, plainErr := plainClient.RecursiveFindNodeDetailed(ctx, target)
	trace := &LookupTrace{}
	traced, tracedErr := tracedClient.RecursiveFindNodeDetailed(WithLookupTrace(ctx, trace), target)

	if (plainErr == nil) != (tracedErr == nil) || plain.Outcome != traced.Outcome || len(plain.Matches) != len(traced.Matches) {
		t.Fatalf("trace changed the lookup: plain=%+v/%v traced=%+v/%v", plain, plainErr, traced, tracedErr)
	}
	if traced.Outcome != LookupFound {
		t.Fatalf("expected the two-hop target to be found, got %s (%v)", traced.Outcome, tracedErr)
	}
	if trace.Space != "node_id" || len(trace.Seeds) != seedCount {
		t.Fatalf("trace seeds/space: %+v", trace)
	}
	if len(trace.Rounds) == 0 || len(trace.Rounds) != traced.Rounds {
		t.Fatalf("trace has %d rounds, lookup reported %d", len(trace.Rounds), traced.Rounds)
	}
	queries, sawMatch := 0, false
	for _, round := range trace.Rounds {
		queries += len(round.Queries)
		for _, query := range round.Queries {
			if query.Result != "ok" {
				t.Fatalf("unexpected query result in healthy mesh: %+v", query)
			}
			for _, contact := range query.Returned {
				sawMatch = sawMatch || contact.Match
			}
		}
	}
	if queries != traced.QueriedNodes || trace.Queries != traced.QueriedNodes {
		t.Fatalf("trace counted %d/%d queries, lookup reported %d", queries, trace.Queries, traced.QueriedNodes)
	}
	if !sawMatch || trace.StopReason != "target found" {
		t.Fatalf("trace did not record the match/stop reason: match=%v reason=%q", sawMatch, trace.StopReason)
	}
}

func TestDiagnosticsAreReadOnlyAndCoverBothIndexes(t *testing.T) {
	srv := newTestServer("diag-self")
	store, err := OpenPeerStore(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := srv.AttachValuePersistence(store, time.Now()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 4; i++ {
		id, err := identity.Generate()
		if err != nil {
			t.Fatal(err)
		}
		rec, err := record.NewEndpointRecordV2(id, fmt.Sprintf("DIAG-%02d", i), fmt.Sprintf("[2001:db8::%x]:4242", i+1), 1, time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		srv.RT.AddNode(NodeInfoFromEndpointRecord(rec))
	}
	if err := store.SaveSnapshot(srv.RT.SnapshotPeers(), now); err != nil {
		t.Fatal(err)
	}
	before := srv.RT.SnapshotPeers()

	diag := srv.Diagnostics(now)

	after := srv.RT.SnapshotPeers()
	if len(before) != len(after) {
		t.Fatalf("diagnostics changed the table: %d -> %d peers", len(before), len(after))
	}
	if diag.Table.Active != 4 || diag.Table.IDIndex.Entries != 4 || diag.Table.NameIndex.Entries != 4 {
		t.Fatalf("expected 4 entries in both XOR indexes: %+v", diag.Table)
	}
	if diag.Table.IDIndex.NonEmptyBuckets == 0 || diag.Table.NameIndex.NonEmptyBuckets == 0 {
		t.Fatalf("missing bucket occupancy: %+v", diag.Table)
	}
	if diag.Table.Capacity.K != K || diag.Table.Capacity.WarmStartFloor != minimumPeerWarmStart {
		t.Fatalf("capacity policy: %+v", diag.Table.Capacity)
	}
	if diag.Store == nil || diag.Store.PeerRows != 4 || len(diag.Store.Categories["active"]) != 4 {
		t.Fatalf("store diagnostics from the attached store: %+v (err %q)", diag.Store, diag.StoreError)
	}
	if diag.Store.Source != "bbolt" || diag.Table.Source != "memory" {
		t.Fatalf("sources not labelled: %q %q", diag.Store.Source, diag.Table.Source)
	}
}
