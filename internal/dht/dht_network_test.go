package dht

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
)

func newTestServer(nodeID string) *Server {
	server := NewServer(nodeID)
	server.SetDialGuard(func(context.Context, string) error { return nil })
	return server
}

func newTestServerWithIdentity(id identity.Identity) *Server {
	server := NewServerWithIdentity(id)
	server.SetDialGuard(func(context.Context, string) error { return nil })
	return server
}

func TestRecursiveFindValueAcrossPeers(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newTestServer("client-node")
	bob := newTestServer("bob-node")
	charlie := newTestServer("charlie-node")

	bobAddr := startDHTListener(t, ctx, bob)
	charlieAddr := startDHTListener(t, ctx, charlie)

	client.RT.AddNode(proto.NodeInfo{ID: "bob-node", Addr: bobAddr})
	client.RT.AddNode(proto.NodeInfo{ID: "charlie-node", Addr: charlieAddr})

	ownerID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate owner identity: %v", err)
	}
	rec := mustServiceRecordForIdentity(t, ownerID, "surya", "echo", "[2001:db8::10]:4242", false, "", time.Now())
	payload := mustJSON(t, rec)
	signed := mustSignedValue(t, ownerID, ServiceKey("surya.echo"), payload, time.Now())

	bob.StoreLocal(ServiceKey("surya.echo"), signed)
	charlie.StoreLocal(ServiceKey("surya.echo"), signed)

	got, err := client.RecursiveFindValueDetailed(ctx, ServiceKey("surya.echo"))
	if err != nil {
		t.Fatalf("recursive find value: %v", err)
	}

	var decoded record.ServiceRecord
	if err := json.Unmarshal([]byte(got.Value), &decoded); err != nil {
		t.Fatalf("decode returned record: %v", err)
	}
	if decoded.ServiceName != "echo" || decoded.NodeName != "surya" {
		t.Fatalf("unexpected resolved record: %+v", decoded)
	}
	if !got.Verified || got.ExactMatchCount < 2 || got.TrustWeight < minTrustedConfirmationScore {
		t.Fatalf("unexpected lookup result: %+v", got)
	}
}

func TestStoreReplicatesAcrossBoundedPeers(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ownerID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate owner identity: %v", err)
	}
	owner := newTestServerWithIdentity(ownerID)

	type target struct {
		server *Server
		addr   string
	}
	targets := make([]target, 0, 8)
	for i := 0; i < 8; i++ {
		srv := newTestServer(fmt.Sprintf("replica-%02d", i))
		addr := startDHTListener(t, ctx, srv)
		targets = append(targets, target{server: srv, addr: addr})
		owner.RT.AddNode(proto.NodeInfo{ID: fmt.Sprintf("replica-node-%02d", i), Addr: addr})
	}

	rec := mustServiceRecordForIdentity(t, ownerID, "bob", "chat", "[2001:db8::20]:4242", false, "", time.Now())
	payload := mustJSON(t, rec)

	if err := owner.Store(ctx, ServiceKey("bob.chat"), payload); err != nil {
		t.Fatalf("store: %v", err)
	}

	replicated := 0
	for _, target := range targets {
		target.server.mu.RLock()
		got := target.server.Values[ServiceKey("bob.chat")]
		target.server.mu.RUnlock()
		if got != "" {
			replicated++
			if _, ok, err := maybeDecodeEnvelope(got); err != nil || !ok {
				t.Fatalf("expected signed envelope at replica, got ok=%v err=%v", ok, err)
			}
		}
	}
	if replicated != replicationFactor {
		t.Fatalf("expected replication to %d peers, got %d", replicationFactor, replicated)
	}
}

func TestMaintainReplicasRepairsShortfallUsingBackupNodes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ownerID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate owner identity: %v", err)
	}
	owner := newTestServerWithIdentity(ownerID)
	key := ServiceKey("owner.echo")

	planned := NewRoutingTable(ownerID.NodeID)
	plannedNodes := make([]proto.NodeInfo, 0, 8)
	for i := 0; i < 8; i++ {
		plannedNodes = append(plannedNodes, proto.NodeInfo{
			ID:   fmt.Sprintf("replica-node-%02d", i),
			Addr: fmt.Sprintf("[::1]:%d", 40000+i),
		})
		planned.AddNode(plannedNodes[len(plannedNodes)-1])
	}
	candidates := selectReplicationNodes(planned.ClosestNodes(key, K), K)
	deadIDs := map[string]struct{}{}
	for _, node := range candidates[:2] {
		deadIDs[node.ID] = struct{}{}
	}

	type target struct {
		id     string
		server *Server
		addr   string
	}
	targets := make([]target, 0, len(plannedNodes))
	liveTargets := map[string]*Server{}
	for _, node := range plannedNodes {
		addr := reserveClosedTCP6Addr(t)
		var srv *Server
		if _, dead := deadIDs[node.ID]; !dead {
			srv = newTestServer(node.ID)
			addr = startDHTListener(t, ctx, srv)
			liveTargets[node.ID] = srv
		}
		targets = append(targets, target{id: node.ID, server: srv, addr: addr})
		owner.RT.AddNode(proto.NodeInfo{ID: node.ID, Addr: addr})
	}

	rec := mustServiceRecordForIdentity(t, ownerID, "owner", "echo", "[2001:db8::30]:4242", false, "", time.Now())
	report, err := owner.MaintainReplicas(ctx, key, mustJSON(t, rec))
	if err != nil {
		t.Fatalf("maintain replicas: %v", err)
	}
	if report.StoredRemotely != replicationFactor {
		t.Fatalf("expected repaired remote replica count %d, got %+v", replicationFactor, report)
	}
	if report.Attempted <= replicationFactor || len(report.Failed) < 2 {
		t.Fatalf("expected fallback attempts after dead replicas, got %+v", report)
	}

	replicated := 0
	for _, srv := range liveTargets {
		srv.mu.RLock()
		got := srv.Values[key]
		srv.mu.RUnlock()
		if got != "" {
			replicated++
		}
	}
	if replicated != replicationFactor {
		t.Fatalf("expected repaired value on %d live replicas, got %d", replicationFactor, replicated)
	}
}

func TestMaintainReplicasSeedsNewPreferredHoldersAfterRoutingChange(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ownerID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate owner identity: %v", err)
	}
	owner := newTestServerWithIdentity(ownerID)
	key := ServiceKey("owner.api")

	type target struct {
		id     string
		server *Server
		addr   string
	}
	targets := map[string]target{}
	baseNodes := make([]proto.NodeInfo, 0, 8)
	for i := 0; i < 8; i++ {
		id := fmt.Sprintf("base-node-%02d", i)
		srv := newTestServer(id)
		addr := startDHTListener(t, ctx, srv)
		node := proto.NodeInfo{ID: id, Addr: addr}
		baseNodes = append(baseNodes, node)
		targets[id] = target{id: id, server: srv, addr: addr}
		owner.RT.AddNode(node)
	}

	rec := mustServiceRecordForIdentity(t, ownerID, "owner", "api", "[2001:db8::41]:4242", false, "", time.Now())
	if _, err := owner.MaintainReplicas(ctx, key, mustJSON(t, rec)); err != nil {
		t.Fatalf("seed initial replicas: %v", err)
	}

	selectedBefore := selectedNodeIDs(selectReplicationNodes(owner.RT.ClosestNodes(key, K), replicationFactor))
	newNodes := findNewPreferredNodes(t, ownerID.NodeID, key, baseNodes, 2)
	if len(newNodes) != 2 {
		t.Fatalf("expected to find 2 new preferred nodes, got %d", len(newNodes))
	}
	for _, node := range newNodes {
		srv := newTestServer(node.ID)
		addr := startDHTListener(t, ctx, srv)
		node.Addr = addr
		targets[node.ID] = target{id: node.ID, server: srv, addr: addr}
		owner.RT.AddNode(node)
	}

	report, err := owner.MaintainReplicas(ctx, key, mustJSON(t, rec))
	if err != nil {
		t.Fatalf("repair replicas after routing change: %v", err)
	}
	if report.StoredRemotely != replicationFactor {
		t.Fatalf("expected full replication after routing change, got %+v", report)
	}

	selectedAfterNodes := selectReplicationNodes(owner.RT.ClosestNodes(key, K), replicationFactor)
	selectedAfter := selectedNodeIDs(selectedAfterNodes)
	if sameStringSet(selectedBefore, selectedAfter) {
		t.Fatalf("expected preferred replica set to change after adding better nodes: before=%v after=%v", selectedBefore, selectedAfter)
	}
	for _, node := range newNodes {
		if _, ok := selectedAfter[node.ID]; !ok {
			t.Fatalf("expected new node %s to join preferred replica set: %v", node.ID, selectedAfter)
		}
	}
	for _, node := range selectedAfterNodes {
		srv := targets[node.ID].server
		srv.mu.RLock()
		got := srv.Values[key]
		srv.mu.RUnlock()
		if got == "" {
			t.Fatalf("expected preferred holder %s to receive refreshed replica", node.ID)
		}
	}
}

func TestReplicaSummaryTracksRefreshHealth(t *testing.T) {
	t.Parallel()

	server := newTestServer("self")
	now := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)

	server.RecordReplicaObservation(ReplicaObservation{
		Key:            "service/public-ok",
		Kind:           ReplicaKindPublicService,
		Subject:        "owner.web",
		Desired:        5,
		StoredRemotely: 5,
		LocalStored:    true,
		PublishedAt:    now,
		RefreshBy:      now.Add(10 * time.Second),
		ExpiresAt:      now.Add(20 * time.Minute),
	})
	server.RecordReplicaObservation(ReplicaObservation{
		Key:            "hidden-desc/v1/1/a",
		Kind:           ReplicaKindHiddenDescriptor,
		Subject:        "ghost",
		Epoch:          1,
		Desired:        5,
		StoredRemotely: 4,
		LocalStored:    true,
		PublishedAt:    now,
		RefreshBy:      now.Add(10 * time.Second),
		ExpiresAt:      now.Add(20 * time.Minute),
	})
	server.RecordReplicaObservation(ReplicaObservation{
		Key:            "hidden-desc/v1/0/b",
		Kind:           ReplicaKindHiddenDescriptor,
		Subject:        "ghost",
		Epoch:          0,
		Desired:        5,
		StoredRemotely: 5,
		LocalStored:    true,
		PublishedAt:    now.Add(-20 * time.Second),
		RefreshBy:      now.Add(-5 * time.Second),
		ExpiresAt:      now.Add(20 * time.Minute),
	})

	summary := server.ReplicaSummary(now, 10*time.Second)
	if summary.Tracked != 3 || summary.Healthy != 1 || summary.Degraded != 1 || summary.Stale != 1 {
		t.Fatalf("unexpected summary counts %+v", summary)
	}
	if summary.HiddenDescriptors != 2 || summary.HiddenDegraded != 1 || summary.HiddenStale != 1 {
		t.Fatalf("unexpected hidden summary counts %+v", summary)
	}
	if summary.HiddenPublishOverlapKey != 2 || summary.HiddenRotation != hiddenDescriptorRotation {
		t.Fatalf("unexpected hidden descriptor policy %+v", summary)
	}
}

func TestAdmitStoreValueRejectsUnsignedTrustedKey(t *testing.T) {
	t.Parallel()

	now := time.Now()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	server := newTestServerWithIdentity(id)
	rec := mustServiceRecordForIdentity(t, id, "owner", "api", "[2001:db8::61]:4242", false, "", now)
	if err := server.admitStoreValue("[2001:db8::10]:4242", ServiceKey("owner.api"), mustJSON(t, rec), now); err == nil {
		t.Fatal("expected unsigned trusted store to be rejected")
	}
}

func TestAdmitStoreValueRejectsNonAuthoritativePublisher(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ownerID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate owner identity: %v", err)
	}
	republisherID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate republisher identity: %v", err)
	}
	server := newTestServerWithIdentity(ownerID)
	rec := mustServiceRecordForIdentity(t, ownerID, "owner", "api", "[2001:db8::61]:4242", false, "", now)
	payload := mustJSON(t, rec)

	info, err := validateInnerLookupValue(ServiceKey("owner.api"), payload, now)
	if err != nil {
		t.Fatalf("validate payload: %v", err)
	}
	wrapped, err := wrapSignedEnvelope(republisherID, ServiceKey("owner.api"), payload, info, now)
	if err != nil {
		t.Fatalf("wrap signed envelope: %v", err)
	}
	if err := server.admitStoreValue("[2001:db8::10]:4242", ServiceKey("owner.api"), wrapped, now); err == nil {
		t.Fatal("expected non-authoritative publisher to be rejected")
	}
}

func TestPrivateCatalogRoundTripAndLookup(t *testing.T) {
	t.Parallel()

	now := time.Now()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	private := mustServiceRecordForIdentity(t, id, "owner", "admin", "[2001:db8::77]:4242", false, "", now)
	private.IsPrivate = true
	if err := record.SignServiceRecord(id, &private); err != nil {
		t.Fatalf("sign private service: %v", err)
	}
	catalog, err := NewPrivateServiceCatalog(id, "owner", []record.ServiceRecord{private}, 10*time.Minute, now)
	if err != nil {
		t.Fatalf("new private catalog: %v", err)
	}
	data, err := json.Marshal(catalog)
	if err != nil {
		t.Fatalf("marshal private catalog: %v", err)
	}

	decoded, err := DecodePrivateServiceCatalog(string(data), now)
	if err != nil {
		t.Fatalf("decode private catalog: %v", err)
	}
	if len(decoded.Services) != 1 || decoded.Services[0].ServiceName != "admin" {
		t.Fatalf("unexpected private catalog contents %+v", decoded)
	}

	server := newTestServerWithIdentity(id)
	wrapped := mustSignedValue(t, id, PrivateCatalogKey("owner"), string(data), now)
	if err := server.Store(context.Background(), PrivateCatalogKey("owner"), string(data)); err != nil {
		t.Fatalf("store private catalog: %v", err)
	}
	if _, err := validateLookupValue(PrivateCatalogKey("owner"), wrapped, now); err != nil {
		t.Fatalf("validate wrapped private catalog: %v", err)
	}
}

func TestLookupCollectorRequiresBranchDiversityForNonLoopbackSources(t *testing.T) {
	t.Parallel()

	now := time.Now()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	rec := mustEndpointRecordForIdentity(t, id, "owner", "[2001:db8::88]:4242", now)
	payload := mustSignedValue(t, id, NodeNameKey("owner"), mustJSON(t, rec), now)

	collector := newLookupCollector(NodeNameKey("owner"), now)
	collector.Observe(sourceObservation{nodeID: "a", addr: "198.51.100.1:4242", trust: 1, branch: 1}, payload)
	collector.Observe(sourceObservation{nodeID: "b", addr: "203.0.113.1:4242", trust: 1, branch: 1}, payload)
	if _, err := collector.Resolve(2); err == nil || !errors.Is(err, ErrInsufficientConfirmation) {
		t.Fatalf("expected insufficient confirmation without branch diversity, got %v", err)
	}

	collector = newLookupCollector(NodeNameKey("owner"), now)
	collector.Observe(sourceObservation{nodeID: "a", addr: "198.51.100.1:4242", trust: 1, branch: 1}, payload)
	collector.Observe(sourceObservation{nodeID: "b", addr: "203.0.113.1:4242", trust: 1, branch: 2}, payload)
	if _, err := collector.Resolve(2); err != nil {
		t.Fatalf("expected branch-diverse confirmation to succeed, got %v", err)
	}
}

func TestLookupCollectorRequiresProviderDiversityForNonLoopbackSources(t *testing.T) {
	t.Parallel()

	now := time.Now()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	rec := mustEndpointRecordForIdentity(t, id, "owner", "[2001:db8::99]:4242", now)
	payload := mustSignedValue(t, id, NodeNameKey("owner"), mustJSON(t, rec), now)

	collector := newLookupCollector(NodeNameKey("owner"), now)
	collector.Observe(sourceObservation{nodeID: "a", addr: "198.51.10.1:4242", trust: 1, branch: 1}, payload)
	collector.Observe(sourceObservation{nodeID: "b", addr: "198.51.20.1:4242", trust: 1, branch: 2}, payload)
	if _, err := collector.Resolve(2); err == nil || !errors.Is(err, ErrInsufficientConfirmation) {
		t.Fatalf("expected insufficient confirmation without provider diversity, got %v", err)
	}

	collector = newLookupCollector(NodeNameKey("owner"), now)
	collector.Observe(sourceObservation{nodeID: "a", addr: "198.51.10.1:4242", trust: 1, branch: 1}, payload)
	collector.Observe(sourceObservation{nodeID: "b", addr: "203.0.113.1:4242", trust: 1, branch: 2}, payload)
	if _, err := collector.Resolve(2); err != nil {
		t.Fatalf("expected provider-diverse confirmation to succeed, got %v", err)
	}
}

func TestRecursiveFindValueFiltersPoisonedValueAndUsesConfirmedRecord(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newTestServer("client-node")
	poison := newTestServer("poison-node")
	goodA := newTestServer("good-a")
	goodB := newTestServer("good-b")

	poisonAddr := startDHTListener(t, ctx, poison)
	goodAAddr := startDHTListener(t, ctx, goodA)
	goodBAddr := startDHTListener(t, ctx, goodB)

	client.RT.AddNode(proto.NodeInfo{ID: "poison-node", Addr: poisonAddr})
	client.RT.AddNode(proto.NodeInfo{ID: "good-a", Addr: goodAAddr})
	client.RT.AddNode(proto.NodeInfo{ID: "good-b", Addr: goodBAddr})

	ownerID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate owner identity: %v", err)
	}
	rec := mustEndpointRecordForIdentity(t, ownerID, "owner", "[2001:db8::42]:4242", time.Now())
	payload := mustJSON(t, rec)
	signed := mustSignedValue(t, ownerID, NodeNameKey("owner"), payload, time.Now())

	poison.StoreLocal(NodeNameKey("owner"), `{"node_name":"owner","address":"[2001:db8::666]:4242"}`)
	goodA.StoreLocal(NodeNameKey("owner"), signed)
	goodB.StoreLocal(NodeNameKey("owner"), signed)

	result, err := client.RecursiveFindValueDetailed(ctx, NodeNameKey("owner"))
	if err != nil {
		t.Fatalf("detailed find value: %v", err)
	}
	if result.Value != payload {
		t.Fatalf("unexpected resolved payload: %q", result.Value)
	}
	if !result.Verified || result.ExactMatchCount < 2 || result.RejectedValues == 0 {
		t.Fatalf("unexpected lookup result: %+v", result)
	}
}

func TestRecursiveFindValueRequiresMultiSourceConfirmation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newTestServer("client-node")
	good := newTestServer("good-node")

	goodAddr := startDHTListener(t, ctx, good)
	client.RT.AddNode(proto.NodeInfo{ID: "good-node", Addr: goodAddr})

	ownerID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate owner identity: %v", err)
	}
	rec := mustEndpointRecordForIdentity(t, ownerID, "solo", "[2001:db8::91]:4242", time.Now())
	payload := mustJSON(t, rec)
	good.StoreLocal(NodeNameKey("solo"), mustSignedValue(t, ownerID, NodeNameKey("solo"), payload, time.Now()))

	_, err = client.RecursiveFindValueDetailed(ctx, NodeNameKey("solo"))
	if err == nil || !errors.Is(err, ErrInsufficientConfirmation) {
		t.Fatalf("expected insufficient confirmation error, got %v", err)
	}
}

func TestRecursiveFindValueRejectsConflictingVerifiedValues(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newTestServer("client-node")
	left := newTestServer("left-node")
	right := newTestServer("right-node")

	leftAddr := startDHTListener(t, ctx, left)
	rightAddr := startDHTListener(t, ctx, right)

	client.RT.AddNode(proto.NodeInfo{ID: "left-node", Addr: leftAddr})
	client.RT.AddNode(proto.NodeInfo{ID: "right-node", Addr: rightAddr})

	leftID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate left identity: %v", err)
	}
	rightID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate right identity: %v", err)
	}

	leftRec := mustEndpointRecordForIdentity(t, leftID, "shared", "[2001:db8::51]:4242", time.Now())
	rightRec := mustEndpointRecordForIdentity(t, rightID, "shared", "[2001:db8::52]:4242", time.Now().Add(time.Second))
	left.StoreLocal(NodeNameKey("shared"), mustSignedValue(t, leftID, NodeNameKey("shared"), mustJSON(t, leftRec), time.Now()))
	right.StoreLocal(NodeNameKey("shared"), mustSignedValue(t, rightID, NodeNameKey("shared"), mustJSON(t, rightRec), time.Now().Add(time.Second)))

	_, err = client.RecursiveFindValueDetailed(ctx, NodeNameKey("shared"))
	if err == nil || !errors.Is(err, ErrConflictingValues) {
		t.Fatalf("expected conflicting value error, got %v", err)
	}
}

func TestStoreTracksNewestVersionAndPreviousHistory(t *testing.T) {
	t.Parallel()

	now := time.Now()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	server := newTestServerWithIdentity(id)

	older := mustServiceRecordForIdentity(t, id, "owner", "api", "[2001:db8::61]:4242", false, "", now)
	newer := mustServiceRecordForIdentity(t, id, "owner", "api", "[2001:db8::62]:4242", false, "", now.Add(time.Minute))

	if err := server.Store(context.Background(), ServiceKey("owner.api"), mustJSON(t, older)); err != nil {
		t.Fatalf("store older record: %v", err)
	}
	if err := server.Store(context.Background(), ServiceKey("owner.api"), mustJSON(t, newer)); err != nil {
		t.Fatalf("store newer record: %v", err)
	}

	state, ok := server.LookupState(ServiceKey("owner.api"))
	if !ok {
		t.Fatal("expected state to be tracked")
	}
	if state.Current.Version != uint64(now.Add(time.Minute).UTC().Unix()) {
		t.Fatalf("unexpected current version: %+v", state.Current)
	}
	if len(state.Previous) == 0 {
		t.Fatalf("expected previous history to be tracked: %+v", state)
	}
}

func TestStoreRejectsConflictingVerifiedFamilyAndTracksConflict(t *testing.T) {
	t.Parallel()

	now := time.Now()
	firstID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate first identity: %v", err)
	}
	secondID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate second identity: %v", err)
	}

	server := newTestServerWithIdentity(firstID)
	first := mustSignedValue(t, firstID, NodeNameKey("owner"), mustJSON(t, mustEndpointRecordForIdentity(t, firstID, "owner", "[2001:db8::71]:4242", now)), now)
	second := mustSignedValue(t, secondID, NodeNameKey("owner"), mustJSON(t, mustEndpointRecordForIdentity(t, secondID, "owner", "[2001:db8::72]:4242", now.Add(time.Second))), now.Add(time.Second))

	if _, _, err := server.storeValidated(NodeNameKey("owner"), first, now); err != nil {
		t.Fatalf("seed first record: %v", err)
	}
	if _, _, err := server.storeValidated(NodeNameKey("owner"), second, now.Add(time.Second)); err == nil || !errors.Is(err, ErrConflictingValues) {
		t.Fatalf("expected conflicting family rejection, got %v", err)
	}

	state, ok := server.LookupState(NodeNameKey("owner"))
	if !ok || len(state.Conflicts) == 0 {
		t.Fatalf("expected conflict history to be tracked: %+v", state)
	}
}

func TestRecursiveFindValueDetailedReportsConflictCandidates(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newTestServer("client-node")
	left := newTestServer("left-node")
	right := newTestServer("right-node")

	leftAddr := startDHTListener(t, ctx, left)
	rightAddr := startDHTListener(t, ctx, right)

	client.RT.AddNode(proto.NodeInfo{ID: "left-node", Addr: leftAddr})
	client.RT.AddNode(proto.NodeInfo{ID: "right-node", Addr: rightAddr})

	leftID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate left identity: %v", err)
	}
	rightID, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate right identity: %v", err)
	}

	leftRec := mustEndpointRecordForIdentity(t, leftID, "shared", "[2001:db8::51]:4242", time.Now())
	rightRec := mustEndpointRecordForIdentity(t, rightID, "shared", "[2001:db8::52]:4242", time.Now().Add(time.Second))
	left.StoreLocal(NodeNameKey("shared"), mustSignedValue(t, leftID, NodeNameKey("shared"), mustJSON(t, leftRec), time.Now()))
	right.StoreLocal(NodeNameKey("shared"), mustSignedValue(t, rightID, NodeNameKey("shared"), mustJSON(t, rightRec), time.Now().Add(time.Second)))

	result, err := client.RecursiveFindValueDetailed(ctx, NodeNameKey("shared"))
	if err == nil || !errors.Is(err, ErrConflictingValues) {
		t.Fatalf("expected conflicting value error, got result=%+v err=%v", result, err)
	}
	if len(result.ConflictValues) < 2 {
		t.Fatalf("expected conflict candidates in result, got %+v", result)
	}
}

func TestSelectReplicationNodesPrefersDistinctProvidersAndNetworks(t *testing.T) {
	t.Parallel()

	nodes := []proto.NodeInfo{
		{ID: "n1", Addr: "198.51.1.1:4242"},
		{ID: "n2", Addr: "198.51.2.1:4242"},
		{ID: "n3", Addr: "203.0.113.1:4242"},
		{ID: "n4", Addr: "192.0.2.1:4242"},
		{ID: "n5", Addr: "198.51.3.1:4242"},
		{ID: "n6", Addr: "203.0.113.2:4242"},
	}

	selected := selectReplicationNodes(nodes, 4)
	if len(selected) != 4 {
		t.Fatalf("expected 4 selected nodes, got %d", len(selected))
	}

	seenProviders := map[string]struct{}{}
	seenNetworks := map[string]struct{}{}
	for _, node := range selected {
		if provider := (sourceObservation{addr: node.Addr}).providerKey(); provider != "" {
			seenProviders[provider] = struct{}{}
		}
		network := sourceObservation{addr: node.Addr}.networkKey()
		if network != "" {
			seenNetworks[network] = struct{}{}
		}
	}
	if len(seenProviders) < 3 {
		t.Fatalf("expected provider spread, got %d providers from %+v", len(seenProviders), selected)
	}
	if len(seenNetworks) < 4 {
		t.Fatalf("expected diverse replicas, got %d networks from %+v", len(seenNetworks), selected)
	}
}

func TestHiddenServiceLookupKeysRotateByEpoch(t *testing.T) {
	t.Parallel()

	base := time.Unix(1_700_000_000, 0).UTC()
	invite := ComposeHiddenLookupInvite("ghost", "super-secret-hidden-token")
	current := HiddenServiceKeyAt(invite, base)
	sameEpoch := HiddenServiceKeyAt(invite, base.Add(20*time.Minute))
	nextEpoch := HiddenServiceKeyAt(invite, base.Add(hiddenDescriptorRotation))

	if current != sameEpoch {
		t.Fatalf("expected key to stay stable within one epoch: %q != %q", current, sameEpoch)
	}
	if current == nextEpoch {
		t.Fatalf("expected key rotation across epochs: %q == %q", current, nextEpoch)
	}
	if current == "hidden/ghost" || nextEpoch == "hidden/ghost" {
		t.Fatalf("expected blinded descriptor keys, got %q and %q", current, nextEpoch)
	}

	keys := HiddenServiceLookupKeys(invite, base.Add(hiddenDescriptorRotation))
	if len(keys) != 2 {
		t.Fatalf("expected current+previous lookup keys, got %d", len(keys))
	}
	if keys[0] != nextEpoch || keys[1] != current {
		t.Fatalf("unexpected rotated lookup keys: %+v", keys)
	}
}

func TestHiddenServiceDescriptorKeyValidatesWrappedRecord(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	rec := mustServiceRecordForIdentity(t, id, "owner", "admin", "", true, "ghost", now)
	invite := ComposeHiddenLookupInvite("ghost", "super-secret-hidden-token")
	key := HiddenServiceKeyAt(invite, now)
	payload, err := EncodeHiddenServiceDescriptor(rec, key, "super-secret-hidden-token")
	if err != nil {
		t.Fatalf("encode hidden descriptor: %v", err)
	}
	if strings.Contains(payload, "\"alias\"") || strings.Contains(payload, "\"intro_points\"") || strings.Contains(payload, "\"address\"") {
		t.Fatalf("expected encrypted hidden descriptor payload, got %s", payload)
	}
	signed := mustSignedValue(t, id, key, payload, now)

	value, err := validateLookupValue(key, signed, now)
	if err != nil {
		t.Fatalf("validate hidden descriptor: %v", err)
	}
	if !value.verified || value.family != "hidden:"+id.NodeID+":"+hiddenServiceTag(rec) {
		t.Fatalf("unexpected validated hidden descriptor: %+v", value)
	}

	decoded, err := DecodeHiddenServiceRecord(key, signed, invite, now)
	if err != nil {
		t.Fatalf("decode encrypted hidden descriptor: %v", err)
	}
	if decoded.Alias != rec.Alias || decoded.NodeID != rec.NodeID || decoded.ServiceName != rec.ServiceName {
		t.Fatalf("unexpected decoded hidden descriptor: %+v", decoded)
	}
}

func TestHiddenServiceDescriptorDecodeLegacyWrappedRecord(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	rec := mustServiceRecordForIdentity(t, id, "owner", "admin", "", true, "ghost", now)
	key := HiddenServiceKeyAt("ghost", now)
	payload := mustJSON(t, rec)
	signed := mustSignedValue(t, id, key, payload, now)

	value, err := validateLookupValue(key, signed, now)
	if err != nil {
		t.Fatalf("validate legacy hidden descriptor: %v", err)
	}
	if !value.verified || value.family != "hidden:"+id.NodeID+":"+hiddenServiceTag(rec) {
		t.Fatalf("unexpected validated legacy hidden descriptor: %+v", value)
	}

	decoded, err := DecodeHiddenServiceRecord(key, signed, "ghost", now)
	if err != nil {
		t.Fatalf("decode legacy hidden descriptor: %v", err)
	}
	if decoded.Alias != rec.Alias || decoded.NodeID != rec.NodeID || decoded.ServiceName != rec.ServiceName {
		t.Fatalf("unexpected decoded legacy hidden descriptor: %+v", decoded)
	}
}

func TestParseHiddenLookupRefSupportsInviteSecret(t *testing.T) {
	t.Parallel()

	ref, err := ParseHiddenLookupRef("ghost#super-secret-hidden-token")
	if err != nil {
		t.Fatalf("parse hidden invite: %v", err)
	}
	if ref.Alias != "ghost" || ref.Secret != "super-secret-hidden-token" {
		t.Fatalf("unexpected hidden invite parse result: %+v", ref)
	}
}

func TestHiddenDescriptorPayloadHasStableSize(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	short := mustServiceRecordForIdentity(t, id, "owner", "a", "", true, "ghost", now)
	short.IntroPoints = []string{"[2001:db8::1]:4242"}
	long := mustServiceRecordForIdentity(t, id, "owner", "administration-panel", "", true, "ghost", now)
	long.IntroPoints = []string{"[2001:db8::1]:4242", "[2001:db8::2]:4242", "[2001:db8::3]:4242"}
	long.StandbyIntroPoints = []string{"[2001:db8::4]:4242", "[2001:db8::5]:4242"}

	key := HiddenServiceKeyAt(ComposeHiddenLookupInvite("ghost", "super-secret-hidden-token"), now)
	shortPayload, err := EncodeHiddenServiceDescriptor(short, key, "super-secret-hidden-token")
	if err != nil {
		t.Fatalf("encode short hidden descriptor: %v", err)
	}
	longPayload, err := EncodeHiddenServiceDescriptor(long, key, "super-secret-hidden-token")
	if err != nil {
		t.Fatalf("encode long hidden descriptor: %v", err)
	}
	if len(shortPayload) != len(longPayload) {
		t.Fatalf("expected padded hidden descriptors to share size, got %d and %d", len(shortPayload), len(longPayload))
	}
}

func TestResolveHiddenServiceFallsBackToShortLivedCache(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	rec := mustServiceRecordForIdentity(t, id, "owner", "admin", "", true, "ghost", now)
	invite := ComposeHiddenLookupInvite("ghost", "super-secret-hidden-token")
	client := newTestServer("client")
	client.storeHiddenServiceCache(invite, HiddenServiceKeyAt(invite, now), rec, now)

	resolved, err := client.ResolveHiddenService(context.Background(), invite, now.Add(40*time.Second))
	if err != nil {
		t.Fatalf("resolve hidden service from short-lived cache: %v", err)
	}
	if resolved.NodeID != rec.NodeID || resolved.Alias != rec.Alias || resolved.ServiceName != rec.ServiceName {
		t.Fatalf("unexpected hidden cache resolution %+v", resolved)
	}
}

func TestHiddenDescriptorLookupRateLimit(t *testing.T) {
	t.Parallel()

	server := newTestServer("ratelimit")
	now := time.Now()
	for i := 0; i < hiddenDescriptorLookupRateLimit; i++ {
		if !server.allowHiddenDescriptorRequest("[2001:db8::1]:4242", "find_value", now) {
			t.Fatalf("unexpected lookup rate-limit at attempt %d", i+1)
		}
	}
	if server.allowHiddenDescriptorRequest("[2001:db8::1]:4242", "find_value", now) {
		t.Fatal("expected hidden descriptor lookup to be rate limited")
	}
	if !server.allowHiddenDescriptorRequest("[2001:db8::1]:4242", "find_value", now.Add(hiddenDescriptorLookupRateWindow+time.Second)) {
		t.Fatal("expected hidden descriptor lookup window to reset")
	}
	for i := 0; i < hiddenDescriptorStoreRateLimit; i++ {
		if !server.allowHiddenDescriptorRequest("[2001:db8::2]:4242", "store", now) {
			t.Fatalf("unexpected store rate-limit at attempt %d", i+1)
		}
	}
	if server.allowHiddenDescriptorRequest("[2001:db8::2]:4242", "store", now) {
		t.Fatal("expected hidden descriptor store to be rate limited")
	}
}

func startDHTListener(t *testing.T, ctx context.Context, srv *Server) string {
	t.Helper()

	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatalf("listen dht: %v", err)
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()

				kind, err := proto.ReadHeader(conn)
				if err != nil || kind != proto.KindDHT {
					return
				}
				payload, err := proto.ReadLengthPrefixed(conn, 1024*1024)
				if err != nil {
					return
				}

				var req proto.DHTRequest
				if err := json.Unmarshal(payload, &req); err != nil {
					return
				}
				_ = srv.HandleDHT(ctx, conn, req)
			}(conn)
		}
	}()

	return ln.Addr().String()
}

func reserveClosedTCP6Addr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatalf("reserve closed dht addr: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func selectedNodeIDs(nodes []proto.NodeInfo) map[string]struct{} {
	out := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		out[node.ID] = struct{}{}
	}
	return out
}

func sameStringSet(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if _, ok := right[key]; !ok {
			return false
		}
	}
	return true
}

func findNewPreferredNodes(t *testing.T, selfID, key string, existing []proto.NodeInfo, want int) []proto.NodeInfo {
	t.Helper()

	found := make([]proto.NodeInfo, 0, want)
	candidates := append([]proto.NodeInfo(nil), existing...)
	for i := 0; len(found) < want && i < 10000; i++ {
		node := proto.NodeInfo{
			ID:   fmt.Sprintf("preferred-node-%04d", i),
			Addr: fmt.Sprintf("[::1]:%d", 45000+i),
		}
		rt := NewRoutingTable(selfID)
		for _, existingNode := range candidates {
			rt.AddNode(existingNode)
		}
		rt.AddNode(node)
		selected := selectedNodeIDs(selectReplicationNodes(rt.ClosestNodes(key, K), replicationFactor))
		if _, ok := selected[node.ID]; ok {
			found = append(found, node)
			candidates = append(candidates, node)
		}
	}
	return found
}

func mustEndpointRecord(t *testing.T, nodeName, address string, now time.Time) record.EndpointRecord {
	t.Helper()

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate endpoint identity: %v", err)
	}
	return mustEndpointRecordForIdentity(t, id, nodeName, address, now)
}

func mustEndpointRecordForIdentity(t *testing.T, id identity.Identity, nodeName, address string, now time.Time) record.EndpointRecord {
	t.Helper()

	rec, err := record.NewEndpointRecord(id, nodeName, address, 10*time.Minute, now)
	if err != nil {
		t.Fatalf("new endpoint record: %v", err)
	}
	return rec
}

func mustServiceRecord(t *testing.T, nodeName, serviceName, address string, hidden bool, alias string, now time.Time) record.ServiceRecord {
	t.Helper()

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate service identity: %v", err)
	}
	return mustServiceRecordForIdentity(t, id, nodeName, serviceName, address, hidden, alias, now)
}

func mustServiceRecordForIdentity(t *testing.T, id identity.Identity, nodeName, serviceName, address string, hidden bool, alias string, now time.Time) record.ServiceRecord {
	t.Helper()

	rec, err := record.NewServiceRecord(id, nodeName, serviceName, address, 10*time.Minute, now)
	if err != nil {
		t.Fatalf("new service record: %v", err)
	}
	return finalizeServiceRecord(t, id, rec, hidden, alias)
}

func finalizeServiceRecord(t *testing.T, id identity.Identity, rec record.ServiceRecord, hidden bool, alias string) record.ServiceRecord {
	t.Helper()

	rec.IsHidden = hidden
	rec.Alias = alias
	if hidden {
		rec.HiddenProfile = "fast"
		rec.Address = ""
		if err := record.SignServiceRecord(id, &rec); err != nil {
			t.Fatalf("sign hidden service record: %v", err)
		}
	}
	return rec
}

func mustSignedValue(t *testing.T, publisher identity.Identity, key, payload string, now time.Time) string {
	t.Helper()

	info, err := validateInnerLookupValue(key, payload, now)
	if err != nil {
		t.Fatalf("validate inner lookup value: %v", err)
	}
	signed, err := wrapSignedEnvelope(publisher, key, payload, info, now)
	if err != nil {
		t.Fatalf("wrap signed envelope: %v", err)
	}
	return signed
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()

	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return string(data)
}
