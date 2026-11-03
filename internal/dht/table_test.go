package dht

import (
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/proto"
)

func TestRoutingTablePromotesReplacementAfterFailures(t *testing.T) {
	t.Parallel()

	rt := NewRoutingTable("self-node")
	bucketIdx := 7

	for i := 0; i < K; i++ {
		entry := &bucketEntry{
			Node: proto.NodeInfo{
				ID:   "active-node-" + string(rune('a'+i)),
				Addr: "[2001:db8::1]:4242",
			},
		}
		rt.peerByID[entry.Node.ID] = entry
		rt.Buckets[bucketIdx] = append(rt.Buckets[bucketIdx], entry)
	}
	replacement := proto.NodeInfo{ID: "replacement-node", Addr: "[2001:db8::2]:4242"}
	replacementEntry := &bucketEntry{Node: replacement}
	rt.peerByID[replacement.ID] = replacementEntry
	rt.Spare[bucketIdx] = append(rt.Spare[bucketIdx], replacementEntry)

	failedID := rt.Buckets[bucketIdx][0].Node.ID
	start := time.Now()
	evicted := rt.NoteFailureAt(failedID, start)
	if evicted {
		t.Fatal("expected first failure to mark stale, not evict immediately")
	}
	if evicted = rt.NoteFailureAt(failedID, start.Add(4*time.Second)); evicted {
		t.Fatal("expected second failure to keep peer suspect")
	}
	evicted = rt.NoteFailureAt(failedID, start.Add(5*time.Second))
	if evicted {
		t.Fatal("second spaced failure must not evict the peer")
	}
	evicted = rt.NoteFailureAt(failedID, start.Add(24*time.Second))
	if evicted {
		t.Fatal("failure before the second backoff elapsed must not evict")
	}
	evicted = rt.NoteFailureAt(failedID, start.Add(25*time.Second))
	if !evicted {
		t.Fatal("expected repeated failure to evict stale node")
	}

	if got := len(rt.Buckets[bucketIdx]); got != K-1 {
		t.Fatalf("replacement must be revalidated before active promotion; got %d active entries", got)
	}
	if _, ok := rt.ActiveNode(replacement.ID); ok {
		t.Fatal("replacement became active without a fresh authenticated check")
	}
	if got := len(rt.CandidateNodes(10)); got == 0 {
		t.Fatal("replacement was not retained as a candidate")
	}
	if _, ok := rt.offline[failedID]; !ok {
		t.Fatal("evicted peer address was not retained in offline history")
	}
}

func TestNameAndIdentityLookupsUseSeparateRoutingCoordinates(t *testing.T) {
	rt := NewRoutingTable("self")
	zeroHash := strings.Repeat("0", 64)
	maxHash := strings.Repeat("f", 64)
	byName := proto.NodeInfo{
		ID: "vx6_" + maxHash, Name: "ALPHA", NameHash: zeroHash, Addr: "[2001:db8::1]:4242",
	}
	byID := proto.NodeInfo{
		ID: "vx6_" + zeroHash, Name: "OMEGA", NameHash: maxHash, Addr: "[2001:db8::2]:4242",
	}
	rt.SetSelfNameHash(strings.Repeat("1", 64))
	rt.AddNode(byName)
	rt.AddNode(byID)

	if got := rt.ClosestNodesByNameHash(zeroHash, 1); len(got) != 1 || got[0].ID != byName.ID {
		t.Fatalf("name lookup chose %+v, want peer closest by NameHash", got)
	}
	if got := rt.ClosestNodes("vx6_"+zeroHash, 1); len(got) != 1 || got[0].ID != byID.ID {
		t.Fatalf("identity lookup chose %+v, want peer closest by NodeID", got)
	}
}

func TestRoutingBucketsAreSparseBoundedAndKeepReplacementCandidates(t *testing.T) {
	rt := NewRoutingTable("vx6_" + strings.Repeat("0", 64))
	if got := nonEmptyBucketCount(rt.Buckets[:]); got != 0 {
		t.Fatalf("new table populated %d buckets", got)
	}
	for i := 0; i < K+5; i++ {
		node := proto.NodeInfo{
			ID: fmt.Sprintf("vx6_8%063x", i+1), Name: fmt.Sprintf("PEER-%d", i),
			Addr: fmt.Sprintf("[2001:db8:%x::1]:4242", i+1),
		}
		rt.AddNode(node)
	}
	if got := len(rt.Buckets[255]); got != K {
		t.Fatalf("active bucket length = %d, want cap %d", got, K)
	}
	if got := len(rt.Spare[255]); got != 5 {
		t.Fatalf("replacement list length = %d, want 5", got)
	}
	if got := len(rt.Nodes()); got != K+5 {
		t.Fatalf("known active and replacement peers = %d, want %d", got, K+5)
	}
}

func TestRoutingUseMovesPeerToFrontWithoutChangingCoordinate(t *testing.T) {
	rt := NewRoutingTable("vx6_" + strings.Repeat("0", 64))
	first := proto.NodeInfo{ID: "vx6_8" + strings.Repeat("0", 63), Name: "FIRST", Addr: "[2001:db8::1]:4242"}
	second := proto.NodeInfo{ID: "vx6_8" + strings.Repeat("0", 62) + "1", Name: "SECOND", Addr: "[2001:db8::2]:4242"}
	rt.AddNode(first)
	rt.AddNode(second)
	idx := rt.bucketIndex(first.ID)
	if rt.Buckets[idx][0].Node.ID != second.ID {
		t.Fatal("newest successful peer should be first")
	}
	rt.RecordUse(first.ID, time.Now().Add(time.Second), time.Millisecond)
	if rt.Buckets[idx][0].Node.ID != first.ID {
		t.Fatal("recently used peer was not moved to the front")
	}
	if first.ID != "vx6_8"+strings.Repeat("0", 63) {
		t.Fatal("recency changed the peer routing coordinate")
	}
}

func TestIPv6PrefixDoesNotHardBlockSparseRoutingBucket(t *testing.T) {
	rt := NewRoutingTable("vx6_" + strings.Repeat("0", 64))
	for i := 0; i < K; i++ {
		rt.AddNode(proto.NodeInfo{
			ID: fmt.Sprintf("vx6_8%063x", i+1), Name: fmt.Sprintf("PEER-%d", i),
			Addr: fmt.Sprintf("[2001:db8:1::%x]:4242", i+1),
		})
	}
	if got := len(rt.Buckets[255]); got != K {
		t.Fatalf("sparse prefix bucket should fill to capacity, got %d", got)
	}
	if got := len(rt.Spare[255]); got != 0 {
		t.Fatalf("sparse bucket should not create replacements before full, got %d", got)
	}
	rt.AddNode(proto.NodeInfo{ID: fmt.Sprintf("vx6_8%063x", 99), Name: "SAME-PREFIX", Addr: "[2001:db8:1::ff]:4242"})
	if got := len(rt.Buckets[255]); got != K {
		t.Fatalf("full bucket changed capacity, active length %d", got)
	}
	if got := len(rt.Spare[255]); got != 1 {
		t.Fatalf("full bucket should keep the overflow peer as a replacement, got %d", got)
	}
	rt.AddNode(proto.NodeInfo{ID: fmt.Sprintf("vx6_8%063x", 100), Name: "OTHER-PREFIX", Addr: "[2001:db8:2::1]:4242"})
	if got := len(rt.Buckets[255]); got != K {
		t.Fatalf("second full-bucket contact changed active capacity, length %d", got)
	}
	if got := len(rt.Spare[255]); got != 2 {
		t.Fatalf("full bucket should retain two replacement candidates, got %d", got)
	}
}

func TestReplacementListPrefersDifferentIPv6Prefixes(t *testing.T) {
	rt := NewRoutingTable("vx6_" + strings.Repeat("0", 64))
	for i := 0; i < K; i++ {
		rt.AddNode(proto.NodeInfo{
			ID: fmt.Sprintf("vx6_8%063x", i+1), Name: fmt.Sprintf("ACTIVE-%d", i),
			Addr: fmt.Sprintf("[2001:db8:%x::1]:4242", i+1),
		})
	}
	rt.AddNode(proto.NodeInfo{ID: fmt.Sprintf("vx6_8%063x", 100), Name: "SAME", Addr: "[2001:db8:1::ff]:4242"})
	rt.AddNode(proto.NodeInfo{ID: fmt.Sprintf("vx6_8%063x", 101), Name: "DIVERSE", Addr: "[2001:db8:100::1]:4242"})
	if got := rt.Spare[255][0].Node.Name; got != "DIVERSE" {
		t.Fatalf("replacement preference chose %q first, want different /48 peer", got)
	}
}

func TestRefreshTargetsAreBoundedAndDoNotPopulateEmptyRanges(t *testing.T) {
	rt := NewRoutingTable("vx6_" + strings.Repeat("0", 64))
	rt.SetSelfNameHash(strings.Repeat("0", 64))
	rt.AddNode(proto.NodeInfo{ID: "vx6_8" + strings.Repeat("0", 63), Name: "PEER", Addr: "[2001:db8::1]:4242"})
	targets := rt.RefreshTargets(time.Now(), 2)
	if len(targets) > 2 {
		t.Fatalf("refresh fanout targets = %d, want <=2", len(targets))
	}
	if len(targets) == 0 {
		t.Fatal("expected an underfilled, non-empty range to be refreshed")
	}
	for _, target := range targets {
		if target.Bucket < 0 || target.Bucket > 255 {
			t.Fatalf("invalid refresh bucket %d", target.Bucket)
		}
		if target.NameHash && !strings.HasPrefix(target.Key, "node/name/") {
			t.Fatalf("name refresh target has wrong lookup namespace: %s", target.Key)
		}
		if !target.NameHash && !strings.HasPrefix(target.Key, "vx6_") {
			t.Fatalf("identity refresh target must use full NodeID wire form: %s", target.Key)
		}
	}
}

func TestFindNodeWireTypesFollowRequestedCoordinate(t *testing.T) {
	nameHash := strings.Repeat("a", 64)
	nameType, nameTarget := nodeLookupTarget("node/name/" + nameHash)
	if nameType != proto.DHTTypeLookupName || nameTarget != nameHash {
		t.Fatalf("name lookup wire request = (%q, %q)", nameType, nameTarget)
	}
	if err := (proto.DHTRequest{Type: nameType, Action: "find_node", Target: nameTarget}).Validate(); err != nil {
		t.Fatalf("valid name-coordinate find_node rejected: %v", err)
	}
	nodeID := "vx6_" + strings.Repeat("b", 64)
	keyType, keyTarget := nodeLookupTarget(nodeID)
	if keyType != proto.DHTTypeLookupKey || keyTarget != nodeID {
		t.Fatalf("identity lookup wire request = (%q, %q)", keyType, keyTarget)
	}
	if err := (proto.DHTRequest{Type: keyType, Action: "find_node", Target: keyTarget}).Validate(); err != nil {
		t.Fatalf("valid identity-coordinate find_node rejected: %v", err)
	}
}

func TestPeerStoreRestoresCandidatesNotActiveRoutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dht-peers.db")
	store, err := OpenPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	peer := PeerObservation{
		Node:     proto.NodeInfo{ID: "vx6_" + strings.Repeat("a", 64), Name: "ALPHA", Addr: "[2001:db8::1]:4242", NameHash: NodeNameHash("ALPHA")},
		LastSeen: now, LastSuccess: now, SuccessCount: 3,
	}
	peer.NextProbeAt = now.Add(5 * time.Second)
	if err := store.SaveSnapshot([]PeerObservation{peer}, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	restored, err := store.LoadCandidates(now, peerCacheHotLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 || restored[0].Node.ID != peer.Node.ID {
		t.Fatalf("restored candidates = %+v", restored)
	}
	if !restored[0].NextProbeAt.Equal(peer.NextProbeAt) {
		t.Fatalf("restored next-probe time = %s, want %s", restored[0].NextProbeAt, peer.NextProbeAt)
	}
	rt := NewRoutingTable("self")
	rt.RestoreCandidates(restored, now)
	if _, active := rt.ActiveNode(peer.Node.ID); active {
		t.Fatal("restored peer became active without live authentication")
	}
	if got := rt.CandidateNodes(1); len(got) != 1 || got[0].ID != peer.Node.ID {
		t.Fatalf("restored peer candidate = %+v", got)
	}
}

func nonEmptyBucketCount(buckets [][]*bucketEntry) int {
	count := 0
	for _, bucket := range buckets {
		if len(bucket) != 0 {
			count++
		}
	}
	return count
}

func TestCandidatesStayOutOfActiveRoutingUntilPromoted(t *testing.T) {
	rt := NewRoutingTable("self-node")
	node := proto.NodeInfo{ID: "candidate", Addr: "[2001:db8::2]:4242"}
	rt.AddCandidate(node)
	if _, ok := rt.ActiveNode(node.ID); ok {
		t.Fatal("candidate became active before verification")
	}
	if got := len(rt.Nodes()); got != 0 {
		t.Fatalf("candidate appeared in active Nodes list: %d entries", got)
	}
	if got, ok := rt.NodeByAddress(node.Addr); !ok || got.ID != node.ID {
		t.Fatal("candidate is not available for its verification query")
	}
	rt.PromoteCandidate(node.ID)
	if _, ok := rt.ActiveNode(node.ID); !ok {
		t.Fatal("verified candidate was not promoted")
	}
}

func TestPendingCandidateMemoryIsBounded(t *testing.T) {
	rt := NewRoutingTable("vx6_" + strings.Repeat("0", 64))
	for bucket := 0; bucket < 256; bucket++ {
		for variant := 0; variant < 3; variant++ {
			if variant == 2 && bucket < 2 {
				continue
			}
			coordinate := new(big.Int).Lsh(big.NewInt(1), uint(bucket))
			if variant == 1 && bucket > 0 {
				coordinate.SetBit(coordinate, bucket-1, 1)
			}
			if variant == 2 {
				coordinate.SetBit(coordinate, bucket-2, 1)
			}
			id := fmt.Sprintf("vx6_%064x", coordinate)
			rt.AddCandidate(proto.NodeInfo{ID: id, Addr: fmt.Sprintf("[2001:db8:%x::1]:4242", bucket*2+variant+1)})
		}
	}
	if got := rt.pendingN; got > maxPendingCandidates {
		t.Fatalf("pending candidates = %d, exceeds global cap %d", got, maxPendingCandidates)
	}
	for i, bucket := range rt.Pending {
		if len(bucket) > maxPendingPerBucket {
			t.Fatalf("pending bucket %d has %d candidates, exceeds %d", i, len(bucket), maxPendingPerBucket)
		}
	}
}

func TestPinnedPeerDoesNotConsumeRoutingSlotAndSurvivesRemoval(t *testing.T) {
	rt := NewRoutingTable("vx6_" + strings.Repeat("0", 64))
	peer := proto.NodeInfo{ID: "vx6_" + strings.Repeat("a", 64), Addr: "[2001:db8::1]:4242"}
	rt.AddNode(peer)
	if !rt.SetPinned(peer.ID, true) {
		t.Fatal("could not pin known peer")
	}
	if got := len(rt.Buckets[rt.bucketIndex(peer.ID)]); got != 1 {
		t.Fatalf("pin changed routing slot count to %d", got)
	}
	start := time.Now()
	for _, delay := range []time.Duration{0, 5 * time.Second, 25 * time.Second} {
		rt.NoteFailureAt(peer.ID, start.Add(delay))
	}
	if !rt.SetPinned(peer.ID, false) {
		t.Fatal("pinned peer metadata was not retained after route removal")
	}
	if got := len(rt.SnapshotPeers()); got != 1 {
		t.Fatalf("recent offline address hint was not retained after unpin: %d", got)
	}
}

func TestFailureBackoffSuppressesRepeatedProbesAndSuccessResetsIt(t *testing.T) {
	rt := NewRoutingTable("self")
	node := proto.NodeInfo{ID: "peer", Addr: "[2001:db8::7]:4242"}
	rt.AddNode(node)
	now := time.Now()
	rt.NoteFailureAt(node.ID, now)
	if rt.ProbeAllowed(node.ID, now.Add(4*time.Second)) {
		t.Fatal("probe was allowed before the five-second initial backoff")
	}
	if !rt.ProbeAllowed(node.ID, now.Add(5*time.Second)) {
		t.Fatal("probe remained blocked after initial backoff")
	}
	rt.AddNode(node)
	if !rt.ProbeAllowed(node.ID, now) {
		t.Fatal("successful authenticated contact did not reset the backoff")
	}
}

func TestPeerStoreDropsExpiredUnpinnedAddressHints(t *testing.T) {
	store, err := OpenPeerStore(filepath.Join(t.TempDir(), "dht-peers.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now()
	peer := PeerObservation{
		Node:     proto.NodeInfo{ID: "vx6_" + strings.Repeat("b", 64), Addr: "[2001:db8::2]:4242"},
		LastSeen: now.Add(-8 * 24 * time.Hour), LastSuccess: now.Add(-8 * 24 * time.Hour),
	}
	if err := store.SaveSnapshot([]PeerObservation{peer}, now); err != nil {
		t.Fatal(err)
	}
	peers, err := store.LoadCandidates(now, peerCacheHotLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Fatalf("expired address hint was restored as candidate: %+v", peers)
	}
}

func TestOfflineHistoryExpiresAfterThirtyDays(t *testing.T) {
	rt := NewRoutingTable("self")
	node := proto.NodeInfo{ID: "peer", Addr: "[2001:db8::9]:4242"}
	rt.AddNode(node)
	start := time.Now()
	for _, delay := range []time.Duration{0, 5 * time.Second, 25 * time.Second} {
		rt.NoteFailureAt(node.ID, start.Add(delay))
	}
	if len(rt.SnapshotPeers()) != 1 {
		t.Fatal("recently offline peer was not retained")
	}
	rt.PruneOffline(time.Now().Add(peerHistoryTTL + time.Minute))
	if len(rt.SnapshotPeers()) != 0 {
		t.Fatal("expired offline history was not pruned")
	}
}
