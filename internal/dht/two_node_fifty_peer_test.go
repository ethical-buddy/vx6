package dht

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
)

// This integration test uses two live DHT nodes. One has 50 additional,
// cryptographically valid peer records in its routing table; those peers are
// intentionally not listening, so this tests referral selection, not reachability.
func TestTwoNodeLookupReturnsFourClosestFromFiftySignedPeers(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	seedID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	seed := newTestServerWithIdentity(seedID)
	seed.RT.SetSelfNameHash(NodeNameHash("SEED"))
	seedAddr := startDHTListener(t, ctx, seed)
	seedRecord, err := record.NewEndpointRecordV2(seedID, "SEED", seedAddr, 1, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	seedInfo := NodeInfoFromEndpointRecord(seedRecord)

	clientID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	client := newTestServerWithIdentity(clientID)
	client.RT.SetSelfNameHash(NodeNameHash("JOINER"))
	client.RT.AddNode(seedInfo)
	clientRecord, err := record.NewEndpointRecordV2(clientID, "JOINER", "[2001:db8::ffff]:4242", 1, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyNodeInfo(NodeInfoFromEndpointRecord(clientRecord), time.Now()); err != nil {
		t.Fatalf("joiner's signed identity is invalid: %v", err)
	}

	peers := make([]proto.NodeInfo, 0, 50)
	for i := 0; i < 50; i++ {
		peerID, err := identity.Generate()
		if err != nil {
			t.Fatalf("generate peer %d: %v", i, err)
		}
		name := fmt.Sprintf("PEER-%02d", i)
		address := fmt.Sprintf("[2001:db8::%x]:4242", i+1)
		rec, err := record.NewEndpointRecordV2(peerID, name, address, 1, time.Hour, time.Now())
		if err != nil {
			t.Fatalf("create peer %s record: %v", name, err)
		}
		info := NodeInfoFromEndpointRecord(rec)
		if err := VerifyNodeInfo(info, time.Now()); err != nil {
			t.Fatalf("peer %s record did not verify: %v", name, err)
		}
		seed.RT.AddNode(info)
		peers = append(peers, info)
	}
	if got := len(seed.RT.ClosestNodes("", 100)); got != 50 {
		t.Fatalf("seed routing table has %d peers, want 50", got)
	}

	// Bootstrap obtains contact referrals only. It does not imply that each
	// referral is reachable or that the seed has certified network membership.
	bootstrap, err := client.QueryBootstrapNode(ctx, seedAddr, NodeIDKey(clientID.NodeID))
	if err != nil {
		t.Fatalf("bootstrap contact query: %v", err)
	}
	assertFourClosest(t, bootstrap, peers, clientID.NodeID, false)

	// A lookup for the joining node's name hash must select the nearest four
	// records in the independent name-hash index, not the node-ID index.
	nameRefs, err := client.QueryNode(ctx, seedAddr, NodeNameKey("JOINER"))
	if err != nil {
		t.Fatalf("joiner name lookup referrals: %v", err)
	}
	if local := seed.RT.ClosestNodesByNameHash(NodeNameHash("JOINER"), 100); len(local) != 50 {
		t.Fatalf("seed name index has %d peers, want 50", len(local))
	}
	wantNameTop := independentlyRankPeers(peers, NodeNameHash("JOINER"), true, 4)
	localNameTop := seed.RT.ClosestNodesByNameHash(NodeNameHash("JOINER"), 4)
	if localNameTop[0].ID != wantNameTop[0].ID {
		t.Fatalf("local name-index closest=%s, independent closest=%s", localNameTop[0].ID, wantNameTop[0].ID)
	}
	assertFourClosest(t, nameRefs, peers, NodeNameHash("JOINER"), true)

	// Known nodes are resolved from their signed record in the referral set.
	// The target itself has zero XOR distance and must be the first match.
	target := peers[17]
	idResult, err := client.RecursiveFindNodeDetailed(ctx, NodeIDKey(target.ID))
	if err != nil {
		t.Fatalf("recursive node-ID lookup: %v", err)
	}
	if idResult.Outcome != LookupFound || len(idResult.Matches) != 1 || idResult.Matches[0].ID != target.ID {
		t.Fatalf("node-ID lookup = %+v, want exact target %s", idResult, target.ID)
	}

	nameResult, err := client.RecursiveFindNodeDetailed(ctx, NodeNameKey(target.Name))
	if len(nameResult.Matches) != 1 || nameResult.Matches[0].ID != target.ID {
		t.Fatalf("name lookup result = %+v (error %v), want exact target %s", nameResult, err, target.ID)
	}
	if nameResult.Outcome != LookupIncomplete || !errors.Is(err, ErrLookupIncomplete) {
		t.Fatalf("name lookup outcome = %s, error = %v; offline referrals must keep conflict detection incomplete", nameResult.Outcome, err)
	}

	assertSignedServiceFetch(t, ctx, seed, client, seedAddr, seedID)
}

func assertFourClosest(t *testing.T, got, peers []proto.NodeInfo, target string, byName bool) {
	t.Helper()
	if len(got) != 4 {
		t.Fatalf("got %d referrals, want exactly 4", len(got))
	}
	want := independentlyRankPeers(peers, target, byName, 4)
	for i := range want {
		if got[i].ID != want[i].ID {
			t.Fatalf("referral[%d]=%s (%s), want closest %s (%s)", i, got[i].ID, got[i].Name, want[i].ID, want[i].Name)
		}
		if err := VerifyNodeInfo(got[i], time.Now()); err != nil {
			t.Fatalf("referral %s has invalid signed identity: %v", got[i].ID, err)
		}
	}
}

// Independently ranks complete 256-bit XOR distances instead of asking the
// production routing table to calculate the expected order.
func independentlyRankPeers(peers []proto.NodeInfo, target string, byName bool, count int) []proto.NodeInfo {
	target = strings.TrimPrefix(target, "vx6_")
	targetBytes, _ := hex.DecodeString(target)
	type ranked struct {
		peer     proto.NodeInfo
		distance []byte
	}
	rankedPeers := make([]ranked, 0, len(peers))
	for _, peer := range peers {
		coordinate := strings.TrimPrefix(peer.ID, "vx6_")
		if byName {
			coordinate = NodeNameHash(peer.Name)
		}
		peerBytes, _ := hex.DecodeString(coordinate)
		distance := make([]byte, len(targetBytes))
		for i := range distance {
			distance[i] = targetBytes[i] ^ peerBytes[i]
		}
		rankedPeers = append(rankedPeers, ranked{peer: peer, distance: distance})
	}
	sort.Slice(rankedPeers, func(i, j int) bool {
		return bytes.Compare(rankedPeers[i].distance, rankedPeers[j].distance) < 0
	})
	if len(rankedPeers) > count {
		rankedPeers = rankedPeers[:count]
	}
	out := make([]proto.NodeInfo, len(rankedPeers))
	for i := range rankedPeers {
		out[i] = rankedPeers[i].peer
	}
	return out
}

func assertSignedServiceFetch(t *testing.T, ctx context.Context, seed, client *Server, seedAddr string, owner identity.Identity) {
	t.Helper()
	const serviceKey = "SEED.web"
	now := time.Now()
	rec, err := record.NewServiceRecord(owner, "SEED", "web", "[2001:db8::50]:4242", time.Hour, now)
	if err != nil {
		t.Fatalf("create service record: %v", err)
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal service record: %v", err)
	}
	key := ServiceKey(serviceKey)
	signed := mustSignedValue(t, owner, key, string(payload), now)
	seed.StoreLocal(key, signed)

	fetched, _, err := client.QueryValue(ctx, seedAddr, key)
	if err != nil {
		t.Fatalf("fetch signed service value: %v", err)
	}
	validated, err := validateLookupValue(key, fetched, time.Now())
	if err != nil {
		t.Fatalf("verify fetched service value: %v", err)
	}
	var got record.ServiceRecord
	if err := json.Unmarshal([]byte(validated.raw), &got); err != nil {
		t.Fatalf("decode fetched service record: %v", err)
	}
	if err := record.VerifyServiceRecord(got, time.Now()); err != nil {
		t.Fatalf("service owner signature invalid: %v", err)
	}
	if got.NodeID != owner.NodeID || got.NodeName != "SEED" || got.ServiceName != "web" {
		t.Fatalf("fetched service metadata = %+v, want signed SEED.web", got)
	}
}
