package dht

import (
	"strings"
	"testing"

	"github.com/vx6/vx6/internal/proto"
)

func TestRoutingTablePromotesReplacementAfterFailures(t *testing.T) {
	t.Parallel()

	rt := NewRoutingTable("self-node")
	bucketIdx := 7

	for i := 0; i < K; i++ {
		rt.Buckets[bucketIdx] = append(rt.Buckets[bucketIdx], bucketEntry{
			Node: proto.NodeInfo{
				ID:   "active-node-" + string(rune('a'+i)),
				Addr: "[2001:db8::1]:4242",
			},
		})
	}
	replacement := proto.NodeInfo{ID: "replacement-node", Addr: "[2001:db8::2]:4242"}
	rt.Spare[bucketIdx] = append(rt.Spare[bucketIdx], replacement)

	evicted := rt.NoteFailure(rt.Buckets[bucketIdx][0].Node.ID)
	if evicted {
		t.Fatal("expected first failure to mark stale, not evict immediately")
	}
	evicted = rt.NoteFailure(rt.Buckets[bucketIdx][0].Node.ID)
	if !evicted {
		t.Fatal("expected repeated failure to evict stale node")
	}

	if got := len(rt.Buckets[bucketIdx]); got != K {
		t.Fatalf("expected replacement to keep bucket at %d entries, got %d", K, got)
	}
	foundReplacement := false
	for _, entry := range rt.Buckets[bucketIdx] {
		if entry.Node.ID == replacement.ID {
			foundReplacement = true
			break
		}
	}
	if !foundReplacement {
		t.Fatalf("expected replacement node %q to be promoted", replacement.ID)
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
	rt.Buckets[0] = []bucketEntry{{Node: byName}, {Node: byID}}

	if got := rt.ClosestNodesByNameHash(zeroHash, 1); len(got) != 1 || got[0].ID != byName.ID {
		t.Fatalf("name lookup chose %+v, want peer closest by NameHash", got)
	}
	if got := rt.ClosestNodes("vx6_"+zeroHash, 1); len(got) != 1 || got[0].ID != byID.ID {
		t.Fatalf("identity lookup chose %+v, want peer closest by NodeID", got)
	}
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
