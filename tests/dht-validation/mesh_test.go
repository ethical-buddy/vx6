package dhtvalidation

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
)

type meshPeer struct {
	server *dht.Server
	info   proto.NodeInfo
	addr   string
	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	requests []proto.DHTRequest
	closeOne sync.Once
}

func newMeshPeer(t *testing.T, name string) *meshPeer {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate %s identity: %v", name, err)
	}
	server := dht.NewServerWithIdentity(id)
	server.RT.SetSelfNameHash(dht.NodeNameHash(name))
	server.SetDialGuard(func(context.Context, string) error { return nil })
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatalf("listen IPv6 for %s: %v", name, err)
	}
	now := time.Now().UTC()
	ep, err := record.NewEndpointRecordV2(id, name, ln.Addr().String(), 1, time.Hour, now)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("create signed endpoint for %s: %v", name, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &meshPeer{server: server, info: dht.NodeInfoFromEndpointRecord(ep), addr: ln.Addr().String(), ln: ln, ctx: ctx, cancel: cancel}
	t.Cleanup(p.close)
	go p.serve()
	return p
}

func (p *meshPeer) close() {
	p.closeOne.Do(func() {
		p.cancel()
		_ = p.ln.Close()
	})
}

func (p *meshPeer) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *meshPeer) handle(conn net.Conn) {
	defer conn.Close()
	if kind, err := proto.ReadHeader(conn); err != nil || kind != proto.KindDHT {
		return
	}
	data, err := proto.ReadLengthPrefixed(conn, 1<<20)
	if err != nil {
		return
	}
	var req proto.DHTRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return
	}
	p.mu.Lock()
	p.requests = append(p.requests, req)
	p.mu.Unlock()
	_ = p.server.HandleDHT(p.ctx, conn, req)
}

func (p *meshPeer) resetRequests() {
	p.mu.Lock()
	p.requests = nil
	p.mu.Unlock()
}

func (p *meshPeer) requestSnapshot() []proto.DHTRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]proto.DHTRequest(nil), p.requests...)
}

func TestThreeFiveTenPeerIPv6IterativeLookups(t *testing.T) {
	for _, count := range []int{3, 5, 10} {
		t.Run(fmt.Sprintf("peers-%d", count), func(t *testing.T) {
			peers := make([]*meshPeer, count)
			for i := range peers {
				peers[i] = newMeshPeer(t, fmt.Sprintf("NODE-%02d", i+1))
			}
			for i := 0; i < count-1; i++ {
				peers[i].server.RT.AddNode(peers[i+1].info)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for _, lookup := range []struct {
				name     string
				key      string
				typeWant proto.DHTRequestType
				target   string
			}{
				{name: "name-hash", key: dht.NodeNameKey(peers[count-1].info.Name), typeWant: proto.DHTTypeLookupName, target: dht.NodeNameHash(peers[count-1].info.Name)},
				{name: "node-id", key: dht.NodeIDKey(peers[count-1].info.ID), typeWant: proto.DHTTypeLookupKey, target: peers[count-1].info.ID},
			} {
				t.Run(lookup.name, func(t *testing.T) {
					for _, peer := range peers {
						peer.resetRequests()
					}
					result, err := peers[0].server.RecursiveFindNodeDetailed(ctx, lookup.key)
					if err != nil {
						t.Fatalf("iterative lookup failed: %v (outcome=%s, queries=%d, rounds=%d)", err, result.Outcome, result.QueriedNodes, result.Rounds)
					}
					if result.Outcome != dht.LookupFound || len(result.Matches) != 1 || result.Matches[0].ID != peers[count-1].info.ID {
						t.Fatalf("lookup result = outcome %s matches %+v; expected target %s", result.Outcome, result.Matches, peers[count-1].info.ID)
					}
					wantQueries := count - 2
					if lookup.name == "name-hash" {
						// Name lookup keeps exploring after a match to surface conflicts.
						wantQueries++
					}
					if result.QueriedNodes != wantQueries {
						t.Fatalf("queried %d peers in %d rounds, want %d chain queries", result.QueriedNodes, result.Rounds, wantQueries)
					}
					for i := 1; i < count-1; i++ {
						requests := peers[i].requestSnapshot()
						if len(requests) != 1 {
							t.Fatalf("peer %d handled %d requests, want exactly one (responders must not recursively fan out)", i+1, len(requests))
						}
						if requests[0].Type != lookup.typeWant || requests[0].Target != lookup.target {
							t.Fatalf("wire request at peer %d = (%q, %q), want (%q, %q)", i+1, requests[0].Type, requests[0].Target, lookup.typeWant, lookup.target)
						}
					}
					targetQueries := 0
					if lookup.name == "name-hash" {
						targetQueries = 1
					}
					if got := len(peers[count-1].requestSnapshot()); got != targetQueries {
						t.Fatalf("target peer received %d queries, want %d for %s lookup", got, targetQueries, lookup.name)
					}
					t.Logf("PASS peers=%d lookup=%s queried=%d rounds=%d matches=%d", count, lookup.name, result.QueriedNodes, result.Rounds, len(result.Matches))
				})
			}
		})
	}
}

func TestFivePeerLookupReturnsIncompleteWhenOneBranchFails(t *testing.T) {
	peers := make([]*meshPeer, 5)
	for i := range peers {
		peers[i] = newMeshPeer(t, fmt.Sprintf("FAULT-%02d", i+1))
	}
	peers[0].server.RT.AddNode(peers[1].info)
	peers[0].server.RT.AddNode(peers[2].info)
	peers[1].server.RT.AddNode(peers[3].info)
	peers[3].server.RT.AddNode(peers[4].info)
	peers[2].close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := peers[0].server.RecursiveFindNodeDetailed(ctx, dht.NodeIDKey(peers[4].info.ID))
	if err != nil || result.Outcome != dht.LookupFound {
		t.Fatalf("valid identity result should succeed despite another failed branch: outcome=%s err=%v", result.Outcome, err)
	}
	if len(result.Matches) != 1 || result.Matches[0].ID != peers[4].info.ID {
		t.Fatalf("reachable branch did not return the target alongside incomplete status: %+v", result)
	}
	t.Logf("PASS peers=5 reachable-match=%s outcome=%s failed-branches=1", peers[4].info.Name, result.Outcome)
}

func TestThreePeerLookupReturnsAllSignedNameConflicts(t *testing.T) {
	root := newMeshPeer(t, "ROOT")
	leftID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	rightID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	left := newMeshPeerWithIdentity(t, leftID, "SHARED-NAME")
	right := newMeshPeerWithIdentity(t, rightID, "SHARED-NAME")
	root.server.RT.AddNode(left.info)
	root.server.RT.AddNode(right.info)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := root.server.RecursiveFindNodeDetailed(ctx, dht.NodeNameKey("SHARED-NAME"))
	if err != nil {
		t.Fatalf("name-conflict lookup: %v", err)
	}
	if result.Outcome != dht.LookupConflict || len(result.Matches) != 2 {
		t.Fatalf("conflict lookup = outcome %s matches %d, want both signed identities", result.Outcome, len(result.Matches))
	}
	if result.Matches[0].ID == result.Matches[1].ID {
		t.Fatal("conflicting name candidates were not distinct identities")
	}
	t.Logf("PASS name-conflict candidates=%d", len(result.Matches))
}

func newMeshPeerWithIdentity(t *testing.T, id identity.Identity, name string) *meshPeer {
	t.Helper()
	server := dht.NewServerWithIdentity(id)
	server.RT.SetSelfNameHash(dht.NodeNameHash(name))
	server.SetDialGuard(func(context.Context, string) error { return nil })
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatalf("listen IPv6 for %s: %v", name, err)
	}
	now := time.Now().UTC()
	ep, err := record.NewEndpointRecordV2(id, name, ln.Addr().String(), 1, time.Hour, now)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("create signed endpoint for %s: %v", name, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &meshPeer{server: server, info: dht.NodeInfoFromEndpointRecord(ep), addr: ln.Addr().String(), ln: ln, ctx: ctx, cancel: cancel}
	t.Cleanup(p.close)
	go p.serve()
	return p
}
