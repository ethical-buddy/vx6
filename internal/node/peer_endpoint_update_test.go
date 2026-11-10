package node

import (
	"context"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/record"
)

type addressCaptureTunnel struct{}

func (addressCaptureTunnel) PreparePeer(context.Context, record.EndpointRecord) error { return nil }
func (addressCaptureTunnel) EnsurePeer(context.Context, record.EndpointRecord) error  { return nil }
func (addressCaptureTunnel) RegisterProbePort(context.Context, string) error          { return nil }
func (addressCaptureTunnel) AuthenticatePeer(context.Context, string) (record.EndpointRecord, bool) {
	return record.EndpointRecord{}, false
}

func TestRuntimePeerTunnelUsesCurrentEndpointForEachOperation(t *testing.T) {
	current := "[2001:db8::1]:4242"
	var used string
	tunnel := runtimePeerTunnel{
		address: func() string { return current },
		client: func(address string, _ identity.Identity) (PeerTunnel, error) {
			used = address
			return addressCaptureTunnel{}, nil
		},
	}
	peer := record.EndpointRecord{NodeID: "peer"}
	if err := tunnel.EnsurePeer(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	if used != current {
		t.Fatalf("client created for %q, want current endpoint %q", used, current)
	}

	current = "[2001:db8::2]:4242"
	if err := tunnel.PreparePeer(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	if used != current {
		t.Fatalf("client kept stale endpoint %q, want refreshed endpoint %q", used, current)
	}
}

func TestRegistryEndpointUpdateWinsOverStaleRoutingTableCopy(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	oldRecord, err := record.NewEndpointRecordV2(id, "PEER", "[2001:db8:1::1]:4242", 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	newRecord, err := record.NewEndpointRecordV2(id, "PEER", "[2001:db8:2::1]:4242", 2, time.Hour, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := discovery.NewRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	server := dht.NewServer("self")
	server.RT.AddNode(dht.NodeInfoFromEndpointRecord(oldRecord))
	registry.SetEndpointObserver(func(rec record.EndpointRecord) {
		server.RT.UpdateKnownNode(dht.NodeInfoFromEndpointRecord(rec))
	})
	if err := registry.Import([]record.EndpointRecord{newRecord}, nil); err != nil {
		t.Fatal(err)
	}

	records := registryRecords(registry, server)
	if len(records) != 1 || records[0].Address != newRecord.Address {
		t.Fatalf("selected peer endpoint = %+v, want newest signed address %s", records, newRecord.Address)
	}
	if got, ok := server.RT.ActiveNode(id.NodeID); !ok || got.Addr != newRecord.Address {
		t.Fatalf("known DHT route endpoint = %+v, found=%v, want %s", got, ok, newRecord.Address)
	}

	otherID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	unknownRecord, err := record.NewEndpointRecordV2(otherID, "UNKNOWN", "[2001:db8:3::1]:4242", 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Import([]record.EndpointRecord{unknownRecord}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := server.RT.ActiveNode(otherID.NodeID); ok {
		t.Fatal("a signed record alone promoted an unknown peer into active routing")
	}
}
