package node

import (
	"testing"
	"time"

	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/record"
)

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
