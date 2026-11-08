package dht

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
)

func TestUpdateIPAcceptsOnlyOwnerSignedMatchingRecord(t *testing.T) {
	now := time.Now()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := record.NewEndpointRecordV2(id, "owner", "[2001:db8::81]:4242", 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(endpoint)
	server := NewServerWithIdentity(id)
	wireData, err := server.prepareStoreValue(NodeIDKey(id.NodeID), string(data), now)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		done <- server.HandleDHT(context.Background(), serverConn, proto.DHTRequest{
			Version: proto.DHTWireVersion, Type: proto.DHTTypeUpdateIP,
			Action: "update_ip", Target: NodeIDKey(id.NodeID), Data: wireData,
		})
	}()
	kind, err := proto.ReadHeader(clientConn)
	if err != nil {
		t.Fatalf("read response header (%v); handler returned: %v", err, <-done)
	}
	if kind != proto.KindDHT {
		t.Fatalf("response kind = %d, want DHT", kind)
	}
	if _, err := proto.ReadLengthPrefixed(clientConn, 4096); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.Close()
	if err := <-done; err != nil {
		t.Fatalf("valid signed endpoint update failed: %v", err)
	}
	if got := server.Values[NodeIDKey(id.NodeID)]; got != wireData {
		t.Fatalf("stored endpoint = %q, want signed update", got)
	}
}

func TestUpdateIPRejectsTargetSubstitution(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := record.NewEndpointRecordV2(id, "owner", "[2001:db8::81]:4242", 1, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(endpoint)
	server := NewServerWithIdentity(id)
	wireData, err := server.prepareStoreValue(NodeIDKey(id.NodeID), string(data), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, right := net.Pipe()
	defer right.Close()
	err = server.HandleDHT(context.Background(), right, proto.DHTRequest{
		Version: proto.DHTWireVersion, Type: proto.DHTTypeUpdateIP,
		Action: "update_ip", Target: NodeIDKey("vx6_" + strings.Repeat("a", 64)), Data: wireData,
	})
	if err == nil {
		t.Fatal("endpoint update with a different target key was accepted")
	}
	if len(server.Values) != 0 {
		t.Fatalf("target-substituted update changed DHT values: %#v", server.Values)
	}
}
