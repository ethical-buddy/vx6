package discovery

import (
	"net"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/strictjson"
)

func TestMalformedDiscoveryRequestDoesNotMutateRegistry(t *testing.T) {
	registry, err := NewRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	done := make(chan error, 1)
	go func() { done <- registry.HandleConn(serverConn) }()
	if err := proto.WriteLengthPrefixed(clientConn, []byte(`{"action":"snapshot","extra":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := proto.ReadHeader(clientConn); err != nil {
		t.Fatal(err)
	}
	payload, err := proto.ReadLengthPrefixed(clientConn, maxMessageSize)
	if err != nil {
		t.Fatal(err)
	}
	var reply response
	if err := strictjson.Decode(payload, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.OK || reply.Error == "" {
		t.Fatalf("malformed request was not rejected: %+v", reply)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handler response: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("discovery handler did not finish")
	}
	if nodes, services := registry.Snapshot(); len(nodes) != 0 || len(services) != 0 {
		t.Fatalf("malformed request mutated registry: %d nodes, %d services", len(nodes), len(services))
	}
}

func FuzzDiscoveryRequestSchema(f *testing.F) {
	f.Add([]byte(`{"action":"snapshot"}`))
	f.Add([]byte(`{"action":"resolve","name":"NODE-A","node_id":"vx6_id"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var request request
		if strictjson.Decode(data, &request) == nil {
			_ = request.validate()
		}
	})
}
