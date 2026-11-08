package dht

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/strictjson"
)

func TestDHTIngressRateLimitIsPerAuthenticatedPeerAndWindowed(t *testing.T) {
	s := NewServer("vx6_test")
	start := time.Unix(1_800_000_000, 0)
	for i := 0; i < dhtIngressBurst; i++ {
		if !s.allowDHTIngress("peer-a", start) {
			t.Fatalf("limited peer-a before burst limit at request %d", i+1)
		}
	}
	if s.allowDHTIngress("peer-a", start) {
		t.Fatal("accepted request beyond configured burst")
	}
	if !s.allowDHTIngress("peer-b", start) {
		t.Fatal("peer-a rate limit affected another peer")
	}
	if !s.allowDHTIngress("peer-a", start.Add(dhtIngressWindow)) {
		t.Fatal("rate window did not reset")
	}
}

func TestDHTRejectsInvalidRequestBeforeStateMutation(t *testing.T) {
	s := NewServer("vx6_local")
	serverConn, peerConn := net.Pipe()
	defer serverConn.Close()
	defer peerConn.Close()
	err := s.HandleDHTFromPeer(context.Background(), serverConn, proto.DHTRequest{
		Version: proto.DHTWireVersion,
		Type:    proto.DHTTypeLookupName,
		Action:  "delete_everything",
		Target:  strings.Repeat("a", 64),
	}, "authenticated-peer")
	if err == nil {
		t.Fatal("accepted an unknown DHT action")
	}
	if len(s.Values) != 0 {
		t.Fatalf("invalid request mutated DHT values: %#v", s.Values)
	}
}

func TestDHTPayloadRateLimitPrecedesStrictDecode(t *testing.T) {
	s := NewServer("vx6_local")
	serverConn, peerConn := net.Pipe()
	defer serverConn.Close()
	defer peerConn.Close()
	payload := []byte(`{"version":1,"type":"lookup_name","action":"find_node","target":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","unknown":true}`)
	for i := 0; i < dhtIngressBurst; i++ {
		if err := s.HandleDHTPayload(context.Background(), serverConn, payload, "peer-a"); err == nil || !strings.Contains(err.Error(), "decode DHT request") {
			t.Fatalf("request %d did not reach strict decoder: %v", i+1, err)
		}
	}
	if err := s.HandleDHTPayload(context.Background(), serverConn, payload, "peer-a"); err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("expected rate limit before decode, got %v", err)
	}
}

func FuzzDHTRequestSchema(f *testing.F) {
	f.Add([]byte(`{"version":1,"type":"lookup_name","action":"find_node","target":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","data":""}`))
	f.Add([]byte(`{"version":1,"type":"lookup_name","action":"store","target":"ABC"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var request proto.DHTRequest
		if strictjson.Decode(data, &request) == nil {
			_ = request.Validate()
		}
	})
}
