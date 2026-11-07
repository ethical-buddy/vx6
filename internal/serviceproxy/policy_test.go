package serviceproxy

import (
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
)

func TestPrivateServicePolicyDefaultsToDeny(t *testing.T) {
	policy := ServicePolicy{Private: true}
	if policy.Allows("vx6_peer") {
		t.Fatal("private service without an allowlist must deny access")
	}
	policy.AllowedNodeIDs = []string{"vx6_allowed"}
	if !policy.Allows("vx6_allowed") {
		t.Fatal("explicitly allowed peer was denied")
	}
	if policy.Allows("vx6_other") {
		t.Fatal("peer missing from the private allowlist was allowed")
	}
	if !(ServicePolicy{}).Allows("vx6_peer") {
		t.Fatal("public service should not require a service allowlist")
	}
}

func TestPublicServiceNeedsNoDHTIdentityRecord(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		conn, err := backend.Accept()
		if err == nil {
			_, _ = conn.Write([]byte("public-ok"))
			_ = conn.Close()
		}
	}()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		serverDone <- HandleInboundWithPolicy(serverConn, map[string]ServicePolicy{
			"web": {Target: backend.Addr().String()},
		}, record.EndpointRecord{})
	}()

	payload, _ := json.Marshal(ConnectRequest{Version: 1, Action: "open", ServiceName: "web"})
	if err := proto.WriteLengthPrefixed(clientConn, payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("public-ok"))
	if _, err := io.ReadFull(clientConn, got); err != nil {
		t.Fatalf("read public service response: %v", err)
	}
	if string(got) != "public-ok" {
		t.Fatalf("unexpected public service response %q", got)
	}
	_ = clientConn.Close()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("public service handler: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("public service handler did not finish")
	}
}

func TestPrivateServiceRejectsMissingAuthenticatedIKERecord(t *testing.T) {
	clientID, _ := identity.Generate()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		serverDone <- HandleInboundWithPolicy(serverConn, map[string]ServicePolicy{
			"admin": {Target: "127.0.0.1:1", Private: true, AllowedNodeIDs: []string{clientID.NodeID}},
		}, record.EndpointRecord{})
	}()
	payload, _ := json.Marshal(ConnectRequest{Version: 1, Action: "open", ServiceName: "admin"})
	if err := proto.WriteLengthPrefixed(clientConn, payload); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverDone:
		if err == nil {
			t.Fatal("unregistered handshake identity was accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service handler did not reject unregistered peer")
	}
}

func TestPrivateServiceAllowsVerifiedIKEPeerOnAllowlist(t *testing.T) {
	clientID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := record.NewEndpointRecord(clientID, "client", "[2001:db8::2]:4242", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		conn, err := backend.Accept()
		if err == nil {
			_, _ = conn.Write([]byte("private-ok"))
			_ = conn.Close()
		}
	}()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		serverDone <- HandleInboundWithPolicy(serverConn, map[string]ServicePolicy{
			"admin": {Target: backend.Addr().String(), Private: true, AllowedNodeIDs: []string{clientID.NodeID}},
		}, peer)
	}()
	payload, _ := json.Marshal(ConnectRequest{Version: 1, Action: "open", ServiceName: "admin"})
	if err := proto.WriteLengthPrefixed(clientConn, payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("private-ok"))
	if _, err := io.ReadFull(clientConn, got); err != nil {
		t.Fatalf("read private service response: %v", err)
	}
	if string(got) != "private-ok" {
		t.Fatalf("unexpected private service response %q", got)
	}
	_ = clientConn.Close()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("private service handler: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("private service handler did not finish")
	}
}
