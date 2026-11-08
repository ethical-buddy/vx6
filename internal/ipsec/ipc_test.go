package ipsec

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/record"
)

func TestIPsecServiceIPCAuthenticatesLocalUID(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "service.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	allowed := map[uint32]struct{}{uint32(os.Getuid()): {}}
	managers := &managerCache{items: make(map[string]*Manager)}
	firewall, err := newFirewall(t.TempDir(), func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			serveIPCConn(ctx, conn, allowed, t.TempDir(), managers, firewall)
		}
	}()
	client, err := NewClient(path, "[2001:db8::1]:4242", id)
	if err != nil {
		t.Fatal(err)
	}
	checkCtx, cancelCheck := context.WithTimeout(ctx, time.Second)
	defer cancelCheck()
	if err := client.Check(checkCtx); err != nil {
		t.Fatalf("authorized service request rejected: %v", err)
	}
}

func TestIPsecClientReceivesAuthenticatedPeerRecord(t *testing.T) {
	localID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	remoteID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := record.NewEndpointRecord(remoteID, "remote", "[2001:db8::2]:4242", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req ipcRequest
		if json.NewDecoder(conn).Decode(&req) != nil || req.Action != "authenticate" {
			return
		}
		_ = json.NewEncoder(conn).Encode(ipcResponse{OK: true, Allow: true, Peer: peer})
	}()
	client, err := NewClient(path, "[2001:db8::1]:4242", localID)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := client.AuthenticatePeer(context.Background(), "[2001:db8::2]:50000")
	if !ok {
		t.Fatal("authenticated peer record was not returned")
	}
	if got.NodeID != remoteID.NodeID {
		t.Fatalf("got peer NodeID %q, want %q", got.NodeID, remoteID.NodeID)
	}
}

func TestIPsecServiceIPCRejectsUnlistedUID(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "service.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	blocked := uint32(os.Getuid() + 1)
	if blocked == uint32(os.Getuid()) {
		blocked++
	}
	allowed := map[uint32]struct{}{blocked: {}}
	managers := &managerCache{items: make(map[string]*Manager)}
	firewall, err := newFirewall(t.TempDir(), func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			serveIPCConn(context.Background(), conn, allowed, t.TempDir(), managers, firewall)
		}
	}()
	client, err := NewClient(path, "[2001:db8::1]:4242", id)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Check(context.Background()); err == nil {
		t.Fatal("unauthorized local UID was accepted")
	}
}
