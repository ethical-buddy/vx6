package ipsec

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
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
