// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/liveness"
	"github.com/vx6/vx6/internal/record"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

type recordingTunnel struct{ ensured []string }

func (t *recordingTunnel) EnsurePeer(_ context.Context, peer record.EndpointRecord) error {
	t.ensured = append(t.ensured, peer.NodeID)
	return nil
}

func TestLookupDialGuardMirrorsNodeRules(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	peerID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer udp.Close()
	addr := net.JoinHostPort("::1", strconv.Itoa(udp.LocalAddr().(*net.UDPAddr).Port-1))
	peer, err := record.NewEndpointRecordV2(peerID, "PEER", addr, 1, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = liveness.NewResponder().Serve(ctx, udp, func() (record.EndpointRecord, error) { return peer, nil }, nil)
	}()

	registry, err := discovery.NewRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	tunnel := &recordingTunnel{}
	guard := newLookupDialGuard(registry, dht.NewServer("self"), tunnel, liveness.NewCache(20*time.Second))

	if err := guard(ctx, addr); err == nil || !strings.Contains(err.Error(), "no verified signed DHT identity") {
		t.Fatalf("unknown endpoint must be rejected, got %v", err)
	}
	if err := registry.Import([]record.EndpointRecord{peer}, nil); err != nil {
		t.Fatal(err)
	}
	other, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := guard(vxtransport.WithExpectedPeerID(ctx, other.NodeID), addr); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected-peer mismatch must be rejected, got %v", err)
	}
	if err := guard(ctx, addr); err != nil {
		t.Fatalf("verified live peer must be allowed: %v", err)
	}
	if len(tunnel.ensured) != 1 || tunnel.ensured[0] != peerID.NodeID {
		t.Fatalf("guard must hand the verified peer to the tunnel, got %v", tunnel.ensured)
	}
}
