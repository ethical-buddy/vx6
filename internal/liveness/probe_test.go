// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package liveness

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

func TestProbePongAndIdentityDiscovery(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	provider := func() (record.EndpointRecord, error) {
		return record.NewEndpointRecord(id, "peer", "[::1]:4242", time.Minute, time.Now())
	}
	var acceptedIdentity string
	acceptIdentity := func(_ context.Context, caller record.EndpointRecord, source net.IP) error {
		if !endpointIPMatches(caller.Address, source) {
			t.Fatalf("caller endpoint did not match UDP source: %s vs %s", caller.Address, source)
		}
		acceptedIdentity = caller.NodeID
		return nil
	}
	go func() { _ = NewResponder().Serve(ctx, conn, provider, acceptIdentity) }()
	probePort := conn.LocalAddr().(*net.UDPAddr).Port
	endpoint := net.JoinHostPort("::1", strconv.Itoa(probePort-1))

	if rec, _, err := Probe(ctx, endpoint, false, time.Second); err != nil || rec != nil {
		t.Fatalf("compact liveness probe = record %v, err %v", rec, err)
	}
	caller, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	callerRecord, err := record.NewEndpointRecord(caller, "caller", "[::1]:4242", time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec, _, err := ExchangeIdentity(ctx, endpoint, callerRecord, time.Second)
	if err != nil {
		t.Fatalf("identity exchange: %v", err)
	}
	if acceptedIdentity != caller.NodeID {
		t.Fatalf("responder did not receive caller identity: got %q want %q", acceptedIdentity, caller.NodeID)
	}
	if rec.NodeID != id.NodeID || rec.NodeName != "PEER" {
		t.Fatalf("unexpected signed identity response: %+v", rec)
	}
	if err := record.VerifyEndpointRecord(*rec, time.Now()); err != nil {
		t.Fatalf("identity response is not signed/valid: %v", err)
	}
}

func TestProbeAddressRequiresIPv6AndAvailableAdjacentPort(t *testing.T) {
	for _, endpoint := range []string{"127.0.0.1:4242", "[::1]:65535", "missing-port"} {
		if _, err := ProbeAddress(endpoint); err == nil {
			t.Errorf("ProbeAddress(%q) unexpectedly succeeded", endpoint)
		}
	}
	got, err := ProbeAddress("[2001:db8::1]:4242")
	if err != nil || got != "[2001:db8::1]:4243" {
		t.Fatalf("ProbeAddress = %q, %v", got, err)
	}
}

func TestDecodeRejectsMalformedAndOversizedProbe(t *testing.T) {
	var nonce [16]byte
	nonce[0] = 1
	valid := encode(message{kind: kindPing, wantIdentity: true, nonce: nonce})
	if _, err := decode(valid); err != nil {
		t.Fatalf("valid padded identity probe rejected: %v", err)
	}
	for _, malformed := range [][]byte{valid[:len(valid)-1], append(append([]byte(nil), valid...), 0), []byte("not-a-probe")} {
		if _, err := decode(malformed); err == nil {
			t.Errorf("malformed packet of %d bytes was accepted", len(malformed))
		}
	}
}

func TestResponderRateLimitsAndBoundsSources(t *testing.T) {
	responder := NewResponder()
	now := time.Now()
	for i := 0; i < 10; i++ {
		if !responder.allow("2001:db8::1", now) {
			t.Fatalf("per-source burst rejected packet %d", i)
		}
	}
	if responder.allow("2001:db8::1", now) {
		t.Fatal("per-source limit allowed packet beyond burst")
	}
	for i := 0; i < 2050; i++ {
		responder.allow(net.JoinHostPort("2001:db8::2", "0"), now.Add(time.Duration(i)*time.Nanosecond))
	}
	if len(responder.sources) > 2048 {
		t.Fatalf("source limiter grew unbounded: %d", len(responder.sources))
	}
}

func TestTunnelPingPongOverGuardedVX6Connection(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		kind, err := proto.ReadHeader(conn)
		if err == nil && kind != proto.KindLiveness {
			err = errors.New("wrong liveness message kind")
		}
		if err == nil {
			err = HandleTunnelConn(conn)
		}
		serverErr <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = vxtransport.WithDialGuard(ctx, func(context.Context, string) error { return nil })
	if err := TunnelPing(ctx, vxtransport.ModeTCP, listener.Addr().String(), time.Second); err != nil {
		t.Fatalf("tunnel ping: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("tunnel PONG handler: %v", err)
	}
}

func TestTunnelPingRequiresChallengeEcho(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
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
		_, _ = proto.ReadHeader(conn)
		payload, _ := proto.ReadLengthPrefixed(conn, maxTunnelMessage)
		var request tunnelMessage
		_ = json.Unmarshal(payload, &request)
		_ = writeTunnelMessage(conn, tunnelMessage{Version: 1, Type: "pong", Nonce: strings.Repeat("0", 32)})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = vxtransport.WithDialGuard(ctx, func(context.Context, string) error { return nil })
	if err := TunnelPing(ctx, vxtransport.ModeTCP, listener.Addr().String(), time.Second); err == nil {
		t.Fatal("accepted a PONG with the wrong nonce")
	}
}
