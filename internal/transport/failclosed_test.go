// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package transport

// Fail-closed transport tests for issues #45 (QUIC stays optional and inside
// ESP) and #46 (TCP is an inner stream, never an IPsec fallback).

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func requireIPv6Loopback(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable on this host: %v", err)
	}
	ln.Close()
}

// Auto must never select QUIC: QUIC is opt-in only (#45).
func TestAutoModeNeverSelectsQUIC(t *testing.T) {
	for _, mode := range []string{"", "auto", "AUTO", " auto ", "tcp", "bogus"} {
		if got := EffectiveMode(mode); got != ModeTCP {
			t.Fatalf("EffectiveMode(%q) = %q, want tcp", mode, got)
		}
	}
	if got := EffectiveMode("quic"); got != ModeQUIC {
		t.Fatalf("explicit quic mode = %q", got)
	}
}

// 0-RTT must stay disabled unless replay-safe service semantics are
// specified (#45).
func TestQUICZeroRTTDisabled(t *testing.T) {
	if quicCfg().Allow0RTT {
		t.Fatal("QUIC 0-RTT must remain disabled")
	}
}

// A rejected IPsec gate must not send a single QUIC datagram, and must not be
// retried through another transport (#45, #46).
func TestQUICDialGuardRejectsBeforeSendingPackets(t *testing.T) {
	requireIPv6Loopback(t)
	pc, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	tcp, err := net.Listen("tcp", net.JoinHostPort("::1", portOf(t, pc.LocalAddr())))
	if err != nil {
		t.Skipf("matching TCP port busy: %v", err)
	}
	defer tcp.Close()
	tcpAccepted := make(chan struct{}, 1)
	go func() {
		if c, err := tcp.Accept(); err == nil {
			c.Close()
			tcpAccepted <- struct{}{}
		}
	}()

	var calls int32
	gateErr := errors.New("no installed CHILD_SA")
	ctx := WithDialGuard(context.Background(), func(context.Context, string) error {
		atomic.AddInt32(&calls, 1)
		return gateErr
	})
	conn, err := DialContext(ctx, ModeQUIC, pc.LocalAddr().String())
	if conn != nil {
		conn.Close()
		t.Fatal("opened a QUIC connection despite rejected IPsec gate")
	}
	if !errors.Is(err, gateErr) {
		t.Fatalf("err = %v, want wrapped gate error", err)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("gate called %d times, want exactly 1 (no retry path)", n)
	}
	_ = pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 1500)
	if n, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatalf("received %d-byte datagram despite rejected gate", n)
	}
	select {
	case <-tcpAccepted:
		t.Fatal("fell back to a TCP connection after QUIC gate rejection")
	case <-time.After(50 * time.Millisecond):
	}
}

// A TCP gate rejection must not cause any TCP connection attempt, and a
// cancelled context must fail before or during dial without fallback (#46).
func TestTCPGateRejectionAndCancellationHaveNoFallback(t *testing.T) {
	requireIPv6Loopback(t)
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&accepted, 1)
			c.Close()
		}
	}()
	for _, mode := range []string{ModeTCP, ModeAuto} {
		var calls int32
		ctx := WithDialGuard(context.Background(), func(context.Context, string) error {
			atomic.AddInt32(&calls, 1)
			return errors.New("IKE authentication failed")
		})
		if conn, err := DialContext(ctx, mode, ln.Addr().String()); err == nil || conn != nil {
			t.Fatalf("mode %s: dial succeeded despite failed IKE gate", mode)
		}
		if calls != 1 {
			t.Fatalf("mode %s: gate called %d times", mode, calls)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx = WithDialGuard(ctx, func(ctx context.Context, _ string) error { return ctx.Err() })
	if _, err := DialContext(ctx, ModeTCP, ln.Addr().String()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled dial err = %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := atomic.LoadInt32(&accepted); n != 0 {
		t.Fatalf("listener saw %d connections; want 0 (no clear fallback)", n)
	}
}

func portOf(t *testing.T, a net.Addr) string {
	t.Helper()
	_, p, err := net.SplitHostPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	return p
}
