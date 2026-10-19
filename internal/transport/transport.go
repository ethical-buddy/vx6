// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package transport

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type dialGuardKey struct{}

// DialGuard authenticates and establishes the peer's IPsec SA before VX6 opens
// an application socket. A guard is attached to a node's context so multiple
// node instances in tests or embedded deployments remain isolated.
type DialGuard func(context.Context, string) error

func WithDialGuard(ctx context.Context, guard DialGuard) context.Context {
	return context.WithValue(ctx, dialGuardKey{}, guard)
}

const (
	ModeAuto = "auto"
	ModeTCP  = "tcp"
	ModeQUIC = "quic"
)

func NormalizeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ModeAuto:
		return ModeAuto
	case ModeTCP:
		return ModeTCP
	case ModeQUIC:
		return ModeQUIC
	default:
		return ""
	}
}

func EffectiveMode(mode string) string {
	switch NormalizeMode(mode) {
	case ModeQUIC:
		return ModeQUIC // ← now returns real QUIC, not TCP
	case ModeTCP, ModeAuto:
		return ModeTCP
	default:
		return ModeTCP
	}
}

func Listen(mode, addr string) (net.Listener, error) {
	if err := validateIPv6Endpoint(addr); err != nil {
		return nil, fmt.Errorf("listen requires an IPv6 endpoint: %w", err)
	}
	if EffectiveMode(mode) == ModeQUIC {
		return quicListen(addr)
	}
	return net.Listen("tcp", addr)
}

func DialContext(ctx context.Context, mode, addr string) (net.Conn, error) {
	if err := validateIPv6Endpoint(addr); err != nil {
		return nil, fmt.Errorf("dial requires an IPv6 endpoint: %w", err)
	}
	guard, ok := ctx.Value(dialGuardKey{}).(DialGuard)
	if !ok || guard == nil {
		return nil, fmt.Errorf("refusing unguarded peer dial to %s", addr)
	}
	if err := guard(ctx, addr); err != nil {
		return nil, fmt.Errorf("IPsec peer gate rejected %s: %w", addr, err)
	}
	if EffectiveMode(mode) == ModeQUIC {
		return quicDial(ctx, addr)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", addr)
}

func validateIPv6Endpoint(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid endpoint %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		return fmt.Errorf("endpoint %q is not an IPv6 address", addr)
	}
	return nil
}

func ProbeContext(ctx context.Context, mode, addr string) bool {
	conn, err := DialContext(ctx, mode, addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
