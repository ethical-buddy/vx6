package transport

import (
	"context"
	"net"
	"strings"
	"time"
)

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
		return ModeQUIC          // ← now returns real QUIC, not TCP
	case ModeTCP, ModeAuto:
		return ModeTCP
	default:
		return ModeTCP
	}
}

func Listen(mode, addr string) (net.Listener, error) {
	if EffectiveMode(mode) == ModeQUIC {
		return quicListen(addr)
	}
	return net.Listen("tcp", addr)
}

func DialContext(ctx context.Context, mode, addr string) (net.Conn, error) {
	if EffectiveMode(mode) == ModeQUIC {
		return quicDial(ctx, addr)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", addr)
}

func DialTimeout(mode, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return DialContext(ctx, mode, addr)
}

func ProbeContext(ctx context.Context, mode, addr string) bool {
	conn, err := DialContext(ctx, mode, addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
