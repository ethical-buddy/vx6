// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package transport

// Benchmarks for issues #45/#46: the cost of the inner stream transport
// alone (TCP vs the optional QUIC mode) on loopback. They intentionally call
// the unexported listen/dial helpers so they run on hosts without IPv6 and
// without an IPsec dial guard. They measure transport overhead only; ESP cost
// is measured by scripts/bench/ipsec-baseline.sh. Results must not be read as
// TCP-over-ESP vs QUIC-over-ESP numbers.

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func loopbackAddr(tb testing.TB) string {
	if ln, err := net.Listen("tcp", "[::1]:0"); err == nil {
		ln.Close()
		return "[::1]:0"
	}
	return "127.0.0.1:0"
}

type pair struct {
	ln   net.Listener
	dial func(context.Context) (net.Conn, error)
}

func newPair(tb testing.TB, mode string) pair {
	addr := loopbackAddr(tb)
	if mode == ModeQUIC {
		ln, err := quicListen(addr)
		if err != nil {
			tb.Skipf("quic listen: %v", err)
		}
		target := ln.Addr().String()
		return pair{ln, func(ctx context.Context) (net.Conn, error) { return quicDial(ctx, target) }}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		tb.Fatal(err)
	}
	target := ln.Addr().String()
	return pair{ln, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target)
	}}
}

func echoServer(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
	}
}

func sinkServer(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() { defer c.Close(); _, _ = io.Copy(io.Discard, c); _, _ = c.Write([]byte{1}) }()
	}
}

func benchRR(b *testing.B, mode string, size int) {
	p := newPair(b, mode)
	defer p.ln.Close()
	go echoServer(p.ln)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := p.dial(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, size)
	b.SetBytes(int64(2 * size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Write(buf); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(c, buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRequestResponse64B_TCP(b *testing.B)  { benchRR(b, ModeTCP, 64) }
func BenchmarkRequestResponse64B_QUIC(b *testing.B) { benchRR(b, ModeQUIC, 64) }
func BenchmarkRequestResponse16K_TCP(b *testing.B)  { benchRR(b, ModeTCP, 16<<10) }
func BenchmarkRequestResponse16K_QUIC(b *testing.B) { benchRR(b, ModeQUIC, 16<<10) }

func benchConnect(b *testing.B, mode string) {
	p := newPair(b, mode)
	defer p.ln.Close()
	go echoServer(p.ln)
	one := []byte{7}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := p.dial(ctx)
		if err != nil {
			cancel()
			b.Fatal(err)
		}
		if _, err := c.Write(one); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(c, one); err != nil {
			b.Fatal(err)
		}
		c.Close()
		cancel()
	}
}

// Connection setup + first round trip. VX6 opens one stream per connection.
func BenchmarkConnectFirstByte_TCP(b *testing.B)  { benchConnect(b, ModeTCP) }
func BenchmarkConnectFirstByte_QUIC(b *testing.B) { benchConnect(b, ModeQUIC) }

func benchBulk(b *testing.B, mode string) {
	p := newPair(b, mode)
	defer p.ln.Close()
	go sinkServer(p.ln)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := p.dial(ctx)
	if err != nil {
		b.Fatal(err)
	}
	chunk := make([]byte, 64<<10)
	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	c.Close()
}

func BenchmarkBulkSend_TCP(b *testing.B)  { benchBulk(b, ModeTCP) }
func BenchmarkBulkSend_QUIC(b *testing.B) { benchBulk(b, ModeQUIC) }
