package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDialTimeoutAndProbeContext(t *testing.T) {
	t.Parallel()

	ln, err := Listen(ModeTCP, "[::1]:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 2)
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
			accepted <- struct{}{}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = WithDialGuard(ctx, func(context.Context, string) error { return nil })
	conn, err := DialContext(ctx, ModeTCP, ln.Addr().String())
	if err != nil {
		t.Fatalf("dial timeout: %v", err)
	}
	_ = conn.Close()

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("listener did not accept transport connection")
	}

	if !ProbeContext(ctx, ModeTCP, ln.Addr().String()) {
		t.Fatal("expected probe to succeed")
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("listener did not accept probe connection")
	}
}

func TestTransportRejectsNonIPv6Endpoints(t *testing.T) {
	t.Parallel()

	if _, err := Listen(ModeTCP, "127.0.0.1:0"); err == nil {
		t.Fatal("expected IPv4 listener to be rejected")
	}
	if _, err := Listen(ModeTCP, "localhost:4242"); err == nil {
		t.Fatal("expected hostname listener to be rejected")
	}
	if _, err := DialContext(context.Background(), ModeTCP, "127.0.0.1:4242"); err == nil {
		t.Fatal("expected IPv4 dial to be rejected")
	}
	if _, err := DialContext(context.Background(), ModeQUIC, "localhost:4242"); err == nil {
		t.Fatal("expected hostname QUIC dial to be rejected")
	}
}

func TestDialGuardRejectsBeforeOpeningSocket(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
			accepted <- struct{}{}
		}
	}()

	wantErr := fmt.Errorf("peer identity is not trusted")
	ctx := WithDialGuard(context.Background(), func(context.Context, string) error {
		return wantErr
	})
	conn, err := DialContext(ctx, ModeTCP, listener.Addr().String())
	if conn != nil {
		_ = conn.Close()
		t.Fatal("opened a socket despite rejected peer gate")
	}
	if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
		t.Fatalf("DialContext error = %v, want guarded rejection", err)
	}
	select {
	case <-accepted:
		t.Fatal("listener accepted a connection despite rejected peer gate")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPeerDialRequiresGuard(t *testing.T) {
	conn, err := DialContext(context.Background(), ModeTCP, "[2001:db8::2]:4242")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("opened a socket without an IPsec peer guard")
	}
	if err == nil || !strings.Contains(err.Error(), "unguarded") {
		t.Fatalf("DialContext error = %v, want unguarded peer rejection", err)
	}
}

func TestQUICRoundTrip(t *testing.T) {
	t.Parallel()

	ln, err := Listen(ModeQUIC, "[::1]:0")
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	defer ln.Close()

	msg := []byte("hello from quic")
	errCh := make(chan error, 1)

	// Server: accept one connection, echo the message back
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			errCh <- fmt.Errorf("server read: %w", err)
			return
		}
		if _, err := conn.Write(buf); err != nil {
			errCh <- fmt.Errorf("server write: %w", err)
			return
		}
		errCh <- nil
	}()

	// Client: dial, send, receive
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = WithDialGuard(ctx, func(context.Context, string) error { return nil })

	conn, err := DialContext(ctx, ModeQUIC, ln.Addr().String())
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("client write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server goroutine timed out")
	}
}
