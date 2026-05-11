package transport

import (
	"context"
	"fmt"
	"io"
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

	conn, err := DialTimeout(ModeTCP, ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial timeout: %v", err)
	}
	_ = conn.Close()

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("listener did not accept transport connection")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !ProbeContext(ctx, ModeTCP, ln.Addr().String()) {
		t.Fatal("expected probe to succeed")
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("listener did not accept probe connection")
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