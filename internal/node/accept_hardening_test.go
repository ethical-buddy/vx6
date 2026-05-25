package node

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/proto"
)

func testListener(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln, ln.Addr().String()
}

func acceptOne(ln net.Listener, deadline time.Duration) (byte, error) {
	conn, err := ln.Accept()
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(deadline)); err != nil {
		return 0, err
	}
	kind, err := proto.ReadHeader(conn)
	if err != nil {
		return 0, err
	}
	_ = conn.SetReadDeadline(time.Time{})
	return kind, nil
}

func TestStalledPeerDisconnected(t *testing.T) {
	t.Parallel()

	ln, addr := testListener(t)
	defer ln.Close()

	deadline := 500 * time.Millisecond

	errCh := make(chan error, 1)
	go func() {
		_, err := acceptOne(ln, deadline)
		errCh <- err
	}()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected header read to fail for stalled peer, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for stalled peer to be disconnected")
	}
}

func TestPartialHeaderTimeout(t *testing.T) {
	t.Parallel()

	ln, addr := testListener(t)
	defer ln.Close()

	deadline := 500 * time.Millisecond

	errCh := make(chan error, 1)
	go func() {
		_, err := acceptOne(ln, deadline)
		errCh <- err
	}()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, _ = conn.Write([]byte{'V', 'X'})

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected header read to fail for partial header, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for partial header timeout")
	}
}

func TestConnectionCapEnforced(t *testing.T) {
	t.Parallel()

	const cap = 3

	ln, addr := testListener(t)
	defer ln.Close()

	sem := make(chan struct{}, cap)
	var mu sync.Mutex
	accepted := 0
	dropped := 0
	done := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case sem <- struct{}{}:
				mu.Lock()
				accepted++
				mu.Unlock()
				go func(c net.Conn) {
					<-done
					c.Close()
					<-sem
				}(conn)
			default:
				mu.Lock()
				dropped++
				mu.Unlock()
				conn.Close()
			}
		}
	}()

	conns := make([]net.Conn, 0, cap)
	for i := 0; i < cap; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if accepted != cap {
		t.Fatalf("expected %d accepted, got %d", cap, accepted)
	}
	mu.Unlock()

	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial extra: %v", err)
	}
	extra.Close()
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if dropped != 1 {
		t.Fatalf("expected 1 dropped, got %d", dropped)
	}
	mu.Unlock()

	close(done)
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	prevAccepted := accepted
	mu.Unlock()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial after release: %v", err)
	}
	c.Close()
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if accepted <= prevAccepted {
		t.Fatalf("expected a new connection to be accepted after slot release, accepted=%d prev=%d", accepted, prevAccepted)
	}
	mu.Unlock()
}

func TestEffectiveMaxConcurrentConns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input int
		want  int
	}{
		{0, defaultMaxConcurrentConns},
		{-1, defaultMaxConcurrentConns},
		{512, 512},
		{2048, 2048},
	}
	for _, tc := range tests {
		got := effectiveMaxConcurrentConns(tc.input)
		if got != tc.want {
			t.Errorf("effectiveMaxConcurrentConns(%d) = %d, want %d", tc.input, got, tc.want)
		}
	}
}
