package serviceproxy

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestUseObserverRunsOnlyAfterApplicationBytesFlow(t *testing.T) {
	left, leftPeer := net.Pipe()
	rightPeer, right := net.Pipe()
	defer left.Close()
	defer leftPeer.Close()
	defer rightPeer.Close()
	defer right.Close()

	var calls atomic.Int32
	called := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- proxyDuplexObserved(leftPeer, rightPeer, func() { calls.Add(1); close(called) }) }()

	writeDone := make(chan error, 1)
	go func() { _, err := left.Write([]byte("request")); writeDone <- err }()
	buf := make([]byte, len("request"))
	if _, err := io.ReadFull(right, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "request" {
		t.Fatalf("forwarded bytes = %q", buf)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("use observer did not run")
	}
	if calls.Load() != 1 {
		t.Fatalf("use observer calls = %d, want 1", calls.Load())
	}

	_ = left.Close()
	_ = right.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy did not stop after endpoints closed")
	}
}
