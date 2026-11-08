package serviceproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/record"
)

func TestUDPServiceDatagramRoundTripOverPeerSocket(t *testing.T) {
	backend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := backend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteToUDP([]byte("reply:"+string(buf[:n])), addr)
		}
	}()

	base, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portText, _ := net.SplitHostPort(base.Addr().String())
	_ = base.Close()
	port, _ := strconv.Atoi(portText)
	if port >= 65535 {
		t.Skip("ephemeral port cannot reserve UDP service port")
	}
	serviceSocket, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: port + 2})
	if err != nil {
		t.Fatal(err)
	}
	defer serviceSocket.Close()

	peerID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := record.NewEndpointRecord(peerID, "peer", "[::1]:4242", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	policies := func() map[string]ServicePolicy {
		return map[string]ServicePolicy{"dns": {
			Target: backend.LocalAddr().String(), Protocol: record.ServiceProtocolUDP,
			Private: true, AllowedNodeIDs: []string{peer.NodeID},
		}}
	}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- ServeUDPServices(ctx, serviceSocket, policies, func(context.Context, string) (record.EndpointRecord, bool) {
			return peer, true
		})
	}()

	service := record.ServiceRecord{NodeName: "PEER", ServiceName: "dns", Protocol: record.ServiceProtocolUDP, Address: net.JoinHostPort("::1", portText)}
	clientDone := make(chan error, 1)
	ready := make(chan net.Addr, 1)
	go func() {
		clientDone <- ServeLocalUDPForwardReady(ctx, "127.0.0.1:0", service, func(context.Context) (net.Conn, error) {
			left, right := net.Pipe()
			_ = right.Close()
			return left, nil
		}, ready)
	}()
	var forwardAddr string
	select {
	case addr := <-ready:
		forwardAddr = addr.String()
	case err := <-clientDone:
		t.Fatalf("UDP forwarder exited before test: %v", err)
	case <-time.After(time.Second):
		t.Fatal("UDP local forwarder did not start")
	}
	var clients sync.WaitGroup
	errCh := make(chan error, 3)
	for i := 0; i < 3; i++ {
		message := "packet-" + strconv.Itoa(i)
		clients.Add(1)
		go func() {
			defer clients.Done()
			conn, err := net.DialTimeout("udp", forwardAddr, time.Second)
			if err != nil {
				errCh <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.WriteString(conn, message); err != nil {
				errCh <- err
				return
			}
			buf := make([]byte, 256)
			n, err := conn.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if got, want := string(buf[:n]), "reply:"+message; got != want {
				errCh <- fmt.Errorf("reply = %q, want %q", got, want)
			}
		}()
	}
	clients.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Error(err)
		}
	}
	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("UDP peer listener: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP peer listener did not stop")
	}
}

func TestUDPAuthenticationCacheHasHardEntryBound(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := record.NewEndpointRecord(id, "peer", "[2001:db8::1]:4242", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cache := make(map[string]peerAuthEntry, maxUDPAuthEntries)
	for i := 0; i < maxUDPAuthEntries; i++ {
		cache[fmt.Sprintf("2001:db8::%x", i+1)] = peerAuthEntry{peer: peer, expires: time.Now().Add(time.Minute)}
	}
	var mu sync.Mutex
	authCalls := 0
	remote := &net.UDPAddr{IP: net.ParseIP("2001:db8::ffff"), Port: 40000}
	_, ok := cachedUDPIdentity(context.Background(), remote, cache, &mu, func(context.Context, string) (record.EndpointRecord, bool) {
		authCalls++
		return peer, true
	})
	if ok || authCalls != 0 || len(cache) != maxUDPAuthEntries {
		t.Fatalf("full UDP auth cache was not fail-closed: ok=%v authCalls=%d entries=%d", ok, authCalls, len(cache))
	}
}

func TestDecodeUDPServiceDatagramRejectsMalformedHeader(t *testing.T) {
	for _, packet := range [][]byte{nil, []byte("notvx6"), []byte("VX6U\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")} {
		if _, _, _, err := DecodeUDPServiceDatagram(packet); err == nil {
			t.Fatalf("accepted malformed envelope %q", packet)
		}
	}
	packet, err := EncodeUDPServiceDatagram("web", 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	name, id, payload, err := DecodeUDPServiceDatagram(packet)
	if err != nil || name != "web" || id != 1 || string(payload) != "payload" {
		t.Fatalf("round trip = %q/%d/%q, err=%v", name, id, payload, err)
	}
}

func TestEncodeUDPServiceDatagramRejectsOversizedPayload(t *testing.T) {
	if _, err := EncodeUDPServiceDatagram("dns", 1, make([]byte, maxUDPDatagramLen)); err == nil {
		t.Fatal("accepted a payload whose VX6 envelope exceeds the UDP datagram limit")
	}
}
