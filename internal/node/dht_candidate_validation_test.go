package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/liveness"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
)

type candidateValidationTunnel struct {
	expectedID string
	ensureErr  error
	ensureCall int
}

func (t *candidateValidationTunnel) PreparePeer(context.Context, record.EndpointRecord) error {
	return nil
}

func (t *candidateValidationTunnel) EnsurePeer(_ context.Context, peer record.EndpointRecord) error {
	t.ensureCall++
	if peer.NodeID != t.expectedID {
		return fmt.Errorf("unexpected peer ID %q", peer.NodeID)
	}
	return t.ensureErr
}

func (t *candidateValidationTunnel) RegisterProbePort(context.Context, string) error {
	return nil
}

func (t *candidateValidationTunnel) AuthenticatePeer(context.Context, string) (record.EndpointRecord, bool) {
	return record.EndpointRecord{}, false
}

func startRoutingValidationPeer(t *testing.T, peerRecord record.EndpointRecord) (string, *candidateValidationTunnel) {
	t.Helper()
	udp, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	tcpPort := udp.LocalAddr().(*net.UDPAddr).Port - 1
	if tcpPort < 1 {
		udp.Close()
		t.Fatal("allocated UDP port cannot provide an adjacent TCP port")
	}
	endpoint := net.JoinHostPort("::1", strconv.Itoa(tcpPort))
	listener, err := net.Listen("tcp6", endpoint)
	if err != nil {
		udp.Close()
		t.Fatalf("listen on adjacent IPv6 TCP endpoint: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = udp.Close()
		_ = listener.Close()
	})
	go func() { _ = liveness.NewResponder().Serve(ctx, udp, nil, nil) }()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		kind, readErr := proto.ReadHeader(conn)
		if readErr != nil || kind != proto.KindLiveness {
			return
		}
		_ = liveness.HandleTunnelConn(conn)
	}()

	tunnel := &candidateValidationTunnel{expectedID: peerRecord.NodeID}
	return endpoint, tunnel
}

func TestCandidatePromotesOnlyAfterIdentityIKEAndProtectedPathChecks(t *testing.T) {
	peerIdentity, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// Reserve an adjacent local endpoint pair first, then sign the advertised TCP address.
	placeholder, err := record.NewEndpointRecordV2(peerIdentity, "ROUTE-PEER", "[::1]:4242", 1, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	endpoint, tunnel := startRoutingValidationPeer(t, placeholder)
	peerRecord, err := record.NewEndpointRecordV2(peerIdentity, "ROUTE-PEER", endpoint, 2, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	peer := dht.NodeInfoFromEndpointRecord(peerRecord)

	t.Run("invalid signed identity stays candidate", func(t *testing.T) {
		bad := peer
		bad.Name = "IMPOSTOR"
		rt := dht.NewRoutingTable("self")
		rt.AddCandidate(bad)
		err := verifyAndPromoteRoutingCandidate(context.Background(), Config{IPsecTunnel: tunnel}, rt, bad)
		if err == nil {
			t.Fatal("invalid signed name was accepted")
		}
		if _, active := rt.ActiveNode(bad.ID); active {
			t.Fatal("invalid signed identity became active")
		}
		if tunnel.ensureCall != 0 {
			t.Fatalf("IKE verifier called %d times before identity validation", tunnel.ensureCall)
		}
	})

	t.Run("IKE rejection stays candidate", func(t *testing.T) {
		rt := dht.NewRoutingTable("self")
		rt.AddCandidate(peer)
		tunnel.ensureErr = errors.New("wrong IKE peer key")
		err := verifyAndPromoteRoutingCandidate(context.Background(), Config{IPsecTunnel: tunnel}, rt, peer)
		if err == nil {
			t.Fatal("candidate passed a rejected IKE peer check")
		}
		if _, active := rt.ActiveNode(peer.ID); active {
			t.Fatal("candidate became active after IKE rejection")
		}
		if tunnel.ensureCall != 1 {
			t.Fatalf("EnsurePeer called %d times, want once", tunnel.ensureCall)
		}
	})

	t.Run("all checks pass and route is promoted", func(t *testing.T) {
		tunnel.ensureErr = nil
		rt := dht.NewRoutingTable("self")
		rt.AddCandidate(peer)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := verifyAndPromoteRoutingCandidate(ctx, Config{TransportMode: "tcp", IPsecTunnel: tunnel}, rt, peer); err != nil {
			t.Fatalf("valid signed identity, IKE gate, and protected health path rejected: %v", err)
		}
		if _, active := rt.ActiveNode(peer.ID); !active {
			t.Fatal("fully checked candidate was not promoted")
		}
		if tunnel.ensureCall != 2 {
			t.Fatalf("EnsurePeer called %d times, want once for each valid identity attempt", tunnel.ensureCall)
		}
	})
}
