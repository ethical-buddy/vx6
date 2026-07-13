package secure

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
)

func TestSessionRoundTrip(t *testing.T) {
	t.Parallel()

	clientID, _ := identity.Generate()
	serverID, _ := identity.Generate()
	left, right := net.Pipe()

	errCh := make(chan error, 2)
	go func() {
		defer left.Close()
		if err := proto.WriteHeader(left, proto.KindFileTransfer); err != nil {
			errCh <- err
			return
		}
		c, err := Client(left, proto.KindFileTransfer, clientID)
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.Write([]byte("hello"))
		errCh <- err
	}()
	go func() {
		defer right.Close()
		kind, err := proto.ReadHeader(right)
		if err != nil {
			errCh <- err
			return
		}
		c, err := Server(right, kind, serverID)
		if err != nil {
			errCh <- err
			return
		}
		buf := make([]byte, 5)
		_, err = io.ReadFull(c, buf)
		if err == nil && string(buf) != "hello" {
			t.Fatalf("unexpected payload %q", string(buf))
		}
		errCh <- err
	}()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

func TestSessionExposesPeerIdentity(t *testing.T) {
	t.Parallel()

	clientID, _ := identity.Generate()
	serverID, _ := identity.Generate()
	left, right := net.Pipe()

	clientCh := make(chan *Conn, 1)
	serverCh := make(chan *Conn, 1)
	errCh := make(chan error, 2)

	go func() {
		defer left.Close()
		c, err := Client(left, proto.KindRendezvous, clientID)
		if err != nil {
			errCh <- err
			return
		}
		clientCh <- c
		errCh <- nil
	}()
	go func() {
		defer right.Close()
		c, err := Server(right, proto.KindRendezvous, serverID)
		if err != nil {
			errCh <- err
			return
		}
		serverCh <- c
		errCh <- nil
	}()

	clientConn := <-clientCh
	serverConn := <-serverCh
	if clientConn.LocalNodeID() != clientID.NodeID || clientConn.PeerNodeID() != serverID.NodeID {
		t.Fatalf("unexpected client session identities: local=%s peer=%s", clientConn.LocalNodeID(), clientConn.PeerNodeID())
	}
	if serverConn.LocalNodeID() != serverID.NodeID || serverConn.PeerNodeID() != clientID.NodeID {
		t.Fatalf("unexpected server session identities: local=%s peer=%s", serverConn.LocalNodeID(), serverConn.PeerNodeID())
	}

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

func TestSessionKeyDerivationUsesCanonicalTranscript(t *testing.T) {
	t.Parallel()

	shared := []byte("shared-secret")
	kind := byte(proto.KindFileTransfer)
	localID := "vx6_node_a"
	peerID := "vx6_node_b"
	localEph := []byte{0x01, 0x02, 0x03}
	peerEph := []byte{0x04, 0x05, 0x06}

	initiatorKey, err := deriveSessionKey(shared, kind, localID, peerID, localEph, peerEph)
	if err != nil {
		t.Fatalf("derive initiator key: %v", err)
	}
	responderKey, err := deriveSessionKey(shared, kind, peerID, localID, peerEph, localEph)
	if err != nil {
		t.Fatalf("derive responder key: %v", err)
	}
	if !bytes.Equal(initiatorKey, responderKey) {
		t.Fatalf("expected canonical transcript ordering to produce identical keys")
	}
}

func TestSessionKeyDerivationChangesWithSessionContext(t *testing.T) {
	t.Parallel()

	shared := []byte("shared-secret")
	kind := byte(proto.KindFileTransfer)
	base, err := deriveSessionKey(shared, kind, "vx6_node_a", "vx6_node_b", []byte{0x01, 0x02, 0x03}, []byte{0x04, 0x05, 0x06})
	if err != nil {
		t.Fatalf("derive base key: %v", err)
	}

	otherKind, err := deriveSessionKey(shared, kind+1, "vx6_node_a", "vx6_node_b", []byte{0x01, 0x02, 0x03}, []byte{0x04, 0x05, 0x06})
	if err != nil {
		t.Fatalf("derive other kind key: %v", err)
	}
	if bytes.Equal(base, otherKind) {
		t.Fatal("expected protocol kind change to alter derived key")
	}
	peerIDChange, err := deriveSessionKey(shared, kind, "vx6_node_a", "vx6_node_c", []byte{0x01, 0x02, 0x03}, []byte{0x04, 0x05, 0x06})
	if err != nil {
		t.Fatalf("derive peer id key: %v", err)
	}
	if bytes.Equal(base, peerIDChange) {
		t.Fatal("expected peer identity change to alter derived key")
	}
	ephChange, err := deriveSessionKey(shared, kind, "vx6_node_a", "vx6_node_b", []byte{0x01, 0x02, 0x04}, []byte{0x04, 0x05, 0x06})
	if err != nil {
		t.Fatalf("derive ephemeral key: %v", err)
	}
	if bytes.Equal(base, ephChange) {
		t.Fatal("expected ephemeral key change to alter derived key")
	}
}

func TestReadHelloRejectsUnsupportedVersion(t *testing.T) {
	t.Parallel()

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	h, err := buildHello(id, proto.KindFileTransfer, []byte("ephemeral"))
	if err != nil {
		t.Fatalf("build hello: %v", err)
	}
	h.Version = 0

	payload, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal hello: %v", err)
	}

	var buf bytes.Buffer
	if err := proto.WriteLengthPrefixed(&buf, payload); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	if _, err := readHello(&buf, proto.KindFileTransfer); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected version error, got %v", err)
	}
}
