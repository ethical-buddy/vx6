package secure

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
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

func TestTranscriptCanonical(t *testing.T) {
	t.Parallel()

	idA, _ := identity.Generate()
	idB, _ := identity.Generate()

	ephA := make([]byte, 32)
	ephB := make([]byte, 32)
	for i := range ephA {
		ephA[i] = byte(i)
		ephB[i] = byte(i + 64)
	}

	fromA := buildTranscript(proto.KindServiceConn, ephA, ephB, []byte(idA.PublicKey), []byte(idB.PublicKey), true)
	fromB := buildTranscript(proto.KindServiceConn, ephB, ephA, []byte(idB.PublicKey), []byte(idA.PublicKey), false)

	if !bytes.Equal(fromA, fromB) {
		t.Fatal("transcript not canonical: initiator and responder produced different transcripts")
	}
}

func TestTranscriptKindSeparation(t *testing.T) {
	t.Parallel()

	idA, _ := identity.Generate()
	idB, _ := identity.Generate()

	ephA := make([]byte, 32)
	ephB := make([]byte, 32)

	t1 := buildTranscript(proto.KindServiceConn, ephA, ephB, []byte(idA.PublicKey), []byte(idB.PublicKey), true)
	t2 := buildTranscript(proto.KindRendezvous, ephA, ephB, []byte(idA.PublicKey), []byte(idB.PublicKey), true)

	if bytes.Equal(t1, t2) {
		t.Fatal("different kind values produced identical transcripts")
	}
}

func TestTranscriptIdentitySeparation(t *testing.T) {
	t.Parallel()

	idA, _ := identity.Generate()
	idB, _ := identity.Generate()
	idC, _ := identity.Generate()

	eph := make([]byte, 32)

	t1 := buildTranscript(proto.KindServiceConn, eph, eph, []byte(idA.PublicKey), []byte(idB.PublicKey), true)
	t2 := buildTranscript(proto.KindServiceConn, eph, eph, []byte(idA.PublicKey), []byte(idC.PublicKey), true)

	if bytes.Equal(t1, t2) {
		t.Fatal("different peer identities produced identical transcripts")
	}
}

func TestTranscriptEphemeralSeparation(t *testing.T) {
	t.Parallel()

	idA, _ := identity.Generate()
	idB, _ := identity.Generate()

	eph1 := make([]byte, 32)
	eph2 := make([]byte, 32)
	eph2[0] = 1

	t1 := buildTranscript(proto.KindServiceConn, eph1, eph1, []byte(idA.PublicKey), []byte(idB.PublicKey), true)
	t2 := buildTranscript(proto.KindServiceConn, eph2, eph2, []byte(idA.PublicKey), []byte(idB.PublicKey), true)

	if bytes.Equal(t1, t2) {
		t.Fatal("different ephemerals produced identical transcripts")
	}
}

func TestTranscriptBindsFullPublicKey(t *testing.T) {
	t.Parallel()

	idA, _ := identity.Generate()
	idB, _ := identity.Generate()

	eph := make([]byte, 32)

	transcript := buildTranscript(proto.KindServiceConn, eph, eph, []byte(idA.PublicKey), []byte(idB.PublicKey), true)

	if !bytes.Contains(transcript, []byte(idA.PublicKey)) {
		t.Fatal("transcript does not contain full client static public key")
	}
	if !bytes.Contains(transcript, []byte(idB.PublicKey)) {
		t.Fatal("transcript does not contain full server static public key")
	}

	nodeIDBytes := []byte(idA.NodeID)
	if bytes.Contains(transcript, nodeIDBytes) {
		t.Fatal("transcript contains truncated node ID instead of full public key")
	}
}

func TestDeriveKeyUnique(t *testing.T) {
	t.Parallel()

	shared := make([]byte, 32)
	for i := range shared {
		shared[i] = byte(i)
	}

	t1 := []byte("transcript-a")
	t2 := []byte("transcript-b")

	k1, err := deriveKey(shared, t1)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := deriveKey(shared, t2)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(k1, k2) {
		t.Fatal("different transcripts derived identical keys")
	}
}

func TestVersionMismatchFails(t *testing.T) {
	t.Parallel()

	clientID, _ := identity.Generate()
	serverID, _ := identity.Generate()

	left, right := net.Pipe()

	errCh := make(chan error, 2)

	go func() {
		defer right.Close()
		_, err := Server(right, proto.KindServiceConn, serverID)
		errCh <- err
	}()

	go func() {
		defer left.Close()
		staleHello := hello{
			Version:   sessionVersion - 1,
			NodeID:    clientID.NodeID,
			PublicKey: base64.StdEncoding.EncodeToString(clientID.PublicKey),
			Ephemeral: base64.StdEncoding.EncodeToString(make([]byte, 32)),
			Signature: base64.StdEncoding.EncodeToString(make([]byte, 64)),
		}
		if err := writeHello(left, staleHello); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	var gotErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			gotErr = err
		}
	}
	if gotErr == nil {
		t.Fatal("expected version mismatch error, got nil")
	}
}
