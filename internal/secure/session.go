// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package secure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
)

const maxHandshakeSize = 8 * 1024
const maxChunkSize = 32 * 1024
const secureSessionVersion byte = 1
const secureSessionLabel = "vx6-secure-session"

type hello struct {
	Version   byte   `json:"version"`
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"`
	Ephemeral string `json:"ephemeral"`
	Signature string `json:"signature"`
}

type Conn struct {
	net.Conn
	aead        cipher.AEAD
	readCounter uint64
	writeCtr    uint64
	readBuf     []byte
	writeDir    byte
	readDir     byte
	localNodeID string
	peerNodeID  string
}

func Client(conn net.Conn, kind byte, id identity.Identity) (*Conn, error) {
	return handshake(conn, kind, id, true)
}

func Server(conn net.Conn, kind byte, id identity.Identity) (*Conn, error) {
	return handshake(conn, kind, id, false)
}

func handshake(conn net.Conn, kind byte, id identity.Identity, initiator bool) (*Conn, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}

	localHello, err := buildHello(id, kind, priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}

	if initiator {
		if err := writeHello(conn, localHello); err != nil {
			return nil, err
		}
	}

	remoteHello, err := readHello(conn, kind)
	if err != nil {
		return nil, err
	}

	if !initiator {
		if err := writeHello(conn, localHello); err != nil {
			return nil, err
		}
	}

	remoteEph, err := remoteHello.ephemeralBytes()
	if err != nil {
		return nil, err
	}
	remotePub, err := curve.NewPublicKey(remoteEph)
	if err != nil {
		return nil, fmt.Errorf("parse remote ephemeral key: %w", err)
	}
	shared, err := priv.ECDH(remotePub)
	if err != nil {
		return nil, fmt.Errorf("derive shared key: %w", err)
	}

	key, err := deriveSessionKey(shared, kind, id.NodeID, remoteHello.NodeID, priv.PublicKey().Bytes(), remoteEph)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	c := &Conn{
		Conn:        conn,
		aead:        aead,
		localNodeID: id.NodeID,
		peerNodeID:  remoteHello.NodeID,
	}
	if initiator {
		c.writeDir = 0
		c.readDir = 1
	} else {
		c.writeDir = 1
		c.readDir = 0
	}
	return c, nil
}

func (c *Conn) LocalNodeID() string {
	return c.localNodeID
}

func (c *Conn) PeerNodeID() string {
	return c.peerNodeID
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(c.readBuf) == 0 {
		payload, err := proto.ReadLengthPrefixed(c.Conn, maxChunkSize+1024)
		if err != nil {
			return 0, err
		}
		plain, err := c.aead.Open(nil, nonce(c.readDir, c.readCounter), payload, nil)
		if err != nil {
			return 0, fmt.Errorf("decrypt chunk: %w", err)
		}
		c.readCounter++
		c.readBuf = plain
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxChunkSize {
			n = maxChunkSize
		}
		sealed := c.aead.Seal(nil, nonce(c.writeDir, c.writeCtr), p[:n], nil)
		if err := proto.WriteLengthPrefixed(c.Conn, sealed); err != nil {
			return total, err
		}
		c.writeCtr++
		total += n
		p = p[n:]
	}
	return total, nil
}

func buildHello(id identity.Identity, kind byte, eph []byte) (hello, error) {
	sig := ed25519.Sign(id.PrivateKey, signingPayload(secureSessionVersion, kind, id.NodeID, eph))
	return hello{
		Version:   secureSessionVersion,
		NodeID:    id.NodeID,
		PublicKey: base64.StdEncoding.EncodeToString(id.PublicKey),
		Ephemeral: base64.StdEncoding.EncodeToString(eph),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

func readHello(r io.Reader, kind byte) (hello, error) {
	payload, err := proto.ReadLengthPrefixed(r, maxHandshakeSize)
	if err != nil {
		return hello{}, err
	}

	var h hello
	if err := json.Unmarshal(payload, &h); err != nil {
		return hello{}, fmt.Errorf("decode handshake: %w", err)
	}

	if h.Version != secureSessionVersion {
		return hello{}, fmt.Errorf("unsupported secure-session version %d", h.Version)
	}

	pub, err := base64.StdEncoding.DecodeString(h.PublicKey)
	if err != nil {
		return hello{}, fmt.Errorf("decode public key: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(h.Signature)
	if err != nil {
		return hello{}, fmt.Errorf("decode signature: %w", err)
	}
	eph, err := h.ephemeralBytes()
	if err != nil {
		return hello{}, err
	}

	if identity.NodeIDFromPublicKey(ed25519.PublicKey(pub)) != h.NodeID {
		return hello{}, fmt.Errorf("handshake node id mismatch")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), signingPayload(secureSessionVersion, kind, h.NodeID, eph), sig) {
		return hello{}, fmt.Errorf("handshake signature verification failed")
	}

	return h, nil
}

func writeHello(w io.Writer, h hello) error {
	payload, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}
	return proto.WriteLengthPrefixed(w, payload)
}

func (h hello) ephemeralBytes() ([]byte, error) {
	eph, err := base64.StdEncoding.DecodeString(h.Ephemeral)
	if err != nil {
		return nil, fmt.Errorf("decode ephemeral key: %w", err)
	}
	return eph, nil
}

func signingPayload(version byte, kind byte, nodeID string, eph []byte) []byte {
	var out []byte
	out = append(out, []byte("vx6-secure\n")...)
	out = append(out, version)
	out = append(out, '\n')
	out = append(out, kind)
	out = append(out, '\n')
	out = append(out, []byte(nodeID)...)
	out = append(out, '\n')
	out = append(out, eph...)
	return out
}

func deriveSessionKey(shared []byte, kind byte, localNodeID, peerNodeID string, localEph, peerEph []byte) ([]byte, error) {
	transcript := sessionTranscript(kind, localNodeID, peerNodeID, localEph, peerEph)
	key, err := hkdf.Key(sha256.New, shared, transcript, secureSessionLabel, 32)
	if err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}
	return key, nil
}

func sessionTranscript(kind byte, localNodeID, peerNodeID string, localEph, peerEph []byte) []byte {
	aID, bID, aEph, bEph := localNodeID, peerNodeID, localEph, peerEph
	if localNodeID > peerNodeID || (localNodeID == peerNodeID && bytes.Compare(localEph, peerEph) > 0) {
		aID, bID, aEph, bEph = peerNodeID, localNodeID, peerEph, localEph
	}

	var out bytes.Buffer
	out.WriteString("vx6-secure-session\n")
	out.WriteByte(kind)
	out.WriteByte('\n')
	out.WriteString(aID)
	out.WriteByte('\n')
	out.WriteString(bID)
	out.WriteByte('\n')
	out.Write(aEph)
	out.WriteByte('\n')
	out.Write(bEph)
	return out.Bytes()
}

func nonce(dir byte, counter uint64) []byte {
	var out [12]byte
	out[0] = dir
	binary.BigEndian.PutUint64(out[4:], counter)
	return out[:]
}
