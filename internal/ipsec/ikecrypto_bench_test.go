// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package ipsec

// Benchmarks for issue #57: the CPU cost of the standard primitives a
// VX6-owned IKEv2 control plane would call from Go's standard library for the
// current proposal (aes128gcm16-prfsha256-curve25519, Ed25519 AUTH). They do
// not implement IKE; they bound the per-handshake crypto cost so it can be
// compared with strongSwan's measured end-to-end setup time (#51).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// prfPlus is RFC 7296 section 2.13 prf+ with PRF_HMAC_SHA2_256.
func prfPlus(key, seed []byte, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	var t []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, key)
		m.Write(t)
		m.Write(seed)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

func BenchmarkIKEX25519KeyExchange(b *testing.B) {
	peer, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := k.ECDH(peer.PublicKey()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIKEEd25519SignAuth(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	octets := make([]byte, 600) // RealMessage1 | NonceR | prf(SK_pi, IDi')
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Sign(priv, octets)
	}
}

func BenchmarkIKEEd25519VerifyAuth(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	octets := make([]byte, 600)
	sig := ed25519.Sign(priv, octets)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !ed25519.Verify(pub, octets, sig) {
			b.Fatal("verify failed")
		}
	}
}

// Key schedule: SKEYSEED, SK_d/ai/ar/ei/er/pi/pr for AES-GCM-128 (no integ),
// and one CHILD_SA KEYMAT (two AES-GCM-128 keys + 4-byte salts).
func BenchmarkIKEKeySchedule(b *testing.B) {
	ni, nr, g := make([]byte, 32), make([]byte, 32), make([]byte, 32)
	spis := make([]byte, 16)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m := hmac.New(sha256.New, append(ni, nr...))
		m.Write(g)
		skeyseed := m.Sum(nil)
		seed := append(append(append([]byte{}, ni...), nr...), spis...)
		keys := prfPlus(skeyseed, seed, 32+2*20+2*32)
		_ = prfPlus(keys[:32], append(ni, nr...), 2*20)
	}
}

// One encrypted IKE message (SK payload) of a typical IKE_AUTH size.
func BenchmarkIKEMessageAESGCM128(b *testing.B) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCMWithNonceSize(block, 12)
	msg := make([]byte, 400)
	nonce := make([]byte, 12)
	aad := make([]byte, 32)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = aead.Seal(nil, nonce, msg, aad)
	}
}

// Everything one side computes for IKE_SA_INIT + IKE_AUTH + first CHILD_SA:
// one X25519 keygen + shared secret, key schedule, one Ed25519 sign, one
// Ed25519 verify, and AEAD for two protected messages.
func BenchmarkIKEFullHandshakeCryptoOneSide(b *testing.B) {
	peer, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	octets := make([]byte, 600)
	peerSig := ed25519.Sign(priv, octets)
	ni, nr := make([]byte, 32), make([]byte, 32)
	block, _ := aes.NewCipher(make([]byte, 16))
	aead, _ := cipher.NewGCM(block)
	msg := make([]byte, 400)
	nonce := make([]byte, 12)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		g, _ := k.ECDH(peer.PublicKey())
		m := hmac.New(sha256.New, append(ni, nr...))
		m.Write(g)
		keys := prfPlus(m.Sum(nil), append(ni, nr...), 136)
		_ = prfPlus(keys[:32], append(ni, nr...), 40)
		_ = ed25519.Sign(priv, octets)
		if !ed25519.Verify(pub, octets, peerSig) {
			b.Fatal("verify")
		}
		_ = aead.Seal(nil, nonce, msg, nil)
		_ = aead.Seal(nil, nonce, msg, nil)
	}
}
