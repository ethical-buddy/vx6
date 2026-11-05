// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

// Package release implements signed update metadata and verification for VX6
// (#67). The design follows the spirit of TUF: the installed binary, not the
// peer that supplies the file, decides whether an update is authorized.
//
//   - Release trust is a set of Ed25519 ROOT keys pinned into the binary, with
//     a signing THRESHOLD. Root keys are offline; a quorum must sign.
//   - A manifest binds version, release sequence, OS, architecture, artifact
//     size and SHA-256 hash, and an expiry. Any DHT peer or mirror may carry
//     the bytes; only a threshold-signed manifest authorizes them.
//   - Rollback and freeze are prevented by a monotonic sequence and expiry.
//   - Keys rotate and revoke through signed root statements; the running client
//     only ever moves trust forward.
//
// This package does cryptographic verification only. Download, staging and
// atomic activation live in installer.go; neither trusts a version number,
// hash or NodeID supplied by a peer.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SchemaVersion is the manifest/root schema version. A client refuses a schema
// it does not understand rather than guessing.
const SchemaVersion = 1

// maxManifestBytes bounds untrusted metadata before any parsing.
const maxManifestBytes = 64 * 1024

// Platform identifies a build target.
type Platform struct {
	OS   string `json:"os"`   // e.g. "linux"
	Arch string `json:"arch"` // e.g. "amd64", "arm64"
}

func (p Platform) String() string { return p.OS + "/" + p.Arch }

func (p Platform) valid() bool {
	return platformToken(p.OS) && platformToken(p.Arch)
}

func platformToken(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// Artifact is one downloadable build named by a manifest.
type Artifact struct {
	Platform Platform `json:"platform"`
	Size     int64    `json:"size"`     // exact bytes
	SHA256   string   `json:"sha256"`   // lowercase hex
	Filename string   `json:"filename"` // advisory; never used as a path
}

// Manifest is the signed release description.
type Manifest struct {
	Schema    int        `json:"schema"`
	Version   string     `json:"version"`  // human version, e.g. "1.4.0"
	Sequence  uint64     `json:"sequence"` // monotonic; rollback/freeze guard
	IssuedAt  string     `json:"issued_at"`
	ExpiresAt string     `json:"expires_at"`
	Artifacts []Artifact `json:"artifacts"`
	// Signatures are detached (see SignedManifest); kept out of the signing
	// payload.
}

// SignedManifest is a manifest plus detached root signatures.
type SignedManifest struct {
	Manifest   Manifest    `json:"manifest"`
	Signatures []Signature `json:"signatures"`
}

// Signature is one root key's signature over the manifest payload.
type Signature struct {
	KeyID string `json:"key_id"` // SHA-256 (hex, 16 bytes) of the public key
	Sig   string `json:"sig"`    // base64 Ed25519 signature
}

// KeyID returns the stable identifier of a public key: first 16 bytes of its
// SHA-256, hex-encoded. Used in signatures and revocation lists.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// manifestSigningPayload is the canonical, deterministic bytes that root keys
// sign. Artifacts are sorted by platform so ordering cannot change the bytes.
// Signatures are never part of the payload.
func manifestSigningPayload(m Manifest) []byte {
	arts := append([]Artifact(nil), m.Artifacts...)
	sort.Slice(arts, func(i, j int) bool { return arts[i].Platform.String() < arts[j].Platform.String() })
	var b strings.Builder
	fmt.Fprintf(&b, "vx6/release-manifest/v%d\n", SchemaVersion)
	fmt.Fprintf(&b, "%d\n%s\n%d\n%s\n%s\n", m.Schema, m.Version, m.Sequence, m.IssuedAt, m.ExpiresAt)
	fmt.Fprintf(&b, "%d\n", len(arts))
	for _, a := range arts {
		fmt.Fprintf(&b, "%s\t%d\t%s\t%s\n", a.Platform.String(), a.Size, strings.ToLower(a.SHA256), a.Filename)
	}
	return []byte(b.String())
}

// ArtifactFor returns the artifact for a platform, if present.
func (m Manifest) ArtifactFor(p Platform) (Artifact, bool) {
	for _, a := range m.Artifacts {
		if a.Platform == p {
			return a, true
		}
	}
	return Artifact{}, false
}

func (m Manifest) validateShape(now time.Time) error {
	if m.Schema != SchemaVersion {
		return fmt.Errorf("unsupported manifest schema %d (want %d)", m.Schema, SchemaVersion)
	}
	if m.Sequence == 0 {
		return errors.New("manifest sequence must be greater than zero")
	}
	if !versionToken(m.Version) {
		return fmt.Errorf("invalid version %q", m.Version)
	}
	issued, err := time.Parse(time.RFC3339, m.IssuedAt)
	if err != nil {
		return fmt.Errorf("invalid issued_at: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil {
		return fmt.Errorf("invalid expires_at: %w", err)
	}
	if !expires.After(issued) {
		return errors.New("expires_at must be after issued_at")
	}
	if now.After(expires) {
		return fmt.Errorf("manifest expired at %s (freeze/stale-metadata guard)", m.ExpiresAt)
	}
	if len(m.Artifacts) == 0 || len(m.Artifacts) > 64 {
		return fmt.Errorf("manifest must name 1..64 artifacts, has %d", len(m.Artifacts))
	}
	seen := map[string]bool{}
	for _, a := range m.Artifacts {
		if !a.Platform.valid() {
			return fmt.Errorf("invalid platform %q", a.Platform.String())
		}
		if seen[a.Platform.String()] {
			return fmt.Errorf("duplicate platform %q", a.Platform.String())
		}
		seen[a.Platform.String()] = true
		if a.Size <= 0 || a.Size > maxArtifactBytes {
			return fmt.Errorf("artifact %s has invalid size %d", a.Platform, a.Size)
		}
		if !isHex64(a.SHA256) {
			return fmt.Errorf("artifact %s has invalid sha256", a.Platform)
		}
		if strings.ContainsAny(a.Filename, "/\\\x00") || len(a.Filename) > 128 {
			return fmt.Errorf("artifact %s has unsafe filename", a.Platform)
		}
	}
	return nil
}

// maxArtifactBytes caps a claimed artifact size (256 MiB) so a hostile manifest
// cannot ask the client to stage an unbounded download.
const maxArtifactBytes = 256 * 1024 * 1024

func versionToken(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '.' || r == '-' || r == '+') {
			return false
		}
	}
	return true
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ParseSignedManifest decodes and shape-checks untrusted manifest bytes. It
// does NOT verify signatures; call Verifier.Verify for that.
func ParseSignedManifest(data []byte) (*SignedManifest, error) {
	if len(data) == 0 {
		return nil, errors.New("empty manifest")
	}
	if len(data) > maxManifestBytes {
		return nil, fmt.Errorf("manifest too large (%d bytes)", len(data))
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var sm SignedManifest
	if err := dec.Decode(&sm); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if len(sm.Signatures) == 0 || len(sm.Signatures) > 32 {
		return nil, fmt.Errorf("manifest must carry 1..32 signatures, has %d", len(sm.Signatures))
	}
	return &sm, nil
}

func decodeSig(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature is %d bytes, want %d", len(raw), ed25519.SignatureSize)
	}
	return raw, nil
}
