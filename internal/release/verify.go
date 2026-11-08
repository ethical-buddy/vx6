// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the VX6 terms in LICENSE-COMMERCIAL.md.
// Sole inventor, maintainer, and rights holder: Suryansh Deshwal (https://github.com/ethical-buddy).

package release

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"runtime"
	"time"
)

// Verifier authorizes updates against a trust root and the running client's
// current release sequence. It holds no secrets.
type Verifier struct {
	trust      TrustRoot
	currentSeq uint64
	platform   Platform
	now        func() time.Time
}

// NewVerifier builds a verifier. currentSequence is the running build's release
// sequence (0 if unknown/first install). The platform defaults to this build's
// GOOS/GOARCH.
func NewVerifier(trust TrustRoot, currentSequence uint64) (*Verifier, error) {
	if err := trust.validateShape(); err != nil {
		return nil, fmt.Errorf("invalid trust root: %w", err)
	}
	return &Verifier{
		trust:      trust.Clone(),
		currentSeq: currentSequence,
		platform:   Platform{OS: runtime.GOOS, Arch: runtime.GOARCH},
		now:        time.Now,
	}, nil
}

// SetPlatform overrides the target platform (tests, cross-checks).
func (v *Verifier) SetPlatform(p Platform) { v.platform = p }

// TrustEpoch reports the verifier's current trust epoch.
func (v *Verifier) TrustEpoch() uint64 { return v.trust.Epoch }

// AdvanceTrust applies a signed trust-root rotation/revocation statement.
func (v *Verifier) AdvanceTrust(data []byte) error {
	next, err := v.trust.AdvanceTrust(data, v.now())
	if err != nil {
		return err
	}
	v.trust = next
	return nil
}

// VerifiedUpdate is the result of a successful manifest verification: the
// authorized artifact for this platform and the manifest it came from.
type VerifiedUpdate struct {
	Manifest Manifest
	Artifact Artifact
}

// ErrNoUpdate means the manifest is valid and authorized but is not newer than
// the running build, so there is nothing to install. It is not a failure.
var ErrNoUpdate = errors.New("manifest sequence is not newer than the running build")

// VerifyManifest checks untrusted manifest bytes end to end:
//   - parse + shape (schema, sizes, platform tokens, hex hashes),
//   - threshold of valid, distinct, non-revoked root signatures,
//   - not expired (freeze/stale guard),
//   - strictly newer sequence than the running build (rollback guard),
//   - an artifact exists for this platform.
//
// A peer's version/NodeID claims are never consulted; only the signed manifest
// authorizes bytes.
func (v *Verifier) VerifyManifest(data []byte) (*VerifiedUpdate, error) {
	sm, err := ParseSignedManifest(data)
	if err != nil {
		return nil, err
	}
	now := v.now()
	if v.trust.ExpiresAt != "" {
		rootExpiry, err := time.Parse(time.RFC3339, v.trust.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("invalid current trust-root expiry: %w", err)
		}
		if now.After(rootExpiry) {
			return nil, fmt.Errorf("current release trust root expired at %s", v.trust.ExpiresAt)
		}
	}
	if err := sm.Manifest.validateShape(now); err != nil {
		return nil, err
	}
	keys, err := v.trust.activeKeys()
	if err != nil {
		return nil, err
	}
	n := countValidSignatures(manifestSigningPayload(sm.Manifest), keys, sm.Signatures)
	if n < v.trust.Threshold {
		return nil, fmt.Errorf("manifest carries %d valid root signatures, need threshold %d", n, v.trust.Threshold)
	}
	if sm.Manifest.Sequence <= v.currentSeq {
		return nil, fmt.Errorf("%w: manifest seq %d, running seq %d", ErrNoUpdate, sm.Manifest.Sequence, v.currentSeq)
	}
	art, ok := sm.Manifest.ArtifactFor(v.platform)
	if !ok {
		return nil, fmt.Errorf("manifest has no artifact for %s", v.platform)
	}
	return &VerifiedUpdate{Manifest: sm.Manifest, Artifact: art}, nil
}

// VerifyArtifact streams artifact bytes and checks them against the authorized
// artifact's exact size and SHA-256. It reads at most the declared size + 1 so
// an oversized (padded) artifact is rejected, and reports a truncated one.
// The hash comparison is constant time.
func VerifyArtifact(r io.Reader, want Artifact) error {
	want.SHA256 = lowerHex(want.SHA256)
	h := sha256.New()
	n, err := copyExact(h, r, want.Size)
	if err != nil {
		return err
	}
	if n != want.Size {
		return fmt.Errorf("artifact is %d bytes, manifest says %d (truncated/interrupted download)", n, want.Size)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(got), []byte(want.SHA256)) != 1 {
		return errors.New("artifact hash does not match signed manifest")
	}
	return nil
}

// copyExact copies up to limit+1 bytes into h and returns how many it read,
// erroring only on read failure. Reading limit+1 lets the caller detect an
// oversized artifact (the extra byte makes n > limit).
func copyExact(h hash.Hash, r io.Reader, limit int64) (int64, error) {
	if limit <= 0 || limit > maxArtifactBytes {
		return 0, fmt.Errorf("refusing artifact with declared size %d", limit)
	}
	limited := io.LimitReader(r, limit+1)
	n, err := io.Copy(h, limited)
	if err != nil {
		return n, fmt.Errorf("read artifact: %w", err)
	}
	return n, nil
}

func lowerHex(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'F' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
