// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// RootKey is one pinned release root public key.
type RootKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // base64 Ed25519 public key
}

func (k RootKey) parse() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("root key %s: %w", k.KeyID, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("root key %s: wrong size", k.KeyID)
	}
	pub := ed25519.PublicKey(raw)
	if KeyID(pub) != k.KeyID {
		return nil, fmt.Errorf("root key id %s does not match its public key", k.KeyID)
	}
	return pub, nil
}

// TrustRoot is the release trust state pinned in the binary and, optionally,
// advanced by signed root statements on disk. It names the current root keys,
// the signing threshold, revoked key IDs, and a monotonic epoch so a client
// never moves trust backward.
type TrustRoot struct {
	Schema    int       `json:"schema"`
	Epoch     uint64    `json:"epoch"`
	Threshold int       `json:"threshold"`
	Keys      []RootKey `json:"keys"`
	Revoked   []string  `json:"revoked,omitempty"` // key IDs no longer trusted
	ExpiresAt string    `json:"expires_at,omitempty"`
}

// SignedTrustRoot is a trust root signed by the PREVIOUS root quorum, used for
// offline rotation/revocation. The very first root is pinned in the binary and
// needs no signature.
type SignedTrustRoot struct {
	Root       TrustRoot   `json:"root"`
	Signatures []Signature `json:"signatures"`
}

func trustRootSigningPayload(r TrustRoot) []byte {
	keys := append([]RootKey(nil), r.Keys...)
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })
	rev := append([]string(nil), r.Revoked...)
	sort.Strings(rev)
	var b strings.Builder
	fmt.Fprintf(&b, "vx6/release-trust-root/v%d\n", SchemaVersion)
	fmt.Fprintf(&b, "%d\n%d\n%d\n%s\n", r.Schema, r.Epoch, r.Threshold, r.ExpiresAt)
	fmt.Fprintf(&b, "keys %d\n", len(keys))
	for _, k := range keys {
		fmt.Fprintf(&b, "%s\t%s\n", k.KeyID, k.PublicKey)
	}
	fmt.Fprintf(&b, "revoked %d\n", len(rev))
	for _, id := range rev {
		fmt.Fprintf(&b, "%s\n", id)
	}
	return []byte(b.String())
}

func (r TrustRoot) validateShape() error {
	if r.Schema != SchemaVersion {
		return fmt.Errorf("unsupported trust-root schema %d", r.Schema)
	}
	if r.Threshold < 1 {
		return errors.New("threshold must be >= 1")
	}
	if len(r.Keys) < r.Threshold {
		return fmt.Errorf("threshold %d exceeds %d keys", r.Threshold, len(r.Keys))
	}
	if len(r.Keys) > 32 {
		return errors.New("at most 32 root keys")
	}
	ids := map[string]bool{}
	revoked := map[string]bool{}
	for _, id := range r.Revoked {
		decoded, err := hex.DecodeString(id)
		if err != nil || len(decoded) != 16 || id != strings.ToLower(id) {
			return fmt.Errorf("invalid revoked key id %q", id)
		}
		if revoked[id] {
			return fmt.Errorf("duplicate revoked key id %s", id)
		}
		revoked[id] = true
	}
	active := 0
	for _, k := range r.Keys {
		if _, err := k.parse(); err != nil {
			return err
		}
		if ids[k.KeyID] {
			return fmt.Errorf("duplicate root key %s", k.KeyID)
		}
		ids[k.KeyID] = true
		if !revoked[k.KeyID] {
			active++
		}
	}
	if active < r.Threshold {
		return fmt.Errorf("only %d non-revoked keys for threshold %d", active, r.Threshold)
	}
	if r.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, r.ExpiresAt); err != nil {
			return fmt.Errorf("invalid trust-root expires_at: %w", err)
		}
	}
	return nil
}

// activeKeys returns non-revoked public keys by key ID.
func (r TrustRoot) activeKeys() (map[string]ed25519.PublicKey, error) {
	if err := r.validateShape(); err != nil {
		return nil, err
	}
	revoked := map[string]bool{}
	for _, id := range r.Revoked {
		revoked[id] = true
	}
	out := map[string]ed25519.PublicKey{}
	for _, k := range r.Keys {
		if revoked[k.KeyID] {
			continue
		}
		pub, _ := k.parse() // validated above
		out[k.KeyID] = pub
	}
	return out, nil
}

// countValidSignatures counts distinct, valid root signatures over payload,
// ignoring unknown/revoked key IDs and duplicates. It is constant in which
// signatures it tries (no early return on first match) to avoid leaking which
// keys signed via timing; threshold crypto here is not secret, but the habit
// is cheap.
func countValidSignatures(payload []byte, keys map[string]ed25519.PublicKey, sigs []Signature) int {
	seen := map[string]bool{}
	count := 0
	for _, s := range sigs {
		pub, ok := keys[s.KeyID]
		if !ok || seen[s.KeyID] {
			continue
		}
		raw, err := decodeSig(s.Sig)
		if err != nil {
			continue
		}
		if ed25519.Verify(pub, payload, raw) {
			seen[s.KeyID] = true
			count++
		}
	}
	return count
}

// AdvanceTrust applies a signed trust-root statement to move the pinned trust
// forward (key rotation / revocation). The new root must:
//   - be signed by a threshold of the CURRENT (pre-advance) non-revoked keys,
//   - have a strictly greater epoch (no rollback),
//   - be internally valid.
//
// It returns the new trust root, or an error leaving the current one in force.
func (r TrustRoot) AdvanceTrust(data []byte, now time.Time) (TrustRoot, error) {
	if len(data) == 0 || len(data) > maxManifestBytes {
		return r, errors.New("invalid trust-root size")
	}
	if err := r.validateShape(); err != nil {
		return r, fmt.Errorf("current trust root invalid: %w", err)
	}
	if r.ExpiresAt != "" {
		currentExpiry, err := time.Parse(time.RFC3339, r.ExpiresAt)
		if err != nil || now.After(currentExpiry) {
			return r, errors.New("current trust root is expired or invalid; refusing trust advancement")
		}
	}
	var st SignedTrustRoot
	if err := decodeStrictJSON(data, &st); err != nil {
		return r, fmt.Errorf("parse trust root: %w", err)
	}
	if err := st.Root.validateShape(); err != nil {
		return r, err
	}
	if st.Root.Epoch <= r.Epoch {
		return r, fmt.Errorf("trust-root epoch %d does not advance current %d (rollback guard)", st.Root.Epoch, r.Epoch)
	}
	if st.Root.ExpiresAt != "" {
		exp, _ := time.Parse(time.RFC3339, st.Root.ExpiresAt)
		if now.After(exp) {
			return r, errors.New("trust-root statement expired")
		}
	}
	cur, err := r.activeKeys()
	if err != nil {
		return r, err
	}
	n := countValidSignatures(trustRootSigningPayload(st.Root), cur, st.Signatures)
	if n < r.Threshold {
		return r, fmt.Errorf("trust-root carries %d valid current-root signatures, need %d", n, r.Threshold)
	}
	return st.Root, nil
}

// Clone returns a deep copy so the pinned root is never mutated in place.
func (r TrustRoot) Clone() TrustRoot {
	c := r
	c.Keys = append([]RootKey(nil), r.Keys...)
	c.Revoked = append([]string(nil), r.Revoked...)
	return c
}
