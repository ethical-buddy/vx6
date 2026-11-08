// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testKeys makes n signer keys with a shared passphrase.
func testKeys(t *testing.T, n int) ([]*Signer, []RootKey) {
	t.Helper()
	pass := []byte("correct horse battery staple")
	var signers []*Signer
	var roots []RootKey
	for i := 0; i < n; i++ {
		enc, _, err := GenerateSignerKey(pass)
		if err != nil {
			t.Fatal(err)
		}
		s, err := enc.Open(pass)
		if err != nil {
			t.Fatal(err)
		}
		signers = append(signers, s)
		roots = append(roots, s.RootKey())
	}
	return signers, roots
}

func artifactFor(data []byte, p Platform) Artifact {
	sum := sha256.Sum256(data)
	return Artifact{Platform: p, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Filename: "vx6"}
}

func signed(t *testing.T, m Manifest, signers []*Signer, which ...int) []byte {
	t.Helper()
	sm := SignedManifest{Manifest: m}
	for _, i := range which {
		sm.Signatures = append(sm.Signatures, signers[i].SignManifest(m))
	}
	data, _ := json.Marshal(sm)
	return data
}

func baseManifest(art Artifact, seq uint64) Manifest {
	now := time.Now().UTC()
	return Manifest{Schema: SchemaVersion, Version: "1.0.0", Sequence: seq,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
		Artifacts: []Artifact{art}}
}

func TestValidReleaseVerifies(t *testing.T) {
	signers, roots := testKeys(t, 3)
	plat := Platform{OS: "linux", Arch: "amd64"}
	data := []byte("the new vx6 binary bytes")
	art := artifactFor(data, plat)
	m := baseManifest(art, 5)
	root := TrustRoot{Schema: SchemaVersion, Epoch: 1, Threshold: 2, Keys: roots}
	v, err := NewVerifier(root, 4)
	if err != nil {
		t.Fatal(err)
	}
	v.SetPlatform(plat)
	up, err := v.VerifyManifest(signed(t, m, signers, 0, 1))
	if err != nil {
		t.Fatalf("valid release rejected: %v", err)
	}
	if err := VerifyArtifact(bytes.NewReader(data), up.Artifact); err != nil {
		t.Fatalf("valid artifact rejected: %v", err)
	}
}

func TestBelowThresholdRejected(t *testing.T) {
	signers, roots := testKeys(t, 3)
	plat := Platform{OS: "linux", Arch: "amd64"}
	art := artifactFor([]byte("x"), plat)
	v, _ := NewVerifier(TrustRoot{Schema: SchemaVersion, Epoch: 1, Threshold: 2, Keys: roots}, 0)
	v.SetPlatform(plat)
	if _, err := v.VerifyManifest(signed(t, baseManifest(art, 1), signers, 0)); err == nil {
		t.Fatal("one signature met a threshold of two")
	}
}

func TestDuplicateSignatureNotCounted(t *testing.T) {
	signers, roots := testKeys(t, 3)
	plat := Platform{OS: "linux", Arch: "amd64"}
	art := artifactFor([]byte("x"), plat)
	m := baseManifest(art, 1)
	// Same key signs twice; must count once and fail threshold 2.
	data := signed(t, m, signers, 0, 0)
	v, _ := NewVerifier(TrustRoot{Schema: SchemaVersion, Epoch: 1, Threshold: 2, Keys: roots}, 0)
	v.SetPlatform(plat)
	if _, err := v.VerifyManifest(data); err == nil {
		t.Fatal("a duplicated single signature satisfied threshold 2")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	signers, roots := testKeys(t, 3)
	other, _ := testKeys(t, 1)
	plat := Platform{OS: "linux", Arch: "amd64"}
	art := artifactFor([]byte("x"), plat)
	m := baseManifest(art, 1)
	sm := SignedManifest{Manifest: m, Signatures: []Signature{
		signers[0].SignManifest(m), other[0].SignManifest(m)}}
	data, _ := json.Marshal(sm)
	v, _ := NewVerifier(TrustRoot{Schema: SchemaVersion, Epoch: 1, Threshold: 2, Keys: roots}, 0)
	v.SetPlatform(plat)
	if _, err := v.VerifyManifest(data); err == nil {
		t.Fatal("a signature from a non-root key counted toward threshold")
	}
}

func TestTamperedHashAndSizeRejected(t *testing.T) {
	plat := Platform{OS: "linux", Arch: "amd64"}
	data := []byte("genuine")
	art := artifactFor(data, plat)
	if err := VerifyArtifact(bytes.NewReader([]byte("genuinX")), art); err == nil {
		t.Fatal("wrong-hash artifact accepted")
	}
	if err := VerifyArtifact(bytes.NewReader([]byte("genuine extra")), art); err == nil {
		t.Fatal("oversized artifact accepted")
	}
	if err := VerifyArtifact(bytes.NewReader([]byte("gen")), art); err == nil {
		t.Fatal("truncated artifact accepted")
	}
}

func TestExpiredManifestRejected(t *testing.T) {
	signers, roots := testKeys(t, 2)
	plat := Platform{OS: "linux", Arch: "amd64"}
	art := artifactFor([]byte("x"), plat)
	m := baseManifest(art, 1)
	past := time.Now().Add(-48 * time.Hour).UTC()
	m.IssuedAt = past.Format(time.RFC3339)
	m.ExpiresAt = past.Add(time.Hour).Format(time.RFC3339)
	v, _ := NewVerifier(TrustRoot{Schema: SchemaVersion, Epoch: 1, Threshold: 2, Keys: roots}, 0)
	v.SetPlatform(plat)
	if _, err := v.VerifyManifest(signed(t, m, signers, 0, 1)); err == nil {
		t.Fatal("expired (frozen/stale) manifest accepted")
	}
}

func TestManifestIssuedTooFarInFutureRejected(t *testing.T) {
	signers, roots := testKeys(t, 1)
	art := artifactFor([]byte("x"), Platform{OS: "linux", Arch: "amd64"})
	m := baseManifest(art, 1)
	m.IssuedAt = time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)
	m.ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	v, _ := NewVerifier(TrustRoot{Schema: SchemaVersion, Epoch: 1, Threshold: 1, Keys: roots}, 0)
	v.SetPlatform(art.Platform)
	if _, err := v.VerifyManifest(signed(t, m, signers, 0)); err == nil {
		t.Fatal("manifest issued far in the future was accepted")
	}
}

func TestExpiredCurrentTrustRootRejectsManifestAndRotation(t *testing.T) {
	signers, roots := testKeys(t, 1)
	art := artifactFor([]byte("x"), Platform{OS: "linux", Arch: "amd64"})
	root := TrustRoot{Schema: SchemaVersion, Epoch: 1, Threshold: 1, Keys: roots,
		ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}
	v, err := NewVerifier(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	v.SetPlatform(art.Platform)
	if _, err := v.VerifyManifest(signed(t, baseManifest(art, 1), signers, 0)); err == nil {
		t.Fatal("manifest verified with an expired trust root")
	}
	rotated := TrustRoot{Schema: SchemaVersion, Epoch: 2, Threshold: 1, Keys: roots}
	st := SignedTrustRoot{Root: rotated, Signatures: []Signature{signers[0].SignTrustRoot(rotated)}}
	data, _ := json.Marshal(st)
	if _, err := root.AdvanceTrust(data, time.Now()); err == nil {
		t.Fatal("expired root authorized a trust rotation")
	}
}

func TestStrictManifestDecoderRejectsDuplicatesAndTrailingJSON(t *testing.T) {
	for _, input := range []string{
		`{"manifest":{},"manifest":{},"signatures":[{"key_id":"x","sig":"eA=="}]}`,
		`{"manifest":{},"signatures":[{"key_id":"x","sig":"eA=="}]} {}`,
	} {
		if _, err := ParseSignedManifest([]byte(input)); err == nil {
			t.Fatalf("accepted ambiguous manifest JSON: %s", input)
		}
	}
}

func TestManifestFilenameCannotInjectCanonicalFields(t *testing.T) {
	signers, roots := testKeys(t, 1)
	art := artifactFor([]byte("x"), Platform{OS: "linux", Arch: "amd64"})
	art.Filename = "vx6\tlinux/arm64\t1"
	m := baseManifest(art, 1)
	v, _ := NewVerifier(TrustRoot{Schema: SchemaVersion, Epoch: 1, Threshold: 1, Keys: roots}, 0)
	v.SetPlatform(art.Platform)
	if _, err := v.VerifyManifest(signed(t, m, signers, 0)); err == nil {
		t.Fatal("manifest with a delimiter-injecting filename was accepted")
	}
}

func TestRollbackBySequenceRejected(t *testing.T) {
	signers, roots := testKeys(t, 2)
	plat := Platform{OS: "linux", Arch: "amd64"}
	art := artifactFor([]byte("x"), plat)
	v, _ := NewVerifier(TrustRoot{Schema: SchemaVersion, Epoch: 1, Threshold: 2, Keys: roots}, 10)
	v.SetPlatform(plat)
	// Lower and equal sequence must both be refused.
	for _, seq := range []uint64{9, 10} {
		if _, err := v.VerifyManifest(signed(t, baseManifest(art, seq), signers, 0, 1)); err == nil {
			t.Fatalf("manifest seq %d (<= running 10) accepted", seq)
		}
	}
}

func TestWrongPlatformRejected(t *testing.T) {
	signers, roots := testKeys(t, 2)
	art := artifactFor([]byte("x"), Platform{OS: "linux", Arch: "arm64"})
	v, _ := NewVerifier(TrustRoot{Schema: SchemaVersion, Epoch: 1, Threshold: 2, Keys: roots}, 0)
	v.SetPlatform(Platform{OS: "linux", Arch: "amd64"})
	if _, err := v.VerifyManifest(signed(t, baseManifest(art, 1), signers, 0, 1)); err == nil {
		t.Fatal("manifest without this platform's artifact accepted")
	}
}

func TestKeyRotationAndRevocation(t *testing.T) {
	signers, roots := testKeys(t, 3) // keys 0,1,2
	plat := Platform{OS: "linux", Arch: "amd64"}
	art := artifactFor([]byte("x"), plat)

	root := TrustRoot{Schema: SchemaVersion, Epoch: 1, Threshold: 2, Keys: roots}
	v, _ := NewVerifier(root, 0)
	v.SetPlatform(plat)

	// Revoke key 0 and add a new key 3; sign the new root with outgoing quorum 1,2.
	newSigners, newRoots := testKeys(t, 1) // key 3
	rotated := TrustRoot{Schema: SchemaVersion, Epoch: 2, Threshold: 2,
		Keys:    append(append([]RootKey(nil), roots...), newRoots[0]),
		Revoked: []string{roots[0].KeyID}}
	st := SignedTrustRoot{Root: rotated, Signatures: []Signature{
		signers[1].SignTrustRoot(rotated), signers[2].SignTrustRoot(rotated)}}
	stData, _ := json.Marshal(st)
	if err := v.AdvanceTrust(stData); err != nil {
		t.Fatalf("legitimate rotation rejected: %v", err)
	}
	if v.TrustEpoch() != 2 {
		t.Fatalf("epoch did not advance")
	}
	// Revoked key 0 + key 1 must now FAIL (0 no longer counts).
	if _, err := v.VerifyManifest(signed(t, baseManifest(art, 1), signers, 0, 1)); err == nil {
		t.Fatal("revoked key still counted toward threshold")
	}
	// New key 3 + key 1 must PASS.
	m := baseManifest(art, 1)
	sm := SignedManifest{Manifest: m, Signatures: []Signature{
		newSigners[0].SignManifest(m), signers[1].SignManifest(m)}}
	data, _ := json.Marshal(sm)
	if _, err := v.VerifyManifest(data); err != nil {
		t.Fatalf("rotated-in key rejected: %v", err)
	}
	// A rotation that does not advance the epoch is refused (rollback guard).
	if err := v.AdvanceTrust(stData); err == nil {
		t.Fatal("trust rollback to same epoch accepted")
	}
}

func TestSignerKeyWrongPassphrase(t *testing.T) {
	enc, _, err := GenerateSignerKey([]byte("the right passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Open([]byte("the wrong passphrase")); err == nil {
		t.Fatal("decrypted signer key with the wrong passphrase")
	}
	s, err := enc.Open([]byte("the right passphrase"))
	if err != nil {
		t.Fatalf("correct passphrase failed: %v", err)
	}
	if s.KeyID() != enc.KeyID {
		t.Fatal("key id mismatch after open")
	}
}

func TestSignerKeyRejectsUntrustedArgonParameters(t *testing.T) {
	enc, _, err := GenerateSignerKey([]byte("a sufficiently long passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	enc.MemKiB = ^uint32(0)
	if _, err := enc.Open([]byte("a sufficiently long passphrase")); err == nil {
		t.Fatal("untrusted Argon2 memory parameters were accepted")
	}
}

func TestSignerKeyFileCarriesNoSecretInClear(t *testing.T) {
	pass := []byte("a sufficiently long passphrase")
	enc, pub, err := GenerateSignerKey(pass)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := enc.Open(pass)
	seed := signerSeedForTest(t, s)
	data, _ := enc.Marshal()
	if bytes.Contains(data, seed) {
		t.Fatal("the raw private seed appears in the key file")
	}
	// The public key is expected in clear; the private seed is not.
	if !bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(pub))) {
		t.Fatal("public key missing from key file")
	}
}

func TestInstallerStageActivateRollback(t *testing.T) {
	dir := t.TempDir()
	in, err := NewInstaller(dir)
	if err != nil {
		t.Fatal(err)
	}
	plat := Platform{OS: "linux", Arch: "amd64"}
	v1 := []byte("build v1 bytes")
	a1 := artifactFor(v1, plat)
	if _, err := in.Stage(1, v1, a1); err != nil {
		t.Fatal(err)
	}
	p1, err := in.Activate(1, 0, a1)
	if err != nil {
		t.Fatal(err)
	}
	if cur, ok := in.Current(); !ok || cur != p1 {
		t.Fatalf("current = %q, want %q", cur, p1)
	}
	// Activate a v2, then a failing health check must roll back to v1.
	v2 := []byte("build v2 bytes which are different")
	a2 := artifactFor(v2, plat)
	if _, err := in.Stage(2, v2, a2); err != nil {
		t.Fatal(err)
	}
	p2, err := in.Activate(2, 1, a2)
	if err != nil {
		t.Fatal(err)
	}
	err = in.HealthCheck(p2, func(string) error { return os.ErrInvalid })
	if err == nil {
		t.Fatal("health check error was swallowed")
	}
	cur, _ := in.Current()
	if cur != p1 {
		t.Fatalf("after failed health check current = %q, want rollback to %q", cur, p1)
	}
	// A staged file must refuse activation if its bytes do not match the artifact.
	bad := filepath.Join(dir, "staging", "vx6-3.stage")
	_ = os.WriteFile(bad, []byte("corrupt"), 0o600)
	if _, err := in.Activate(3, 2, artifactFor([]byte("different"), plat)); err == nil {
		t.Fatal("activated a staged file whose hash did not match the manifest")
	}
}

func TestFirstActivationClearsStaleRollbackRecord(t *testing.T) {
	dir := t.TempDir()
	in, err := NewInstaller(dir)
	if err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "versions", "vx6-99")
	if err := os.WriteFile(stale, []byte("old unrelated build"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "previous"), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	data := []byte("first build")
	art := artifactFor(data, Platform{OS: "linux", Arch: "amd64"})
	if _, err := in.Stage(1, data, art); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Activate(1, 0, art); err != nil {
		t.Fatal(err)
	}
	if _, err := in.RollBack(); err == nil {
		t.Fatal("first activation retained a stale rollback target")
	}
}

func TestStagedFileIsNotExecutable(t *testing.T) {
	dir := t.TempDir()
	in, err := NewInstaller(dir)
	if err != nil {
		t.Fatal(err)
	}
	plat := Platform{OS: "linux", Arch: "amd64"}
	data := []byte("payload")
	path, err := in.Stage(1, data, artifactFor(data, plat))
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 != 0 {
		t.Fatalf("staged file is executable (mode %o); must be inert until activation", fi.Mode().Perm())
	}
}

func TestInstallerRejectsSymlinkStateDirectory(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "state-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewInstaller(link); err == nil {
		t.Fatal("installer accepted a symlink state directory")
	}
	if _, err := os.Stat(filepath.Join(target, "staging")); !os.IsNotExist(err) {
		t.Fatalf("installer wrote through the directory symlink: %v", err)
	}
}

func TestStageDoesNotFollowPreexistingSymlink(t *testing.T) {
	dir := t.TempDir()
	in, err := NewInstaller(dir)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside")
	contents := []byte("do not overwrite")
	if err := os.WriteFile(target, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(dir, "staging", "vx6-1.stage")
	if err := os.Symlink(target, stage); err != nil {
		t.Fatal(err)
	}
	data := []byte("payload")
	if _, err := in.Stage(1, data, artifactFor(data, Platform{OS: "linux", Arch: "amd64"})); err == nil {
		t.Fatal("stage overwrote a preexisting symlink")
	}
	after, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(after, contents) {
		t.Fatalf("outside target changed: %q, err=%v", after, err)
	}
}

func TestActivateDoesNotFollowPreexistingVersionSymlink(t *testing.T) {
	dir := t.TempDir()
	in, err := NewInstaller(dir)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("payload")
	art := artifactFor(data, Platform{OS: "linux", Arch: "amd64"})
	if _, err := in.Stage(1, data, art); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside")
	contents := []byte("do not overwrite")
	if err := os.WriteFile(target, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "versions", "vx6-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Activate(1, 0, art); err == nil {
		t.Fatal("activation overwrote a preexisting version symlink")
	}
	after, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(after, contents) {
		t.Fatalf("outside target changed: %q, err=%v", after, err)
	}
}

func TestRollbackRejectsPathOutsideVersionStore(t *testing.T) {
	dir := t.TempDir()
	in, err := NewInstaller(dir)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "previous"), []byte(outside), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := in.RollBack(); err == nil {
		t.Fatal("rollback accepted a path outside the versions directory")
	}
}
