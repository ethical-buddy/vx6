// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the VX6 terms in LICENSE-COMMERCIAL.md.
// Sole inventor, maintainer, and rights holder: Suryansh Deshwal (https://github.com/ethical-buddy).

// vx6-release is the OFFLINE release-signing tool for VX6 updates (#67). It runs
// on a maintainer's trusted, offline machine, never on a node. It:
//
//	keygen        generate a passphrase-encrypted Ed25519 release key
//	pin-root      render internal/release/pinned.go from a set of public keys
//	sign-manifest add this key's signature to a manifest (threshold signing)
//	rotate-root   sign a new trust root with the outgoing quorum (rotate/revoke)
//	verify        dry-run verify a manifest against a trust root (no secrets)
//
// Private keys live only in the encrypted files this tool reads; the passphrase
// is read from the VX6_RELEASE_PASSPHRASE env var or a terminal prompt, never a
// flag (flags leak into shell history and process lists).
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vx6/vx6/internal/release"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "pin-root":
		err = pinRoot(os.Args[2:])
	case "sign-manifest":
		err = signManifest(os.Args[2:])
	case "rotate-root":
		err = rotateRoot(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vx6-release:", err)
		os.Exit(1)
	}
}

func flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	return fs
}

func usage() {
	fmt.Fprint(os.Stderr, `vx6-release - offline VX6 update signing (#67)

  vx6-release keygen        -out root1.key.json
  vx6-release pin-root      -threshold 2 -key root1.key.json -key root2.key.json -key root3.key.json -out internal/release/pinned.go
  vx6-release sign-manifest -key root1.key.json -in manifest.json -out manifest.json
  vx6-release rotate-root   -key oldroot1.key.json -key oldroot2.key.json -root newroot.json -out signed-root.json
  vx6-release verify        -root pinned-root.json -manifest manifest.json -seq N [-os linux -arch amd64]

Passphrase: VX6_RELEASE_PASSPHRASE env var, or interactive prompt. Never a flag.
`)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func readPassphrase(confirm bool) ([]byte, error) {
	if v := os.Getenv("VX6_RELEASE_PASSPHRASE"); v != "" {
		return []byte(v), nil
	}
	fmt.Fprint(os.Stderr, "Release key passphrase: ")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		p2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if string(p1) != string(p2) {
			return nil, errors.New("passphrases do not match")
		}
	}
	return p1, nil
}

func openSigner(path string) (*release.Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	enc, err := release.LoadEncryptedSignerKey(f)
	if err != nil {
		return nil, err
	}
	pass, err := readPassphrase(false)
	if err != nil {
		return nil, err
	}
	defer zero(pass)
	return enc.Open(pass)
}

func keygen(args []string) error {
	fs := flagSet("keygen")
	out := fs.String("out", "", "output key file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("refusing to overwrite existing %s", *out)
	}
	pass, err := readPassphrase(true)
	if err != nil {
		return err
	}
	defer zero(pass)
	enc, pub, err := release.GenerateSignerKey(pass)
	if err != nil {
		return err
	}
	data, err := enc.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("key id: %s\npublic: %s\nwrote encrypted key to %s (keep it offline; back up the passphrase)\n",
		release.KeyID(pub), base64.StdEncoding.EncodeToString(pub), *out)
	return nil
}

// loadPublicFromKeyfile reads only the public half of an encrypted key file
// (no passphrase needed).
func loadPublicFromKeyfile(path string) (release.RootKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return release.RootKey{}, err
	}
	defer f.Close()
	enc, err := release.LoadEncryptedSignerKey(f)
	if err != nil {
		return release.RootKey{}, err
	}
	return release.RootKey{KeyID: enc.KeyID, PublicKey: enc.Public}, nil
}

func pinRoot(args []string) error {
	fs := flagSet("pin-root")
	var keys multiFlag
	fs.Var(&keys, "key", "encrypted key file (public half is read); repeatable")
	threshold := fs.Int("threshold", 0, "signing threshold (required)")
	epoch := fs.Uint64("epoch", 1, "trust-root epoch")
	out := fs.String("out", "", "output Go file (e.g. internal/release/pinned.go)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(keys) == 0 || *threshold < 1 || *out == "" {
		return errors.New("-key (>=1), -threshold and -out are required")
	}
	var rootKeys []release.RootKey
	for _, k := range keys {
		rk, err := loadPublicFromKeyfile(k)
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		rootKeys = append(rootKeys, rk)
	}
	root := release.TrustRoot{Schema: release.SchemaVersion, Epoch: *epoch, Threshold: *threshold, Keys: rootKeys}
	src, err := release.RenderPinnedRoot(root)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote pinned trust root (%d keys, threshold %d, epoch %d) to %s\n", len(rootKeys), *threshold, *epoch, *out)
	return nil
}

func signManifest(args []string) error {
	fs := flagSet("sign-manifest")
	keyPath := fs.String("key", "", "encrypted signing key (required)")
	in := fs.String("in", "", "manifest JSON to sign (required)")
	out := fs.String("out", "", "output (default: overwrite -in)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *in == "" {
		return errors.New("-key and -in are required")
	}
	if *out == "" {
		*out = *in
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var sm release.SignedManifest
	if err := json.Unmarshal(raw, &sm); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}
	signer, err := openSigner(*keyPath)
	if err != nil {
		return err
	}
	defer signer.Close()
	sig := signer.SignManifest(sm.Manifest)
	for i, s := range sm.Signatures {
		if s.KeyID == sig.KeyID {
			sm.Signatures[i] = sig // replace a prior signature by the same key
			return writeJSON(*out, sm, fmt.Sprintf("re-signed with key %s", sig.KeyID))
		}
	}
	sm.Signatures = append(sm.Signatures, sig)
	return writeJSON(*out, sm, fmt.Sprintf("added signature from key %s (%d total)", sig.KeyID, len(sm.Signatures)))
}

func rotateRoot(args []string) error {
	fs := flagSet("rotate-root")
	var keys multiFlag
	fs.Var(&keys, "key", "OUTGOING quorum signing key(s); repeatable")
	rootPath := fs.String("root", "", "new TrustRoot JSON to sign (required)")
	out := fs.String("out", "", "output SignedTrustRoot JSON (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(keys) == 0 || *rootPath == "" || *out == "" {
		return errors.New("-key (>=1), -root and -out are required")
	}
	raw, err := os.ReadFile(*rootPath)
	if err != nil {
		return err
	}
	var newRoot release.TrustRoot
	if err := json.Unmarshal(raw, &newRoot); err != nil {
		return fmt.Errorf("parse new trust root: %w", err)
	}
	st := release.SignedTrustRoot{Root: newRoot}
	for _, k := range keys {
		signer, err := openSigner(k)
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		st.Signatures = append(st.Signatures, signer.SignTrustRoot(newRoot))
		signer.Close()
	}
	return writeJSON(*out, st, fmt.Sprintf("signed new trust root (epoch %d) with %d outgoing key(s)", newRoot.Epoch, len(keys)))
}

func verify(args []string) error {
	fs := flagSet("verify")
	rootPath := fs.String("root", "", "TrustRoot JSON (public keys + threshold)")
	manifestPath := fs.String("manifest", "", "SignedManifest JSON")
	seq := fs.Uint64("seq", 0, "running build's release sequence")
	osArg := fs.String("os", "", "target OS (default this build)")
	arch := fs.String("arch", "", "target arch (default this build)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rootPath == "" || *manifestPath == "" {
		return errors.New("-root and -manifest are required")
	}
	sequenceProvided := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "seq" {
			sequenceProvided = true
		}
	})
	if !sequenceProvided {
		return errors.New("-seq is required; rollback checking needs a trusted current sequence")
	}
	rootRaw, err := os.ReadFile(*rootPath)
	if err != nil {
		return err
	}
	var root release.TrustRoot
	if err := json.Unmarshal(rootRaw, &root); err != nil {
		return err
	}
	v, err := release.NewVerifier(root, *seq)
	if err != nil {
		return err
	}
	if *osArg != "" && *arch != "" {
		v.SetPlatform(release.Platform{OS: *osArg, Arch: *arch})
	}
	manRaw, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	res, err := v.VerifyManifest(manRaw)
	if err != nil {
		return err
	}
	fmt.Printf("OK: version %s seq %d authorizes %s (%d bytes, sha256 %s)\n",
		res.Manifest.Version, res.Manifest.Sequence, res.Artifact.Platform, res.Artifact.Size, res.Artifact.SHA256)
	return nil
}

func writeJSON(path string, v any, msg string) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("%s -> %s\n", msg, path)
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
