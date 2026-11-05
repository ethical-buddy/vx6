// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"encoding/json"

	"github.com/vx6/vx6/internal/release"
)

// runUpdate implements `vx6 update ...`. The client only ever VERIFIES: it
// decides, against keys pinned in this binary, whether an update is authorized.
// It never trusts a version number, hash or NodeID from the peer that supplied
// the file. Fetching bytes from DHT peers/mirrors and the privileged,
// service-manager-owned activation use internal/release from the node service;
// this command lets an operator or that service check metadata and artifacts.
func runUpdate(args []string) error {
	if len(args) == 0 {
		printUpdateUsage(os.Stderr)
		return errors.New("missing update subcommand")
	}
	switch args[0] {
	case "verify":
		return runUpdateVerify(args[1:])
	case "trust-info":
		return runUpdateTrustInfo(args[1:])
	default:
		printUpdateUsage(os.Stderr)
		return fmt.Errorf("unknown update subcommand %q", args[0])
	}
}

func printUpdateUsage(w io.Writer) {
	fmt.Fprintln(w, "Update commands:")
	fmt.Fprintln(w, "  vx6 update trust-info")
	fmt.Fprintln(w, "  vx6 update verify --manifest FILE [--artifact FILE] [--current-seq N]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The client verifies updates against release keys pinned in this binary.")
	fmt.Fprintln(w, "A peer may carry bytes, but only a threshold-signed manifest authorizes them.")
}

func runUpdateTrustInfo(args []string) error {
	fs := flag.NewFlagSet("update trust-info", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}
	root, err := release.PinnedTrustRoot()
	if errors.Is(err, release.ErrNoPinnedRoot) {
		fmt.Println("Automatic updates: DISABLED (no release trust root pinned in this build).")
		fmt.Println("Updates must be installed manually by an operator / package manager.")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Printf("Automatic updates: enabled\nTrust epoch: %d\nThreshold: %d of %d keys\n",
		root.Epoch, root.Threshold, len(root.Keys))
	for _, k := range root.Keys {
		revoked := ""
		for _, r := range root.Revoked {
			if r == k.KeyID {
				revoked = " (revoked)"
			}
		}
		fmt.Printf("  key %s%s\n", k.KeyID, revoked)
	}
	return nil
}

func runUpdateVerify(args []string) error {
	fs := flag.NewFlagSet("update verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifestPath := fs.String("manifest", "", "signed manifest JSON (required)")
	artifactPath := fs.String("artifact", "", "downloaded artifact to check against the manifest")
	currentSeq := fs.Uint64("current-seq", 0, "running build's release sequence")
	rootPath := fs.String("root", "", "trust root JSON (default: pinned in this binary)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" {
		return errors.New("--manifest is required")
	}
	var root release.TrustRoot
	var err error
	if *rootPath != "" {
		data, rerr := os.ReadFile(*rootPath)
		if rerr != nil {
			return rerr
		}
		if jerr := jsonUnmarshalStrict(data, &root); jerr != nil {
			return jerr
		}
	} else {
		root, err = release.PinnedTrustRoot()
		if err != nil {
			return fmt.Errorf("%w (pass --root to verify against an explicit trust root)", err)
		}
	}
	v, err := release.NewVerifier(root, *currentSeq)
	if err != nil {
		return err
	}
	manData, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	up, err := v.VerifyManifest(manData)
	if err != nil {
		return fmt.Errorf("manifest NOT authorized: %w", err)
	}
	fmt.Printf("manifest authorized: version %s, sequence %d, artifact %s (%d bytes)\n",
		up.Manifest.Version, up.Manifest.Sequence, up.Artifact.Platform, up.Artifact.Size)
	if *artifactPath != "" {
		f, err := os.Open(*artifactPath)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := release.VerifyArtifact(f, up.Artifact); err != nil {
			return fmt.Errorf("artifact NOT authorized: %w", err)
		}
		fmt.Println("artifact authorized: size and SHA-256 match the signed manifest")
	}
	return nil
}

func jsonUnmarshalStrict(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
