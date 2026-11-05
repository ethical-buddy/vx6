// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package release

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Installer stages a verified artifact to a non-executable file, then activates
// it atomically while retaining the previous build for rollback. It never runs
// a partially downloaded file and never trusts anything a peer said: callers
// pass only an already-verified artifact (see Verifier) and an io source.
//
// Privileged placement (replacing a root-owned binary, restarting the service)
// is the OS/service manager's job, not this package's. Installer works inside a
// state directory it owns and emits the final move as an explicit step.
type Installer struct {
	// dir holds staging/, current (symlink), and previous/ for rollback.
	dir string
}

func NewInstaller(dir string) (*Installer, error) {
	for _, sub := range []string{"", "staging", "versions"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, err
		}
	}
	return &Installer{dir: dir}, nil
}

// Stage writes verified bytes to a non-executable staging file named by the
// manifest sequence. The reader MUST already have passed VerifyArtifact; Stage
// re-checks size and hash while writing so a staging file can never be
// activated unverified.
func (in *Installer) Stage(seq uint64, data []byte, art Artifact) (string, error) {
	if err := VerifyArtifactBytes(data, art); err != nil {
		return "", err
	}
	name := filepath.Join(in.dir, "staging", fmt.Sprintf("vx6-%d.stage", seq))
	// 0600 and no execute bit: a staged file is data, not a program, until
	// activation deliberately makes it executable.
	if err := os.WriteFile(name, data, 0o600); err != nil {
		return "", err
	}
	return name, nil
}

// Activate atomically makes the staged sequence the current build:
//   - verifies the staged file again,
//   - copies the current build (if any) into versions/<prevSeq> for rollback,
//   - moves the staged file to versions/<seq> with mode 0755,
//   - repoints the "current" symlink to it via an atomic rename.
//
// It returns the path the "current" symlink now resolves to. It does not touch
// any system path outside in.dir; a service manager points at in.dir/current.
func (in *Installer) Activate(seq, prevSeq uint64, art Artifact) (string, error) {
	stage := filepath.Join(in.dir, "staging", fmt.Sprintf("vx6-%d.stage", seq))
	data, err := os.ReadFile(stage)
	if err != nil {
		return "", fmt.Errorf("read staged build: %w", err)
	}
	if err := VerifyArtifactBytes(data, art); err != nil {
		return "", fmt.Errorf("staged build failed re-verification: %w", err)
	}
	dst := filepath.Join(in.dir, "versions", fmt.Sprintf("vx6-%d", seq))
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		return "", err
	}
	cur := filepath.Join(in.dir, "current")
	// Record what we are replacing so RollBack can restore it.
	if target, err := os.Readlink(cur); err == nil {
		_ = os.WriteFile(filepath.Join(in.dir, "previous"), []byte(target), 0o644)
	} else if prevSeq != 0 {
		_ = os.WriteFile(filepath.Join(in.dir, "previous"),
			[]byte(filepath.Join(in.dir, "versions", fmt.Sprintf("vx6-%d", prevSeq))), 0o644)
	}
	if err := atomicSymlink(dst, cur); err != nil {
		return "", err
	}
	_ = os.Remove(stage)
	return dst, nil
}

// RollBack repoints current to the recorded previous build after a failed
// health check. It returns the restored path, or an error if there is no
// last-known-good to return to.
func (in *Installer) RollBack() (string, error) {
	prevFile := filepath.Join(in.dir, "previous")
	target, err := os.ReadFile(prevFile)
	if err != nil {
		return "", errors.New("no last-known-good build recorded; cannot roll back")
	}
	prev := string(target)
	if _, err := os.Stat(prev); err != nil {
		return "", fmt.Errorf("recorded previous build missing: %w", err)
	}
	if err := atomicSymlink(prev, filepath.Join(in.dir, "current")); err != nil {
		return "", err
	}
	return prev, nil
}

// Current resolves the active build path, if any.
func (in *Installer) Current() (string, bool) {
	t, err := os.Readlink(filepath.Join(in.dir, "current"))
	if err != nil {
		return "", false
	}
	return t, true
}

// HealthCheck runs fn against the newly activated path and rolls back on
// failure, returning the rollback result. On success it prunes older versions,
// keeping the current and previous.
func (in *Installer) HealthCheck(activated string, fn func(path string) error) error {
	if err := fn(activated); err != nil {
		restored, rbErr := in.RollBack()
		if rbErr != nil {
			return fmt.Errorf("health check failed (%v) and rollback failed (%v)", err, rbErr)
		}
		return fmt.Errorf("health check failed (%v); rolled back to %s", err, restored)
	}
	in.prune(activated)
	return nil
}

// prune removes versions other than the activated and previous builds.
func (in *Installer) prune(keep string) {
	prev, _ := os.ReadFile(filepath.Join(in.dir, "previous"))
	entries, _ := os.ReadDir(filepath.Join(in.dir, "versions"))
	for _, e := range entries {
		p := filepath.Join(in.dir, "versions", e.Name())
		if p == keep || p == string(prev) {
			continue
		}
		_ = os.Remove(p)
	}
}

// atomicSymlink points name at target by creating a temp link and renaming,
// so a reader never sees a missing or half-written symlink.
func atomicSymlink(target, name string) error {
	tmp := name + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// VerifyArtifactBytes is VerifyArtifact for an in-memory artifact.
func VerifyArtifactBytes(data []byte, art Artifact) error {
	if int64(len(data)) != art.Size {
		return fmt.Errorf("artifact is %d bytes, manifest says %d", len(data), art.Size)
	}
	return VerifyArtifact(bytes.NewReader(data), art)
}
