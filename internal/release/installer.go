// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the VX6 terms in LICENSE-COMMERCIAL.md.
// Sole inventor, maintainer, and rights holder: Suryansh Deshwal (https://github.com/ethical-buddy).

package release

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	if dir == "" {
		return nil, errors.New("installer state directory is required")
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	dir = absolute
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := requirePrivateDirectory(dir); err != nil {
		return nil, err
	}
	for _, sub := range []string{"", "staging", "versions"} {
		path := filepath.Join(dir, sub)
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, err
		}
		if err := requirePrivateDirectory(path); err != nil {
			return nil, err
		}
	}
	return &Installer{dir: dir}, nil
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("installer path is not a real directory: %s", path)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("restrict installer directory permissions: %w", err)
	}
	secured, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, secured) || secured.Mode()&os.ModeSymlink != 0 || secured.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("installer directory changed while securing it: %s", path)
	}
	return nil
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
	if err := writeExclusiveFile(name, data, 0o600); err != nil {
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
	data, err := readRegularFile(stage, maxArtifactBytes+1)
	if err != nil {
		return "", fmt.Errorf("read staged build: %w", err)
	}
	if err := VerifyArtifactBytes(data, art); err != nil {
		return "", fmt.Errorf("staged build failed re-verification: %w", err)
	}
	dst := filepath.Join(in.dir, "versions", fmt.Sprintf("vx6-%d", seq))
	if err := writeExclusiveFile(dst, data, 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		_ = os.Remove(dst)
		return "", err
	}
	cur := filepath.Join(in.dir, "current")
	// Record what we are replacing so RollBack can restore it.
	if target, err := os.Readlink(cur); err == nil {
		if !in.isVersionPath(target) {
			_ = os.Remove(dst)
			return "", errors.New("current symlink does not point inside the versions directory")
		}
		if _, err := readRegularFile(target, maxArtifactBytes+1); err != nil {
			_ = os.Remove(dst)
			return "", fmt.Errorf("current build is unavailable: %w", err)
		}
		if err := writeAtomicFile(filepath.Join(in.dir, "previous"), []byte(target), 0o600); err != nil {
			_ = os.Remove(dst)
			return "", err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(dst)
		return "", fmt.Errorf("inspect current build link: %w", err)
	} else if prevSeq != 0 {
		previous := filepath.Join(in.dir, "versions", fmt.Sprintf("vx6-%d", prevSeq))
		if _, err := readRegularFile(previous, maxArtifactBytes+1); err != nil {
			_ = os.Remove(dst)
			return "", fmt.Errorf("previous build is unavailable: %w", err)
		}
		if err := writeAtomicFile(filepath.Join(in.dir, "previous"), []byte(previous), 0o600); err != nil {
			_ = os.Remove(dst)
			return "", err
		}
	} else if err := os.Remove(filepath.Join(in.dir, "previous")); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(dst)
		return "", fmt.Errorf("clear stale rollback record: %w", err)
	}
	if err := atomicSymlink(dst, cur); err != nil {
		_ = os.Remove(dst)
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
	target, err := readRegularFile(prevFile, 4096)
	if err != nil {
		return "", errors.New("no last-known-good build recorded; cannot roll back")
	}
	prev := string(target)
	if !in.isVersionPath(prev) {
		return "", errors.New("recorded rollback path is outside the versions directory")
	}
	if _, err := readRegularFile(prev, maxArtifactBytes+1); err != nil {
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
	if err != nil || !in.isVersionPath(t) {
		return "", false
	}
	return t, true
}

func (in *Installer) isVersionPath(path string) bool {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	root := filepath.Join(in.dir, "versions")
	rel, err := filepath.Rel(root, absolute)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
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
	prev, _ := readRegularFile(filepath.Join(in.dir, "previous"), 4096)
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
	f, err := os.CreateTemp(filepath.Dir(name), ".vx6-link-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Remove(tmp); err != nil {
		return err
	}
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func writeExclusiveFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".vx6-state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("installer state file is not a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("installer state file changed while opening")
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// VerifyArtifactBytes is VerifyArtifact for an in-memory artifact.
func VerifyArtifactBytes(data []byte, art Artifact) error {
	if int64(len(data)) != art.Size {
		return fmt.Errorf("artifact is %d bytes, manifest says %d", len(data), art.Size)
	}
	return VerifyArtifact(bytes.NewReader(data), art)
}
