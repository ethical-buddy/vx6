//go:build windows

package identity

import (
	"fmt"
	"os"
	"path/filepath"
)

const identityFilePermissionsEnforced = false

func validateIdentityFileMode(string, os.FileMode) error { return nil }

func writeIdentityAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vx6-identity-*")
	if err != nil {
		return fmt.Errorf("create temporary identity file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write identity: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync identity: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close identity: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace identity: %w", err)
	}
	return nil
}
