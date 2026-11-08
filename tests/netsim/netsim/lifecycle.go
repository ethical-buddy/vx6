// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

var runIDPattern = regexp.MustCompile(`^[0-9a-f]{6}$`)

func newRunID() (string, error) {
	var raw [3]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// isolateNamespaces gives each privileged run names that cannot collide with
// ordinary host namespaces or another netsim run.
func isolateNamespaces(t *Topology, runID string) error {
	if t == nil || !runIDPattern.MatchString(runID) {
		return errors.New("invalid simulation run ID")
	}
	t.RunID = runID
	for _, as := range t.ASes {
		as.RouterNS = fmt.Sprintf("v6%s-r%d", runID, as.ASN)
	}
	for i := range t.Nodes {
		t.Nodes[i].NS = fmt.Sprintf("v6%s-n%d", runID, t.Nodes[i].Index)
	}
	return validateOwnedTopology(t)
}

func validateOwnedTopology(t *Topology) error {
	if t == nil || !runIDPattern.MatchString(t.RunID) {
		return errors.New("topology has no valid netsim run ID; refusing namespace cleanup")
	}
	seen := make(map[string]struct{}, len(t.ASes)+len(t.Nodes))
	check := func(name, expected string) error {
		if name != expected || len(name) > 15 {
			return fmt.Errorf("topology namespace %q is not an owned namespace", name)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate namespace %q in topology", name)
		}
		seen[name] = struct{}{}
		return nil
	}
	for _, as := range t.ASes {
		if as == nil {
			return errors.New("topology contains a nil AS")
		}
		if err := check(as.RouterNS, fmt.Sprintf("v6%s-r%d", t.RunID, as.ASN)); err != nil {
			return err
		}
	}
	for _, node := range t.Nodes {
		if err := check(node.NS, fmt.Sprintf("v6%s-n%d", t.RunID, node.Index)); err != nil {
			return err
		}
	}
	return nil
}

func topologyNamespaces(t *Topology) ([]string, error) {
	if err := validateOwnedTopology(t); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(t.ASes)+len(t.Nodes))
	for _, node := range t.Nodes {
		names = append(names, node.NS)
	}
	for _, as := range t.ASes {
		names = append(names, as.RouterNS)
	}
	return names, nil
}

func parseNamespaceList(output string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			result[fields[0]] = struct{}{}
		}
	}
	return result
}

func parsePID(raw string) (int, error) {
	pid, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || pid <= 1 {
		return 0, errors.New("invalid process ID")
	}
	return pid, nil
}

func preflightNamespaces(t *Topology) error {
	names, err := topologyNamespaces(t)
	if err != nil {
		return err
	}
	output, err := exec.Command("ip", "netns", "list").Output()
	if err != nil {
		return fmt.Errorf("list existing network namespaces: %w", err)
	}
	existing := parseNamespaceList(string(output))
	for _, name := range names {
		if _, found := existing[name]; found {
			return fmt.Errorf("namespace %s already exists; refusing to reuse it", name)
		}
	}
	return nil
}

func deleteOwnedNamespaces(t *Topology, r *runner) error {
	names, err := topologyNamespaces(t)
	if err != nil {
		return err
	}
	if r.dry {
		for _, name := range names {
			if err := r.run(ip("netns", "del", name)); err != nil {
				return err
			}
		}
		return nil
	}
	output, err := exec.Command("ip", "netns", "list").Output()
	if err != nil {
		return fmt.Errorf("list namespaces before cleanup: %w", err)
	}
	existing := parseNamespaceList(string(output))
	for _, name := range names {
		if _, found := existing[name]; !found {
			continue
		}
		if err := r.run(ip("netns", "del", name)); err != nil {
			return fmt.Errorf("delete owned namespace %s: %w", name, err)
		}
	}
	output, err = exec.Command("ip", "netns", "list").Output()
	if err != nil {
		return fmt.Errorf("verify namespace cleanup: %w", err)
	}
	existing = parseNamespaceList(string(output))
	for _, name := range names {
		if _, found := existing[name]; found {
			return fmt.Errorf("owned namespace %s remains after cleanup", name)
		}
	}
	return nil
}

func secureRunDirectory(path string, privileged, create bool) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if privileged {
		for current := absolute; ; current = filepath.Dir(current) {
			info, statErr := os.Lstat(current)
			if statErr == nil {
				if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
					return "", fmt.Errorf("privileged run path contains a symlink or non-directory: %s", current)
				}
				owner, ok := info.Sys().(*syscall.Stat_t)
				if !ok || owner.Uid != 0 {
					return "", fmt.Errorf("privileged run path ancestor must be root-owned: %s", current)
				}
				mode := info.Mode()
				if mode.Perm()&0o022 != 0 && mode&os.ModeSticky == 0 {
					return "", fmt.Errorf("privileged run path ancestor is writable by other users: %s", current)
				}
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return "", statErr
			}
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
		}
	}
	if create {
		if err := os.MkdirAll(absolute, 0o700); err != nil {
			return "", err
		}
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("run output path must be a real directory")
	}
	if privileged {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			return "", errors.New("privileged run output directory must be root-owned")
		}
	}
	if privileged && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("privileged run output directory must not be accessible by other users")
	}
	return absolute, nil
}
