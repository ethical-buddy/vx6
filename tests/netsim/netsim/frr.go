// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// frrStateRoot holds each run's FRR pid files and sockets. Every AS router
// gets its own directory so that many zebra/bgpd pairs can run side by side
// without contending for the packaged /var/run/frr pid files and sockets.
// The run directory itself stays root-only (0700); FRR drops privileges to
// the frr user, so its state lives here instead.
var frrStateRoot = "/run/vx6-netsim"

// frrAccount is the account FRR drops privileges to after starting as root.
type frrAccount struct {
	uid, gid int
}

func lookupFRRAccount() (frrAccount, error) {
	u, err := user.Lookup("frr")
	if err != nil {
		return frrAccount{}, fmt.Errorf("FRR user %q not found (install the FRR package): %w", "frr", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return frrAccount{}, fmt.Errorf("FRR user uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return frrAccount{}, fmt.Errorf("FRR user gid %q: %w", u.Gid, err)
	}
	return frrAccount{uid: uid, gid: gid}, nil
}

// frrRunStateDir returns the run-specific FRR state directory.
func frrRunStateDir(runID string) (string, error) {
	if !runIDPattern.MatchString(runID) {
		return "", errors.New("invalid simulation run ID for FRR state")
	}
	return filepath.Join(frrStateRoot, runID), nil
}

// prepareFRRRunState creates frrStateRoot (if needed) and a fresh run
// directory. It refuses symlinks and pre-existing run directories so root
// never writes into a location another user prepared.
func prepareFRRRunState(runID string) (string, error) {
	runDir, err := frrRunStateDir(runID)
	if err != nil {
		return "", err
	}
	if err := os.Mkdir(frrStateRoot, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	if err := requireRootOwnedDir(frrStateRoot); err != nil {
		return "", err
	}
	if err := os.Mkdir(runDir, 0o755); err != nil {
		return "", fmt.Errorf("create FRR run state %s: %w", runDir, err)
	}
	return runDir, nil
}

func requireRootOwnedDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s must be a real directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("%s must be owned by root", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must not be group- or world-writable", path)
	}
	return nil
}

// prepareFRRRouterState creates <run>/<ns> owned by the FRR account and writes
// the daemon configs there, readable by the FRR group.
func prepareFRRRouterState(runDir, namespace string, acct frrAccount, configs map[string]string) (string, error) {
	dir := filepath.Join(runDir, namespace)
	if err := os.Mkdir(dir, 0o750); err != nil {
		return "", err
	}
	if err := os.Chown(dir, acct.uid, acct.gid); err != nil {
		return "", err
	}
	names := make([]string, 0, len(configs))
	for name := range configs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(configs[name]), 0o640); err != nil {
			return "", err
		}
		if err := os.Chown(path, 0, acct.gid); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// frrDaemonArgs keeps every path a daemon touches inside its own state dir.
func frrDaemonArgs(stateDir, daemon, config string) []string {
	return []string{
		"-f", config,
		"-z", filepath.Join(stateDir, "zserv.api"),
		"-i", filepath.Join(stateDir, daemon+".pid"),
		"--vty_socket", stateDir,
	}
}

// removeFRRRunState deletes only the run-specific FRR state directory.
func removeFRRRunState(runID string) error {
	runDir, err := frrRunStateDir(runID)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(runDir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := requireRootOwnedDir(frrStateRoot); err != nil {
		return err
	}
	return os.RemoveAll(runDir)
}

// waitBGPConverged polls each AS router's kernel table until it holds a BGP
// route for every other AS prefix. Nodes join only after inter-AS routing
// works; otherwise early bootstrap pings fail and the run measures nothing.
func waitBGPConverged(ctx context.Context, t *Topology, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	deadline := start.Add(timeout)
	var missing []string
	for {
		missing = missing[:0]
		for _, a := range t.ASes {
			out, err := exec.CommandContext(ctx, "ip", "-n", a.RouterNS, "-6", "route", "show", "proto", "bgp").Output()
			if err != nil {
				return 0, fmt.Errorf("read routes in %s: %w", a.RouterNS, err)
			}
			have := bgpRoutePrefixes(string(out))
			for _, b := range t.ASes {
				if b.Index == a.Index {
					continue
				}
				if _, ok := have[b.Prefix]; !ok {
					missing = append(missing, fmt.Sprintf("AS%d lacks %s", a.ASN, b.Prefix))
				}
			}
		}
		if len(missing) == 0 {
			return time.Since(start), nil
		}
		if time.Now().After(deadline) {
			sample := missing
			if len(sample) > 5 {
				sample = sample[:5]
			}
			return time.Since(start), fmt.Errorf("BGP did not converge within %s (%d missing routes, e.g. %s); check logs/*-bgpd.log",
				timeout, len(missing), strings.Join(sample, "; "))
		}
		select {
		case <-ctx.Done():
			return time.Since(start), ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// bgpRoutePrefixes extracts destination prefixes from `ip -6 route` output.
func bgpRoutePrefixes(output string) map[string]struct{} {
	prefixes := map[string]struct{}{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.Contains(fields[0], "/") {
			prefixes[fields[0]] = struct{}{}
		}
	}
	return prefixes
}
