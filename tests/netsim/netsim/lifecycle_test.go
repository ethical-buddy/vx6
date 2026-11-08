// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func smallTopology(t *testing.T) *Topology {
	t.Helper()
	p := Params{Seed: 7, Tier1: 2, ISPs: 1, Orgs: 1, Nodes: 3, LANSize: 8, Schedule: "1,2", Seeds: 1}
	topology, err := Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	return topology
}

func TestIsolatedNamespacesAreUniqueAndLinuxSafe(t *testing.T) {
	first := smallTopology(t)
	second := smallTopology(t)
	if err := isolateNamespaces(first, "012abc"); err != nil {
		t.Fatal(err)
	}
	if err := isolateNamespaces(second, "def456"); err != nil {
		t.Fatal(err)
	}
	firstNames, err := topologyNamespaces(first)
	if err != nil {
		t.Fatal(err)
	}
	secondNames, err := topologyNamespaces(second)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, name := range firstNames {
		if len(name) > 15 || seen[name] {
			t.Fatalf("invalid or duplicate namespace %q", name)
		}
		seen[name] = true
	}
	for _, name := range secondNames {
		if seen[name] {
			t.Fatalf("separate runs share namespace %q", name)
		}
	}
}

func TestCleanupRejectsUnownedOrModifiedNamespaceNames(t *testing.T) {
	topology := smallTopology(t)
	if err := isolateNamespaces(topology, "012abc"); err != nil {
		t.Fatal(err)
	}
	topology.Nodes[0].NS = "host-network"
	if _, err := topologyNamespaces(topology); err == nil {
		t.Fatal("cleanup accepted a namespace not owned by this run")
	}
	if _, err := topologyNamespaces(smallTopology(t)); err == nil {
		t.Fatal("cleanup accepted a topology without a run ID")
	}
}

func TestParseNamespaceListAndPID(t *testing.T) {
	got := parseNamespaceList("v6abc123-n0 (id: 7)\nv6abc123-r64512\n")
	if _, ok := got["v6abc123-n0"]; !ok || len(got) != 2 {
		t.Fatalf("unexpected namespace parse: %#v", got)
	}
	for _, input := range []string{"2", "12345"} {
		if _, err := parsePID(input); err != nil {
			t.Fatalf("valid PID %q rejected: %v", input, err)
		}
	}
	for _, input := range []string{"", "0", "1", "nope"} {
		if _, err := parsePID(input); err == nil {
			t.Fatalf("invalid PID %q accepted", input)
		}
	}
}

func TestSecureRunDirectoryCreatesPrivateDirectoryAndDoesNotChangeExistingMode(t *testing.T) {
	root := t.TempDir()
	created := filepath.Join(root, "created")
	if _, err := secureRunDirectory(created, false, true); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(created)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("new run directory mode = %o, want private", info.Mode().Perm())
	}

	existing := filepath.Join(root, "existing")
	if err := os.Mkdir(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := secureRunDirectory(existing, false, false); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(existing)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("validation changed existing directory mode to %o", info.Mode().Perm())
	}
}

func TestSecureRunDirectoryRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := secureRunDirectory(link, false, false); err == nil {
		t.Fatal("accepted a symlink as the output directory")
	}
}

func TestDryRunReportDoesNotClaimCoverage(t *testing.T) {
	items := coverage(&Report{DryRun: true, RestartCount: 1})
	for _, item := range items {
		if item.status == "EXERCISED" || item.status == "PARTIAL" {
			t.Errorf("dry run incorrectly claims %q is %s", item.name, item.status)
		}
	}
}
