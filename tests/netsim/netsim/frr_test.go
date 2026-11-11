// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRouterSysctlsAvoidInitNamespaceOnlyKeys(t *testing.T) {
	topo, err := Generate(DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range RouterCmds(topo) {
		if strings.Contains(c.String(), "neigh.default.gc_thresh") {
			t.Fatalf("router command sets an init-namespace-only sysctl: %s", c)
		}
	}
}

func TestFRRDaemonArgsStayInsideStateDir(t *testing.T) {
	state := filepath.Join("/run/vx6-netsim", "abc123", "v6abc123-r64512")
	args := frrDaemonArgs(state, "bgpd", filepath.Join(state, "bgpd.conf"))
	want := map[string]string{
		"-f":           filepath.Join(state, "bgpd.conf"),
		"-z":           filepath.Join(state, "zserv.api"),
		"-i":           filepath.Join(state, "bgpd.pid"),
		"--vty_socket": state,
	}
	if len(args) != 2*len(want) {
		t.Fatalf("unexpected args %v", args)
	}
	for i := 0; i < len(args); i += 2 {
		if want[args[i]] != args[i+1] {
			t.Fatalf("%s = %q, want %q", args[i], args[i+1], want[args[i]])
		}
	}
}

func TestFRRRunStateDirRejectsInvalidRunID(t *testing.T) {
	for _, id := range []string{"", "../etc", "ABCDEF", "abc12", "abc1234"} {
		if _, err := frrRunStateDir(id); err == nil {
			t.Fatalf("run ID %q accepted", id)
		}
	}
	if dir, err := frrRunStateDir("0a1b2c"); err != nil || dir != filepath.Join(frrStateRoot, "0a1b2c") {
		t.Fatalf("valid run ID: %q, %v", dir, err)
	}
}

func TestBGPRoutePrefixes(t *testing.T) {
	out := "2001:db8:200::/40 nhid 8 via fe80::1 dev x0a proto bgp metric 20 pref medium\n" +
		"2001:db8:300::/40 nhid 10 via fe80::2 dev x2b proto bgp metric 20 pref medium\n\n"
	got := bgpRoutePrefixes(out)
	for _, p := range []string{"2001:db8:200::/40", "2001:db8:300::/40"} {
		if _, ok := got[p]; !ok {
			t.Fatalf("missing %s in %v", p, got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("unexpected prefixes %v", got)
	}
}

func TestIsProgramMatchesArgv0Only(t *testing.T) {
	if !isProgram([]string{"/usr/lib/frr/zebra", "-f", "x"}, "zebra") {
		t.Fatal("argv[0] zebra not matched")
	}
	if isProgram([]string{"less", "/var/tmp/run/logs/zebra"}, "zebra") {
		t.Fatal("matched a later argument")
	}
	if isProgram([]string{"ip", "netns", "exec", "ns", "/tmp/vx6-simnode"}, "/tmp/vx6-simnode") {
		t.Fatal("matched the ip netns exec wrapper")
	}
	if isProgram(nil, "zebra") {
		t.Fatal("matched empty argv")
	}
}

func TestRunVerdict(t *testing.T) {
	// A sampled run with hits is measured, never a blanket PASS.
	sampled := &Report{LookupMode: LookupModeSample, Rounds: []RoundReport{{Label: "settle-0", NodesJoined: 3, SnapshotsOK: 3, MaxActivePeers: 2}},
		Totals: LookupStats{Attempts: 10, N: 10, Found: 9}}
	if v, _ := runVerdict(sampled); v != "MEASURED" {
		t.Fatalf("sampled run: %s", v)
	}
	// Exhaustive mode passes only with 100% in the final round.
	full := &Report{LookupMode: LookupModeExhaustive, Rounds: []RoundReport{
		{Label: "settle-0", NodesJoined: 3, SnapshotsOK: 3, MaxActivePeers: 2, Lookups: LookupStats{Attempts: 12, N: 12, Found: 10}},
		{Label: "settle-1", NodesJoined: 3, SnapshotsOK: 3, MaxActivePeers: 2, Lookups: LookupStats{Attempts: 12, N: 12, Found: 12}}}}
	if v, reasons := runVerdict(full); v != "PASS" || len(reasons) != 0 {
		t.Fatalf("exhaustive 100%% final round: %s %v", v, reasons)
	}
	full.Rounds[1].Lookups = LookupStats{Attempts: 12, N: 12, Found: 11, Missed: 1, Other: 1}
	if v, reasons := runVerdict(full); v != "FAIL" || len(reasons) != 1 {
		t.Fatalf("exhaustive 11/12: %s %v", v, reasons)
	}
	dead := &Report{Rounds: []RoundReport{{Label: "settle-1", NodesJoined: 5, SnapshotsOK: 5, MaxActivePeers: 0}},
		Totals: LookupStats{Attempts: 62, N: 62, Found: 0}}
	v, reasons := runVerdict(dead)
	if v != "FAIL" || len(reasons) != 2 {
		t.Fatalf("dead run: %s %v", v, reasons)
	}
	if v, _ := runVerdict(&Report{DryRun: true}); v != "PREVIEW" {
		t.Fatalf("dry run verdict %s", v)
	}
	if v, _ := runVerdict(&Report{}); v != "FAIL" {
		t.Fatalf("empty live run verdict %s", v)
	}
	items := coverage(dead)
	for _, item := range items {
		if (item.name == "Identity-ID lookup" || item.name == "Canonical-name lookup") && item.status != "FAILED" {
			t.Fatalf("%s status %s", item.name, item.status)
		}
	}
}
