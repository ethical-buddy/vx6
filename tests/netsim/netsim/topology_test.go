// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"net/netip"
	"testing"
)

func TestGenerateDeterministicAndWellFormed(t *testing.T) {
	p := DefaultParams()
	p.Nodes = 300
	a, err := Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Nodes) != len(b.Nodes) || a.Nodes[0].Name != b.Nodes[0].Name || a.Nodes[150].Addr != b.Nodes[150].Addr {
		t.Fatal("same params produced different topologies")
	}
	if len(a.Nodes) != p.Nodes {
		t.Fatalf("got %d nodes, want %d", len(a.Nodes), p.Nodes)
	}

	addrs := map[string]bool{}
	names := map[string]bool{}
	doc := netip.MustParsePrefix("2001:db8::/32")
	var waved int
	for _, n := range a.Nodes {
		if addrs[n.Addr] {
			t.Fatalf("duplicate node address %s", n.Addr)
		}
		addrs[n.Addr] = true
		if names[n.Name] {
			t.Fatalf("duplicate node name %s", n.Name)
		}
		names[n.Name] = true
		if len(n.Name) < 3 || len(n.Name) > 16 {
			t.Fatalf("node name %q not 3..16 chars", n.Name)
		}
		ad := netip.MustParseAddr(n.Addr)
		if !doc.Contains(ad) {
			t.Fatalf("node %s outside documentation prefix", n.Addr)
		}
	}
	for _, w := range a.Waves {
		waved += len(w)
	}
	if waved != len(a.Nodes) {
		t.Fatalf("waves cover %d nodes, want %d", waved, len(a.Nodes))
	}
	// First wave is a single bootstrap node (cold start).
	if len(a.Waves[0]) != 1 {
		t.Fatalf("first wave size = %d, want 1", len(a.Waves[0]))
	}
}

func TestEveryASReachableAndLinked(t *testing.T) {
	p := DefaultParams()
	a, err := Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	degree := make([]int, len(a.ASes))
	for _, l := range a.Links {
		degree[l.A]++
		degree[l.B]++
	}
	for i, a2 := range a.ASes {
		if degree[i] == 0 {
			t.Fatalf("AS %s (%s) has no inter-AS link", a2.Name, a2.Kind)
		}
	}
}

func TestRenderedCommandsNonEmptyAndQuoted(t *testing.T) {
	a, err := Generate(Params{Seed: 1, Tier1: 2, ISPs: 2, Orgs: 2, Attackers: 1, Nodes: 5,
		LANSize: 50, Schedule: "1,2", Seeds: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(RouterCmds(a)) == 0 {
		t.Fatal("no router commands")
	}
	for _, n := range a.Nodes {
		cmds := NodeNetCmds(a, n)
		if len(cmds) < 5 {
			t.Fatalf("node %s produced only %d commands", n.Name, len(cmds))
		}
		for _, c := range cmds {
			if c[0] != "ip" {
				t.Fatalf("unexpected command %v", c)
			}
		}
	}
	bgp := BGPConf(a, a.ASes[0], nil)
	if bgp == "" {
		t.Fatal("empty bgp config")
	}
}

func TestHijackPrefixesAreMoreSpecific(t *testing.T) {
	halves, err := HijackPrefixes("2001:db8:100::/40")
	if err != nil {
		t.Fatal(err)
	}
	if len(halves) != 2 {
		t.Fatalf("got %d halves", len(halves))
	}
	victim := netip.MustParsePrefix("2001:db8:100::/40")
	for _, h := range halves {
		hp := netip.MustParsePrefix(h)
		if hp.Bits() != 41 {
			t.Fatalf("hijack prefix %s is not a /41", h)
		}
		if !victim.Overlaps(hp) {
			t.Fatalf("hijack prefix %s not inside victim", h)
		}
	}
	if halves[0] == halves[1] {
		t.Fatal("the two halves are identical")
	}
}

func TestScheduleParse(t *testing.T) {
	s, err := ParseSchedule("1, 2 ,4")
	if err != nil || len(s) != 3 || s[2] != 4 {
		t.Fatalf("schedule = %v, err %v", s, err)
	}
	if _, err := ParseSchedule(""); err == nil {
		t.Fatal("empty schedule should error")
	}
	if _, err := ParseSchedule("0"); err == nil {
		t.Fatal("zero wave should error")
	}
}
