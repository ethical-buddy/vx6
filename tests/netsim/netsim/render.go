// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"fmt"
	"net/netip"
	"strings"
)

// Cmd is one command the runner executes (or prints in -dry-run).
type Cmd []string

func ip(args ...string) Cmd { return append(Cmd{"ip"}, args...) }

func nsSysctl(ns string, kv ...string) Cmd {
	return append(Cmd{"ip", "netns", "exec", ns, "sysctl", "-qw"}, kv...)
}

// RouterCmds creates every AS router namespace, inter-AS links and LAN bridges.
func RouterCmds(t *Topology) []Cmd {
	var out []Cmd
	for _, a := range t.ASes {
		ns := a.RouterNS
		out = append(out,
			ip("netns", "add", ns),
			ip("-n", ns, "link", "set", "lo", "up"),
			nsSysctl(ns, "net.ipv6.conf.all.forwarding=1", "net.ipv6.conf.all.accept_ra=0",
				"net.ipv6.conf.default.accept_dad=0", "net.ipv6.conf.all.accept_dad=0",
				// Large LANs: room for thousands of neighbour entries.
				"net.ipv6.neigh.default.gc_thresh1=4096", "net.ipv6.neigh.default.gc_thresh2=16384",
				"net.ipv6.neigh.default.gc_thresh3=32768", "net.ipv6.route.max_size=262144"),
			// Blackhole the whole AS block so BGP can originate it; LANs are more specific.
			ip("-n", ns, "-6", "route", "add", "blackhole", a.Prefix),
		)
	}
	for _, l := range t.Links {
		a, b := t.ASes[l.A], t.ASes[l.B]
		out = append(out,
			ip("link", "add", l.AIf, "netns", a.RouterNS, "type", "veth", "peer", "name", l.BIf, "netns", b.RouterNS),
			ip("-n", a.RouterNS, "-6", "addr", "add", l.AAddr+"/64", "dev", l.AIf, "nodad"),
			ip("-n", b.RouterNS, "-6", "addr", "add", l.BAddr+"/64", "dev", l.BIf, "nodad"),
			ip("-n", a.RouterNS, "link", "set", l.AIf, "up"),
			ip("-n", b.RouterNS, "link", "set", l.BIf, "up"),
		)
	}
	for _, lan := range t.LANs {
		ns := t.ASes[lan.AS].RouterNS
		bits := netip.MustParsePrefix(lan.Prefix).Bits()
		out = append(out,
			ip("-n", ns, "link", "add", lan.Bridge, "type", "bridge"),
			ip("-n", ns, "-6", "addr", "add", fmt.Sprintf("%s/%d", lan.Gateway, bits), "dev", lan.Bridge, "nodad"),
			ip("-n", ns, "link", "set", lan.Bridge, "up"),
		)
	}
	return out
}

// NodeNetCmds creates one node's namespace and plugs it into its LAN.
func NodeNetCmds(t *Topology, n Node) []Cmd {
	lan := t.LANs[n.LAN]
	rns := t.ASes[n.AS].RouterNS
	bits := netip.MustParsePrefix(lan.Prefix).Bits()
	return []Cmd{
		ip("netns", "add", n.NS),
		ip("-n", n.NS, "link", "set", "lo", "up"),
		nsSysctl(n.NS, "net.ipv6.conf.all.accept_ra=0", "net.ipv6.conf.default.accept_dad=0", "net.ipv6.conf.all.accept_dad=0"),
		ip("link", "add", n.VethN, "netns", n.NS, "type", "veth", "peer", "name", n.VethR, "netns", rns),
		ip("-n", rns, "link", "set", n.VethR, "master", lan.Bridge),
		ip("-n", rns, "link", "set", n.VethR, "up"),
		ip("-n", n.NS, "-6", "addr", "add", fmt.Sprintf("%s/%d", n.Addr, bits), "dev", n.VethN, "nodad"),
		ip("-n", n.NS, "link", "set", n.VethN, "up"),
		ip("-n", n.NS, "-6", "route", "add", "default", "via", lan.Gateway),
	}
}

// NodeUnplugCmds removes a node's namespace (and with it the veth pair).
func NodeUnplugCmds(n Node) []Cmd {
	return []Cmd{ip("netns", "del", n.NS)}
}

// ZebraConf / BGPConf render FRR configs for one AS router.
func ZebraConf(a *AS) string {
	return fmt.Sprintf("hostname %s\nlog file /dev/null\n!\n", a.RouterNS)
}

// BGPConf renders eBGP sessions to every neighbouring AS. extra lets
// scenarios (prefix hijack) add origin prefixes.
func BGPConf(t *Topology, a *AS, extra []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "frr defaults traditional\nhostname %s\nlog file /dev/null\n!\n", a.RouterNS)
	fmt.Fprintf(&b, "router bgp %d\n bgp router-id %s\n no bgp ebgp-requires-policy\n no bgp network import-check\n bgp bestpath as-path multipath-relax\n", a.ASN, a.RouterID)
	type nb struct {
		addr string
		asn  uint32
	}
	var nbs []nb
	for _, l := range t.Links {
		switch a.Index {
		case l.A:
			nbs = append(nbs, nb{l.BAddr, t.ASes[l.B].ASN})
		case l.B:
			nbs = append(nbs, nb{l.AAddr, t.ASes[l.A].ASN})
		}
	}
	for _, n := range nbs {
		fmt.Fprintf(&b, " neighbor %s remote-as %d\n neighbor %s timers 3 9\n neighbor %s timers connect 5\n", n.addr, n.asn, n.addr, n.addr)
	}
	b.WriteString(" !\n address-family ipv6 unicast\n")
	fmt.Fprintf(&b, "  network %s\n", a.Prefix)
	for _, p := range extra {
		fmt.Fprintf(&b, "  network %s\n", p)
	}
	for _, n := range nbs {
		fmt.Fprintf(&b, "  neighbor %s activate\n", n.addr)
	}
	b.WriteString(" exit-address-family\n!\n")
	return b.String()
}

// HijackPrefixes splits a victim /40 into two /41s. More-specific routes win
// longest-prefix match everywhere, which is how a BGP hijack diverts traffic.
func HijackPrefixes(victim string) ([]string, error) {
	p, err := netip.ParsePrefix(victim)
	if err != nil {
		return nil, err
	}
	bits := p.Bits() + 1
	lo := netip.PrefixFrom(p.Addr(), bits)
	hi := p.Addr().As16()
	hi[bits/8-1+boolInt(bits%8 != 0)] |= byte(0x80 >> uint((bits-1)%8))
	return []string{lo.String(), netip.PrefixFrom(netip.AddrFrom16(hi), bits).String()}, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (c Cmd) String() string {
	parts := make([]string, len(c))
	for i, s := range c {
		if strings.ContainsAny(s, " \t'\"$") {
			parts[i] = "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		} else {
			parts[i] = s
		}
	}
	return strings.Join(parts, " ")
}
