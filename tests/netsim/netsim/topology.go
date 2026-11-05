// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// AS kinds in the Internet-like topology.
const (
	KindTier1    = "tier1"    // transit core ("the Internet" / IGW)
	KindISP      = "isp"      // regional ISP, also hosts residential LANs
	KindOrg      = "org"      // organization / enterprise / campus
	KindAttacker = "attacker" // hostile AS used for hijack/MITM scenarios
)

// Node tiers.
const (
	TierSim   = "sim"   // simnode: real node code, pass-through tunnel (DHT scale)
	TierIPsec = "ipsec" // real vx6 + vx6-ipsecd + charon (security scenarios)
)

// Params control topology generation. The same Params (including Seed)
// always produce the same topology.
type Params struct {
	Seed             int64   `json:"seed"`
	Tier1            int     `json:"tier1"`
	ISPs             int     `json:"isps"`
	Orgs             int     `json:"orgs"`
	Attackers        int     `json:"attackers"`
	Nodes            int     `json:"nodes"`
	IPsecNodes       int     `json:"ipsec_nodes"`
	LANSize          int     `json:"lan_size"`
	Multihome        float64 `json:"multihome"`
	ResidentialShare float64 `json:"residential_share"`
	Schedule         string  `json:"schedule"`
	Seeds            int     `json:"seeds_per_join"`
}

// DefaultParams is a 500-node, 34-AS network.
func DefaultParams() Params {
	return Params{Seed: 69, Tier1: 3, ISPs: 6, Orgs: 24, Attackers: 1, Nodes: 500, IPsecNodes: 0,
		LANSize: 200, Multihome: 0.4, ResidentialShare: 0.3, Schedule: "1,1,1,3,6,12,24,48,96,192", Seeds: 3}
}

type Topology struct {
	Params     Params  `json:"params"`
	ASes       []*AS   `json:"ases"`
	Links      []Link  `json:"links"`
	LANs       []*LAN  `json:"lans"`
	Nodes      []Node  `json:"nodes"`
	Waves      [][]int `json:"waves"` // node indexes per join wave (sim tier)
	IPsecWaves [][]int `json:"ipsec_waves"`
}

type AS struct {
	Index    int    `json:"index"`
	ASN      uint32 `json:"asn"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Prefix   string `json:"prefix"` // /40 block announced via BGP
	RouterNS string `json:"router_ns"`
	RouterID string `json:"router_id"`
	LANs     []int  `json:"lans"`
}

type Link struct {
	Index int    `json:"index"`
	A     int    `json:"a"` // AS index
	B     int    `json:"b"`
	AAddr string `json:"a_addr"`
	BAddr string `json:"b_addr"`
	AIf   string `json:"a_if"`
	BIf   string `json:"b_if"`
}

type LAN struct {
	Index   int    `json:"index"`
	AS      int    `json:"as"`
	Prefix  string `json:"prefix"` // /64
	Gateway string `json:"gateway"`
	Bridge  string `json:"bridge"`
	Kind    string `json:"kind"` // "office" or "residential"
	Hosts   int    `json:"hosts"`
}

type Node struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	Tier  string `json:"tier"`
	AS    int    `json:"as"`
	ASN   uint32 `json:"asn"`
	LAN   int    `json:"lan"`
	Addr  string `json:"addr"` // IPv6 host address
	NS    string `json:"ns"`
	VethN string `json:"veth_node"`
	VethR string `json:"veth_router"`
	Wave  int    `json:"wave"`
}

func (n Node) Endpoint() string { return "[" + n.Addr + "]:4242" }

func (p Params) validate() error {
	switch {
	case p.Tier1 < 2:
		return errors.New("need at least 2 tier-1 ASes")
	case p.ISPs < 1 || p.Orgs < 1:
		return errors.New("need at least one ISP and one org")
	case p.Tier1+p.ISPs+p.Orgs+p.Attackers > 250:
		return errors.New("at most 250 ASes (one /40 of 2001:db8::/32 each)")
	case p.Nodes < 1 || p.Nodes > 60000:
		return errors.New("nodes must be 1..60000")
	case p.IPsecNodes < 0 || p.IPsecNodes > 2000:
		return errors.New("ipsec nodes must be 0..2000")
	case p.LANSize < 2 || p.LANSize > 1000:
		return errors.New("lan size must be 2..1000 (Linux bridges allow 1024 ports)")
	case p.Seeds < 1:
		return errors.New("seeds per join must be >= 1")
	}
	return nil
}

// Generate builds a deterministic Internet-like topology.
func Generate(p Params) (*Topology, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	rng := rand.New(rand.NewSource(p.Seed))
	t := &Topology{Params: p}
	addAS := func(kind string, n int, label func(int) string) []int {
		var idx []int
		for i := 0; i < n; i++ {
			k := len(t.ASes)
			asn := uint32(64512 + k)
			t.ASes = append(t.ASes, &AS{
				Index: k, ASN: asn, Name: label(i), Kind: kind,
				Prefix:   fmt.Sprintf("2001:db8:%x00::/40", k+1),
				RouterNS: "r" + strconv.Itoa(int(asn)),
				RouterID: fmt.Sprintf("10.%d.%d.1", (k+1)/256, (k+1)%256),
			})
			idx = append(idx, k)
		}
		return idx
	}
	tier1 := addAS(KindTier1, p.Tier1, func(i int) string { return "transit-" + strconv.Itoa(i+1) })
	isps := addAS(KindISP, p.ISPs, func(i int) string { return pick(ispNames, i) })
	orgs := addAS(KindOrg, p.Orgs, func(i int) string { return pick(orgNames, i) })
	attackers := addAS(KindAttacker, p.Attackers, func(i int) string { return "rogue-" + strconv.Itoa(i+1) })

	link := func(a, b int) {
		for _, l := range t.Links {
			if (l.A == a && l.B == b) || (l.A == b && l.B == a) {
				return
			}
		}
		i := len(t.Links)
		t.Links = append(t.Links, Link{Index: i, A: a, B: b,
			AAddr: fmt.Sprintf("fd5e:e000:0:%x::1", i+1), BAddr: fmt.Sprintf("fd5e:e000:0:%x::2", i+1),
			AIf: fmt.Sprintf("x%da", i), BIf: fmt.Sprintf("x%db", i)})
	}
	// Tier-1 full mesh.
	for i := range tier1 {
		for j := i + 1; j < len(tier1); j++ {
			link(tier1[i], tier1[j])
		}
	}
	// Each ISP buys transit from two distinct tier-1s.
	for _, isp := range isps {
		perm := rng.Perm(len(tier1))
		link(isp, tier1[perm[0]])
		link(isp, tier1[perm[1]])
	}
	// Orgs: one upstream ISP, sometimes two (multihoming).
	for _, org := range orgs {
		perm := rng.Perm(len(isps))
		link(org, isps[perm[0]])
		if len(isps) > 1 && rng.Float64() < p.Multihome {
			link(org, isps[perm[1]])
		}
	}
	// Attackers hang off a random ISP like any customer.
	for _, a := range attackers {
		link(a, isps[rng.Intn(len(isps))])
	}

	// Place nodes. Org sizes are skewed (a few big orgs, many small ones), so
	// ASN concentration is realistic for the DHT diversity policy.
	total := p.Nodes + p.IPsecNodes
	weights := make([]float64, 0, len(orgs)+len(isps))
	hostAS := make([]int, 0, len(orgs)+len(isps))
	officeShare := 1 - p.ResidentialShare
	var orgW float64
	for r := range orgs {
		orgW += 1 / float64(r+1)
	}
	for r, org := range orgs {
		weights = append(weights, officeShare*(1/float64(r+1))/orgW)
		hostAS = append(hostAS, org)
	}
	for _, isp := range isps {
		weights = append(weights, p.ResidentialShare/float64(len(isps)))
		hostAS = append(hostAS, isp)
	}
	counts := apportion(weights, total)
	lanFor := func(as int, kind string) *LAN {
		a := t.ASes[as]
		if len(a.LANs) > 0 {
			last := t.LANs[a.LANs[len(a.LANs)-1]]
			if last.Hosts < p.LANSize {
				return last
			}
		}
		i := len(t.LANs)
		sub := len(a.LANs) + 1
		pref := netip.MustParsePrefix(a.Prefix).Addr().As16()
		pref[6], pref[7] = byte(sub>>8), byte(sub)
		lanPrefix := netip.PrefixFrom(netip.AddrFrom16(pref), 64)
		gw := pref
		gw[15] = 1
		l := &LAN{Index: i, AS: as, Prefix: lanPrefix.String(), Gateway: netip.AddrFrom16(gw).String(),
			Bridge: fmt.Sprintf("b%d", i), Kind: kind}
		t.LANs = append(t.LANs, l)
		a.LANs = append(a.LANs, i)
		return l
	}

	names := newNamer(rng)
	order := make([]int, 0, total)
	for h, c := range counts {
		for j := 0; j < c; j++ {
			order = append(order, hostAS[h])
		}
	}
	rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	for i, as := range order {
		kind := "office"
		if t.ASes[as].Kind == KindISP {
			kind = "residential"
		}
		lan := lanFor(as, kind)
		lan.Hosts++
		addr := netip.MustParsePrefix(lan.Prefix).Addr().As16()
		host := 0x10 + lan.Hosts
		addr[14], addr[15] = byte(host>>8), byte(host)
		tier := TierSim
		if i >= p.Nodes {
			tier = TierIPsec
		}
		t.Nodes = append(t.Nodes, Node{Index: i, Name: names.next(), Tier: tier, AS: as, ASN: t.ASes[as].ASN,
			LAN: lan.Index, Addr: netip.AddrFrom16(addr).String(), NS: "n" + strconv.Itoa(i),
			VethN: "v" + strconv.Itoa(i), VethR: "p" + strconv.Itoa(i)})
	}

	sched, err := ParseSchedule(p.Schedule)
	if err != nil {
		return nil, err
	}
	var sim, sec []int
	for _, n := range t.Nodes {
		if n.Tier == TierSim {
			sim = append(sim, n.Index)
		} else {
			sec = append(sec, n.Index)
		}
	}
	t.Waves = waves(sim, sched)
	t.IPsecWaves = waves(sec, sched)
	for w, idx := range t.Waves {
		for _, i := range idx {
			t.Nodes[i].Wave = w
		}
	}
	for w, idx := range t.IPsecWaves {
		for _, i := range idx {
			t.Nodes[i].Wave = w
		}
	}
	return t, nil
}

// ParseSchedule parses "1,1,1,3,6" join-wave sizes. After the list is used
// up, the last wave size keeps doubling until every node has joined.
func ParseSchedule(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.Atoi(part)
		if err != nil || v < 1 {
			return nil, fmt.Errorf("bad schedule entry %q", part)
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, errors.New("empty join schedule")
	}
	return out, nil
}

func waves(idx []int, sched []int) [][]int {
	var out [][]int
	for i, w := 0, 0; i < len(idx); w++ {
		size := 0
		if w < len(sched) {
			size = sched[w]
		} else {
			size = sched[len(sched)-1] << uint(w-len(sched)+1)
			if size <= 0 || size > len(idx) {
				size = len(idx)
			}
		}
		end := i + size
		if end > len(idx) {
			end = len(idx)
		}
		out = append(out, append([]int(nil), idx[i:end]...))
		i = end
	}
	return out
}

// apportion splits total across weights (largest remainder method).
func apportion(w []float64, total int) []int {
	var sum float64
	for _, v := range w {
		sum += v
	}
	out := make([]int, len(w))
	type rem struct {
		i int
		r float64
	}
	rems := make([]rem, len(w))
	used := 0
	for i, v := range w {
		exact := v / sum * float64(total)
		out[i] = int(exact)
		used += out[i]
		rems[i] = rem{i, exact - float64(out[i])}
	}
	sort.SliceStable(rems, func(a, b int) bool { return rems[a].r > rems[b].r })
	for k := 0; used < total; k++ {
		out[rems[k%len(rems)].i]++
		used++
	}
	return out
}

func pick(list []string, i int) string {
	if i < len(list) {
		return list[i]
	}
	return list[i%len(list)] + "-" + strconv.Itoa(i/len(list)+1)
}

var ispNames = []string{"northnet", "riverline", "skyfiber", "metrolink", "coastal", "highland", "sunwave", "polaris", "granite", "lakeside"}
var orgNames = []string{"acme", "globex", "initech", "umbrella", "hooli", "vandelay", "wonka", "stark", "wayne", "cyberdyne",
	"tyrell", "aperture", "monarch", "soylent", "oscorp", "massive", "virtucon", "gringotts", "nakatomi", "rekall",
	"duff", "kramerica", "zorg", "vehement", "ollivander", "krusty", "dunder", "pied", "bluth", "prestige"}

var adjectives = []string{"AMBER", "BOLD", "CALM", "DARK", "EAGER", "FAST", "GOLD", "HAZY", "ICY", "JADE", "KEEN", "LUCKY",
	"MISTY", "NOBLE", "OLIVE", "PROUD", "QUIET", "RAPID", "SOLAR", "TIDY", "ULTRA", "VIVID", "WILD", "YOUNG", "ZESTY"}
var nouns = []string{"FOX", "OWL", "LYNX", "BEAR", "HAWK", "WOLF", "ORCA", "MOTH", "CRAB", "DEER", "ELK", "GNU", "IBIS",
	"KOI", "LARK", "MINK", "NEWT", "PUMA", "RAVEN", "SEAL", "TOAD", "VOLE", "WREN", "YAK", "ZEBU"}

// namer hands out unique, human-looking VX6 node names (3..16 chars).
type namer struct {
	rng  *rand.Rand
	used map[string]bool
}

func newNamer(rng *rand.Rand) *namer { return &namer{rng: rng, used: map[string]bool{}} }

func (n *namer) next() string {
	for {
		base := adjectives[n.rng.Intn(len(adjectives))] + "-" + nouns[n.rng.Intn(len(nouns))]
		name := base
		if n.used[name] {
			name = base + "-" + strconv.Itoa(n.rng.Intn(1000))
		}
		if len(name) <= 16 && !n.used[name] {
			n.used[name] = true
			return name
		}
	}
}
