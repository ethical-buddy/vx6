// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

// netsim orchestrates the #69 Internet-like VX6 network simulation.
//
// It builds a deterministic topology (tier-1 transit, ISPs, orgs, an attacker
// AS, real IPv6 /40 blocks, BGP via FRR, named LANs), then on Linux creates
// the matching network namespaces, bridges and veth pairs, starts one FRR BGP
// speaker per AS, and launches one simnode per node joining in waves. Between
// waves it collects a DHT snapshot from every node and runs lookup probes, so
// you can see how many refresh rounds the routing tables need to settle and how
// bootstrap behaves as the network grows.
//
// Subcommands:
//
//	netsim plan    -out plan.json [params]      generate + validate topology, no root
//	netsim render  -params plan.json            print every ip/FRR command (dry run)
//	netsim run     [params] -out results/       build and drive the sim (Linux root)
//	netsim doctor                               check host prerequisites
//
// All node code is the real VX6 node; only the IPsec tunnel is replaced (see
// simnode). This measures DHT scale/churn/eclipse and bootstrap flow, not ESP.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "plan":
		err = cmdPlan(os.Args[2:])
	case "render":
		err = cmdRender(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "netsim:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `netsim - VX6 Internet-like DHT simulation (#69)

  netsim plan    -out plan.json [-nodes N -isps N -orgs N ...]
  netsim render  -params plan.json            print ip/FRR commands (no changes)
  netsim run     -out DIR [params]            build and drive (Linux, root)
  netsim doctor                               check prerequisites

Params: -seed -tier1 -isps -orgs -attackers -nodes -ipsec-nodes -lan-size
        -multihome -residential -schedule -seeds-per-join
`)
}

func paramFlags(fs *flag.FlagSet) *Params {
	p := DefaultParams()
	fs.Int64Var(&p.Seed, "seed", p.Seed, "deterministic seed")
	fs.IntVar(&p.Tier1, "tier1", p.Tier1, "tier-1 transit ASes")
	fs.IntVar(&p.ISPs, "isps", p.ISPs, "ISP ASes")
	fs.IntVar(&p.Orgs, "orgs", p.Orgs, "organization ASes")
	fs.IntVar(&p.Attackers, "attackers", p.Attackers, "attacker ASes")
	fs.IntVar(&p.Nodes, "nodes", p.Nodes, "sim-tier nodes (pass-through tunnel)")
	fs.IntVar(&p.IPsecNodes, "ipsec-nodes", p.IPsecNodes, "real-IPsec nodes (security tier)")
	fs.IntVar(&p.LANSize, "lan-size", p.LANSize, "max hosts per LAN bridge")
	fs.Float64Var(&p.Multihome, "multihome", p.Multihome, "fraction of orgs with two upstreams")
	fs.Float64Var(&p.ResidentialShare, "residential", p.ResidentialShare, "fraction of nodes on ISP residential LANs")
	fs.StringVar(&p.Schedule, "schedule", p.Schedule, "join-wave sizes, comma-separated")
	fs.IntVar(&p.Seeds, "seeds-per-join", p.Seeds, "bootstrap records given to each joining node")
	return &p
}

func cmdPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	p := paramFlags(fs)
	out := fs.String("out", "", "write topology JSON here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	t, err := Generate(*p)
	if err != nil {
		return err
	}
	summary := Summarize(t)
	b, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Println(string(b))
	if *out != "" {
		data, _ := json.Marshal(t)
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "topology written to %s\n", *out)
	}
	return nil
}

func loadTopology(path string) (*Topology, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Topology
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func cmdRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	params := fs.String("params", "", "topology JSON from `netsim plan`")
	p := paramFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	var t *Topology
	var err error
	if *params != "" {
		t, err = loadTopology(*params)
	} else {
		t, err = Generate(*p)
	}
	if err != nil {
		return err
	}
	for _, c := range RouterCmds(t) {
		fmt.Println(c)
	}
	for _, a := range t.ASes {
		fmt.Printf("# FRR bgpd config for %s (AS%d):\n", a.RouterNS, a.ASN)
	}
	for _, n := range t.Nodes {
		for _, c := range NodeNetCmds(t, n) {
			fmt.Println(c)
		}
	}
	return nil
}

func cmdDoctor(args []string) error {
	ok := true
	report := func(name string, err error) {
		if err != nil {
			ok = false
			fmt.Printf("  [MISSING] %s: %v\n", name, err)
		} else {
			fmt.Printf("  [ok]      %s\n", name)
		}
	}
	fmt.Println("netsim prerequisites:")
	for _, bin := range []string{"ip", "sysctl"} {
		_, err := exec.LookPath(bin)
		report(bin, err)
	}
	// FRR is optional: without it, ASes still route statically within the sim
	// is not possible across ASes, so BGP scenarios need it.
	if _, err := exec.LookPath("bgpd"); err != nil {
		fmt.Println("  [warn]    bgpd (FRR) not found: inter-AS BGP and hijack scenarios unavailable; install frr")
	} else {
		fmt.Println("  [ok]      bgpd (FRR)")
	}
	if _, err := os.Stat("/proc/sys/net/ipv6"); err != nil {
		ok = false
		fmt.Println("  [MISSING] IPv6: /proc/sys/net/ipv6 absent; this kernel cannot run the sim")
	} else {
		fmt.Println("  [ok]      IPv6 enabled")
	}
	if os.Geteuid() != 0 {
		fmt.Println("  [warn]    not root: `netsim run` needs root (or CAP_NET_ADMIN + CAP_SYS_ADMIN)")
	}
	if _, err := exec.LookPath("simnode"); err != nil {
		fmt.Println("  [warn]    simnode not on PATH: build it with `go build -o /usr/local/bin/simnode ./tests/netsim/simnode`")
	}
	if !ok {
		return errors.New("prerequisites missing")
	}
	return nil
}

// runner executes or prints commands.
type runner struct {
	dry bool
	log *os.File
}

func (r *runner) run(c Cmd) error {
	if r.log != nil {
		fmt.Fprintln(r.log, c.String())
	}
	if r.dry {
		fmt.Println(c)
		return nil
	}
	cmd := exec.Command(c[0], c[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", c, err, out)
	}
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	params := fs.String("params", "", "topology JSON (else generated from flags)")
	outDir := fs.String("out", "", "results directory (required)")
	dry := fs.Bool("dry-run", false, "print commands instead of running them")
	simnodeBin := fs.String("simnode", "simnode", "path to the simnode binary")
	settleRounds := fs.Int("settle-rounds", 6, "snapshot rounds to take after the last join")
	settleGap := fs.Duration("settle-gap", 30*time.Second, "delay between settle snapshots")
	probes := fs.Int("probes", 50, "random lookup probes per snapshot round")
	p := paramFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outDir == "" {
		return errors.New("-out is required")
	}
	if !*dry && os.Geteuid() != 0 {
		return errors.New("run needs root; use -dry-run to preview")
	}
	var t *Topology
	var err error
	if *params != "" {
		t, err = loadTopology(*params)
	} else {
		t, err = Generate(*p)
	}
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	logf, err := os.Create(filepath.Join(*outDir, "commands.log"))
	if err != nil {
		return err
	}
	defer logf.Close()
	r := &runner{dry: *dry, log: logf}

	sim := NewSimRun(t, r, *outDir, *simnodeBin)
	if err := sim.BuildFabric(); err != nil {
		return fmt.Errorf("build fabric: %w", err)
	}
	ctx := context.Background()
	report, err := sim.DriveWaves(ctx, *settleRounds, *settleGap, *probes)
	if err != nil {
		return fmt.Errorf("drive waves: %w", err)
	}
	data, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(filepath.Join(*outDir, "report.json"), data, 0o644); err != nil {
		return err
	}
	fmt.Printf("done: %d nodes, %d waves. Report: %s\n", len(t.Nodes), len(report.Rounds), filepath.Join(*outDir, "report.json"))
	if !*dry {
		fmt.Printf("Tear down with: netsim teardown -params %s  (or reboot the lab host)\n", filepath.Join(*outDir, "topology.json"))
	}
	return nil
}

// Summary is the human-readable digest from `netsim plan`.
type Summary struct {
	Params      Params         `json:"params"`
	ASCount     int            `json:"as_count"`
	NodeCount   int            `json:"node_count"`
	SimNodes    int            `json:"sim_nodes"`
	IPsecNodes  int            `json:"ipsec_nodes"`
	LANCount    int            `json:"lan_count"`
	Links       int            `json:"inter_as_links"`
	WaveCount   int            `json:"wave_count"`
	WaveSizes   []int          `json:"wave_sizes"`
	NodesPerASN map[string]int `json:"nodes_per_asn_top"`
	MaxASNShare float64        `json:"max_single_asn_share"`
}

func Summarize(t *Topology) Summary {
	s := Summary{Params: t.Params, ASCount: len(t.ASes), NodeCount: len(t.Nodes),
		LANCount: len(t.LANs), Links: len(t.Links), WaveCount: len(t.Waves)}
	perASN := map[uint32]int{}
	for _, n := range t.Nodes {
		perASN[n.ASN]++
		if n.Tier == TierSim {
			s.SimNodes++
		} else {
			s.IPsecNodes++
		}
	}
	for _, w := range t.Waves {
		s.WaveSizes = append(s.WaveSizes, len(w))
	}
	type kv struct {
		asn uint32
		n   int
	}
	var list []kv
	for a, n := range perASN {
		list = append(list, kv{a, n})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
	s.NodesPerASN = map[string]int{}
	for i, e := range list {
		if i >= 5 {
			break
		}
		s.NodesPerASN["AS"+strconv.Itoa(int(e.asn))] = e.n
		if i == 0 && len(t.Nodes) > 0 {
			s.MaxASNShare = float64(e.n) / float64(len(t.Nodes))
		}
	}
	return s
}
