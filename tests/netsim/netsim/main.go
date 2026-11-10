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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var buildRevision = "unknown"

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
	case "teardown":
		err = cmdTeardown(os.Args[2:])
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
  netsim teardown -params DIR/topology.json   stop and remove this run only
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
	fmt.Println("# PREVIEW ONLY: commands are not run; use `netsim run` for managed setup and cleanup.")
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
	for _, bin := range []string{"bgpd", "zebra"} {
		_, err := exec.LookPath(bin)
		if err != nil {
			// Debian/Ubuntu install the daemons outside PATH.
			if _, statErr := os.Stat(filepath.Join("/usr/lib/frr", bin)); statErr == nil {
				err = fmt.Errorf("found /usr/lib/frr/%s; run with PATH=/usr/lib/frr:$PATH", bin)
			}
		}
		report(bin+" (FRR)", err)
	}
	if _, err := lookupFRRAccount(); err != nil {
		report("frr user (FRR)", err)
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

func cmdRun(args []string) (retErr error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	params := fs.String("params", "", "topology JSON (else generated from flags)")
	outDir := fs.String("out", "", "results directory (required)")
	dry := fs.Bool("dry-run", false, "print commands instead of running them")
	simnodeBin := fs.String("simnode", "simnode", "path to the simnode binary")
	settleRounds := fs.Int("settle-rounds", 6, "snapshot rounds to take after the last join")
	settleGap := fs.Duration("settle-gap", 30*time.Second, "delay between settle snapshots")
	probes := fs.Int("probes", 50, "random lookup probes per snapshot round")
	restartCount := fs.Int("restart-count", 1, "nodes to restart after joining to check bbolt recovery (0 disables)")
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
	if !*dry {
		for _, bin := range []string{"ip", "sysctl", "bgpd", "zebra"} {
			if _, err := exec.LookPath(bin); err != nil {
				return fmt.Errorf("live run requires %s in PATH", bin)
			}
		}
		if _, err := os.Stat("/proc/sys/net/ipv6"); err != nil {
			return errors.New("live run requires Linux IPv6 support")
		}
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
	runID, err := newRunID()
	if err != nil {
		return fmt.Errorf("create isolated run ID: %w", err)
	}
	if err := isolateNamespaces(t, runID); err != nil {
		return err
	}
	if err := validateRunOptions(*settleRounds, *settleGap, *probes, *restartCount, len(t.Nodes)); err != nil {
		return err
	}
	securedOutDir, err := secureRunDirectory(*outDir, !*dry, true)
	if err != nil {
		return fmt.Errorf("secure output directory: %w", err)
	}
	*outDir = securedOutDir
	entries, err := os.ReadDir(*outDir)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("output directory %s is not empty; use a fresh directory per run", *outDir)
	}
	if !*dry {
		if err := preflightNamespaces(t); err != nil {
			return err
		}
	}
	logf, err := os.Create(filepath.Join(*outDir, "commands.log"))
	if err != nil {
		return err
	}
	defer logf.Close()
	r := &runner{dry: *dry, log: logf}

	sim := NewSimRun(t, r, *outDir, *simnodeBin)
	started := time.Now().UTC()
	hostMetricsStart := captureHostMetrics()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	topologyData, _ := json.Marshal(t)
	simnodePath, _ := exec.LookPath(*simnodeBin)
	hostKernel, hostCPUModel := hostPlatformInfo()
	report := &Report{SchemaVersion: 1, RunID: runID, StartedAt: started,
		BuildRevision: buildRevision, TopologySHA256: hashHex(topologyData),
		SimnodeSHA256: hashFile(simnodePath), Params: t.Params,
		HostOS: runtime.GOOS, HostArch: runtime.GOARCH, GoVersion: runtime.Version(),
		HostKernel: hostKernel, HostCPUModel: hostCPUModel, LogicalCPUs: runtime.NumCPU(),
		SettleRounds: *settleRounds, SettleGap: *settleGap, ProbesPerRound: *probes,
		RestartCount: *restartCount, DryRun: *dry}
	defer func() {
		report.FinishedAt = time.Now().UTC()
		report.HostResources = summarizeHostMetrics(hostMetricsStart, captureHostMetrics())
		report.HostResources.SimnodeCPUTimeMS, report.HostResources.SimnodeCPUStatsAvailable = simnodeCPUTimeMS(*outDir, filepath.Base(*simnodeBin))
		if *dry {
			report.CleanupStatus = "not applicable (dry run)"
		} else if cleanupErr := sim.Cleanup(); cleanupErr != nil {
			report.CleanupStatus = "FAILED: " + cleanupErr.Error()
			if retErr == nil {
				retErr = cleanupErr
			} else {
				retErr = fmt.Errorf("%v; cleanup also failed: %w", retErr, cleanupErr)
			}
		} else {
			report.CleanupStatus = "complete"
		}
		report.BGPConvergedMS = float64(sim.BGPConverged.Microseconds()) / 1000
		finalizeReport(report)
		if report.Verdict == "FAIL" && retErr == nil {
			retErr = fmt.Errorf("simulation verdict FAIL: %s (see %s)", strings.Join(report.VerdictReasons, "; "),
				filepath.Join(*outDir, "report.md"))
		}
		if writeErr := writeReportFiles(*outDir, report); writeErr != nil {
			if retErr == nil {
				retErr = writeErr
			} else {
				retErr = fmt.Errorf("%v; report write failed: %w", retErr, writeErr)
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := sim.BuildFabric(); err != nil {
		return fmt.Errorf("build fabric: %w", err)
	}
	partial, err := sim.DriveWaves(ctx, *settleRounds, *settleGap, *probes, *restartCount)
	if partial != nil {
		report.Rounds = partial.Rounds
		report.Restarts = partial.Restarts
		report.RunID = runID
		report.StartedAt = started
		report.BuildRevision = buildRevision
		report.TopologySHA256 = hashHex(topologyData)
		report.SimnodeSHA256 = hashFile(simnodePath)
	}
	if err != nil {
		return fmt.Errorf("drive waves: %w", err)
	}
	fmt.Printf("done: %d nodes, %d rounds. Reports: %s and %s\n", len(t.Nodes), len(report.Rounds),
		filepath.Join(*outDir, "report.json"), filepath.Join(*outDir, "report.md"))
	return nil
}

func cmdTeardown(args []string) error {
	fs := flag.NewFlagSet("teardown", flag.ContinueOnError)
	params := fs.String("params", "", "topology.json emitted by netsim run")
	dry := fs.Bool("dry-run", false, "print cleanup actions without changing the host")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *params == "" {
		return errors.New("-params is required")
	}
	if !*dry && os.Geteuid() != 0 {
		return errors.New("teardown needs root; use -dry-run to preview")
	}
	t, err := loadTopology(*params)
	if err != nil {
		return err
	}
	if err := validateOwnedTopology(t); err != nil {
		return err
	}
	runDir := filepath.Dir(*params)
	securedRunDir, err := secureRunDirectory(runDir, !*dry, false)
	if err != nil {
		return fmt.Errorf("validate run directory: %w", err)
	}
	runDir = securedRunDir
	if *dry {
		files, err := filepath.Glob(filepath.Join(runDir, "pids", "*.json"))
		if err != nil {
			return err
		}
		for _, file := range files {
			fmt.Printf("would stop recorded process: %s\n", filepath.Base(file))
		}
	} else {
		if err := stopPersistedProcesses(filepath.Join(runDir, "pids")); err != nil {
			return fmt.Errorf("stop recorded processes: %w", err)
		}
	}
	r := &runner{dry: *dry}
	if err := deleteOwnedNamespaces(t, r); err != nil {
		return err
	}
	if *dry {
		if state, err := frrRunStateDir(t.RunID); err == nil {
			fmt.Printf("would remove FRR state directory: %s\n", state)
		}
	} else if err := removeFRRRunState(t.RunID); err != nil {
		return fmt.Errorf("remove FRR state: %w", err)
	}
	fmt.Printf("teardown complete for netsim run %s\n", t.RunID)
	return nil
}

func validateRunOptions(settleRounds int, settleGap time.Duration, probes, restartCount, nodes int) error {
	if settleRounds < 0 || settleRounds > 100 {
		return errors.New("-settle-rounds must be 0..100")
	}
	if settleGap < 0 || settleGap > 24*time.Hour {
		return errors.New("-settle-gap must be 0..24h")
	}
	if probes < 0 || probes > 10000 {
		return errors.New("-probes must be 0..10000")
	}
	if restartCount < 0 || restartCount > nodes {
		return errors.New("-restart-count must be 0..nodes")
	}
	return nil
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hashFile(path string) string {
	if path == "" {
		return "unavailable"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "unavailable"
	}
	return hashHex(data)
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
