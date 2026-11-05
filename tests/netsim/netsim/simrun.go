// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

// SimRun owns the live simulation state.
type SimRun struct {
	t       *Topology
	r       *runner
	dir     string
	simnode string
	nodeDir string
	procs   map[int]*exec.Cmd // node index -> simnode process
	bgps    map[int]*exec.Cmd // AS index -> bgpd process (unused in dry-run)
	hasFRR  bool
}

func NewSimRun(t *Topology, r *runner, dir, simnode string) *SimRun {
	_, frrErr := exec.LookPath("bgpd")
	return &SimRun{t: t, r: r, dir: dir, simnode: simnode,
		nodeDir: filepath.Join(dir, "nodes"), procs: map[int]*exec.Cmd{},
		bgps: map[int]*exec.Cmd{}, hasFRR: frrErr == nil}
}

// BuildFabric creates routers, links, bridges and starts BGP.
func (s *SimRun) BuildFabric() error {
	if err := os.MkdirAll(s.nodeDir, 0o755); err != nil {
		return err
	}
	data, _ := json.Marshal(s.t)
	if err := os.WriteFile(filepath.Join(s.dir, "topology.json"), data, 0o644); err != nil {
		return err
	}
	for _, c := range RouterCmds(s.t) {
		if err := s.r.run(c); err != nil {
			return err
		}
	}
	if s.hasFRR || s.r.dry {
		for _, a := range s.t.ASes {
			if err := s.startBGP(a, nil); err != nil {
				return fmt.Errorf("bgp %s: %w", a.RouterNS, err)
			}
		}
	} else {
		fmt.Fprintln(os.Stderr, "warning: FRR not installed; inter-AS routing is absent, only same-AS lookups will work")
	}
	return nil
}

// startBGP writes an FRR config and launches bgpd/zebra in the AS namespace.
func (s *SimRun) startBGP(a *AS, hijack []string) error {
	cfgDir := filepath.Join(s.dir, "frr", a.RouterNS)
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		return err
	}
	zebra := filepath.Join(cfgDir, "zebra.conf")
	bgp := filepath.Join(cfgDir, "bgpd.conf")
	if err := os.WriteFile(zebra, []byte(ZebraConf(a)), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(bgp, []byte(BGPConf(s.t, a, hijack)), 0o644); err != nil {
		return err
	}
	if s.r.dry {
		fmt.Printf("ip netns exec %s zebra -d -f %s -i %s/zebra.pid -z %s/zserv.api\n", a.RouterNS, zebra, cfgDir, cfgDir)
		fmt.Printf("ip netns exec %s bgpd  -d -f %s -i %s/bgpd.pid  -z %s/zserv.api\n", a.RouterNS, bgp, cfgDir, cfgDir)
		return nil
	}
	zcmd := exec.Command("ip", "netns", "exec", a.RouterNS, "zebra", "-d", "-f", zebra,
		"-i", filepath.Join(cfgDir, "zebra.pid"), "-z", filepath.Join(cfgDir, "zserv.api"))
	if out, err := zcmd.CombinedOutput(); err != nil {
		return fmt.Errorf("zebra: %w: %s", err, out)
	}
	bcmd := exec.Command("ip", "netns", "exec", a.RouterNS, "bgpd", "-d", "-f", bgp,
		"-i", filepath.Join(cfgDir, "bgpd.pid"), "-z", filepath.Join(cfgDir, "zserv.api"))
	if out, err := bcmd.CombinedOutput(); err != nil {
		return fmt.Errorf("bgpd: %w: %s", err, out)
	}
	s.bgps[a.Index] = bcmd
	return nil
}

// startNode brings up a node namespace and launches simnode with signed seeds.
func (s *SimRun) startNode(n Node, seeds []string) error {
	for _, c := range NodeNetCmds(s.t, n) {
		if err := s.r.run(c); err != nil {
			return err
		}
	}
	nd := filepath.Join(s.nodeDir, n.Name)
	if err := os.MkdirAll(nd, 0o700); err != nil {
		return err
	}
	if len(seeds) > 0 {
		recs := make([]json.RawMessage, 0, len(seeds))
		for _, sd := range seeds {
			if b, err := os.ReadFile(sd); err == nil {
				recs = append(recs, json.RawMessage(b))
			}
		}
		data, _ := json.Marshal(recs)
		_ = os.WriteFile(filepath.Join(nd, "seeds.json"), data, 0o600)
	}
	args := []string{"netns", "exec", n.NS, s.simnode,
		"-name", n.Name, "-dir", nd, "-listen", n.Endpoint(), "-seeds", filepath.Join(nd, "seeds.json")}
	if s.r.dry {
		fmt.Printf("VX6_NETSIM_NO_IPSEC=I_UNDERSTAND ip %s\n", Cmd(args).String())
		return nil
	}
	cmd := exec.Command("ip", args...)
	cmd.Env = append(os.Environ(), "VX6_NETSIM_NO_IPSEC=I_UNDERSTAND")
	logFile, err := os.Create(filepath.Join(nd, "simnode.out"))
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		return err
	}
	s.procs[n.Index] = cmd
	return nil
}

// adminGet calls a node's admin socket.
func (s *SimRun) adminGet(n Node, path string, v any) error {
	sock := filepath.Join(s.nodeDir, n.Name, "admin.sock")
	client := http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
	resp, err := client.Get("http://unix" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

// Report is the simulation output.
type Report struct {
	Params Params        `json:"params"`
	Rounds []RoundReport `json:"rounds"`
}

type RoundReport struct {
	Label          string         `json:"label"`
	Time           time.Time      `json:"time"`
	NodesJoined    int            `json:"nodes_joined"`
	AvgActivePeers float64        `json:"avg_active_peers"`
	MinActivePeers int            `json:"min_active_peers"`
	MaxActivePeers int            `json:"max_active_peers"`
	AvgRSSKB       float64        `json:"avg_rss_kb"`
	Lookups        LookupStats    `json:"lookups"`
	Probes         []LookupReport `json:"-"`
}

type LookupStats struct {
	N        int     `json:"n"`
	Found    int     `json:"found_verified"`
	NotFound int     `json:"not_found_reachable"`
	Other    int     `json:"incomplete_or_conflict"`
	P50ms    float64 `json:"p50_ms"`
	P95ms    float64 `json:"p95_ms"`
	AvgRound float64 `json:"avg_rounds"`
}

// DriveWaves joins each wave, then snapshots until settle rounds are done.
func (s *SimRun) DriveWaves(ctx context.Context, settleRounds int, gap time.Duration, probes int) (*Report, error) {
	rep := &Report{Params: s.t.Params}
	rng := rand.New(rand.NewSource(s.t.Params.Seed + 1))
	joined := make([]Node, 0, len(s.t.Nodes))
	byIndex := make(map[int]Node, len(s.t.Nodes))
	for _, n := range s.t.Nodes {
		byIndex[n.Index] = n
	}
	endpointPath := func(n Node) string { return filepath.Join(s.nodeDir, n.Name, "endpoint.json") }

	for w, wave := range s.t.Waves {
		for _, idx := range wave {
			n := byIndex[idx]
			var seeds []string
			if len(joined) > 0 {
				perm := rng.Perm(len(joined))
				for i := 0; i < s.t.Params.Seeds && i < len(joined); i++ {
					seeds = append(seeds, endpointPath(joined[perm[i]]))
				}
			}
			if err := s.startNode(n, seeds); err != nil {
				return rep, fmt.Errorf("start node %s: %w", n.Name, err)
			}
			joined = append(joined, n)
		}
		if !s.r.dry {
			s.waitEndpoints(wave, byIndex, 10*time.Second)
		}
		rr := s.snapshotRound(ctx, fmt.Sprintf("after-wave-%d", w), joined, probes, rng)
		rep.Rounds = append(rep.Rounds, rr)
		s.writeRound(w, rr)
	}
	for i := 0; i < settleRounds; i++ {
		if !s.r.dry {
			select {
			case <-ctx.Done():
				return rep, ctx.Err()
			case <-time.After(gap):
			}
		}
		rr := s.snapshotRound(ctx, fmt.Sprintf("settle-%d", i), joined, probes, rng)
		rep.Rounds = append(rep.Rounds, rr)
		s.writeRound(len(s.t.Waves)+i, rr)
	}
	return rep, nil
}

func (s *SimRun) waitEndpoints(wave []int, byIndex map[int]Node, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for _, idx := range wave {
		n := byIndex[idx]
		p := filepath.Join(s.nodeDir, n.Name, "admin.sock")
		for time.Now().Before(deadline) {
			if _, err := os.Stat(p); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func (s *SimRun) snapshotRound(ctx context.Context, label string, joined []Node, probes int, rng *rand.Rand) RoundReport {
	rr := RoundReport{Label: label, Time: time.Now().UTC(), NodesJoined: len(joined)}
	if s.r.dry {
		return rr
	}
	var totalActive, minA, maxA, n int
	var totalRSS float64
	snapDir := filepath.Join(s.dir, "snapshots", label)
	_ = os.MkdirAll(snapDir, 0o755)
	for _, nd := range joined {
		var snap Snapshot
		if err := s.adminGet(nd, "/snapshot", &snap); err != nil {
			continue
		}
		data, _ := json.Marshal(snap)
		_ = os.WriteFile(filepath.Join(snapDir, nd.Name+".json"), data, 0o644)
		if n == 0 || snap.Active < minA {
			minA = snap.Active
		}
		if snap.Active > maxA {
			maxA = snap.Active
		}
		totalActive += snap.Active
		totalRSS += float64(snap.RSSKB)
		n++
	}
	if n > 0 {
		rr.AvgActivePeers = float64(totalActive) / float64(n)
		rr.AvgRSSKB = totalRSS / float64(n)
		rr.MinActivePeers, rr.MaxActivePeers = minA, maxA
	}
	rr.Lookups = s.runProbes(ctx, joined, probes, rng)
	return rr
}

// runProbes asks random source nodes to resolve random (existing) target IDs.
func (s *SimRun) runProbes(ctx context.Context, joined []Node, probes int, rng *rand.Rand) LookupStats {
	var st LookupStats
	if len(joined) < 2 {
		return st
	}
	var lat []float64
	var rounds float64
	for i := 0; i < probes; i++ {
		src := joined[rng.Intn(len(joined))]
		dst := joined[rng.Intn(len(joined))]
		if dst.Index == src.Index {
			continue
		}
		var target struct {
			NodeID string `json:"node_id"`
		}
		if err := s.adminGet(dst, "/status", &target); err != nil || target.NodeID == "" {
			continue
		}
		var rep LookupReport
		if err := s.adminGet(src, "/lookup?target="+target.NodeID+"&timeout_s=30", &rep); err != nil {
			continue
		}
		st.N++
		switch rep.Outcome {
		case "found_verified":
			st.Found++
		case "not_found_reachable":
			st.NotFound++
		default:
			st.Other++
		}
		lat = append(lat, rep.LatencyMS)
		rounds += float64(rep.Rounds)
	}
	if len(lat) > 0 {
		sort.Float64s(lat)
		st.P50ms = lat[len(lat)*50/100]
		st.P95ms = lat[min(len(lat)-1, len(lat)*95/100)]
		st.AvgRound = rounds / float64(len(lat))
	}
	return st
}

func (s *SimRun) writeRound(i int, rr RoundReport) {
	data, _ := json.MarshalIndent(rr, "", "  ")
	_ = os.WriteFile(filepath.Join(s.dir, fmt.Sprintf("round-%02d.json", i)), data, 0o644)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
