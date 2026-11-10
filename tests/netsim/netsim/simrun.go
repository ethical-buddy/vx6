// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vx6/vx6/internal/dht"
)

// SimRun owns the live simulation state.
type SimRun struct {
	t       *Topology
	r       *runner
	dir     string
	simnode string
	nodeDir string
	procs   map[string]*exec.Cmd
	hasFRR  bool
	cleaned bool
	// frrState is the run-specific FRR state directory (live runs only).
	frrState string
	frrAcct  frrAccount
	// BGPConverged is how long inter-AS routing took to converge.
	BGPConverged time.Duration
	// Measurement options (see SetMeasurement).
	lookupMode   string
	idle         time.Duration
	idleInterval time.Duration
	capacity     *CapacityPolicy
}

// SetMeasurement selects the lookup mode and the idle observation window.
func (s *SimRun) SetMeasurement(lookupMode string, idle, idleInterval time.Duration) {
	s.lookupMode, s.idle, s.idleInterval = lookupMode, idle, idleInterval
}

// effectiveLookupMode resolves "auto" against the topology size.
func (s *SimRun) effectiveLookupMode() string {
	switch s.lookupMode {
	case LookupModeExhaustive, LookupModeSample:
		return s.lookupMode
	}
	if len(s.t.Nodes) <= exhaustiveMaxNodes {
		return LookupModeExhaustive
	}
	return LookupModeSample
}

// bgpConvergeTimeout bounds the wait for inter-AS routes before nodes join.
var bgpConvergeTimeout = 90 * time.Second

func NewSimRun(t *Topology, r *runner, dir, simnode string) *SimRun {
	_, frrErr := exec.LookPath("bgpd")
	return &SimRun{t: t, r: r, dir: dir, simnode: simnode,
		nodeDir: filepath.Join(dir, "nodes"), procs: map[string]*exec.Cmd{},
		hasFRR: frrErr == nil}
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
		if !s.r.dry {
			acct, err := lookupFRRAccount()
			if err != nil {
				return err
			}
			state, err := prepareFRRRunState(s.t.RunID)
			if err != nil {
				return err
			}
			s.frrAcct, s.frrState = acct, state
		}
		for _, a := range s.t.ASes {
			if err := s.startBGP(a, nil); err != nil {
				return fmt.Errorf("bgp %s: %w", a.RouterNS, err)
			}
		}
		if !s.r.dry {
			took, err := waitBGPConverged(context.Background(), s.t, bgpConvergeTimeout)
			if err != nil {
				return err
			}
			s.BGPConverged = took
			fmt.Printf("BGP converged across %d ASes in %s\n", len(s.t.ASes), took.Round(time.Millisecond))
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
	// The copies above are evidence in the root-only run directory; the
	// daemons read their own copies from the per-router FRR state directory.
	if s.r.dry {
		state := filepath.Join(frrStateRoot, s.t.RunID, a.RouterNS)
		fmt.Printf("ip netns exec %s zebra %s\n", a.RouterNS, strings.Join(frrDaemonArgs(state, "zebra", filepath.Join(state, "zebra.conf")), " "))
		fmt.Printf("ip netns exec %s bgpd %s\n", a.RouterNS, strings.Join(frrDaemonArgs(state, "bgpd", filepath.Join(state, "bgpd.conf")), " "))
		return nil
	}
	state, err := prepareFRRRouterState(s.frrState, a.RouterNS, s.frrAcct, map[string]string{
		"zebra.conf": ZebraConf(a),
		"bgpd.conf":  BGPConf(s.t, a, hijack),
	})
	if err != nil {
		return fmt.Errorf("FRR state: %w", err)
	}
	if err := s.startManagedProcess(a.RouterNS, "zebra", frrDaemonArgs(state, "zebra", filepath.Join(state, "zebra.conf"))...); err != nil {
		return fmt.Errorf("zebra: %w", err)
	}
	if err := s.startManagedProcess(a.RouterNS, "bgpd", frrDaemonArgs(state, "bgpd", filepath.Join(state, "bgpd.conf"))...); err != nil {
		return fmt.Errorf("bgpd: %w", err)
	}
	return nil
}

func (s *SimRun) startManagedProcess(namespace, program string, args ...string) error {
	cmdArgs := append([]string{"netns", "exec", namespace, program}, args...)
	if s.r.log != nil {
		fmt.Fprintln(s.r.log, Cmd(append([]string{"ip"}, cmdArgs...)).String())
	}
	cmd := exec.Command("ip", cmdArgs...)
	logDir := filepath.Join(s.dir, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(logDir, namespace+"-"+program+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return err
	}
	_ = logFile.Close()
	key := namespace + "/" + program
	s.procs[key] = cmd
	if err := recordProcess(s.dir, namespace, program, cmd); err != nil {
		return err
	}
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
	recs := make([]json.RawMessage, 0, len(seeds))
	if !s.r.dry {
		for _, sd := range seeds {
			b, err := os.ReadFile(sd)
			if err != nil {
				return fmt.Errorf("read bootstrap record %s: %w", sd, err)
			}
			if !json.Valid(b) {
				return fmt.Errorf("bootstrap record %s is invalid JSON", sd)
			}
			recs = append(recs, json.RawMessage(b))
		}
	}
	data, err := json.Marshal(recs)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(nd, "seeds.json"), data, 0o600); err != nil {
		return err
	}
	return s.launchNode(n)
}

func (s *SimRun) launchNode(n Node) error {
	nd := filepath.Join(s.nodeDir, n.Name)
	args := []string{"netns", "exec", n.NS, s.simnode,
		"-name", n.Name, "-dir", nd, "-listen", n.Endpoint(), "-seeds", filepath.Join(nd, "seeds.json")}
	if s.r.dry {
		fmt.Printf("VX6_NETSIM_NO_IPSEC=I_UNDERSTAND ip %s\n", Cmd(args).String())
		return nil
	}
	cmd := exec.Command("ip", args...)
	if s.r.log != nil {
		fmt.Fprintln(s.r.log, Cmd(append([]string{"VX6_NETSIM_NO_IPSEC=I_UNDERSTAND", "ip"}, args...)).String())
	}
	cmd.Env = append(os.Environ(), "VX6_NETSIM_NO_IPSEC=I_UNDERSTAND")
	logFile, err := os.OpenFile(filepath.Join(nd, "simnode.out"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return err
	}
	_ = logFile.Close()
	key := n.NS + "/" + filepath.Base(s.simnode)
	s.procs[key] = cmd
	if err := recordProcess(s.dir, n.NS, s.simnode, cmd); err != nil {
		return err
	}
	return nil
}

func (s *SimRun) Cleanup() error {
	if s == nil || s.cleaned || s.r.dry {
		return nil
	}
	s.cleaned = true
	var cleanupErr error
	keys := make([]string, 0, len(s.procs))
	for key := range s.procs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := stopChild(s.procs[key], 4*time.Second); err != nil && cleanupErr == nil {
			cleanupErr = fmt.Errorf("stop %s: %w", key, err)
		}
	}
	if err := stopPersistedProcesses(filepath.Join(s.dir, "pids")); err != nil && cleanupErr == nil {
		cleanupErr = err
	}
	if err := deleteOwnedNamespaces(s.t, s.r); err != nil && cleanupErr == nil {
		cleanupErr = err
	}
	if err := removeFRRRunState(s.t.RunID); err != nil && cleanupErr == nil {
		cleanupErr = fmt.Errorf("remove FRR state: %w", err)
	}
	return cleanupErr
}

// adminGet calls a node's admin socket.
func (s *SimRun) adminGet(ctx context.Context, n Node, path string, v any) error {
	sock := filepath.Join(s.nodeDir, n.Name, "admin.sock")
	client := http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("admin API returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}

// Report is the simulation output.
type Report struct {
	SchemaVersion  int                `json:"schema_version"`
	RunID          string             `json:"run_id"`
	StartedAt      time.Time          `json:"started_at"`
	FinishedAt     time.Time          `json:"finished_at,omitempty"`
	BuildRevision  string             `json:"build_revision"`
	HostOS         string             `json:"host_os"`
	HostArch       string             `json:"host_arch"`
	GoVersion      string             `json:"go_version"`
	HostKernel     string             `json:"host_kernel,omitempty"`
	HostCPUModel   string             `json:"host_cpu_model,omitempty"`
	LogicalCPUs    int                `json:"logical_cpus"`
	TopologySHA256 string             `json:"topology_sha256"`
	SimnodeSHA256  string             `json:"simnode_sha256"`
	Params         Params             `json:"params"`
	SettleRounds   int                `json:"settle_rounds"`
	SettleGap      time.Duration      `json:"settle_gap_ns"`
	ProbesPerRound int                `json:"probes_per_round"`
	RestartCount   int                `json:"restart_count"`
	DryRun         bool               `json:"dry_run"`
	HostResources  HostResourceReport `json:"host_resources"`
	Totals         LookupStats        `json:"lookup_totals"`
	SnapshotTotal  int                `json:"snapshots_total"`
	SnapshotErrors int                `json:"snapshot_errors_total"`
	CleanupStatus  string             `json:"cleanup_status,omitempty"`
	BGPConvergedMS float64            `json:"bgp_converged_ms,omitempty"`
	// LookupMode is exhaustive (every ordered pair, by ID and name) or sample.
	LookupMode string `json:"lookup_mode"`
	// Capacity is the routing-table capacity policy reported by the nodes.
	Capacity *CapacityPolicy `json:"dht_capacity_policy,omitempty"`
	// Idle holds the post-measurement idle captures (no lookups).
	Idle         []IdleSample  `json:"idle,omitempty"`
	IdleDuration time.Duration `json:"idle_duration_ns,omitempty"`
	// Verdict is PASS, FAIL or PREVIEW (dry run). A FAIL makes `run` exit
	// non-zero so a broken fabric cannot produce a green run.
	Verdict        string          `json:"verdict"`
	VerdictReasons []string        `json:"verdict_reasons,omitempty"`
	Restarts       []RestartReport `json:"restarts,omitempty"`
	Rounds         []RoundReport   `json:"rounds"`
}

type HostResourceReport struct {
	StartMemoryTotalKB       uint64  `json:"start_memory_total_kb,omitempty"`
	StartMemoryAvailableKB   uint64  `json:"start_memory_available_kb,omitempty"`
	EndMemoryTotalKB         uint64  `json:"end_memory_total_kb,omitempty"`
	EndMemoryAvailableKB     uint64  `json:"end_memory_available_kb,omitempty"`
	HostCPUUtilizationPct    float64 `json:"host_cpu_utilization_pct,omitempty"`
	SimnodeCPUTimeMS         uint64  `json:"simnode_cpu_time_ms,omitempty"`
	CPUStatsAvailable        bool    `json:"cpu_stats_available"`
	MemoryStatsAvailable     bool    `json:"memory_stats_available"`
	SimnodeCPUStatsAvailable bool    `json:"simnode_cpu_stats_available"`
}

type RestartReport struct {
	NodeName              string   `json:"node_name"`
	NodeID                string   `json:"node_id"`
	IdentityStable        bool     `json:"identity_stable"`
	ActivePeersBefore     int      `json:"active_peers_before"`
	ActivePeersAfter      int      `json:"active_peers_after"`
	PersistedCandidateIDs []string `json:"persisted_candidate_ids"`
	RestoredCandidateIDs  []string `json:"restored_candidate_ids"`
	PersistenceVerified   bool     `json:"persistence_verified"`
	Error                 string   `json:"error,omitempty"`
}

type RoundReport struct {
	Label              string              `json:"label"`
	Time               time.Time           `json:"time"`
	NodesJoined        int                 `json:"nodes_joined"`
	SnapshotsOK        int                 `json:"snapshots_ok"`
	SnapshotErrors     int                 `json:"snapshot_errors"`
	SnapshotErrorNodes []string            `json:"snapshot_error_nodes,omitempty"`
	LookupPolicy       *LookupPolicy       `json:"lookup_policy,omitempty"`
	AvgActivePeers     float64             `json:"avg_active_peers"`
	MinActivePeers     int                 `json:"min_active_peers"`
	MaxActivePeers     int                 `json:"max_active_peers"`
	AvgRSSKB           float64             `json:"avg_rss_kb"`
	MinRSSKB           int                 `json:"min_rss_kb"`
	MaxRSSKB           int                 `json:"max_rss_kb"`
	TotalRSSKB         int                 `json:"total_rss_kb"`
	Diversity          RouteDiversityStats `json:"route_diversity"`
	JoinDurationMS     float64             `json:"join_duration_ms"`
	RoundDurationMS    float64             `json:"round_duration_ms"`
	Lookups            LookupStats         `json:"lookups"`
	Probes             []LookupReport      `json:"probes"`
	// Nodes summarizes every node's diagnostics at this round; the full
	// documents are in diagnostics/<label>/.
	Nodes []NodeRoundSummary `json:"nodes,omitempty"`
}

type RouteDiversityStats struct {
	Tables                      int     `json:"tables_sampled"`
	AvgUniqueASNsPerTable       float64 `json:"avg_unique_asns_per_table"`
	MinUniqueASNsPerTable       int     `json:"min_unique_asns_per_table"`
	MaxUniqueASNsPerTable       int     `json:"max_unique_asns_per_table"`
	MaxPeersFromOneASN          int     `json:"max_peers_from_one_asn"`
	MaxPeersFromOneIPv6Prefix48 int     `json:"max_peers_from_one_ipv6_prefix_48"`
}

type LookupStats struct {
	Attempts     int     `json:"attempts"`
	N            int     `json:"n"`
	Found        int     `json:"found_verified"`
	NotFound     int     `json:"not_found_reachable"`
	Missed       int     `json:"expected_target_not_returned"`
	Errors       int     `json:"request_errors"`
	LookupErrors int     `json:"lookup_errors"`
	Other        int     `json:"incomplete_or_conflict"`
	FoundRatePct float64 `json:"found_rate_pct"`
	P50ms        float64 `json:"p50_ms"`
	P95ms        float64 `json:"p95_ms"`
	P99ms        float64 `json:"p99_ms"`
	AvgRound     float64 `json:"avg_rounds"`
	AvgQueries   float64 `json:"avg_peer_queries"`
	P50Queries   int     `json:"p50_peer_queries"`
	P95Queries   int     `json:"p95_peer_queries"`
	P50Rounds    float64 `json:"p50_lookup_rounds"`
	P95Rounds    float64 `json:"p95_lookup_rounds"`
}

// DriveWaves joins each wave, then snapshots until settle rounds are done.
func (s *SimRun) DriveWaves(ctx context.Context, settleRounds int, gap time.Duration, probes, restartCount int) (*Report, error) {
	rep := &Report{SchemaVersion: 1, RunID: s.t.RunID, Params: s.t.Params}
	rng := rand.New(rand.NewSource(s.t.Params.Seed + 1))
	joined := make([]Node, 0, len(s.t.Nodes))
	byIndex := make(map[int]Node, len(s.t.Nodes))
	for _, n := range s.t.Nodes {
		byIndex[n.Index] = n
	}
	endpointPath := func(n Node) string { return filepath.Join(s.nodeDir, n.Name, "endpoint.json") }

	for w, wave := range s.t.Waves {
		waveStarted := time.Now()
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
			if err := s.waitEndpoints(ctx, wave, byIndex, 20*time.Second); err != nil {
				return rep, err
			}
		}
		joinDurationMS := float64(time.Since(waveStarted).Microseconds()) / 1000
		rr, err := s.snapshotRound(ctx, fmt.Sprintf("after-wave-%d", w), joined, probes, rng)
		if err != nil {
			return rep, err
		}
		rr.JoinDurationMS = joinDurationMS
		rep.Rounds = append(rep.Rounds, rr)
		if err := s.writeRound(w, rr); err != nil {
			return rep, err
		}
	}
	if restartCount > len(joined) {
		restartCount = len(joined)
	}
	if !s.r.dry {
		type peerScore struct {
			node   Node
			active int
		}
		scores := make([]peerScore, 0, len(joined))
		for _, node := range joined {
			var snapshot Snapshot
			if err := s.adminGet(ctx, node, "/snapshot", &snapshot); err != nil {
				return rep, fmt.Errorf("snapshot before restart of %s: %w", node.Name, err)
			}
			scores = append(scores, peerScore{node: node, active: snapshot.Active})
		}
		sort.Slice(scores, func(i, j int) bool {
			if scores[i].active != scores[j].active {
				return scores[i].active > scores[j].active
			}
			return scores[i].node.Name < scores[j].node.Name
		})
		for _, score := range scores[:restartCount] {
			evidence, err := s.restartNode(ctx, score.node)
			rep.Restarts = append(rep.Restarts, evidence)
			if err != nil {
				return rep, err
			}
		}
	}
	for i := 0; i < settleRounds; i++ {
		if !s.r.dry {
			select {
			case <-ctx.Done():
				return rep, ctx.Err()
			case <-time.After(gap):
			}
		}
		rr, err := s.snapshotRound(ctx, fmt.Sprintf("settle-%d", i), joined, probes, rng)
		if err != nil {
			return rep, err
		}
		rep.Rounds = append(rep.Rounds, rr)
		if err := s.writeRound(len(s.t.Waves)+i, rr); err != nil {
			return rep, err
		}
	}
	idle, err := s.runIdle(ctx, joined, s.idle, s.idleInterval)
	rep.Idle = idle
	if err != nil {
		return rep, fmt.Errorf("idle observation: %w", err)
	}
	return rep, nil
}

func (s *SimRun) restartNode(ctx context.Context, node Node) (RestartReport, error) {
	evidence := RestartReport{NodeName: node.Name}
	var before Snapshot
	if err := s.adminGet(ctx, node, "/snapshot", &before); err != nil {
		evidence.Error = err.Error()
		return evidence, err
	}
	evidence.NodeID = before.NodeID
	evidence.ActivePeersBefore = before.Active
	if _, err := s.captureDiagnostics(ctx, "restart-before-"+node.Name, []Node{node}); err != nil {
		evidence.Error = err.Error()
		return evidence, err
	}
	key := node.NS + "/" + filepath.Base(s.simnode)
	process, ok := s.procs[key]
	if !ok {
		err := fmt.Errorf("no running simnode process recorded for %s", node.Name)
		evidence.Error = err.Error()
		return evidence, err
	}
	if err := stopChild(process, 8*time.Second); err != nil {
		evidence.Error = err.Error()
		return evidence, err
	}
	delete(s.procs, key)
	_ = os.Remove(filepath.Join(s.dir, "pids", node.NS+"-"+filepath.Base(s.simnode)+".json"))

	store, err := dht.OpenPeerStore(filepath.Join(s.nodeDir, node.Name, "data", "dht-peers.db"))
	if err != nil {
		evidence.Error = err.Error()
		return evidence, err
	}
	candidates, loadErr := store.LoadCandidates(time.Now(), 512)
	closeErr := store.Close()
	if loadErr != nil {
		evidence.Error = loadErr.Error()
		return evidence, loadErr
	}
	if closeErr != nil {
		evidence.Error = closeErr.Error()
		return evidence, closeErr
	}
	for _, candidate := range candidates {
		evidence.PersistedCandidateIDs = append(evidence.PersistedCandidateIDs, candidate.Node.ID)
	}
	sort.Strings(evidence.PersistedCandidateIDs)
	if err := s.launchNode(node); err != nil {
		evidence.Error = err.Error()
		return evidence, err
	}
	if _, err := s.waitNodeReady(ctx, node, 20*time.Second); err != nil {
		evidence.Error = err.Error()
		return evidence, err
	}
	var after Snapshot
	if err := s.adminGet(ctx, node, "/snapshot", &after); err != nil {
		evidence.Error = err.Error()
		return evidence, err
	}
	evidence.ActivePeersAfter = after.Active
	if _, err := s.captureDiagnostics(ctx, "restart-after-"+node.Name, []Node{node}); err != nil {
		evidence.Error = err.Error()
		return evidence, err
	}
	evidence.IdentityStable = before.NodeID != "" && before.NodeID == after.NodeID && before.NameHash == after.NameHash
	active := make(map[string]struct{}, len(after.Peers))
	for _, peer := range after.Peers {
		active[peer.ID] = struct{}{}
	}
	for _, id := range evidence.PersistedCandidateIDs {
		if _, found := active[id]; found {
			evidence.RestoredCandidateIDs = append(evidence.RestoredCandidateIDs, id)
		}
	}
	evidence.PersistenceVerified = len(evidence.PersistedCandidateIDs) > 0 && len(evidence.RestoredCandidateIDs) > 0
	if !evidence.IdentityStable {
		err := errors.New("identity changed across restart")
		evidence.Error = err.Error()
		return evidence, err
	}
	if before.Active > 0 && len(evidence.PersistedCandidateIDs) == 0 {
		err := errors.New("graceful shutdown did not persist any DHT peer candidates")
		evidence.Error = err.Error()
		return evidence, err
	}
	if len(evidence.PersistedCandidateIDs) > 0 && len(evidence.RestoredCandidateIDs) == 0 {
		err := errors.New("no persisted DHT peer candidate appeared in the restarted routing snapshot")
		evidence.Error = err.Error()
		return evidence, err
	}
	return evidence, nil
}

func (s *SimRun) waitEndpoints(ctx context.Context, wave []int, byIndex map[int]Node, timeout time.Duration) error {
	var missing []string
	for _, idx := range wave {
		n := byIndex[idx]
		if _, err := s.waitNodeReady(ctx, n, timeout); err != nil {
			missing = append(missing, n.Name+" ("+err.Error()+")")
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("admin API did not become ready for nodes: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (s *SimRun) waitNodeReady(ctx context.Context, node Node, timeout time.Duration) (Snapshot, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		probeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		var status Snapshot
		err := s.adminGet(probeCtx, node, "/status", &status)
		cancel()
		if err == nil && status.Name == node.Name && status.NodeID != "" && status.NameHash != "" {
			return status, nil
		}
		if ctx.Err() != nil {
			return Snapshot{}, ctx.Err()
		}
		time.Sleep(100 * time.Millisecond)
	}
	return Snapshot{}, fmt.Errorf("admin API did not become ready within %s", timeout)
}

func (s *SimRun) snapshotRound(ctx context.Context, label string, joined []Node, probes int, rng *rand.Rand) (RoundReport, error) {
	started := time.Now()
	rr := RoundReport{Label: label, Time: time.Now().UTC(), NodesJoined: len(joined)}
	if s.r.dry {
		rr.RoundDurationMS = float64(time.Since(started).Microseconds()) / 1000
		return rr, nil
	}
	var totalActive, minA, maxA, n int
	var totalRSS float64
	var totalUniqueASNs int
	minUniqueASNs := -1
	addressASN := make(map[string]uint32, len(s.t.Nodes))
	for _, node := range s.t.Nodes {
		if addr, err := netip.ParseAddr(node.Addr); err == nil {
			addressASN[addr.String()] = node.ASN
		}
	}
	snapDir := filepath.Join(s.dir, "snapshots", label)
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		return rr, err
	}
	for _, nd := range joined {
		var snap Snapshot
		if err := s.adminGet(ctx, nd, "/snapshot", &snap); err != nil {
			rr.SnapshotErrors++
			rr.SnapshotErrorNodes = append(rr.SnapshotErrorNodes, nd.Name)
			continue
		}
		for peerIndex := range snap.Peers {
			host, _, splitErr := net.SplitHostPort(snap.Peers[peerIndex].Addr)
			if splitErr != nil {
				continue
			}
			addr, parseErr := netip.ParseAddr(host)
			if parseErr != nil || !addr.Is6() {
				continue
			}
			if asn, ok := addressASN[addr.String()]; ok {
				snap.Peers[peerIndex].ASN = asn
			}
			snap.Peers[peerIndex].Prefix48 = netip.PrefixFrom(addr, 48).Masked().String()
		}
		rr.SnapshotsOK++
		if rr.LookupPolicy == nil {
			policy := snap.Lookup
			rr.LookupPolicy = &policy
		}
		data, err := json.MarshalIndent(snap, "", "  ")
		if err != nil {
			return rr, err
		}
		if err := os.WriteFile(filepath.Join(snapDir, nd.Name+".json"), data, 0o600); err != nil {
			return rr, err
		}
		if n == 0 || snap.Active < minA {
			minA = snap.Active
		}
		if snap.Active > maxA {
			maxA = snap.Active
		}
		totalActive += snap.Active
		totalRSS += float64(snap.RSSKB)
		rr.TotalRSSKB += snap.RSSKB
		if n == 0 || snap.RSSKB < rr.MinRSSKB {
			rr.MinRSSKB = snap.RSSKB
		}
		if snap.RSSKB > rr.MaxRSSKB {
			rr.MaxRSSKB = snap.RSSKB
		}
		n++
		uniqueASNs, maxASN, maxPrefix := routeDiversity(snap.Peers)
		totalUniqueASNs += uniqueASNs
		if minUniqueASNs < 0 || uniqueASNs < minUniqueASNs {
			minUniqueASNs = uniqueASNs
		}
		if uniqueASNs > rr.Diversity.MaxUniqueASNsPerTable {
			rr.Diversity.MaxUniqueASNsPerTable = uniqueASNs
		}
		if maxASN > rr.Diversity.MaxPeersFromOneASN {
			rr.Diversity.MaxPeersFromOneASN = maxASN
		}
		if maxPrefix > rr.Diversity.MaxPeersFromOneIPv6Prefix48 {
			rr.Diversity.MaxPeersFromOneIPv6Prefix48 = maxPrefix
		}
	}
	if n > 0 {
		rr.AvgActivePeers = float64(totalActive) / float64(n)
		rr.AvgRSSKB = totalRSS / float64(n)
		rr.MinActivePeers, rr.MaxActivePeers = minA, maxA
		rr.Diversity.Tables = n
		rr.Diversity.AvgUniqueASNsPerTable = float64(totalUniqueASNs) / float64(n)
		rr.Diversity.MinUniqueASNsPerTable = minUniqueASNs
	}
	nodes, err := s.captureDiagnostics(ctx, label, joined)
	if err != nil {
		return rr, err
	}
	for _, node := range nodes {
		if node.capacityCaptured && s.capacity == nil {
			policy := node.capacity
			s.capacity = &policy
		}
	}
	var reports []LookupReport
	if s.effectiveLookupMode() == LookupModeExhaustive {
		reports = s.exhaustiveLookups(ctx, joined)
		rr.Lookups = lookupStatsFromReports(reports)
	} else {
		rr.Lookups, reports = s.runProbes(ctx, joined, probes, rng)
	}
	attachSourceStats(nodes, reports)
	rr.Nodes = sortedSummaries(nodes)
	rr.Probes, err = s.writeLookupTraces(label, reports)
	if err != nil {
		return rr, err
	}
	rr.RoundDurationMS = float64(time.Since(started).Microseconds()) / 1000
	return rr, nil
}

// runProbes asks random source nodes to resolve random (existing) target IDs.
func (s *SimRun) runProbes(ctx context.Context, joined []Node, probes int, rng *rand.Rand) (LookupStats, []LookupReport) {
	var reports []LookupReport
	if len(joined) < 2 {
		return LookupStats{}, reports
	}
	var reportsForStats []LookupReport
	for i := 0; i < probes; i++ {
		if err := ctx.Err(); err != nil {
			break
		}
		src := joined[rng.Intn(len(joined))]
		dst := joined[rng.Intn(len(joined))]
		if dst.Index == src.Index {
			continue
		}
		var target struct {
			NodeID string `json:"node_id"`
			Name   string `json:"name"`
		}
		statusCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		statusErr := s.adminGet(statusCtx, dst, "/status", &target)
		cancel()
		if statusErr != nil || target.NodeID == "" || target.Name == "" {
			reports = append(reports,
				LookupReport{Source: src.Name, TargetType: "id", Outcome: "admin_error", Error: fmt.Sprint(statusErr)},
				LookupReport{Source: src.Name, TargetType: "name", Outcome: "admin_error", Error: fmt.Sprint(statusErr)})
			reportsForStats = append(reportsForStats, reports[len(reports)-2:]...)
			continue
		}
		for _, query := range []struct{ kind, value string }{{"id", target.NodeID}, {"name", target.Name}} {
			var rep LookupReport
			path := "/lookup?type=" + query.kind + "&target=" + url.QueryEscape(query.value) + "&timeout_s=10"
			if err := s.adminGet(ctx, src, path, &rep); err != nil {
				rep = LookupReport{Source: src.Name, TargetType: query.kind, Outcome: "admin_error", Error: err.Error()}
			}
			rep.Source = src.Name
			rep.ExpectedNodeID = target.NodeID
			reports = append(reports, rep)
			reportsForStats = append(reportsForStats, rep)
		}
	}
	st := lookupStatsFromReports(reportsForStats)
	return st, reports
}

func (s *SimRun) writeRound(i int, rr RoundReport) error {
	data, err := json.MarshalIndent(rr, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, fmt.Sprintf("round-%02d.json", i)), data, 0o600)
}

func lookupStatsFromReports(reports []LookupReport) LookupStats {
	stats := LookupStats{Attempts: len(reports)}
	var latencies, rounds []float64
	var queries []int
	for _, result := range reports {
		if result.Outcome == "admin_error" {
			stats.Errors++
			continue
		}
		stats.N++
		if result.Error != "" {
			stats.LookupErrors++
		}
		if result.Found {
			stats.Found++
		} else {
			stats.Missed++
			switch result.Outcome {
			case "not_found_reachable":
				stats.NotFound++
			default:
				stats.Other++
			}
		}
		latencies = append(latencies, result.LatencyMS)
		rounds = append(rounds, float64(result.Rounds))
		queries = append(queries, result.Queried)
	}
	if stats.N > 0 {
		stats.FoundRatePct = float64(stats.Found) * 100 / float64(stats.N)
	}
	sort.Float64s(latencies)
	sort.Float64s(rounds)
	sort.Ints(queries)
	if len(latencies) > 0 {
		stats.P50ms = percentileFloat(latencies, 50)
		stats.P95ms = percentileFloat(latencies, 95)
		stats.P99ms = percentileFloat(latencies, 99)
		stats.P50Rounds = percentileFloat(rounds, 50)
		stats.P95Rounds = percentileFloat(rounds, 95)
		for _, value := range rounds {
			stats.AvgRound += value
		}
		stats.AvgRound /= float64(len(rounds))
		for _, value := range queries {
			stats.AvgQueries += float64(value)
		}
		stats.AvgQueries /= float64(len(queries))
		stats.P50Queries = percentileInt(queries, 50)
		stats.P95Queries = percentileInt(queries, 95)
	}
	return stats
}

func routeDiversity(peers []PeerView) (uniqueASNs, maxPerASN, maxPerPrefix int) {
	byASN := make(map[uint32]int)
	byPrefix := make(map[string]int)
	for _, peer := range peers {
		if peer.ASN != 0 {
			byASN[peer.ASN]++
		}
		if peer.Prefix48 != "" {
			byPrefix[peer.Prefix48]++
		}
	}
	uniqueASNs = len(byASN)
	for _, count := range byASN {
		if count > maxPerASN {
			maxPerASN = count
		}
	}
	for _, count := range byPrefix {
		if count > maxPerPrefix {
			maxPerPrefix = count
		}
	}
	return uniqueASNs, maxPerASN, maxPerPrefix
}

func percentileIndex(length, percentile int) int {
	if length <= 1 {
		return 0
	}
	index := (length*percentile+99)/100 - 1
	return min(length-1, max(0, index))
}

func percentileFloat(values []float64, percentile int) float64 {
	if len(values) == 0 {
		return 0
	}
	return values[percentileIndex(len(values), percentile)]
}

func percentileInt(values []int, percentile int) int {
	if len(values) == 0 {
		return 0
	}
	return values[percentileIndex(len(values), percentile)]
}

func finalizeReport(report *Report) {
	var probes []LookupReport
	for _, round := range report.Rounds {
		report.SnapshotTotal += round.SnapshotsOK
		report.SnapshotErrors += round.SnapshotErrors
		probes = append(probes, round.Probes...)
	}
	report.Totals = lookupStatsFromReports(probes)
	report.Verdict, report.VerdictReasons = runVerdict(report)
}

// runVerdict judges a live run.
//
// Exhaustive mode (small stable meshes): PASS only if every known-target
// lookup in the final measurement round found its target; anything else is
// FAIL, with incomplete (transport/time budget) and not-found counted apart.
// Sample mode: the result is MEASURED, never PASS, because a sampled hit rate
// is not a readiness claim; it is FAIL only when the DHT clearly never worked.
func runVerdict(report *Report) (string, []string) {
	if report.DryRun {
		return "PREVIEW", nil
	}
	var reasons []string
	if len(report.Rounds) == 0 {
		return "FAIL", []string{"no measurement rounds completed"}
	}
	last := report.Rounds[len(report.Rounds)-1]
	if last.NodesJoined > 1 && last.SnapshotsOK > 0 && last.MaxActivePeers == 0 {
		reasons = append(reasons, fmt.Sprintf("no node had an active DHT peer in the final round (%s)", last.Label))
	}
	if report.LookupMode == LookupModeExhaustive {
		l := last.Lookups
		if l.Attempts == 0 {
			reasons = append(reasons, fmt.Sprintf("no exhaustive lookups ran in the final round (%s)", last.Label))
		} else if l.Found != l.Attempts {
			reasons = append(reasons, fmt.Sprintf("final round %s found %d of %d known targets (not found among reachable peers %d, incomplete/conflict %d, admin request errors %d); exhaustive small-mesh lookups require 100%%",
				last.Label, l.Found, l.Attempts, l.NotFound, l.Other, l.Errors))
		}
		if len(reasons) > 0 {
			return "FAIL", reasons
		}
		return "PASS", nil
	}
	if report.Totals.Attempts > 0 && report.Totals.Found == 0 {
		reasons = append(reasons, fmt.Sprintf("no lookup found its known-existing target (0 of %d attempts)", report.Totals.Attempts))
	}
	if len(reasons) > 0 {
		return "FAIL", reasons
	}
	return "MEASURED", []string{"sampled lookups: see found/incomplete/not-found denominators; a nonzero hit rate is not a readiness verdict"}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
