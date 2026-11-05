// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

// simnode runs the real VX6 node (node.Run with the real DHT, registry,
// signed records and liveness code) for the #69 network simulation. It replaces
// only the IPsec tunnel provider with the same pass-through used by
// internal/integration: peers must still present valid signed endpoint
// records, but no IKE/ESP is negotiated. That lets thousands of nodes share one
// machine for DHT-scale tests. ESP/IKE security is tested separately by the
// simulator's "ipsec" tier, which runs the real vx6 + vx6-ipsecd + charon.
//
// THIS BINARY MUST NEVER RUN OUTSIDE THE LAB. It refuses to start unless:
//   - VX6_NETSIM_NO_IPSEC=I_UNDERSTAND is set, and
//   - its listen address is inside 2001:db8::/32 (documentation) or fc00::/7 (ULA).
//
// Usage (inside a node's network namespace):
//
//	simnode -name amber-falcon -dir /var/lib/vx6sim/nodes/amber-falcon \
//	        -listen '[2001:db8:1:1::10]:4242' -seeds seeds.json
//
// Admin API (HTTP over a Unix socket at <dir>/admin.sock):
//
//	GET  /status               identity, address, peer counts, RSS
//	GET  /snapshot             routing-table peers (DHT snapshot)
//	GET  /lookup?target=ID     RecursiveFindNodeDetailed result + latency
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/node"
	"github.com/vx6/vx6/internal/record"
)

const interlockEnv = "VX6_NETSIM_NO_IPSEC"

var labPrefixes = []netip.Prefix{
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
}

// passThroughTunnel mirrors internal/integration's test provider: it accepts
// only peers with a valid signed endpoint record but negotiates no IPsec.
type passThroughTunnel struct{}

func (passThroughTunnel) PreparePeer(_ context.Context, p record.EndpointRecord) error {
	return record.VerifyEndpointRecord(p, time.Now())
}
func (passThroughTunnel) EnsurePeer(_ context.Context, p record.EndpointRecord) error {
	return record.VerifyEndpointRecord(p, time.Now())
}
func (passThroughTunnel) RegisterProbePort(context.Context, string) error { return nil }
func (passThroughTunnel) AcceptPeer(context.Context, string) bool         { return true }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "simnode:", err)
		os.Exit(1)
	}
}

// checkLabAddress enforces the lab-only interlock.
func checkLabAddress(listen string) error {
	if os.Getenv(interlockEnv) != "I_UNDERSTAND" {
		return fmt.Errorf("refusing to start: simnode has no IPsec; set %s=I_UNDERSTAND inside the lab only", interlockEnv)
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("invalid -listen: %w", err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return fmt.Errorf("-listen must be an IPv6 address")
	}
	for _, p := range labPrefixes {
		if p.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("refusing to start: %s is not in a lab range (2001:db8::/32 or fc00::/7)", addr)
}

func run() error {
	name := flag.String("name", "", "node name")
	dir := flag.String("dir", "", "state directory")
	listen := flag.String("listen", "", "IPv6 listen/advertise address, e.g. [2001:db8::10]:4242")
	seeds := flag.String("seeds", "", "JSON file with signed endpoint records of bootstrap peers")
	flag.Parse()
	if *name == "" || *dir == "" || *listen == "" {
		return errors.New("-name, -dir and -listen are required")
	}
	if err := checkLabAddress(*listen); err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}

	idStore, err := identity.NewStore(filepath.Join(*dir, "identity.json"))
	if err != nil {
		return err
	}
	id, _, err := idStore.Ensure() // same identity across restarts (churn tests)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	dataDir := filepath.Join(*dir, "data")
	registry, err := discovery.NewRegistry(filepath.Join(dataDir, "registry.json"))
	if err != nil {
		return err
	}
	var seedAddrs []string
	if *seeds != "" {
		recs, err := readRecords(*seeds)
		if err != nil {
			return fmt.Errorf("seeds: %w", err)
		}
		if err := registry.Import(recs, nil); err != nil {
			return fmt.Errorf("import seeds: %w", err)
		}
		for _, r := range recs {
			seedAddrs = append(seedAddrs, r.Address)
		}
	}

	// Publish our own signed record for the orchestrator to hand to newcomers.
	own, err := record.NewEndpointRecord(id, *name, *listen, 24*time.Hour, time.Now())
	if err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(*dir, "endpoint.json"), own); err != nil {
		return err
	}

	configPath := filepath.Join(*dir, "config.json")
	store, err := config.NewStore(configPath)
	if err != nil {
		return err
	}
	cfgFile := config.File{
		Node: config.NodeConfig{
			Name: *name, ListenAddr: *listen, AdvertiseAddr: *listen,
			DataDir: dataDir, KnownPeerAddrs: seedAddrs,
		},
		Peers:    map[string]config.PeerEntry{},
		Services: map[string]config.ServiceEntry{},
	}
	if prev, err := store.Load(); err == nil {
		cfgFile.Node.RecordSequence = prev.Node.RecordSequence
		cfgFile.Node.RecordName = prev.Node.RecordName
		cfgFile.Node.RecordAddress = prev.Node.RecordAddress
	}
	if err := store.Save(cfgFile); err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	srv := dht.NewServerWithIdentity(id)
	cfg := node.Config{
		Name: *name, NodeID: id.NodeID, ListenAddr: *listen, AdvertiseAddr: *listen,
		DataDir: dataDir, ConfigPath: configPath, PeerAddrs: seedAddrs,
		Services: map[string]string{}, DHT: srv, Identity: id, Registry: registry,
		IPsecTunnel:     passThroughTunnel{},
		RefreshServices: func() map[string]string { return map[string]string{} },
	}

	logFile, err := os.OpenFile(filepath.Join(*dir, "node.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()

	admin, err := startAdmin(filepath.Join(*dir, "admin.sock"), &adminState{
		name: *name, id: id.NodeID, addr: *listen, srv: srv, registry: registry, started: time.Now(),
	})
	if err != nil {
		return err
	}
	defer admin.Close()

	err = node.Run(ctx, logFile, cfg)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func readRecords(path string) ([]record.EndpointRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var recs []record.EndpointRecord
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type adminState struct {
	name, id, addr string
	srv            *dht.Server
	registry       *discovery.Registry
	started        time.Time
}

// Snapshot is the per-node DHT state the orchestrator collects.
type Snapshot struct {
	Time    time.Time  `json:"time"`
	Name    string     `json:"name"`
	NodeID  string     `json:"node_id"`
	Addr    string     `json:"addr"`
	Active  int        `json:"active"`
	Peers   []PeerView `json:"peers"`
	Records int        `json:"registry_records"`
	RSSKB   int        `json:"rss_kb"`
	Uptime  float64    `json:"uptime_sec"`
}

type PeerView struct {
	ID       string `json:"id"`
	Addr     string `json:"addr"`
	Success  uint32 `json:"success"`
	Fail     uint8  `json:"fail"`
	RTTMicro uint32 `json:"rtt_us"`
	Pinned   bool   `json:"pinned,omitempty"`
}

// LookupReport is returned by /lookup.
type LookupReport struct {
	Target    string  `json:"target"`
	Outcome   string  `json:"outcome"`
	Found     bool    `json:"found"`
	Rounds    int     `json:"rounds"`
	Queried   int     `json:"queried"`
	LatencyMS float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
}

func (a *adminState) snapshot() Snapshot {
	obs := a.srv.RT.SnapshotPeers()
	peers := make([]PeerView, 0, len(obs))
	for _, o := range obs {
		peers = append(peers, PeerView{ID: o.Node.ID, Addr: o.Node.Addr, Success: o.SuccessCount,
			Fail: o.FailCount, RTTMicro: o.RTTMicros, Pinned: o.Pinned})
	}
	recs, _ := a.registry.Snapshot()
	return Snapshot{Time: time.Now().UTC(), Name: a.name, NodeID: a.id, Addr: a.addr,
		Active: len(a.srv.RT.Nodes()), Peers: peers, Records: len(recs), RSSKB: rssKB(),
		Uptime: time.Since(a.started).Seconds()}
}

func (a *adminState) lookup(ctx context.Context, target string) LookupReport {
	t0 := time.Now()
	res, err := a.srv.RecursiveFindNodeDetailed(ctx, target)
	rep := LookupReport{Target: target, Outcome: string(res.Outcome), Rounds: res.Rounds,
		Queried: res.QueriedNodes, LatencyMS: float64(time.Since(t0).Microseconds()) / 1000}
	for _, m := range res.Matches {
		if m.ID == target {
			rep.Found = true
		}
	}
	if err != nil {
		rep.Error = err.Error()
	}
	return rep
}

func startAdmin(sock string, st *adminState) (net.Listener, error) {
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(sock, 0o600)
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		s := st.snapshot()
		s.Peers = nil
		writeHTTP(w, s)
	})
	mux.HandleFunc("/snapshot", func(w http.ResponseWriter, _ *http.Request) { writeHTTP(w, st.snapshot()) })
	mux.HandleFunc("/lookup", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" || len(target) > 256 {
			http.Error(w, "target required", http.StatusBadRequest)
			return
		}
		timeout := 30 * time.Second
		if v, err := strconv.Atoi(r.URL.Query().Get("timeout_s")); err == nil && v > 0 && v <= 120 {
			timeout = time.Duration(v) * time.Second
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		writeHTTP(w, st.lookup(ctx, target))
	})
	go func() { _ = http.Serve(ln, mux) }()
	return ln, nil
}

func writeHTTP(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func rssKB() int {
	if runtime.GOOS != "linux" {
		return 0
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				n, _ := strconv.Atoi(f[1])
				return n
			}
		}
	}
	return 0
}
