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
//	GET  /lookup?type=id&target=ID
//	GET  /lookup?type=name&target=NAME (the DHT receives only the name hash)
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
	"sync"
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
type passThroughTunnel struct {
	mu    sync.RWMutex
	peers map[string]record.EndpointRecord
}

func (p *passThroughTunnel) PreparePeer(_ context.Context, peer record.EndpointRecord) error {
	if err := record.VerifyEndpointRecord(peer, time.Now()); err != nil {
		return err
	}
	p.mu.Lock()
	p.peers[peerHost(peer.Address)] = peer
	p.mu.Unlock()
	return nil
}
func (p *passThroughTunnel) EnsurePeer(ctx context.Context, peer record.EndpointRecord) error {
	return p.PreparePeer(ctx, peer)
}
func (*passThroughTunnel) RegisterProbePort(context.Context, string) error { return nil }
func (p *passThroughTunnel) AuthenticatePeer(_ context.Context, remote string) (record.EndpointRecord, bool) {
	p.mu.RLock()
	peer, ok := p.peers[peerHost(remote)]
	p.mu.RUnlock()
	if !ok || record.VerifyEndpointRecord(peer, time.Now()) != nil {
		return record.EndpointRecord{}, false
	}
	return peer, true
}
func (p *passThroughTunnel) AcceptPeer(ctx context.Context, remote string) bool {
	_, ok := p.AuthenticatePeer(ctx, remote)
	return ok
}

func peerHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	return parsed.String()
}

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
		IPsecTunnel:     &passThroughTunnel{peers: make(map[string]record.EndpointRecord)},
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
	Time     time.Time    `json:"time"`
	Name     string       `json:"name"`
	NodeID   string       `json:"node_id"`
	NameHash string       `json:"name_hash"`
	Addr     string       `json:"addr"`
	Active   int          `json:"active"`
	Peers    []PeerView   `json:"peers"`
	Records  int          `json:"registry_records"`
	RSSKB    int          `json:"rss_kb"`
	Uptime   float64      `json:"uptime_sec"`
	Lookup   LookupPolicy `json:"lookup_policy"`
}

type LookupPolicy struct {
	MaxRounds      int   `json:"max_rounds"`
	MaxConcurrent  int   `json:"max_concurrent"`
	MaxPeerQueries int   `json:"max_peer_queries"`
	MaxReferrals   int   `json:"max_referrals_per_reply"`
	PeerTimeoutMS  int64 `json:"peer_timeout_ms"`
	TotalTimeoutMS int64 `json:"total_timeout_ms"`
}

type PeerView struct {
	ID       string `json:"id"`
	NameHash string `json:"name_hash"`
	Addr     string `json:"addr"`
	ASN      uint32 `json:"asn,omitempty"`
	Prefix48 string `json:"prefix_48,omitempty"`
	Success  uint32 `json:"success"`
	Fail     uint8  `json:"fail"`
	RTTMicro uint32 `json:"rtt_us"`
	Pinned   bool   `json:"pinned,omitempty"`
}

// LookupReport is returned by /lookup.
type LookupReport struct {
	Source         string  `json:"source,omitempty"`
	TargetType     string  `json:"target_type"`
	Target         string  `json:"target"`
	ExpectedNodeID string  `json:"expected_node_id,omitempty"`
	Outcome        string  `json:"outcome"`
	Found          bool    `json:"found_expected"`
	MatchCount     int     `json:"match_count"`
	Rounds         int     `json:"rounds"`
	Queried        int     `json:"queried"`
	LatencyMS      float64 `json:"latency_ms"`
	Error          string  `json:"error,omitempty"`
	// Trace is the per-round lookup path, included when requested.
	Trace *dht.LookupTrace `json:"trace,omitempty"`
}

// Diagnostics is the full read-only per-node DHT state: both XOR indexes of
// the in-memory table plus the node's already-open bbolt store.
type Diagnostics struct {
	Time     time.Time             `json:"time"`
	Name     string                `json:"name"`
	NodeID   string                `json:"node_id"`
	NameHash string                `json:"name_hash"`
	Addr     string                `json:"addr"`
	Uptime   float64               `json:"uptime_sec"`
	RSSKB    int                   `json:"rss_kb"`
	Records  int                   `json:"registry_records"`
	DHT      dht.ServerDiagnostics `json:"dht"`
}

func (a *adminState) diagnostics() Diagnostics {
	recs, _ := a.registry.Snapshot()
	now := time.Now().UTC()
	return Diagnostics{Time: now, Name: a.name, NodeID: a.id, NameHash: dht.NodeNameHash(a.name), Addr: a.addr,
		Uptime: time.Since(a.started).Seconds(), RSSKB: rssKB(), Records: len(recs), DHT: a.srv.Diagnostics(now)}
}

func (a *adminState) snapshot() Snapshot {
	obs := a.srv.RT.SnapshotPeers()
	peers := make([]PeerView, 0, len(obs))
	for _, o := range obs {
		peers = append(peers, PeerView{ID: o.Node.ID, NameHash: o.Node.NameHash, Addr: o.Node.Addr, Success: o.SuccessCount,
			Fail: o.FailCount, RTTMicro: o.RTTMicros, Pinned: o.Pinned})
	}
	recs, _ := a.registry.Snapshot()
	limits := a.srv.LookupLimits()
	return Snapshot{Time: time.Now().UTC(), Name: a.name, NodeID: a.id, NameHash: dht.NodeNameHash(a.name), Addr: a.addr,
		Active: len(a.srv.RT.Nodes()), Peers: peers, Records: len(recs), RSSKB: rssKB(),
		Uptime: time.Since(a.started).Seconds(), Lookup: LookupPolicy{MaxRounds: limits.MaxRounds,
			MaxConcurrent: limits.MaxConcurrent, MaxPeerQueries: limits.MaxPeerQueries, MaxReferrals: limits.MaxReferrals,
			PeerTimeoutMS: limits.PeerTimeout.Milliseconds(), TotalTimeoutMS: limits.TotalTimeout.Milliseconds()}}
}

func (a *adminState) lookup(ctx context.Context, targetType, target string, withTrace bool) LookupReport {
	lookupTarget, expectedID, reportTarget, err := nodeLookupTarget(targetType, target)
	if err != nil {
		return LookupReport{TargetType: targetType, Outcome: "invalid_target", Error: err.Error()}
	}
	var trace *dht.LookupTrace
	if withTrace {
		trace = &dht.LookupTrace{}
		ctx = dht.WithLookupTrace(ctx, trace)
	}
	t0 := time.Now()
	res, err := a.srv.RecursiveFindNodeDetailed(ctx, lookupTarget)
	rep := LookupReport{TargetType: targetType, Target: reportTarget, ExpectedNodeID: expectedID,
		Outcome: string(res.Outcome), MatchCount: len(res.Matches), Rounds: res.Rounds,
		Queried: res.QueriedNodes, LatencyMS: float64(time.Since(t0).Microseconds()) / 1000}
	for _, m := range res.Matches {
		if targetType == "id" && m.ID == expectedID || targetType == "name" && dht.NodeNameHash(m.Name) == strings.TrimPrefix(lookupTarget, "node/name/") {
			rep.Found = true
		}
	}
	if err != nil {
		rep.Error = err.Error()
	}
	rep.Trace = trace
	return rep
}

func nodeLookupTarget(targetType, target string) (lookupTarget, expectedID, reportTarget string, err error) {
	switch targetType {
	case "id":
		if len(target) != len("vx6_")+64 || !strings.HasPrefix(target, "vx6_") {
			return "", "", "", errors.New("node ID must be vx6_ followed by a full SHA-256 digest")
		}
		for _, c := range target[len("vx6_"):] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return "", "", "", errors.New("node ID digest must use lowercase hexadecimal")
			}
		}
		return "node/id/" + target, target, target, nil
	case "name":
		canonical, err := record.NormalizeNodeName(target)
		if err != nil {
			return "", "", "", err
		}
		hash := dht.NodeNameHash(canonical)
		return "node/name/" + hash, "", hash, nil
	default:
		return "", "", "", errors.New("type must be id or name")
	}
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
	mux.HandleFunc("/diagnostics", func(w http.ResponseWriter, _ *http.Request) { writeHTTP(w, st.diagnostics()) })
	mux.HandleFunc("/lookup", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		targetType := r.URL.Query().Get("type")
		if target == "" || len(target) > 256 || (targetType != "id" && targetType != "name") {
			http.Error(w, "target required", http.StatusBadRequest)
			return
		}
		timeout := 10 * time.Second
		if v, err := strconv.Atoi(r.URL.Query().Get("timeout_s")); err == nil && v > 0 && v <= 10 {
			timeout = time.Duration(v) * time.Second
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		writeHTTP(w, st.lookup(ctx, targetType, target, r.URL.Query().Get("trace") == "1"))
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
