// dht-scale runs the production DHT server and lookup implementation over
// IPv6 loopback. It is a DHT simulator, not an IPsec or adversarial-security test.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
)

type peer struct {
	id     identity.Identity
	info   proto.NodeInfo
	server *dht.Server
	ln     net.Listener
	cancel context.CancelFunc
}

type lookupSample struct {
	Sequence       int              `json:"sequence"`
	NegativeTarget bool             `json:"negative_target"`
	SourceID       string           `json:"source_id"`
	TargetID       string           `json:"target_id"`
	TargetName     string           `json:"target_name"`
	Space          string           `json:"space"`
	ExpectedTop4   []string         `json:"oracle_top4_node_ids"`
	FoundTarget    bool             `json:"found_target"`
	ExactTop4      bool             `json:"returned_top4_matches_oracle"`
	Outcome        string           `json:"outcome"`
	Error          string           `json:"error,omitempty"`
	Queries        int              `json:"queries"`
	Rounds         int              `json:"rounds"`
	DurationMS     float64          `json:"duration_ms"`
	Trace          *dht.LookupTrace `json:"trace"`
}

type nodeSnapshot struct {
	NodeID                    string                `json:"node_id"`
	Name                      string                `json:"name"`
	SignedIdentity            proto.NodeInfo        `json:"signed_identity_record"`
	JoinIndex                 int                   `json:"join_index"`
	Active                    int                   `json:"active_peers"`
	IDIndex                   dht.DiagnosticIndex   `json:"node_id_index"`
	NameIndex                 dht.DiagnosticIndex   `json:"name_hash_index"`
	Offline                   []dht.DiagnosticPeer  `json:"offline_peers,omitempty"`
	Pending                   []dht.DiagnosticPeer  `json:"pending_peers,omitempty"`
	Bbolt                     *dht.StoreDiagnostics `json:"bbolt_peer_store,omitempty"`
	StoreError                string                `json:"store_error,omitempty"`
	IDBucketPlacementErrors   int                   `json:"node_id_bucket_placement_errors"`
	NameBucketPlacementErrors int                   `json:"name_hash_bucket_placement_errors"`
	BboltReloadedCandidates   int                   `json:"bbolt_reloaded_candidates"`
}

type metrics struct {
	Nodes                     int     `json:"nodes"`
	LookupAttempts            int     `json:"lookup_attempts"`
	Found                     int     `json:"found"`
	FoundComplete             int     `json:"found_complete"`
	FoundIncomplete           int     `json:"found_incomplete"`
	NegativeLookups           int     `json:"negative_lookups"`
	NegativeNotFound          int     `json:"negative_not_found"`
	NegativeIncomplete        int     `json:"negative_incomplete"`
	NegativeFalsePositive     int     `json:"negative_false_positive"`
	NotFound                  int     `json:"not_found"`
	Incomplete                int     `json:"incomplete"`
	Errors                    int     `json:"errors"`
	NameLookupAttempts        int     `json:"name_lookup_attempts"`
	NameLookupFound           int     `json:"name_lookup_found"`
	NameLookupCompleteFound   int     `json:"name_lookup_complete_found"`
	IDLookupAttempts          int     `json:"id_lookup_attempts"`
	IDLookupFound             int     `json:"id_lookup_found"`
	IDLookupCompleteFound     int     `json:"id_lookup_complete_found"`
	ExactTop4                 int     `json:"exact_top4_matches"`
	Top4Checks                int     `json:"top4_checks"`
	MeanQueries               float64 `json:"mean_queries"`
	P50Queries                int     `json:"p50_queries"`
	P95Queries                int     `json:"p95_queries"`
	P50DurationMS             float64 `json:"p50_duration_ms"`
	P95DurationMS             float64 `json:"p95_duration_ms"`
	ActivePeerCount           int     `json:"active_peer_count"`
	MeanActivePeers           float64 `json:"mean_active_peers"`
	MinActivePeers            int     `json:"min_active_peers"`
	MaxActivePeers            int     `json:"max_active_peers"`
	IDNonEmptyBuckets         int     `json:"node_id_non_empty_bucket_total"`
	NameNonEmptyBuckets       int     `json:"name_hash_non_empty_bucket_total"`
	IDGlobalTop4Recall        float64 `json:"node_id_global_top4_recall_percent"`
	NameGlobalTop4Recall      float64 `json:"name_hash_global_top4_recall_percent"`
	IDBucketPlacementErrors   int     `json:"node_id_bucket_placement_errors"`
	NameBucketPlacementErrors int     `json:"name_hash_bucket_placement_errors"`
	BboltPeerRows             int     `json:"bbolt_peer_rows"`
	BboltBytes                int64   `json:"bbolt_bytes"`
	HeapAllocBytes            uint64  `json:"heap_alloc_bytes_after_capture"`
	HeapSysBytes              uint64  `json:"heap_sys_bytes_after_capture"`
	Goroutines                int     `json:"goroutines_after_capture"`
	ElapsedSeconds            float64 `json:"elapsed_seconds"`
	PassCriteria              string  `json:"pass_criteria"`
}

type report struct {
	Schema       string             `json:"schema"`
	Revision     string             `json:"revision"`
	Seed         int64              `json:"seed"`
	StartedAt    time.Time          `json:"started_at"`
	FinishedAt   time.Time          `json:"finished_at"`
	Platform     string             `json:"platform"`
	Transport    string             `json:"transport"`
	LookupPolicy dht.CapacityPolicy `json:"routing_capacity_policy"`
	Metrics      metrics            `json:"metrics"`
	JoinLog      []joinEvent        `json:"join_log"`
}

type joinEvent struct {
	JoinIndex               int      `json:"join_index"`
	NodeID                  string   `json:"node_id"`
	SeedID                  string   `json:"seed_id,omitempty"`
	Referrals               []string `json:"referrals,omitempty"`
	VerifiedContacts        int      `json:"verified_contacts"`
	IDLookupQueries         int      `json:"self_node_id_lookup_queries"`
	IDLookupRounds          int      `json:"self_node_id_lookup_rounds"`
	NameLookupQueries       int      `json:"self_name_hash_lookup_queries"`
	NameLookupRounds        int      `json:"self_name_hash_lookup_rounds"`
	ReciprocalAnnouncements int      `json:"reciprocal_announcements_simulated"`
	AdmissionNote           string   `json:"admission_model_note"`
}

func main() {
	nodes := flag.Int("nodes", 100, "number of simulated nodes (start with 3, 10, 100, then 500/1000)")
	pairs := flag.Int("pairs", 200, "additional seeded random source/target pairs; every target is also looked up from a sampled source")
	seed := flag.Int64("seed", 75, "deterministic topology and lookup sampling seed")
	out := flag.String("out", "", "new output directory; defaults to ./dht-scale-<nodes>-<UTC timestamp>")
	flag.Parse()
	if *nodes < 2 || *nodes > 5000 || *pairs < 0 {
		fatal("nodes must be 2..5000 and pairs must be nonnegative")
	}
	started := time.Now().UTC()
	if *out == "" {
		*out = fmt.Sprintf("dht-scale-%d-%s", *nodes, started.Format("20060102T150405Z"))
	}
	if _, err := os.Stat(*out); err == nil {
		fatal("output path already exists: %s", *out)
	}
	for _, dir := range []string{"snapshots", "lookups", "stores", "join"} {
		if err := os.MkdirAll(filepath.Join(*out, dir), 0o700); err != nil {
			fatal("create output directory: %v", err)
		}
	}
	rng := rand.New(rand.NewSource(*seed))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peers := make([]*peer, 0, *nodes)
	joinLog := make([]joinEvent, 0, *nodes)

	for i := 0; i < *nodes; i++ {
		p, err := newPeer(ctx, i, *seed)
		if err != nil {
			closePeers(peers)
			fatal("start node %d: %v", i, err)
		}
		peers = append(peers, p)
		if i == 0 {
			joinLog = append(joinLog, joinEvent{JoinIndex: i, NodeID: p.info.ID})
			continue
		}
		seedPeer := peers[rng.Intn(i)]
		seedPeer.server.RT.AddNode(p.info) // the joining node proves its identity to this one contact
		p.server.RT.AddNode(seedPeer.info)
		ctxLookup, stop := context.WithTimeout(ctx, 10*time.Second)
		refs, err := p.server.QueryBootstrapNode(ctxLookup, seedPeer.info.Addr, p.info.ID)
		stop()
		event := joinEvent{JoinIndex: i, NodeID: p.info.ID, SeedID: seedPeer.info.ID,
			AdmissionNote: "successful signed-record and DHT-response contacts are promoted; reciprocal peer admission models the post-IKE contact exchange, but IKE is not run by this simulator"}
		if err == nil {
			for _, ref := range refs {
				event.Referrals = append(event.Referrals, ref.ID)
				if ref.ID == p.info.ID || ref.ID == seedPeer.info.ID || dht.VerifyNodeInfo(ref, time.Now()) != nil {
					continue
				}
				ctxProbe, stopProbe := context.WithTimeout(ctx, 3*time.Second)
				_, probeErr := p.server.QueryNode(ctxProbe, ref.Addr, p.info.ID)
				stopProbe()
				if probeErr == nil {
					p.server.RT.AddNode(ref)
					event.VerifiedContacts++
				}
			}
		}
		idTrace := &dht.LookupTrace{}
		idCtx, idCancel := context.WithTimeout(dht.WithLookupTrace(ctx, idTrace), 10*time.Second)
		idResult, idErr := p.server.RecursiveFindNodeDetailed(idCtx, dht.NodeIDKey(p.info.ID))
		idCancel()
		event.IDLookupQueries, event.IDLookupRounds = idResult.QueriedNodes, idResult.Rounds
		writeJSON(filepath.Join(*out, "join", fmt.Sprintf("%06d-self-node-id-lookup.json", i)), map[string]any{"result": idResult, "error": errorString(idErr), "trace": idTrace})
		nameTrace := &dht.LookupTrace{}
		nameCtx, nameCancel := context.WithTimeout(dht.WithLookupTrace(ctx, nameTrace), 10*time.Second)
		nameResult, nameErr := p.server.RecursiveFindNodeDetailed(nameCtx, dht.NodeNameKey(p.info.Name))
		nameCancel()
		event.NameLookupQueries, event.NameLookupRounds = nameResult.QueriedNodes, nameResult.Rounds
		writeJSON(filepath.Join(*out, "join", fmt.Sprintf("%06d-self-name-hash-lookup.json", i)), map[string]any{"result": nameResult, "error": errorString(nameErr), "trace": nameTrace})
		verifiedContacts := promoteResponders(p, peers, idTrace, nameTrace)
		event.VerifiedContacts += len(verifiedContacts)
		announced := make(map[string]struct{})
		announceClosest(p, dht.NodeIDKey(p.info.ID), false, verifiedContacts, announced)
		announceClosest(p, dht.NodeNameKey(p.info.Name), true, verifiedContacts, announced)
		event.ReciprocalAnnouncements = len(announced)
		joinLog = append(joinLog, event)
		writeJSON(filepath.Join(*out, "join", fmt.Sprintf("%06d.json", i)), event)
	}
	defer closePeers(peers)

	lookups := make([]lookupSample, 0, 2*(*nodes+*pairs))
	lookupSequence := 0
	// Every identity is targeted once by both independent lookup spaces. This
	// catches target coverage gaps without doing an all-pairs quadratic run.
	for targetIndex, target := range peers {
		sourceIndex := (targetIndex + 1 + rng.Intn(*nodes-1)) % *nodes
		for _, byName := range []bool{false, true} {
			if sourceIndex == targetIndex {
				sourceIndex = (sourceIndex + 1) % *nodes
			}
			lookups = append(lookups, runLookup(ctx, lookupSequence, false, peers[sourceIndex], target, byName, peers, *out))
			lookupSequence++
		}
	}
	for i := 0; i < *pairs; i++ {
		sourceIndex := rng.Intn(*nodes)
		targetIndex := rng.Intn(*nodes - 1)
		if targetIndex >= sourceIndex {
			targetIndex++
		}
		for _, byName := range []bool{false, true} {
			lookups = append(lookups, runLookup(ctx, lookupSequence, false, peers[sourceIndex], peers[targetIndex], byName, peers, *out))
			lookupSequence++
		}
	}
	missingIDHash := sha256.Sum256([]byte(fmt.Sprintf("vx6-dht-scale-missing-id/%d", *seed)))
	missing := &peer{info: proto.NodeInfo{ID: "vx6_" + hex.EncodeToString(missingIDHash[:]), Name: fmt.Sprintf("MISSING-%d", *seed)}}
	missing.info.NameHash = dht.NodeNameHash(missing.info.Name)
	for _, byName := range []bool{false, true} {
		lookups = append(lookups, runLookup(ctx, lookupSequence, true, peers[rng.Intn(*nodes)], missing, byName, peers, *out))
		lookupSequence++
	}
	writeJSON(filepath.Join(*out, "lookups", "index.json"), lookups)

	snapshots := make([]nodeSnapshot, 0, len(peers))
	minActive, maxActive, activeTotal, idBuckets, nameBuckets := *nodes, 0, 0, 0, 0
	var bboltRows, bboltBytes int64
	for i, p := range peers {
		snapshot, err := captureNode(p, i, filepath.Join(*out, "stores"))
		if err != nil {
			fatal("capture node %s: %v", p.info.ID, err)
		}
		snapshots = append(snapshots, snapshot)
		activeTotal += snapshot.Active
		if snapshot.Active < minActive {
			minActive = snapshot.Active
		}
		if snapshot.Active > maxActive {
			maxActive = snapshot.Active
		}
		idBuckets += snapshot.IDIndex.NonEmptyBuckets
		nameBuckets += snapshot.NameIndex.NonEmptyBuckets
		if snapshot.Bbolt != nil {
			bboltRows += int64(snapshot.Bbolt.PeerRows)
		}
		storeInfo, statErr := os.Stat(filepath.Join(*out, "stores", fmt.Sprintf("%06d.db", i)))
		if statErr == nil {
			bboltBytes += storeInfo.Size()
		}
	}
	writeJSON(filepath.Join(*out, "snapshots", "all-nodes.json"), snapshots)

	m := summarize(*nodes, lookups, snapshots, idBuckets, nameBuckets, time.Since(started))
	m.BboltPeerRows, m.BboltBytes = int(bboltRows), bboltBytes
	if *nodes > 0 {
		m.MeanActivePeers = float64(activeTotal) / float64(*nodes)
		for _, p := range peers {
			m.IDGlobalTop4Recall += topRecall(p.server.RT.ClosestNodes(p.info.ID, 4), independentTop(peers, p.info.ID, false, 4))
			m.NameGlobalTop4Recall += topRecall(p.server.RT.ClosestNodesByNameHash(p.info.NameHash, 4), independentTop(peers, p.info.NameHash, true, 4))
		}
		m.IDGlobalTop4Recall /= float64(*nodes)
		m.NameGlobalTop4Recall /= float64(*nodes)
	}
	for _, snapshot := range snapshots {
		m.IDBucketPlacementErrors += snapshot.IDBucketPlacementErrors
		m.NameBucketPlacementErrors += snapshot.NameBucketPlacementErrors
	}
	m.MinActivePeers, m.MaxActivePeers = minActive, maxActive
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	m.HeapAllocBytes, m.HeapSysBytes, m.Goroutines = mem.HeapAlloc, mem.HeapSys, runtime.NumGoroutine()
	rv := report{Schema: "vx6-dht-scale-report/v1", Seed: *seed, StartedAt: started,
		FinishedAt: time.Now().UTC(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Transport:    "production VX6 DHT wire protocol over IPv6 loopback TCP; IPsec intentionally bypassed",
		LookupPolicy: dht.CapacityPolicyInfo(), Metrics: m, JoinLog: joinLog}
	if revision := os.Getenv("VX6_BUILD_REVISION"); revision != "" {
		rv.Revision = revision
	} else if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				rv.Revision = setting.Value
			}
		}
	}
	writeJSON(filepath.Join(*out, "report.json"), rv)
	writeMarkdown(filepath.Join(*out, "report.md"), rv, lookups, snapshots)
	writeJSON(filepath.Join(*out, "host.json"), map[string]any{"go_version": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "cpus": runtime.NumCPU(), "goroutines": runtime.NumGoroutine(), "heap_alloc_bytes": mem.HeapAlloc, "heap_sys_bytes": mem.HeapSys})
	fmt.Printf("report=%s\nnodes=%d attempts=%d positive_found=%d negative_not_found=%d/%d incomplete=%d exact_top4=%d/%d mean_active=%.2f heap_alloc=%d bytes\n", *out, m.Nodes, m.LookupAttempts, m.Found, m.NegativeNotFound, m.NegativeLookups, m.Incomplete, m.ExactTop4, m.Top4Checks, m.MeanActivePeers, m.HeapAllocBytes)
	if m.IDBucketPlacementErrors+m.NameBucketPlacementErrors > 0 {
		fatal("routing bucket audit found %d misplaced peer entries; see report.json and snapshots", m.IDBucketPlacementErrors+m.NameBucketPlacementErrors)
	}
	if m.NegativeFalsePositive > 0 {
		fatal("negative lookup control returned %d false positives; see report.json and lookup traces", m.NegativeFalsePositive)
	}
}

func newPeer(parent context.Context, index int, seed int64) (*peer, error) {
	material := sha256.Sum256([]byte(fmt.Sprintf("vx6-dht-scale/%d/%d", seed, index)))
	private := ed25519.NewKeyFromSeed(material[:])
	public := private.Public().(ed25519.PublicKey)
	id := identity.Identity{NodeID: identity.NodeIDFromPublicKey(public), PublicKey: public, PrivateKey: private}
	server := dht.NewServerWithIdentity(id)
	name := fmt.Sprintf("NODE-%06d", index)
	server.RT.SetSelfNameHash(dht.NodeNameHash(name))
	server.SetDialGuard(func(context.Context, string) error { return nil })
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	rec, err := record.NewEndpointRecordV2(id, name, ln.Addr().String(), 1, 365*24*time.Hour, now)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	p := &peer{id: id, info: dht.NodeInfoFromEndpointRecord(rec), server: server, ln: ln, cancel: cancel}
	go p.serve(ctx)
	return p, nil
}

func (p *peer) serve(ctx context.Context) {
	go func() { <-ctx.Done(); _ = p.ln.Close() }()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			kind, err := proto.ReadHeader(conn)
			if err != nil || kind != proto.KindDHT {
				return
			}
			data, err := proto.ReadLengthPrefixed(conn, 1<<20)
			if err != nil {
				return
			}
			var req proto.DHTRequest
			if json.Unmarshal(data, &req) != nil {
				return
			}
			_ = p.server.HandleDHT(ctx, conn, req)
		}(conn)
	}
}

func (p *peer) close() { p.cancel(); _ = p.ln.Close() }

func closePeers(peers []*peer) {
	for _, p := range peers {
		p.close()
	}
}

func promoteResponders(joiner *peer, all []*peer, traces ...*dht.LookupTrace) map[string]*peer {
	byID := make(map[string]*peer)
	known := make(map[string]*peer, len(all))
	for _, p := range all {
		known[p.info.ID] = p
	}
	for _, trace := range traces {
		for _, round := range trace.Rounds {
			for _, query := range round.Queries {
				remote := known[query.Responder.NodeID]
				if query.Result != "ok" || remote == nil || dht.VerifyNodeInfo(remote.info, time.Now()) != nil {
					continue
				}
				joiner.server.RT.AddNode(remote.info)
				byID[remote.info.ID] = remote
			}
		}
	}
	return byID
}

func announceClosest(joiner *peer, target string, byName bool, responders map[string]*peer, announced map[string]struct{}) {
	var closest []proto.NodeInfo
	if byName {
		closest = joiner.server.RT.ClosestNodesByNameHash(strings.TrimPrefix(target, "node/name/"), 4)
	} else {
		closest = joiner.server.RT.ClosestNodes(strings.TrimPrefix(target, "node/id/"), 4)
	}
	for _, candidate := range closest {
		remote, responsive := responders[candidate.ID]
		if !responsive || remote == nil || candidate.ID == joiner.info.ID {
			continue
		}
		remote.server.RT.AddNode(joiner.info)
		announced[candidate.ID] = struct{}{}
	}
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func runLookup(ctx context.Context, sequence int, negative bool, source, target *peer, byName bool, all []*peer, out string) lookupSample {
	targetKey := dht.NodeIDKey(target.info.ID)
	targetCoord := target.info.ID
	space := "node_id"
	if byName {
		targetKey, targetCoord, space = dht.NodeNameKey(target.info.Name), dht.NodeNameHash(target.info.Name), "name_hash"
	}
	trace := &dht.LookupTrace{}
	lookupCtx, cancel := context.WithTimeout(dht.WithLookupTrace(ctx, trace), 10*time.Second)
	start := time.Now()
	result, err := source.server.RecursiveFindNodeDetailed(lookupCtx, targetKey)
	cancel()
	sample := lookupSample{Sequence: sequence, NegativeTarget: negative, SourceID: source.info.ID, TargetID: target.info.ID, TargetName: target.info.Name, Space: space,
		Outcome: string(result.Outcome), Queries: result.QueriedNodes, Rounds: result.Rounds,
		DurationMS: float64(time.Since(start).Microseconds()) / 1000, Trace: trace}
	if err != nil {
		sample.Error = err.Error()
	}
	for _, n := range independentTop(all, targetCoord, byName, 4) {
		sample.ExpectedTop4 = append(sample.ExpectedTop4, n.ID)
	}
	if byName {
		for _, n := range result.Matches {
			if n.ID == target.info.ID {
				sample.FoundTarget = true
			}
		}
	} else {
		sample.FoundTarget = result.Outcome == dht.LookupFound && len(result.Matches) > 0 && result.Matches[0].ID == target.info.ID
	}
	got := result.Closest
	sample.ExactTop4 = len(got) >= len(sample.ExpectedTop4)
	if sample.ExactTop4 {
		for i, id := range sample.ExpectedTop4 {
			if got[i].ID != id {
				sample.ExactTop4 = false
				break
			}
		}
	}
	filename := fmt.Sprintf("%06d-%s-%s-%s.json", sequence, source.info.ID, target.info.ID, space)
	writeJSON(filepath.Join(out, "lookups", filename), sample)
	return sample
}

func topRecall(got, expected []proto.NodeInfo) float64 {
	if len(expected) == 0 {
		return 100
	}
	ids := make(map[string]struct{}, len(got))
	for _, node := range got {
		ids[node.ID] = struct{}{}
	}
	matched := 0
	for _, node := range expected {
		if _, ok := ids[node.ID]; ok {
			matched++
		}
	}
	return 100 * float64(matched) / float64(len(expected))
}

func independentTop(peers []*peer, target string, byName bool, k int) []proto.NodeInfo {
	target = strings.TrimPrefix(target, "vx6_")
	tb, _ := hex.DecodeString(target)
	type ranked struct {
		info proto.NodeInfo
		d    []byte
	}
	rows := make([]ranked, 0, len(peers))
	for _, p := range peers {
		coord := strings.TrimPrefix(p.info.ID, "vx6_")
		if byName {
			coord = p.info.NameHash
		}
		b, _ := hex.DecodeString(coord)
		d := make([]byte, len(tb))
		for i := range d {
			d[i] = tb[i] ^ b[i]
		}
		rows = append(rows, ranked{p.info, d})
	}
	sort.Slice(rows, func(i, j int) bool {
		for k := range rows[i].d {
			if rows[i].d[k] != rows[j].d[k] {
				return rows[i].d[k] < rows[j].d[k]
			}
		}
		return rows[i].info.ID < rows[j].info.ID
	})
	if len(rows) > k {
		rows = rows[:k]
	}
	out := make([]proto.NodeInfo, len(rows))
	for i := range rows {
		out[i] = rows[i].info
	}
	return out
}

func captureNode(p *peer, index int, storesDir string) (nodeSnapshot, error) {
	now := time.Now().UTC()
	storePath := filepath.Join(storesDir, fmt.Sprintf("%06d.db", index))
	store, err := dht.OpenPeerStore(storePath)
	if err != nil {
		return nodeSnapshot{}, err
	}
	if err := store.SaveSnapshot(p.server.RT.SnapshotPeers(), now); err != nil {
		_ = store.Close()
		return nodeSnapshot{}, err
	}
	storeDiag, diagErr := store.Diagnostics(now)
	_ = store.Close()
	table := p.server.RT.Diagnostics(now)
	s := nodeSnapshot{NodeID: p.info.ID, Name: p.info.Name, SignedIdentity: p.info, JoinIndex: index, Active: table.Active,
		IDIndex: table.IDIndex, NameIndex: table.NameIndex, Offline: table.OfflinePeers, Pending: table.PendingPeers}
	s.IDBucketPlacementErrors = bucketPlacementErrors(table.IDIndex, p.info.ID)
	s.NameBucketPlacementErrors = bucketPlacementErrors(table.NameIndex, p.info.NameHash)
	if diagErr != nil {
		s.StoreError = diagErr.Error()
	} else {
		s.Bbolt = &storeDiag
	}
	reloaded, err := dht.OpenPeerStore(storePath)
	if err != nil {
		return nodeSnapshot{}, err
	}
	candidates, err := reloaded.LoadCandidates(now, 512)
	_ = reloaded.Close()
	if err != nil {
		return nodeSnapshot{}, err
	}
	s.BboltReloadedCandidates = len(candidates)
	return s, nil
}

func bucketPlacementErrors(index dht.DiagnosticIndex, selfCoordinate string) int {
	bad := 0
	for _, bucket := range index.Buckets {
		for _, peer := range bucket.Peers {
			coordinate := peer.NodeID
			if index.Space == "name_hash" {
				coordinate = peer.NameHash
			}
			if xorBucketIndex(selfCoordinate, coordinate) != bucket.Index {
				bad++
			}
		}
	}
	return bad
}

func xorBucketIndex(left, right string) int {
	left = strings.TrimPrefix(left, "vx6_")
	right = strings.TrimPrefix(right, "vx6_")
	a, errA := hex.DecodeString(left)
	b, errB := hex.DecodeString(right)
	if errA != nil || errB != nil || len(a) != 32 || len(b) != 32 {
		return -2
	}
	xor := make([]byte, 32)
	for i := range xor {
		xor[i] = a[i] ^ b[i]
	}
	return new(big.Int).SetBytes(xor).BitLen() - 1
}

func summarize(nodes int, rows []lookupSample, snaps []nodeSnapshot, idBuckets, nameBuckets int, elapsed time.Duration) metrics {
	m := metrics{Nodes: nodes, LookupAttempts: len(rows), MinActivePeers: nodes, IDNonEmptyBuckets: idBuckets, NameNonEmptyBuckets: nameBuckets,
		PassCriteria: "measurement only: report rates and failures; no global-reachability claim. Exact-top4 means first four returned candidates equal the global oracle and is expected only where lookup has enough complete knowledge."}
	queries, durations := make([]int, 0, len(rows)), make([]float64, 0, len(rows))
	for _, row := range rows {
		queries = append(queries, row.Queries)
		durations = append(durations, row.DurationMS)
		if row.FoundTarget {
			m.Found++
			if row.Outcome == string(dht.LookupFound) || row.Outcome == string(dht.LookupConflict) {
				m.FoundComplete++
			}
			if row.Outcome == string(dht.LookupIncomplete) {
				m.FoundIncomplete++
			}
		}
		if row.NegativeTarget {
			m.NegativeLookups++
			if row.Outcome == string(dht.LookupNotFound) {
				m.NegativeNotFound++
			}
			if row.Outcome == string(dht.LookupIncomplete) {
				m.NegativeIncomplete++
			}
			if row.FoundTarget {
				m.NegativeFalsePositive++
			}
		}
		if row.Outcome == string(dht.LookupNotFound) {
			m.NotFound++
		}
		if row.Outcome == string(dht.LookupIncomplete) {
			m.Incomplete++
		}
		if row.Error != "" && row.Outcome != string(dht.LookupIncomplete) {
			m.Errors++
		}
		if row.Space == "name_hash" {
			m.NameLookupAttempts++
			if row.FoundTarget {
				m.NameLookupFound++
				if row.Outcome == string(dht.LookupFound) || row.Outcome == string(dht.LookupConflict) {
					m.NameLookupCompleteFound++
				}
			}
		} else {
			m.IDLookupAttempts++
			if row.FoundTarget {
				m.IDLookupFound++
				if row.Outcome == string(dht.LookupFound) || row.Outcome == string(dht.LookupConflict) {
					m.IDLookupCompleteFound++
				}
			}
		}
		if len(row.ExpectedTop4) == 4 {
			m.Top4Checks++
			if row.ExactTop4 {
				m.ExactTop4++
			}
		}
	}
	sort.Ints(queries)
	sort.Float64s(durations)
	if len(rows) > 0 {
		sum := 0
		for _, q := range queries {
			sum += q
		}
		m.MeanQueries = float64(sum) / float64(len(rows))
		m.P50Queries, m.P95Queries = percentileInt(queries, .50), percentileInt(queries, .95)
		m.P50DurationMS, m.P95DurationMS = percentileFloat(durations, .50), percentileFloat(durations, .95)
	}
	for _, s := range snaps {
		m.ActivePeerCount += s.Active
		if s.Active < m.MinActivePeers {
			m.MinActivePeers = s.Active
		}
		if s.Active > m.MaxActivePeers {
			m.MaxActivePeers = s.Active
		}
	}
	if nodes > 0 {
		m.MeanActivePeers = float64(m.ActivePeerCount) / float64(nodes)
	}
	m.ElapsedSeconds = elapsed.Seconds()
	return m
}

func percentileInt(a []int, p float64) int {
	if len(a) == 0 {
		return 0
	}
	i := int(float64(len(a)-1) * p)
	return a[i]
}
func percentileFloat(a []float64, p float64) float64 {
	if len(a) == 0 {
		return 0
	}
	i := int(float64(len(a)-1) * p)
	return a[i]
}
func percent(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return 100 * float64(n) / float64(d)
}
func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		fatal("write %s: %v", path, err)
	}
}
func writeMarkdown(path string, r report, lookups []lookupSample, snaps []nodeSnapshot) {
	m := r.Metrics
	var b strings.Builder
	fmt.Fprintf(&b, "# VX6 DHT Scale Run\n\n- Revision: `%s`\n- Started: %s\n- Platform: `%s`\n- Transport: %s\n- Seed: `%d`\n- Nodes: **%d**\n- Routing K: **%d**; active/offline caps: **%d/%d** (0 means uncapped)\n\n", r.Revision, r.StartedAt.Format(time.RFC3339), r.Platform, r.Transport, r.Seed, m.Nodes, r.LookupPolicy.K, r.LookupPolicy.MaxActivePeers, r.LookupPolicy.MaxOfflinePeers)
	fmt.Fprintf(&b, "## Lookup Results\n\n| Metric | Result |\n|---|---:|\n| Total attempts | %d |\n| Found | %d (%.2f%%) |\n| Name-hash found | %d/%d (%.2f%%) |\n| NodeID found | %d/%d (%.2f%%) |\n| Not found in reachable view | %d |\n| Incomplete | %d |\n| Other errors | %d |\n| Returned first-four equal global oracle | %d/%d (%.2f%%) |\n| Queries p50 / p95 | %d / %d |\n| Duration p50 / p95 | %.2f / %.2f ms |\n\n", m.LookupAttempts, m.Found, percent(m.Found, m.LookupAttempts), m.NameLookupFound, m.NameLookupAttempts, percent(m.NameLookupFound, m.NameLookupAttempts), m.IDLookupFound, m.IDLookupAttempts, percent(m.IDLookupFound, m.IDLookupAttempts), m.NotFound, m.Incomplete, m.Errors, m.ExactTop4, m.Top4Checks, percent(m.ExactTop4, m.Top4Checks), m.P50Queries, m.P95Queries, m.P50DurationMS, m.P95DurationMS)
	fmt.Fprintf(&b, "- Complete found (no exhausted lookup budget): **%d**; matched target but incomplete: **%d**\n- Complete found by coordinate: NodeID **%d/%d**, name hash **%d/%d**\n- Negative controls: not-found **%d/%d**, incomplete **%d**, false positives **%d**\n\n", m.FoundComplete, m.FoundIncomplete, m.IDLookupCompleteFound, m.IDLookupAttempts-m.NegativeLookups/2, m.NameLookupCompleteFound, m.NameLookupAttempts-m.NegativeLookups/2, m.NegativeNotFound, m.NegativeLookups, m.NegativeIncomplete, m.NegativeFalsePositive)
	fmt.Fprintf(&b, "## Idle Routing Snapshot\n\nThis is a final-state snapshot after all staged joins and sampled lookups; this run does not wait through the production 5-minute maintenance cadence.\n\n- Active peer entries: %d total; mean %.2f, min %d, max %d\n- Non-empty NodeID buckets summed across nodes: %d\n- Non-empty name-hash buckets summed across nodes: %d\n- Active-table recall of each node's global nearest four: NodeID %.2f%%; name-hash %.2f%%\n- Heap allocation after capture: %d bytes; heap system: %d bytes; goroutines: %d\n- Elapsed: %.2f seconds\n- Per-node snapshots: `snapshots/all-nodes.json`\n- Per-lookup records and traces: `lookups/`\n- Per-node bbolt files: `stores/`\n- Join events: `join/`\n\n", m.ActivePeerCount, m.MeanActivePeers, m.MinActivePeers, m.MaxActivePeers, m.IDNonEmptyBuckets, m.NameNonEmptyBuckets, m.IDGlobalTop4Recall, m.NameGlobalTop4Recall, m.HeapAllocBytes, m.HeapSysBytes, m.Goroutines, m.ElapsedSeconds)
	fmt.Fprintf(&b, "- Bucket-placement errors (independent XOR audit): NodeID **%d**, name hash **%d**\n- bbolt peer rows / total store bytes: **%d / %d**\n", m.IDBucketPlacementErrors, m.NameBucketPlacementErrors, m.BboltPeerRows, m.BboltBytes)
	fmt.Fprintf(&b, "## Interpretation\n\nThis is a deterministic-growth simulation using production `RoutingTable`, DHT request validation/handler, signed endpoint records, and iterative lookup over loopback TCP. IPsec, IKE, public Internet routing, realistic IPv6/ASN diversity, malicious Sybil behavior, and multi-host packet loss are not exercised. The global XOR oracle is only a test oracle: a DHT is not expected to return a globally closest peer unless its reachable referrals expose that peer. `not_found_reachable` means the search exhausted the reachable view; it is not proof the target is globally absent. `incomplete` means a query failed or the lookup budget expired.\n\nThe snapshots show locally stored peers in both indexes; the two indexes are views over each node's local verified peer set, not globally complete maps. Compare route degree and bucket ranks with lookup traces. The bbolt files record the peer observations at capture time and are not a claim that restart bootstrap was exercised.\n\n### Sampled query outcomes\n\n| Space | Attempts | Found | Exact top four | Mean queries | p95 queries |\n|---|---:|---:|---:|---:|---:|\n")
	for _, space := range []string{"node_id", "name_hash"} {
		var count, found, exact, q int
		var qs []int
		for _, row := range lookups {
			if row.Space == space {
				count++
				q += row.Queries
				qs = append(qs, row.Queries)
				if row.FoundTarget {
					found++
				}
				if row.ExactTop4 {
					exact++
				}
			}
		}
		if count > 0 {
			sort.Ints(qs)
			fmt.Fprintf(&b, "| %s | %d | %d (%.1f%%) | %d (%.1f%%) | %.2f | %d |\n", space, count, found, percent(found, count), exact, percent(exact, count), float64(q)/float64(count), percentileInt(qs, .95))
		}
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		fatal("write report markdown: %v", err)
	}
}
func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
