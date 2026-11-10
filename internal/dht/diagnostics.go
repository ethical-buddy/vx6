package dht

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vx6/vx6/internal/proto"
	bolt "go.etcd.io/bbolt"
)

// This file exposes read-only diagnostics for simulators and tests. Nothing
// here admits, promotes, evicts or persists peers, and nothing changes lookup
// behaviour: every function takes read locks or a bbolt View transaction and
// returns copies.

// DiagnosticPeer is one routing-table entry with its local observations.
type DiagnosticPeer struct {
	Name             string    `json:"name,omitempty"`
	NodeID           string    `json:"node_id"`
	NameHash         string    `json:"name_hash,omitempty"`
	Addr             string    `json:"addr"`
	State            string    `json:"state"` // active, offline or pending
	Transient        bool      `json:"transient,omitempty"`
	SuccessCount     uint32    `json:"success_count"`
	FailCount        uint8     `json:"fail_count"`
	RTTMicros        uint32    `json:"rtt_us,omitempty"`
	FirstSeen        time.Time `json:"first_seen,omitempty"`
	LastSeen         time.Time `json:"last_seen,omitempty"`
	LastSuccess      time.Time `json:"last_success,omitempty"`
	LastUsed         time.Time `json:"last_used,omitempty"`
	LastFailure      time.Time `json:"last_failure,omitempty"`
	LastProbe        time.Time `json:"last_probe,omitempty"`
	LastProbeFailure time.Time `json:"last_probe_failure,omitempty"`
	NextProbeAt      time.Time `json:"next_probe_at,omitempty"`
	OfflineSince     time.Time `json:"offline_since,omitempty"`
	ProbeMisses      uint8     `json:"probe_misses,omitempty"`
	ProbationUntil   time.Time `json:"probation_until,omitempty"`
	InProbation      bool      `json:"in_probation"`
	Friend           bool      `json:"friend,omitempty"`
	Pinned           bool      `json:"pinned,omitempty"`
	UseCount         uint32    `json:"use_count,omitempty"`
	ClosestIDRank    uint16    `json:"closest_id_rank,omitempty"`
	ClosestNameRank  uint16    `json:"closest_name_rank,omitempty"`
}

// DiagnosticBucket is one non-empty XOR bucket.
type DiagnosticBucket struct {
	Index int              `json:"index"`
	Peers []DiagnosticPeer `json:"peers"`
}

// DiagnosticIndex describes one XOR coordinate space over the shared active
// peer set. Empty buckets are summarized by NonEmptyBuckets, not listed.
type DiagnosticIndex struct {
	Space           string             `json:"space"` // node_id or name_hash
	Entries         int                `json:"entries"`
	NonEmptyBuckets int                `json:"non_empty_buckets"`
	Occupancy       map[int]int        `json:"occupancy_histogram"` // bucket size -> number of buckets
	Buckets         []DiagnosticBucket `json:"buckets"`
}

// CapacityPolicy records the routing-table limits this build enforces, so a
// report states which capacity policy it measured.
type CapacityPolicy struct {
	K                    int `json:"k"`
	MaxPendingCandidates int `json:"max_pending_candidates"`
	// MaxActivePeers / MaxOfflinePeers are 0 when this build has no cap.
	MaxActivePeers  int `json:"max_active_peers"`
	MaxOfflinePeers int `json:"max_offline_peers"`
	WarmStartFloor  int `json:"warm_start_candidates"`
}

// Builds whose table enforces active/offline caps must report them here (see
// CapacityPolicyInfo). This revision has no such caps.
var (
	diagnosticActivePeerCap  = 0
	diagnosticOfflinePeerCap = 0
)

func CapacityPolicyInfo() CapacityPolicy {
	return CapacityPolicy{K: K, MaxPendingCandidates: maxPendingCandidates,
		MaxActivePeers: diagnosticActivePeerCap, MaxOfflinePeers: diagnosticOfflinePeerCap,
		WarmStartFloor: minimumPeerWarmStart}
}

// TableDiagnostics is an in-memory routing-table snapshot.
type TableDiagnostics struct {
	Source       string           `json:"source"` // always "memory"
	SelfID       string           `json:"self_id"`
	SelfNameHash string           `json:"self_name_hash"`
	Active       int              `json:"active"`
	Offline      int              `json:"offline"`
	Pending      int              `json:"pending"`
	IDIndex      DiagnosticIndex  `json:"node_id_index"`
	NameIndex    DiagnosticIndex  `json:"name_hash_index"`
	OfflinePeers []DiagnosticPeer `json:"offline_peers,omitempty"`
	PendingPeers []DiagnosticPeer `json:"pending_peers,omitempty"`
	Capacity     CapacityPolicy   `json:"capacity_policy"`
}

// Diagnostics returns a copy of both XOR indexes plus offline and pending
// entries. It holds only the table's read lock.
func (rt *RoutingTable) Diagnostics(now time.Time) TableDiagnostics {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := TableDiagnostics{Source: "memory", SelfID: rt.SelfID, SelfNameHash: rt.SelfNameHash,
		Capacity: CapacityPolicyInfo()}
	out.IDIndex = diagnosticIndexLocked("node_id", rt.Buckets[:], "active", now)
	out.NameIndex = diagnosticIndexLocked("name_hash", rt.NameBuckets[:], "active", now)
	out.Active = out.IDIndex.Entries
	for _, entry := range rt.offline {
		out.OfflinePeers = append(out.OfflinePeers, diagnosticPeer(entry, "offline", now))
	}
	sort.Slice(out.OfflinePeers, func(i, j int) bool { return out.OfflinePeers[i].NodeID < out.OfflinePeers[j].NodeID })
	out.Offline = len(out.OfflinePeers)
	for _, bucket := range rt.Pending {
		for _, entry := range bucket {
			out.PendingPeers = append(out.PendingPeers, diagnosticPeer(entry, "pending", now))
		}
	}
	sort.Slice(out.PendingPeers, func(i, j int) bool { return out.PendingPeers[i].NodeID < out.PendingPeers[j].NodeID })
	out.Pending = len(out.PendingPeers)
	return out
}

func diagnosticIndexLocked(space string, buckets [][]*bucketEntry, state string, now time.Time) DiagnosticIndex {
	index := DiagnosticIndex{Space: space, Occupancy: map[int]int{}}
	for i, bucket := range buckets {
		if len(bucket) == 0 {
			continue
		}
		index.NonEmptyBuckets++
		index.Entries += len(bucket)
		index.Occupancy[len(bucket)]++
		row := DiagnosticBucket{Index: i, Peers: make([]DiagnosticPeer, 0, len(bucket))}
		for _, entry := range bucket {
			row.Peers = append(row.Peers, diagnosticPeer(entry, state, now))
		}
		index.Buckets = append(index.Buckets, row)
	}
	return index
}

func diagnosticPeer(entry *bucketEntry, state string, now time.Time) DiagnosticPeer {
	if state == "active" && !entry.OfflineSince.IsZero() {
		state = "offline"
	}
	return DiagnosticPeer{Name: entry.Node.Name, NodeID: entry.Node.ID, NameHash: nodeNameHash(entry.Node),
		Addr: entry.Node.Addr, State: state, Transient: entry.Transient,
		SuccessCount: entry.SuccessCount, FailCount: entry.FailCount, RTTMicros: entry.RTTMicros,
		FirstSeen: entry.FirstSeen, LastSeen: entry.LastSeen, LastSuccess: entry.LastSuccess,
		LastUsed: entry.LastUsed, LastFailure: entry.LastFailure, LastProbe: entry.LastProbe,
		LastProbeFailure: entry.LastProbeFailure, NextProbeAt: entry.NextProbeAt,
		OfflineSince: entry.OfflineSince, ProbeMisses: entry.ProbeMisses, ProbationUntil: entry.ProbationUntil,
		InProbation: !entry.ProbationUntil.IsZero() && now.Before(entry.ProbationUntil),
		Friend:      entry.Friend, Pinned: entry.Pinned, UseCount: entry.UseCount,
		ClosestIDRank: entry.ClosestIDRank, ClosestNameRank: entry.ClosestNameRank}
}

// StoreDiagnostics summarizes the persisted bbolt state. Payloads of stored
// values are never included.
type StoreDiagnostics struct {
	Source        string              `json:"source"` // always "bbolt"
	PeerRows      int                 `json:"peer_rows"`
	NameIndexRows int                 `json:"name_index_rows"`
	DiversityRows int                 `json:"diversity_rows"`
	Categories    map[string][]string `json:"categories"` // category -> NodeIDs
	Values        []StoredValueHealth `json:"values"`
}

// StoredValueHealth is the validity and expiry of one persisted value.
type StoredValueHealth struct {
	Key       string    `json:"key"`
	Bytes     int       `json:"bytes"`
	Valid     bool      `json:"valid"`
	Family    string    `json:"family,omitempty"`
	IssuedAt  time.Time `json:"issued_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// Diagnostics reads the already-open store in one View transaction.
func (s *PeerStore) Diagnostics(now time.Time) (StoreDiagnostics, error) {
	out := StoreDiagnostics{Source: "bbolt", Categories: map[string][]string{}}
	err := s.db.View(func(tx *bolt.Tx) error {
		count := func(name string) int {
			bucket := tx.Bucket([]byte(name))
			if bucket == nil {
				return 0
			}
			return bucket.Stats().KeyN
		}
		out.PeerRows = count(peerBucketName)
		out.NameIndexRows = count(peerNameIndexName)
		out.DiversityRows = count(peerDiversityIndexName)
		for _, name := range peerCategoryIndexNames {
			members := []string{}
			if bucket := tx.Bucket([]byte(name)); bucket != nil {
				_ = bucket.ForEach(func(key, _ []byte) error {
					members = append(members, string(key))
					return nil
				})
			}
			out.Categories[strings.TrimSuffix(name, "-v1")] = members
		}
		if bucket := tx.Bucket([]byte(peerValuesBucketName)); bucket != nil {
			_ = bucket.ForEach(func(key, value []byte) error {
				health := StoredValueHealth{Key: string(key), Bytes: len(value)}
				validated, err := validateLookupValue(string(key), string(value), now)
				if err != nil {
					health.Error = err.Error()
				} else {
					health.Valid = validated.verified
					health.Family = validated.family
					health.IssuedAt = validated.issuedAt
					health.ExpiresAt = validated.expiresAt
				}
				out.Values = append(out.Values, health)
				return nil
			})
		}
		return nil
	})
	return out, err
}

// ServerDiagnostics combines the in-memory table with the persisted store.
type ServerDiagnostics struct {
	Table          TableDiagnostics  `json:"table"`
	Store          *StoreDiagnostics `json:"store,omitempty"`
	StoreError     string            `json:"store_error,omitempty"`
	CachedValues   int               `json:"cached_values"`
	CachedValueKey []string          `json:"cached_value_keys,omitempty"`
}

// Diagnostics reads the routing table and, when this server was given a
// PeerStore for value persistence, that same open store. It never opens a
// second bbolt handle.
func (s *Server) Diagnostics(now time.Time) ServerDiagnostics {
	out := ServerDiagnostics{Table: s.RT.Diagnostics(now)}
	s.mu.RLock()
	store, _ := s.valuePersistence.(*PeerStore)
	out.CachedValues = len(s.Values)
	for key := range s.Values {
		out.CachedValueKey = append(out.CachedValueKey, key)
	}
	s.mu.RUnlock()
	sort.Strings(out.CachedValueKey)
	if store != nil {
		diag, err := store.Diagnostics(now)
		if err != nil {
			out.StoreError = err.Error()
		} else {
			out.Store = &diag
		}
	}
	return out
}

// LookupTrace records how one node lookup progressed. Attach it with
// WithLookupTrace; lookups without a trace behave and allocate as before.
type LookupTrace struct {
	mu         sync.Mutex
	Target     string         `json:"target"`
	Space      string         `json:"space"` // node_id or name_hash
	Seeds      []TraceContact `json:"seeds"`
	Rounds     []TraceRound   `json:"rounds"`
	StopReason string         `json:"stop_reason"`
	Outcome    string         `json:"outcome"`
	Queries    int            `json:"queries"`
}

// TraceRound is one batch of parallel peer queries.
type TraceRound struct {
	Round         int          `json:"round"`
	Queries       []TraceQuery `json:"queries"`
	BestBefore    int          `json:"best_shared_prefix_bits_before"`
	BestAfter     int          `json:"best_shared_prefix_bits_after"`
	Progress      bool         `json:"progress"`
	NewCandidates int          `json:"new_candidates"`
	Duplicates    int          `json:"duplicate_candidates"`
	Rejected      int          `json:"rejected_referrals"`
}

// TraceQuery is one responder's answer within a round.
type TraceQuery struct {
	Responder TraceContact   `json:"responder"`
	Result    string         `json:"result"` // ok, error or timeout
	Error     string         `json:"error,omitempty"`
	Returned  []TraceContact `json:"returned,omitempty"`
}

// TraceContact identifies a contact and how close it is to the target, as
// the number of leading bits it shares with the target (higher is closer).
type TraceContact struct {
	NodeID          string `json:"node_id"`
	Name            string `json:"name,omitempty"`
	Addr            string `json:"addr,omitempty"`
	SharedPrefixLen int    `json:"shared_prefix_bits"`
	Duplicate       bool   `json:"duplicate,omitempty"`
	Match           bool   `json:"match,omitempty"`
}

type lookupTraceKey struct{}

// WithLookupTrace returns a context whose node lookups record into trace.
func WithLookupTrace(ctx context.Context, trace *LookupTrace) context.Context {
	return context.WithValue(ctx, lookupTraceKey{}, trace)
}

func lookupTraceFrom(ctx context.Context) *LookupTrace {
	trace, _ := ctx.Value(lookupTraceKey{}).(*LookupTrace)
	return trace
}

func traceContact(node proto.NodeInfo, target string) TraceContact {
	return TraceContact{NodeID: node.ID, Name: node.Name, Addr: node.Addr,
		SharedPrefixLen: 256 - xorDistanceForNode(node, target).BitLen(),
		Match:           matchesNodeLookupTarget(node, target)}
}

func bestSharedPrefix(known map[string]proto.NodeInfo, target string) int {
	best := -1
	for _, node := range known {
		if bits := 256 - xorDistanceForNode(node, target).BitLen(); bits > best {
			best = bits
		}
	}
	return best
}

func (t *LookupTrace) start(target string, seeds map[string]proto.NodeInfo) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Target = target
	t.Space = "node_id"
	if strings.HasPrefix(target, "node/name/") {
		t.Space = "name_hash"
	}
	for _, node := range seeds {
		t.Seeds = append(t.Seeds, traceContact(node, target))
	}
	sort.Slice(t.Seeds, func(i, j int) bool { return t.Seeds[i].SharedPrefixLen > t.Seeds[j].SharedPrefixLen })
}

func (t *LookupTrace) addRound(round TraceRound) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.Rounds = append(t.Rounds, round)
	t.mu.Unlock()
}

// finish derives why the lookup stopped from its outcome and error.
func (t *LookupTrace) finish(res NodeLookupResult, err error) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Outcome = string(res.Outcome)
	t.Queries = res.QueriedNodes
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	switch {
	case res.Outcome == LookupFound && res.Rounds == 0:
		t.StopReason = "target found among local seeds"
	case res.Outcome == LookupFound || res.Outcome == LookupConflict:
		t.StopReason = "target found"
	case res.Outcome == LookupNotFound:
		t.StopReason = "converged: no unqueried contacts left"
	case strings.Contains(msg, "query/round limit"):
		t.StopReason = "incomplete: query/round limit reached"
	case strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "context canceled"):
		t.StopReason = "incomplete: time budget exhausted"
	case strings.Contains(msg, "peer queries failed"):
		t.StopReason = "incomplete: converged but some peer queries failed"
	case err != nil:
		t.StopReason = "incomplete: " + msg
	default:
		t.StopReason = "stopped"
	}
}

func classifyQueryError(err error) string {
	if err == nil {
		return "ok"
	}
	msg := err.Error()
	if strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "timeout") {
		return "timeout"
	}
	return "error"
}
