package dht

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
)

const K = 20

const (
	maxPendingCandidates  = 512
	staleFailureThreshold = 3
	livenessProbeInterval = 5 * time.Minute
	peerProbationPeriod   = 2 * time.Hour
	bucketRefillThreshold = 15
	bucketRefreshInterval = 5 * time.Minute
	peerAddressHintTTL    = 30 * 24 * time.Hour
	peerCacheHotLimit     = 512
	minimumPeerWarmStart  = 50
)

type bucketEntry struct {
	Node             proto.NodeInfo `json:"node"`
	Transient        bool           `json:"-"`
	FailCount        uint8          `json:"fail_count,omitempty"`
	SuccessCount     uint32         `json:"success_count,omitempty"`
	LastSeen         time.Time      `json:"last_seen,omitempty"`
	FirstSeen        time.Time      `json:"first_seen,omitempty"`
	LastSuccess      time.Time      `json:"last_success,omitempty"`
	LastUsed         time.Time      `json:"last_used,omitempty"`
	LastFailure      time.Time      `json:"last_failure,omitempty"`
	LastProbe        time.Time      `json:"last_probe,omitempty"`
	LastProbeFailure time.Time      `json:"last_probe_failure,omitempty"`
	OfflineSince     time.Time      `json:"offline_since,omitempty"`
	ProbeMisses      uint8          `json:"probe_misses,omitempty"`
	ProbationUntil   time.Time      `json:"probation_until,omitempty"`
	NextProbeAt      time.Time      `json:"next_probe_at,omitempty"`
	RTTMicros        uint32         `json:"rtt_micros,omitempty"`
	Pinned           bool           `json:"pinned,omitempty"`
	Friend           bool           `json:"friend,omitempty"`
	UseCount         uint32         `json:"use_count,omitempty"`
	ClosestIDRank    uint16         `json:"closest_id_rank,omitempty"`
	ClosestNameRank  uint16         `json:"closest_name_rank,omitempty"`
}

type PeerObservation struct {
	Node             proto.NodeInfo
	FailCount        uint8
	SuccessCount     uint32
	LastSeen         time.Time
	FirstSeen        time.Time
	LastSuccess      time.Time
	LastUsed         time.Time
	LastFailure      time.Time
	LastProbe        time.Time
	LastProbeFailure time.Time
	OfflineSince     time.Time
	ProbeMisses      uint8
	ProbationUntil   time.Time
	NextProbeAt      time.Time
	RTTMicros        uint32
	Pinned           bool
	Friend           bool
	UseCount         uint32
	ClosestIDRank    uint16
	ClosestNameRank  uint16
}

type RefreshTarget struct {
	Key      string
	NameHash bool
	Bucket   int
}

type RoutingTable struct {
	SelfID       string
	SelfNameHash string
	mu           sync.RWMutex

	// Bucket arrays have fixed, cheap headers; their peer slices grow only when
	// verified peers are actually learned.
	Buckets         [256][]*bucketEntry
	NameBuckets     [256][]*bucketEntry
	Pending         [256][]*bucketEntry
	peerByID        map[string]*bucketEntry
	offline         map[string]*bucketEntry
	pendingN        int
	lastIDRefresh   [256]time.Time
	lastNameRefresh [256]time.Time
	refreshNameNext bool
}

func NewRoutingTable(selfID string) *RoutingTable {
	return &RoutingTable{SelfID: selfID, SelfNameHash: NodeNameHash(selfID), peerByID: make(map[string]*bucketEntry), offline: make(map[string]*bucketEntry)}
}

func (rt *RoutingTable) SetSelfNameHash(hash string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.SelfNameHash = hash
	rt.NameBuckets = [256][]*bucketEntry{}
	entries := make([]*bucketEntry, 0, len(rt.peerByID))
	for _, entry := range rt.peerByID {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Node.ID < entries[j].Node.ID })
	for _, entry := range entries {
		if rt.containsEntry(rt.Buckets, entry.Node.ID) {
			rt.insertIndexLocked(rt.NameBuckets[:], entry, rt.nameBucketIndex(entry.Node))
		}
	}
}

// AddNode records an authenticated, successful peer exchange and makes the
// peer eligible for active routing slots.
func (rt *RoutingTable) AddNode(node proto.NodeInfo) {
	if node.ID == "" || node.ID == rt.SelfID || node.Addr == "" {
		return
	}
	now := time.Now()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	entry := rt.peerByID[node.ID]
	if entry == nil {
		entry = &bucketEntry{Node: node, ProbationUntil: now.Add(peerProbationPeriod)}
		rt.peerByID[node.ID] = entry
	} else {
		if nodeNameHash(entry.Node) != nodeNameHash(node) {
			rt.removeFromIndexLocked(rt.NameBuckets[:], node.ID)
		}
		entry.Node = node
		if entry.ProbationUntil.IsZero() && entry.SuccessCount == 0 && !entry.Pinned {
			entry.ProbationUntil = now.Add(peerProbationPeriod)
		}
	}
	entry.Transient = false
	delete(rt.offline, node.ID)
	entry.FailCount = 0
	entry.NextProbeAt = time.Time{}
	entry.LastSeen = now
	if entry.FirstSeen.IsZero() {
		entry.FirstSeen = now
	}
	entry.LastSuccess = now
	entry.LastProbe = now
	entry.NextProbeAt = now.Add(initialProbeDelay(node.ID))
	entry.ProbeMisses = 0
	entry.LastProbeFailure = time.Time{}
	entry.OfflineSince = time.Time{}
	if entry.SuccessCount < ^uint32(0) {
		entry.SuccessCount++
	}
	rt.removePendingLocked(node.ID)
	rt.insertIndexLocked(rt.Buckets[:], entry, rt.bucketIndex(node.ID))
	if rt.SelfNameHash != "" {
		rt.insertIndexLocked(rt.NameBuckets[:], entry, rt.nameBucketIndex(node))
	}
}

// UpdateKnownNode refreshes signed endpoint metadata for a peer this table
// already knows. It never creates or promotes a peer from a record alone.
func (rt *RoutingTable) UpdateKnownNode(node proto.NodeInfo) bool {
	if node.ID == "" || node.ID == rt.SelfID || node.Addr == "" || VerifyNodeInfo(node, time.Now()) != nil {
		return false
	}
	incoming := endpointRecordFromNodeInfo(node)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	entry := rt.peerByID[node.ID]
	if entry == nil {
		return false
	}
	current := endpointRecordFromNodeInfo(entry.Node)
	if !record.EndpointRecordNewer(incoming, current) {
		return false
	}
	if nodeNameHash(entry.Node) != nodeNameHash(node) {
		rt.removeFromIndexLocked(rt.NameBuckets[:], node.ID)
	}
	entry.Node = node
	if rt.inIndexLocked(rt.Buckets[:], node.ID) && rt.SelfNameHash != "" {
		rt.insertIndexLocked(rt.NameBuckets[:], entry, rt.nameBucketIndex(node))
	}
	return true
}

func endpointRecordFromNodeInfo(node proto.NodeInfo) record.EndpointRecord {
	return record.EndpointRecord{
		Version: node.IdentityVersion, Sequence: node.IdentitySequence,
		NodeID: node.ID, NodeName: node.Name, Address: node.Addr,
		PublicKey: node.PublicKey, IssuedAt: node.IdentityIssuedAt,
		ExpiresAt: node.IdentityExpiresAt, Signature: node.IdentitySignature,
	}
}

// AddCandidate keeps a referral or persisted peer out of active routes until
// it has responded successfully through the authenticated VX6 path.
func (rt *RoutingTable) AddCandidate(node proto.NodeInfo) {
	rt.addCandidate(node)
}

// AddLookupCandidate makes a signed referral available to the guarded transport
// during one lookup without allowing periodic peer-store snapshots to persist it.
func (rt *RoutingTable) AddLookupCandidate(node proto.NodeInfo) bool {
	if node.ID == "" || node.ID == rt.SelfID || node.Addr == "" {
		return false
	}
	idx := rt.bucketIndex(node.ID)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.peerByID[node.ID] != nil || rt.pendingN >= maxPendingCandidates {
		return false
	}
	entry := &bucketEntry{Node: node, Transient: true}
	rt.peerByID[node.ID] = entry
	rt.Pending[idx] = append(rt.Pending[idx], entry)
	rt.pendingN++
	return true
}

func (rt *RoutingTable) addCandidate(node proto.NodeInfo) {
	if node.ID == "" || node.ID == rt.SelfID || node.Addr == "" {
		return
	}
	idx := rt.bucketIndex(node.ID)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.inIndexLocked(rt.Buckets[:], node.ID) || rt.inIndexLocked(rt.NameBuckets[:], node.ID) {
		return
	}
	entry := rt.peerByID[node.ID]
	if entry != nil && rt.removePendingLocked(node.ID) {
		// Refreshing a candidate must not consume a second slot.
		entry.Node = node
		delete(rt.offline, node.ID)
		rt.Pending[idx] = append(rt.Pending[idx], entry)
		return
	}
	if rt.pendingN >= maxPendingCandidates {
		return
	}
	if entry == nil {
		entry = &bucketEntry{Node: node}
		rt.peerByID[node.ID] = entry
	} else {
		entry.Node = node
	}
	entry.Transient = false
	delete(rt.offline, node.ID)
	rt.Pending[idx] = append(rt.Pending[idx], entry)
	rt.pendingN++
}

func (rt *RoutingTable) RestoreCandidates(peers []PeerObservation, now time.Time) {
	if len(peers) > peerCacheHotLimit {
		sort.Slice(peers, func(i, j int) bool { return peers[i].LastSuccess.After(peers[j].LastSuccess) })
		peers = peers[:peerCacheHotLimit]
	}
	for _, peer := range peers {
		if peer.Node.ID == "" || peer.Node.Addr == "" ||
			(!peer.Pinned && !peer.Friend && ((!peer.OfflineSince.IsZero() && now.Sub(peer.OfflineSince) > peerHistoryTTL) ||
				(peer.OfflineSince.IsZero() && !peer.LastSeen.IsZero() && now.Sub(peer.LastSeen) > peerAddressHintTTL))) {
			continue
		}
		rt.AddCandidate(peer.Node)
		rt.mu.Lock()
		if entry := rt.peerByID[peer.Node.ID]; entry != nil {
			entry.FailCount = peer.FailCount
			entry.SuccessCount = peer.SuccessCount
			entry.LastSeen = peer.LastSeen
			entry.LastSuccess = peer.LastSuccess
			entry.LastUsed = peer.LastUsed
			entry.FirstSeen = peer.FirstSeen
			entry.LastFailure = peer.LastFailure
			entry.LastProbe = peer.LastProbe
			entry.LastProbeFailure = peer.LastProbeFailure
			entry.OfflineSince = peer.OfflineSince
			entry.ProbeMisses = peer.ProbeMisses
			entry.ProbationUntil = peer.ProbationUntil
			entry.NextProbeAt = peer.NextProbeAt
			if !peer.OfflineSince.IsZero() {
				rt.removePendingLocked(peer.Node.ID)
				rt.offline[peer.Node.ID] = entry
			}
			entry.RTTMicros = peer.RTTMicros
			entry.Pinned = peer.Pinned
			entry.Friend = peer.Friend
			entry.UseCount = peer.UseCount
			entry.ClosestIDRank = peer.ClosestIDRank
			entry.ClosestNameRank = peer.ClosestNameRank
		}
		rt.mu.Unlock()
	}
}

func (rt *RoutingTable) PromoteCandidate(nodeID string) {
	var node proto.NodeInfo
	rt.mu.Lock()
	for i := range rt.Pending {
		for j, entry := range rt.Pending[i] {
			if entry.Node.ID != nodeID {
				continue
			}
			node = entry.Node
			rt.Pending[i] = append(rt.Pending[i][:j], rt.Pending[i][j+1:]...)
			rt.pendingN--
			break
		}
		if node.ID != "" {
			break
		}
	}
	rt.mu.Unlock()
	if node.ID != "" {
		rt.AddNode(node)
	}
}

func (rt *RoutingTable) DiscardCandidate(nodeID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.removePendingLocked(nodeID) {
		rt.removePeerIfUnindexedLocked(nodeID)
	}
}

func (rt *RoutingTable) NoteFailure(nodeID string) bool {
	return rt.NoteFailureAt(nodeID, time.Now())
}

func (rt *RoutingTable) NoteFailureAt(nodeID string, now time.Time) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	entry := rt.peerByID[nodeID]
	if entry == nil || nodeID == rt.SelfID {
		return false
	}
	entry.LastFailure = now
	if entry.FailCount < ^uint8(0) {
		entry.FailCount++
	}
	return false
}

// BeginLivenessProbe reserves one due peer. Callers should run only one probe
// at a time; reserving it prevents another maintenance pass from duplicating it.
func (rt *RoutingTable) BeginLivenessProbe(now time.Time) (proto.NodeInfo, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	var selected *bucketEntry
	for _, entry := range rt.peerByID {
		if !rt.inIndexLocked(rt.Buckets[:], entry.Node.ID) || now.Before(entry.NextProbeAt) {
			continue
		}
		if selected == nil || entry.LastProbe.Before(selected.LastProbe) {
			selected = entry
		}
	}
	if selected == nil {
		return proto.NodeInfo{}, false
	}
	selected.LastProbe = now
	selected.NextProbeAt = now.Add(livenessProbeInterval)
	return selected.Node, true
}

// RecordLivenessResult counts only explicit identity and tunnel checks. A
// failed lookup alone must not mark a peer offline.
func (rt *RoutingTable) RecordLivenessResult(nodeID string, now time.Time, alive bool) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	entry := rt.peerByID[nodeID]
	if entry == nil {
		return false
	}
	entry.LastProbe = now
	entry.NextProbeAt = now.Add(livenessProbeInterval)
	if alive {
		entry.ProbeMisses = 0
		entry.FailCount = 0
		entry.LastSeen = now
		entry.LastSuccess = now
		entry.LastFailure = time.Time{}
		entry.LastProbeFailure = time.Time{}
		entry.OfflineSince = time.Time{}
		if entry.ProbationUntil.IsZero() {
			entry.ProbationUntil = now.Add(peerProbationPeriod)
		}
		return false
	}
	if !entry.LastProbeFailure.IsZero() && now.Sub(entry.LastProbeFailure) < livenessProbeInterval {
		return false
	}
	if entry.ProbeMisses < ^uint8(0) {
		entry.ProbeMisses++
	}
	entry.LastFailure = now
	entry.LastProbeFailure = now
	if entry.ProbeMisses < staleFailureThreshold {
		return false
	}
	removed := rt.removeFromIndexLocked(rt.Buckets[:], nodeID)
	removed = rt.removeFromIndexLocked(rt.NameBuckets[:], nodeID) || removed
	if removed {
		if entry.OfflineSince.IsZero() {
			entry.OfflineSince = now
		}
		rt.offline[nodeID] = entry
		rt.removePeerIfUnindexedLocked(nodeID)
	} else if entry.ProbeMisses >= staleFailureThreshold {
		rt.removePendingLocked(nodeID)
		if entry.SuccessCount > 0 || entry.Pinned {
			if entry.OfflineSince.IsZero() {
				entry.OfflineSince = now
			}
			rt.offline[nodeID] = entry
		} else {
			delete(rt.peerByID, nodeID)
		}
	}
	return removed
}

func (rt *RoutingTable) RecordUse(nodeID string, now time.Time, rtt time.Duration) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	entry := rt.peerByID[nodeID]
	if entry == nil {
		return
	}
	entry.LastUsed = now
	if entry.UseCount < ^uint32(0) {
		entry.UseCount++
	}
	entry.LastSeen = now
	entry.FailCount = 0
	entry.ProbeMisses = 0
	entry.LastProbeFailure = time.Time{}
	entry.LastProbe = now
	entry.NextProbeAt = now.Add(livenessProbeInterval)
	if rtt > 0 {
		micros := uint64(rtt.Microseconds())
		if micros > uint64(^uint32(0)) {
			micros = uint64(^uint32(0))
		}
		if entry.RTTMicros == 0 {
			entry.RTTMicros = uint32(micros)
		} else {
			entry.RTTMicros = uint32((uint64(entry.RTTMicros)*7 + micros) / 8)
		}
	}
	rt.moveToFrontLocked(rt.Buckets[:], nodeID, rt.bucketIndex(nodeID))
	if rt.SelfNameHash != "" {
		if entry.Node.NameHash == "" {
			entry.Node.NameHash = NodeNameHash(entry.Node.Name)
		}
		rt.moveToFrontLocked(rt.NameBuckets[:], nodeID, rt.nameBucketIndex(entry.Node))
	}
}

// SetPinned keeps a user's trust preference independent from routing slots.
func (rt *RoutingTable) SetPinned(nodeID string, pinned bool) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	entry := rt.peerByID[nodeID]
	if entry == nil {
		return false
	}
	entry.Pinned = pinned
	if !pinned {
		rt.removePeerIfUnindexedLocked(nodeID)
	}
	return true
}

// SetFriend records a local retention preference without changing XOR routing.
func (rt *RoutingTable) SetFriend(nodeID string, friend bool) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	entry := rt.peerByID[nodeID]
	if entry == nil {
		return false
	}
	entry.Friend = friend
	return true
}

func (rt *RoutingTable) ProbeAllowed(nodeID string, now time.Time) bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	entry := rt.peerByID[nodeID]
	return entry == nil || entry.NextProbeAt.IsZero() || !now.Before(entry.NextProbeAt)
}

func (rt *RoutingTable) ClosestNodes(targetID string, count int) []proto.NodeInfo {
	return rt.closestFrom(rt.Buckets[:], targetID, count, false)
}

func (rt *RoutingTable) ClosestNodesByNameHash(targetHash string, count int) []proto.NodeInfo {
	return rt.closestFrom(rt.NameBuckets[:], targetHash, count, true)
}

// DiversityContacts returns active, authenticated peers that add a previously
// unseen IPv6 prefix or ASN to this node's local view. It is a fallback contact
// pool only; normal referrals remain sorted strictly by XOR distance.
func (rt *RoutingTable) DiversityContacts() []proto.NodeInfo {
	rt.mu.RLock()
	entries := make([]bucketEntry, 0, len(rt.peerByID))
	for _, entry := range rt.peerByID {
		if rt.inIndexLocked(rt.Buckets[:], entry.Node.ID) {
			entries = append(entries, *entry)
		}
	}
	rt.mu.RUnlock()
	sort.Slice(entries, func(i, j int) bool {
		left, right := observationOf(&entries[i]), observationOf(&entries[j])
		if peerRetentionLess(left, right) {
			return true
		}
		if peerRetentionLess(right, left) {
			return false
		}
		return entries[i].Node.ID < entries[j].Node.ID
	})

	seen := make(map[string]struct{})
	contacts := make([]proto.NodeInfo, 0)
	for _, entry := range entries {
		keys := peerDiversityKeys(entry.Node.Addr)
		addsCoverage := false
		for _, key := range keys {
			if _, ok := seen[key]; !ok {
				addsCoverage = true
			}
		}
		if !addsCoverage {
			continue
		}
		contacts = append(contacts, entry.Node)
		for _, key := range keys {
			seen[key] = struct{}{}
		}
	}
	return contacts
}

// ClosestNodesForBootstrap includes recent offline contacts as hints. Returning
// a hint never promotes it into active routing; the requester must validate it.
func (rt *RoutingTable) ClosestNodesForBootstrap(target string, count int, byNameHash bool) []proto.NodeInfo {
	if count <= 0 {
		return nil
	}
	rt.mu.RLock()
	all := make([]bucketEntry, 0, len(rt.peerByID))
	seen := make(map[string]struct{}, len(rt.peerByID))
	buckets := rt.Buckets[:]
	if byNameHash {
		buckets = rt.NameBuckets[:]
	}
	for _, bucket := range buckets {
		for _, entry := range bucket {
			seen[entry.Node.ID] = struct{}{}
			all = append(all, *entry)
		}
	}
	for _, entry := range rt.offline {
		if entry.OfflineSince.IsZero() || time.Since(entry.OfflineSince) > peerHistoryTTL {
			continue
		}
		if _, ok := seen[entry.Node.ID]; !ok {
			all = append(all, *entry)
		}
	}
	rt.mu.RUnlock()
	return sortClosestEntries(all, target, count, byNameHash)
}

func (rt *RoutingTable) closestFrom(buckets [][]*bucketEntry, target string, count int, byNameHash bool) []proto.NodeInfo {
	if count <= 0 {
		return nil
	}
	rt.mu.RLock()
	all := make([]bucketEntry, 0)
	for _, bucket := range buckets {
		for _, entry := range bucket {
			all = append(all, *entry)
		}
	}
	rt.mu.RUnlock()
	return sortClosestEntries(all, target, count, byNameHash)
}

func sortClosestEntries(all []bucketEntry, target string, count int, byNameHash bool) []proto.NodeInfo {
	if count <= 0 {
		return nil
	}
	sort.Slice(all, func(i, j int) bool {
		left, right := all[i].Node.ID, all[j].Node.ID
		if byNameHash {
			left, right = all[i].Node.NameHash, all[j].Node.NameHash
			if left == "" {
				left = NodeNameHash(all[i].Node.Name)
			}
			if right == "" {
				right = NodeNameHash(all[j].Node.Name)
			}
		}
		dl := xorDistance(left, target)
		dr := xorDistance(right, target)
		if cmp := dl.Cmp(dr); cmp != 0 {
			return cmp < 0
		}
		return all[i].Node.ID < all[j].Node.ID
	})
	if len(all) > count {
		all = all[:count]
	}
	out := make([]proto.NodeInfo, 0, len(all))
	for _, entry := range all {
		out = append(out, entry.Node)
	}
	return out
}

func (rt *RoutingTable) lookupDistance(node proto.NodeInfo, target string) *big.Int {
	if strings.HasPrefix(target, "node/name/") {
		nameHash := node.NameHash
		if nameHash == "" {
			nameHash = NodeNameHash(node.Name)
		}
		return xorDistance(nameHash, strings.TrimPrefix(target, "node/name/"))
	}
	return xorDistance(node.ID, target)
}

func (rt *RoutingTable) NodeByAddress(addr string) (proto.NodeInfo, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for _, entry := range rt.peerByID {
		if entry.Node.Addr == addr {
			return entry.Node, true
		}
	}
	return proto.NodeInfo{}, false
}

func (rt *RoutingTable) ActiveNode(nodeID string) (proto.NodeInfo, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	entry := rt.peerByID[nodeID]
	if entry == nil || (!rt.inIndexLocked(rt.Buckets[:], nodeID) && !rt.inIndexLocked(rt.NameBuckets[:], nodeID)) {
		return proto.NodeInfo{}, false
	}
	return entry.Node, true
}

func (rt *RoutingTable) Nodes() []proto.NodeInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	ids := make([]string, 0, len(rt.peerByID))
	for _, bucket := range rt.Buckets {
		for _, entry := range bucket {
			ids = append(ids, entry.Node.ID)
		}
	}
	sort.Strings(ids)
	out := make([]proto.NodeInfo, 0, len(ids))
	lastID := ""
	for _, id := range ids {
		if id == lastID {
			continue
		}
		lastID = id
		out = append(out, rt.peerByID[id].Node)
	}
	return out
}

func (rt *RoutingTable) ActivePeerCount() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	count := 0
	for _, bucket := range rt.Buckets {
		count += len(bucket)
	}
	return count
}

func (rt *RoutingTable) CandidateNodes(limit int) []proto.NodeInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if limit <= 0 || limit > maxPendingCandidates {
		limit = maxPendingCandidates
	}
	out := make([]proto.NodeInfo, 0, limit)
	seen := make(map[string]struct{}, limit)
	appendUnique := func(entry *bucketEntry) bool {
		if _, ok := seen[entry.Node.ID]; ok {
			return false
		}
		seen[entry.Node.ID] = struct{}{}
		out = append(out, entry.Node)
		return len(out) == limit
	}
	var candidates []*bucketEntry
	for i := range rt.Pending {
		candidates = append(candidates, rt.Pending[i]...)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return peerRetentionLess(observationOf(candidates[i]), observationOf(candidates[j]))
	})
	for _, entry := range candidates {
		if appendUnique(entry) {
			return out
		}
	}
	for _, entry := range rt.peerByID {
		if !entry.Pinned && !entry.Friend {
			continue
		}
		if appendUnique(entry) {
			return out
		}
	}
	offline := make([]*bucketEntry, 0, len(rt.offline))
	for _, entry := range rt.offline {
		if entry.Pinned || entry.Friend || entry.OfflineSince.IsZero() || time.Since(entry.OfflineSince) <= peerHistoryTTL {
			offline = append(offline, entry)
		}
	}
	sort.Slice(offline, func(i, j int) bool {
		return peerRetentionLess(observationOf(offline[i]), observationOf(offline[j]))
	})
	for _, entry := range offline {
		if appendUnique(entry) {
			return out
		}
	}
	return out
}

func observationOf(entry *bucketEntry) PeerObservation {
	return PeerObservation{
		Node: entry.Node, Pinned: entry.Pinned, Friend: entry.Friend, UseCount: entry.UseCount, SuccessCount: entry.SuccessCount,
		FirstSeen: entry.FirstSeen, LastSuccess: entry.LastSuccess, LastUsed: entry.LastUsed,
		OfflineSince: entry.OfflineSince, ClosestIDRank: entry.ClosestIDRank,
		ClosestNameRank: entry.ClosestNameRank,
	}
}

func (rt *RoutingTable) SnapshotPeers() []PeerObservation {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := make([]PeerObservation, 0, len(rt.peerByID))
	for _, entry := range rt.peerByID {
		if entry.Transient {
			continue
		}
		if entry.SuccessCount == 0 && !entry.Pinned && !entry.Friend {
			continue
		}
		out = append(out, PeerObservation{
			Node: entry.Node, FailCount: entry.FailCount, SuccessCount: entry.SuccessCount,
			LastSeen: entry.LastSeen, FirstSeen: entry.FirstSeen,
			LastSuccess: entry.LastSuccess, LastUsed: entry.LastUsed,
			LastFailure: entry.LastFailure, RTTMicros: entry.RTTMicros, Pinned: entry.Pinned,
			Friend: entry.Friend, UseCount: entry.UseCount,
			ClosestIDRank: entry.ClosestIDRank, ClosestNameRank: entry.ClosestNameRank,
			NextProbeAt: entry.NextProbeAt, LastProbe: entry.LastProbe,
			LastProbeFailure: entry.LastProbeFailure,
			OfflineSince:     entry.OfflineSince, ProbeMisses: entry.ProbeMisses,
			ProbationUntil: entry.ProbationUntil,
		})
	}
	assignClosestRanks(out, rt.SelfID, rt.SelfNameHash)
	return out
}

func assignClosestRanks(peers []PeerObservation, selfID, selfNameHash string) {
	byID := append([]PeerObservation(nil), peers...)
	sort.Slice(byID, func(i, j int) bool {
		return xorDistance(selfID, byID[i].Node.ID).Cmp(xorDistance(selfID, byID[j].Node.ID)) < 0
	})
	idRanks := make(map[string]uint16, len(byID))
	for i, peer := range byID {
		if i >= 50 {
			break
		}
		idRanks[peer.Node.ID] = uint16(i + 1)
	}
	byName := append([]PeerObservation(nil), peers...)
	sort.Slice(byName, func(i, j int) bool {
		return xorDistance(selfNameHash, nodeNameHash(byName[i].Node)).Cmp(xorDistance(selfNameHash, nodeNameHash(byName[j].Node))) < 0
	})
	nameRanks := make(map[string]uint16, len(byName))
	for i, peer := range byName {
		if i >= 50 {
			break
		}
		nameRanks[peer.Node.ID] = uint16(i + 1)
	}
	for i := range peers {
		peers[i].ClosestIDRank = idRanks[peers[i].Node.ID]
		peers[i].ClosestNameRank = nameRanks[peers[i].Node.ID]
	}
}

func (rt *RoutingTable) PruneOffline(now time.Time) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for id, entry := range rt.offline {
		if !entry.Pinned && !entry.Friend && !entry.OfflineSince.IsZero() && now.Sub(entry.OfflineSince) > peerHistoryTTL {
			delete(rt.offline, id)
			delete(rt.peerByID, id)
		}
	}
}

func (rt *RoutingTable) RefreshTargets(now time.Time, limit int) []RefreshTarget {
	if limit <= 0 {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	targets := make([]RefreshTarget, 0, limit)
	for pass := 0; pass < 2 && len(targets) < limit; pass++ {
		byName := pass == 1
		if rt.refreshNameNext {
			byName = pass == 0
		}
		buckets, refreshed := rt.Buckets[:], &rt.lastIDRefresh
		selfCoordinate := rt.SelfID
		if byName {
			if rt.SelfNameHash == "" {
				continue
			}
			buckets, refreshed = rt.NameBuckets[:], &rt.lastNameRefresh
			selfCoordinate = rt.SelfNameHash
		}
		for i := 255; i >= 0 && len(targets) < limit; i-- {
			if len(buckets[i]) == 0 || (len(buckets[i]) >= bucketRefillThreshold && now.Sub(refreshed[i]) < bucketRefreshInterval) {
				continue
			}
			if now.Sub(refreshed[i]) < bucketRefreshInterval/2 {
				continue
			}
			target, err := randomTargetInBucket(selfCoordinate, i)
			if err != nil {
				continue
			}
			if byName {
				target = "node/name/" + target
			} else {
				target = "vx6_" + target
			}
			targets = append(targets, RefreshTarget{Key: target, NameHash: byName, Bucket: i})
			refreshed[i] = now
		}
	}
	rt.refreshNameNext = !rt.refreshNameNext
	return targets
}

func (rt *RoutingTable) bucketIndex(nodeID string) int {
	return xorDistance(rt.SelfID, nodeID).BitLen() - 1
}

func (rt *RoutingTable) nameBucketIndex(node proto.NodeInfo) int {
	return xorDistance(rt.SelfNameHash, nodeNameHash(node)).BitLen() - 1
}

func nodeNameHash(node proto.NodeInfo) string {
	if node.NameHash != "" {
		return node.NameHash
	}
	return NodeNameHash(node.Name)
}

func (rt *RoutingTable) insertIndexLocked(buckets [][]*bucketEntry, entry *bucketEntry, idx int) {
	if idx < 0 {
		idx = 0
	}
	if idx > 255 {
		idx = 255
	}
	if pos := indexOfEntry(buckets[idx], entry.Node.ID); pos >= 0 {
		buckets[idx] = moveToFront(buckets[idx], pos)
		return
	}
	// K is the normal referral/replication target, not a hard per-range
	// ceiling. The local active-peer limit bounds total memory as the view grows.
	buckets[idx] = append([]*bucketEntry{entry}, buckets[idx]...)
}

func initialProbeDelay(nodeID string) time.Duration {
	digest := sha256.Sum256([]byte(nodeID))
	value := new(big.Int).SetBytes(digest[:8])
	window := big.NewInt(int64(livenessProbeInterval))
	value.Mod(value, window)
	return time.Duration(value.Int64())
}

func (rt *RoutingTable) containsEntry(buckets [256][]*bucketEntry, nodeID string) bool {
	for i := range buckets {
		if indexOfEntry(buckets[i], nodeID) >= 0 {
			return true
		}
	}
	return false
}

func (rt *RoutingTable) inIndexLocked(buckets [][]*bucketEntry, nodeID string) bool {
	for i := range buckets {
		if indexOfEntry(buckets[i], nodeID) >= 0 {
			return true
		}
	}
	return false
}

func (rt *RoutingTable) removePendingLocked(nodeID string) bool {
	for i := range rt.Pending {
		for j, entry := range rt.Pending[i] {
			if entry.Node.ID == nodeID {
				rt.Pending[i] = append(rt.Pending[i][:j], rt.Pending[i][j+1:]...)
				rt.pendingN--
				return true
			}
		}
	}
	return false
}

func (rt *RoutingTable) removeFromIndexLocked(buckets [][]*bucketEntry, nodeID string) bool {
	removed := false
	for i := range buckets {
		if pos := indexOfEntry(buckets[i], nodeID); pos >= 0 {
			buckets[i] = append(buckets[i][:pos], buckets[i][pos+1:]...)
			removed = true
		}
	}
	return removed
}

func (rt *RoutingTable) removePeerIfUnindexedLocked(nodeID string) {
	if entry := rt.peerByID[nodeID]; entry != nil && entry.Pinned {
		return
	}
	if rt.inIndexLocked(rt.Buckets[:], nodeID) || rt.inIndexLocked(rt.NameBuckets[:], nodeID) {
		return
	}
	if _, ok := rt.offline[nodeID]; ok {
		return
	}
	for _, entries := range rt.Pending {
		for _, entry := range entries {
			if entry.Node.ID == nodeID {
				return
			}
		}
	}
	delete(rt.peerByID, nodeID)
}

func (rt *RoutingTable) moveToFrontLocked(buckets [][]*bucketEntry, nodeID string, bucketIdx int) {
	if bucketIdx < 0 || bucketIdx > 255 {
		return
	}
	if pos := indexOfEntry(buckets[bucketIdx], nodeID); pos > 0 {
		buckets[bucketIdx] = moveToFront(buckets[bucketIdx], pos)
	}
}

func indexOfEntry(entries []*bucketEntry, nodeID string) int {
	for i, entry := range entries {
		if entry.Node.ID == nodeID {
			return i
		}
	}
	return -1
}

func moveToFront(entries []*bucketEntry, pos int) []*bucketEntry {
	entry := entries[pos]
	copy(entries[1:pos+1], entries[:pos])
	entries[0] = entry
	return entries
}

func randomTargetInBucket(selfCoordinate string, bucket int) (string, error) {
	if bucket < 0 || bucket > 255 {
		return "", nil
	}
	upper := new(big.Int).Lsh(big.NewInt(1), uint(bucket))
	lower, err := rand.Int(rand.Reader, upper)
	if err != nil {
		return "", err
	}
	delta := lower.SetBit(lower, bucket, 1)
	self := new(big.Int).SetBytes(routingIDBytes(selfCoordinate))
	target := new(big.Int).Xor(self, delta)
	encoded := target.FillBytes(make([]byte, sha256.Size))
	return hex.EncodeToString(encoded), nil
}

func xorDistance(id1, id2 string) *big.Int {
	i1 := new(big.Int).SetBytes(routingIDBytes(id1))
	i2 := new(big.Int).SetBytes(routingIDBytes(id2))
	return new(big.Int).Xor(i1, i2)
}

func routingIDBytes(value string) []byte {
	var encoded string
	switch {
	case strings.HasPrefix(value, "vx6_"):
		encoded = strings.TrimPrefix(value, "vx6_")
	case strings.HasPrefix(value, "node/name/"):
		encoded = strings.TrimPrefix(value, "node/name/")
	case strings.HasPrefix(value, "node/id/"):
		encoded = strings.TrimPrefix(value, "node/id/vx6_")
	default:
		// Name coordinates and refresh targets are already full SHA-256
		// digests. Treat canonical bare digests as coordinates, not labels to hash.
		encoded = value
	}
	if len(encoded) == sha256.Size*2 {
		if decoded, err := hex.DecodeString(encoded); err == nil {
			return decoded
		}
	}
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}
