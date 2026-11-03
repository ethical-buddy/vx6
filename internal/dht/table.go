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
)

const K = 20

const (
	replacementCacheSize    = 10
	maxPendingCandidates    = 512
	maxPendingPerBucket     = 10
	staleFailureThreshold   = 3
	bucketRefillThreshold   = 15
	bucketRefreshInterval   = 10 * time.Minute
	peerAddressHintTTL      = 7 * 24 * time.Hour
	peerCacheHotLimit       = 512
	maxPrefixPeersPerBucket = 2
	maxASNPeersPerBucket    = 4
)

type bucketEntry struct {
	Node         proto.NodeInfo `json:"node"`
	Transient    bool           `json:"-"`
	FailCount    uint8          `json:"fail_count,omitempty"`
	SuccessCount uint32         `json:"success_count,omitempty"`
	LastSeen     time.Time      `json:"last_seen,omitempty"`
	LastSuccess  time.Time      `json:"last_success,omitempty"`
	LastUsed     time.Time      `json:"last_used,omitempty"`
	LastFailure  time.Time      `json:"last_failure,omitempty"`
	NextProbeAt  time.Time      `json:"next_probe_at,omitempty"`
	RTTMicros    uint32         `json:"rtt_micros,omitempty"`
	Pinned       bool           `json:"pinned,omitempty"`
}

type PeerObservation struct {
	Node         proto.NodeInfo
	FailCount    uint8
	SuccessCount uint32
	LastSeen     time.Time
	LastSuccess  time.Time
	LastUsed     time.Time
	LastFailure  time.Time
	NextProbeAt  time.Time
	RTTMicros    uint32
	Pinned       bool
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
	Spare           [256][]*bucketEntry
	NameSpare       [256][]*bucketEntry
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
	rt.NameSpare = [256][]*bucketEntry{}
	entries := make([]*bucketEntry, 0, len(rt.peerByID))
	for _, entry := range rt.peerByID {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Node.ID < entries[j].Node.ID })
	for _, entry := range entries {
		if rt.containsEntry(rt.Buckets, entry.Node.ID) {
			rt.insertIndexLocked(rt.NameBuckets[:], rt.NameSpare[:], entry, rt.nameBucketIndex(entry.Node))
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
		entry = &bucketEntry{Node: node}
		rt.peerByID[node.ID] = entry
	} else {
		entry.Node = node
	}
	entry.Transient = false
	delete(rt.offline, node.ID)
	entry.FailCount = 0
	entry.NextProbeAt = time.Time{}
	entry.LastSeen = now
	entry.LastSuccess = now
	entry.LastUsed = now
	if entry.SuccessCount < ^uint32(0) {
		entry.SuccessCount++
	}
	rt.removePendingLocked(node.ID)
	rt.insertIndexLocked(rt.Buckets[:], rt.Spare[:], entry, rt.bucketIndex(node.ID))
	if rt.SelfNameHash != "" {
		rt.insertIndexLocked(rt.NameBuckets[:], rt.NameSpare[:], entry, rt.nameBucketIndex(node))
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
	if rt.peerByID[node.ID] != nil || rt.pendingN >= maxPendingCandidates || len(rt.Pending[idx]) >= maxPendingPerBucket {
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
	if rt.inIndexLocked(rt.Buckets[:], node.ID) || rt.inIndexLocked(rt.NameBuckets[:], node.ID) ||
		rt.inIndexLocked(rt.Spare[:], node.ID) || rt.inIndexLocked(rt.NameSpare[:], node.ID) {
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
	if rt.pendingN >= maxPendingCandidates || len(rt.Pending[idx]) >= maxPendingPerBucket {
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
			(!peer.Pinned && !peer.LastSeen.IsZero() && now.Sub(peer.LastSeen) > peerAddressHintTTL) {
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
			entry.LastFailure = peer.LastFailure
			entry.NextProbeAt = peer.NextProbeAt
			entry.RTTMicros = peer.RTTMicros
			entry.Pinned = peer.Pinned
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
	if now.Before(entry.NextProbeAt) {
		return false
	}
	entry.LastFailure = now
	if entry.FailCount < ^uint8(0) {
		entry.FailCount++
	}
	backoff := []time.Duration{5 * time.Second, 20 * time.Second, time.Minute}
	entry.NextProbeAt = now.Add(backoff[min(int(entry.FailCount)-1, len(backoff)-1)])
	if entry.FailCount < staleFailureThreshold {
		return false
	}
	removed := rt.removeFromIndexLocked(rt.Buckets[:], nodeID)
	removed = rt.removeFromIndexLocked(rt.NameBuckets[:], nodeID) || removed
	removed = rt.removeFromIndexLocked(rt.Spare[:], nodeID) || removed
	removed = rt.removeFromIndexLocked(rt.NameSpare[:], nodeID) || removed
	if removed {
		rt.offline[nodeID] = entry
		rt.removePeerIfUnindexedLocked(nodeID)
		for i := 0; i < 256; i++ {
			rt.promoteReplacementLocked(i, false)
			rt.promoteReplacementLocked(i, true)
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
	entry.LastSeen = now
	entry.FailCount = 0
	entry.NextProbeAt = time.Time{}
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
	if pinned && !entry.Pinned {
		count := 0
		for _, peer := range rt.peerByID {
			if peer.Pinned {
				count++
			}
		}
		if count >= maxPersistedPeers {
			return false
		}
	}
	entry.Pinned = pinned
	if !pinned {
		rt.removePeerIfUnindexedLocked(nodeID)
	}
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

func (rt *RoutingTable) closestFrom(buckets [][]*bucketEntry, target string, count int, byNameHash bool) []proto.NodeInfo {
	if count <= 0 {
		return nil
	}
	rt.mu.RLock()
	all := make([]*bucketEntry, 0)
	for _, bucket := range buckets {
		all = append(all, bucket...)
	}
	rt.mu.RUnlock()
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
	for _, buckets := range [][][]*bucketEntry{rt.Buckets[:], rt.Spare[:], rt.NameSpare[:]} {
		for _, bucket := range buckets {
			for _, entry := range bucket {
				ids = append(ids, entry.Node.ID)
			}
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
	for i := range rt.Pending {
		for _, entry := range rt.Pending[i] {
			if appendUnique(entry) {
				return out
			}
		}
	}
	for _, buckets := range [][][]*bucketEntry{rt.Spare[:], rt.NameSpare[:]} {
		for i := range buckets {
			for _, entry := range buckets[i] {
				if appendUnique(entry) {
					return out
				}
			}
		}
	}
	for _, entry := range rt.peerByID {
		if !entry.Pinned {
			continue
		}
		if appendUnique(entry) {
			return out
		}
	}
	offline := make([]*bucketEntry, 0, len(rt.offline))
	for _, entry := range rt.offline {
		if entry.Pinned || entry.LastSeen.IsZero() || time.Since(entry.LastSeen) <= peerAddressHintTTL {
			offline = append(offline, entry)
		}
	}
	sort.Slice(offline, func(i, j int) bool { return offline[i].LastSuccess.After(offline[j].LastSuccess) })
	for _, entry := range offline {
		if appendUnique(entry) {
			return out
		}
	}
	return out
}

func (rt *RoutingTable) SnapshotPeers() []PeerObservation {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := make([]PeerObservation, 0, len(rt.peerByID))
	for _, entry := range rt.peerByID {
		if entry.Transient {
			continue
		}
		out = append(out, PeerObservation{
			Node: entry.Node, FailCount: entry.FailCount, SuccessCount: entry.SuccessCount,
			LastSeen: entry.LastSeen, LastSuccess: entry.LastSuccess, LastUsed: entry.LastUsed,
			LastFailure: entry.LastFailure, RTTMicros: entry.RTTMicros, Pinned: entry.Pinned,
			NextProbeAt: entry.NextProbeAt,
		})
	}
	return out
}

func (rt *RoutingTable) PruneOffline(now time.Time) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for id, entry := range rt.offline {
		if !entry.Pinned && !entry.LastSeen.IsZero() && now.Sub(entry.LastSeen) > peerHistoryTTL {
			delete(rt.offline, id)
			delete(rt.peerByID, id)
		}
	}
	if len(rt.offline) <= maxPersistedPeers {
		return
	}
	entries := make([]*bucketEntry, 0, len(rt.offline))
	for _, entry := range rt.offline {
		if !entry.Pinned {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].LastSuccess.Before(entries[j].LastSuccess) })
	for _, entry := range entries {
		if len(rt.offline) <= maxPersistedPeers {
			break
		}
		delete(rt.offline, entry.Node.ID)
		delete(rt.peerByID, entry.Node.ID)
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
	hash := node.NameHash
	if hash == "" {
		hash = NodeNameHash(node.Name)
	}
	return xorDistance(rt.SelfNameHash, hash).BitLen() - 1
}

func (rt *RoutingTable) insertIndexLocked(buckets, spares [][]*bucketEntry, entry *bucketEntry, idx int) {
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
	if len(buckets[idx]) < K {
		buckets[idx] = append([]*bucketEntry{entry}, buckets[idx]...)
		return
	}
	spares[idx] = rememberDiverseReplacement(spares[idx], entry, replacementCacheSize)
}

func (rt *RoutingTable) rememberReplacementLocked(bucketIdx int, node proto.NodeInfo) {
	entry := rt.peerByID[node.ID]
	if entry == nil {
		entry = &bucketEntry{Node: node}
		rt.peerByID[node.ID] = entry
	}
	rt.Spare[bucketIdx] = rememberDiverseReplacement(rt.Spare[bucketIdx], entry, replacementCacheSize)
}

func (rt *RoutingTable) promoteReplacementLocked(bucketIdx int, byName bool) {
	buckets, spares := rt.Buckets[:], rt.Spare[:]
	if byName {
		buckets, spares = rt.NameBuckets[:], rt.NameSpare[:]
	}
	if len(buckets[bucketIdx]) >= K || len(spares[bucketIdx]) == 0 {
		return
	}
	entry := spares[bucketIdx][0]
	spares[bucketIdx] = spares[bucketIdx][1:]
	idx := rt.bucketIndex(entry.Node.ID)
	if byName {
		idx = rt.nameBucketIndex(entry.Node)
	}
	if entry.FailCount >= staleFailureThreshold || rt.pendingN >= maxPendingCandidates || len(rt.Pending[idx]) >= maxPendingPerBucket {
		rt.removePeerIfUnindexedLocked(entry.Node.ID)
		return
	}
	// A replacement is an address hint, not proof of current reachability.
	rt.Pending[idx] = append(rt.Pending[idx], entry)
	rt.pendingN++
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
	if rt.inIndexLocked(rt.Buckets[:], nodeID) || rt.inIndexLocked(rt.NameBuckets[:], nodeID) ||
		rt.inIndexLocked(rt.Spare[:], nodeID) || rt.inIndexLocked(rt.NameSpare[:], nodeID) {
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

func rememberDiverseReplacement(entries []*bucketEntry, candidate *bucketEntry, limit int) []*bucketEntry {
	if pos := indexOfEntry(entries, candidate.Node.ID); pos >= 0 {
		entries = append(entries[:pos], entries[pos+1:]...)
	}
	entries = append(entries, candidate)
	scores := make(map[string]int, len(entries))
	for _, entry := range entries {
		prefix := ipv6Prefix48(entry.Node.Addr)
		asn := (sourceObservation{addr: entry.Node.Addr}).asnKey()
		duplicates := 0
		for _, other := range entries {
			if other.Node.ID == entry.Node.ID {
				continue
			}
			if prefix != "" && ipv6Prefix48(other.Node.Addr) == prefix {
				duplicates += 2
			}
			if asn != "" && (sourceObservation{addr: other.Node.Addr}).asnKey() == asn {
				duplicates++
			}
		}
		scores[entry.Node.ID] = duplicates
	}
	sort.SliceStable(entries, func(i, j int) bool {
		scoreI, scoreJ := scores[entries[i].Node.ID], scores[entries[j].Node.ID]
		if scoreI != scoreJ {
			return scoreI < scoreJ
		}
		if !entries[i].LastSuccess.Equal(entries[j].LastSuccess) {
			return entries[i].LastSuccess.After(entries[j].LastSuccess)
		}
		return entries[i].Node.ID < entries[j].Node.ID
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
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
	}
	if len(encoded) == sha256.Size*2 {
		if decoded, err := hex.DecodeString(encoded); err == nil {
			return decoded
		}
	}
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}
