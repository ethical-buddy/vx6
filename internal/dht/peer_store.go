package dht

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vx6/vx6/internal/proto"
	bolt "go.etcd.io/bbolt"
)

const (
	peerBucketName         = "peers-v1"
	peerNameIndexName      = "name-hash-v1"
	peerDiversityIndexName = "diversity-v1"
	peerFriendIndexName    = "friends-v1"
	peerUsedIndexName      = "used-v1"
	peerClosestIDIndex     = "closest-id-v1"
	peerClosestNameIndex   = "closest-name-v1"
	peerActiveIndexName    = "active-v1"
	peerProbationIndexName = "probation-v1"
	peerInactiveIndexName  = "inactive-v1"
	peerValuesBucketName   = "values-v1"
	peerStoreFileMode      = 0o600
	peerStoreDirMode       = 0o700
	peerHistoryTTL         = 30 * 24 * time.Hour
)

var peerCategoryIndexNames = []string{
	peerFriendIndexName, peerUsedIndexName, peerClosestIDIndex, peerClosestNameIndex,
	peerActiveIndexName, peerProbationIndexName, peerInactiveIndexName,
}

// PeerStore persists signed peer metadata and local observations. Loaded rows
// are deliberately returned as candidates; persistence never grants liveness.
type PeerStore struct{ db *bolt.DB }

func OpenPeerStore(path string) (*PeerStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), peerStoreDirMode); err != nil {
		return nil, fmt.Errorf("create DHT peer-store directory: %w", err)
	}
	db, err := bolt.Open(path, peerStoreFileMode, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open DHT peer store: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(peerBucketName)); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists([]byte(peerNameIndexName))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte(peerDiversityIndexName))
		if err != nil {
			return err
		}
		for _, name := range peerCategoryIndexNames {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(peerValuesBucketName)); err != nil {
			return err
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize DHT peer store: %w", err)
	}
	return &PeerStore{db: db}, nil
}

// PutValue persists a validated, non-hidden DHT value. The caller performs
// signature/key validation before writing; reads validate again on restart.
func (s *PeerStore) PutValue(key, value string) error {
	if s == nil || s.db == nil || strings.HasPrefix(key, "hidden-desc/v1/") {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(peerValuesBucketName)).Put([]byte(key), []byte(value))
	})
}

// LoadValues returns raw rows for the DHT layer to cryptographically validate.
func (s *PeerStore) LoadValues() (map[string]string, error) {
	values := make(map[string]string)
	if s == nil || s.db == nil {
		return values, nil
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(peerValuesBucketName)).ForEach(func(key, value []byte) error {
			values[string(key)] = string(value)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("read persisted DHT values: %w", err)
	}
	return values, nil
}

func (s *PeerStore) DeleteValue(key string) error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(peerValuesBucketName)).Delete([]byte(key))
	})
}

func (s *PeerStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// SaveSnapshot atomically updates observations and their name-hash index.
// Unpinned offline hints expire after 30 days; durable history is bounded.
func (s *PeerStore) SaveSnapshot(peers []PeerObservation, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	peers = append([]PeerObservation(nil), peers...)
	// Retain CLI-side friend/use updates when the running node has not yet
	// incorporated those observations into its in-memory routing table.
	prior, err := s.loadAll()
	if err != nil {
		return err
	}
	merged := make(map[string]PeerObservation, len(prior)+len(peers))
	for _, peer := range prior {
		merged[peer.Node.ID] = peer
	}
	for _, peer := range peers {
		if old, ok := merged[peer.Node.ID]; ok {
			peer.Friend = peer.Friend || old.Friend
			if old.UseCount > peer.UseCount {
				peer.UseCount = old.UseCount
			}
			if old.LastUsed.After(peer.LastUsed) {
				peer.LastUsed = old.LastUsed
			}
			if peer.FirstSeen.IsZero() || (!old.FirstSeen.IsZero() && old.FirstSeen.Before(peer.FirstSeen)) {
				peer.FirstSeen = old.FirstSeen
			}
		}
		merged[peer.Node.ID] = peer
	}
	peers = peers[:0]
	for _, peer := range merged {
		peers = append(peers, peer)
	}
	sort.Slice(peers, func(i, j int) bool { return peerRetentionLess(peers[i], peers[j]) })
	eligible := make([]PeerObservation, 0, len(peers))
	for _, peer := range peers {
		tooOldOffline := !peer.OfflineSince.IsZero() && now.Sub(peer.OfflineSince) > peerHistoryTTL
		staleUnclassified := peer.OfflineSince.IsZero() && !peer.LastSeen.IsZero() && now.Sub(peer.LastSeen) > peerHistoryTTL
		if peer.Node.ID == "" || peer.Node.Addr == "" || (!peer.Pinned && !peer.Friend && (tooOldOffline || staleUnclassified)) {
			continue
		}
		eligible = append(eligible, peer)
	}
	selected := selectPeerRetention(eligible, peerCacheHotLimit)
	return s.db.Update(func(tx *bolt.Tx) error {
		peersBucket := tx.Bucket([]byte(peerBucketName))
		nameBucket := tx.Bucket([]byte(peerNameIndexName))
		diversityBucket := tx.Bucket([]byte(peerDiversityIndexName))
		for _, name := range peerCategoryIndexNames {
			bucket := tx.Bucket([]byte(name))
			cursor := bucket.Cursor()
			for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
				if err := cursor.Delete(); err != nil {
					return err
				}
			}
		}
		cursor := diversityBucket.Cursor()
		for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
		keep := make(map[string]struct{}, len(selected))
		seenDiversity := make(map[string]struct{})
		for _, peer := range selected {
			keep[peer.Node.ID] = struct{}{}
		}
		var stale [][]byte
		if err := peersBucket.ForEach(func(key, value []byte) error {
			if _, ok := keep[string(key)]; !ok {
				var old PeerObservation
				if json.Unmarshal(value, &old) == nil {
					if oldHash := peerNameHash(old.Node); oldHash != "" {
						if err := nameBucket.Delete([]byte(oldHash + "/" + old.Node.ID)); err != nil {
							return err
						}
					}
				}
				stale = append(stale, append([]byte(nil), key...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, key := range stale {
			if err := peersBucket.Delete(key); err != nil {
				return err
			}
		}
		for _, peer := range selected {
			data, err := json.Marshal(peer)
			if err != nil {
				return err
			}
			oldData := append([]byte(nil), peersBucket.Get([]byte(peer.Node.ID))...)
			var old PeerObservation
			if len(oldData) > 0 && json.Unmarshal(oldData, &old) == nil {
				oldHash, newHash := peerNameHash(old.Node), peerNameHash(peer.Node)
				if oldHash != "" && oldHash != newHash {
					if err := nameBucket.Delete([]byte(oldHash + "/" + peer.Node.ID)); err != nil {
						return err
					}
				}
			}
			if !bytes.Equal(oldData, data) {
				if err := peersBucket.Put([]byte(peer.Node.ID), data); err != nil {
					return err
				}
				nameHash := peerNameHash(peer.Node)
				if nameHash != "" {
					if err := nameBucket.Put([]byte(nameHash+"/"+peer.Node.ID), []byte(peer.Node.ID)); err != nil {
						return err
					}
				}
			}
			if peer.OfflineSince.IsZero() {
				for _, key := range peerDiversityKeys(peer.Node.Addr) {
					if _, exists := seenDiversity[key]; exists {
						continue
					}
					if err := diversityBucket.Put([]byte(key), []byte(peer.Node.ID)); err != nil {
						return err
					}
					seenDiversity[key] = struct{}{}
				}
			}
			for _, category := range peerCategories(peer, now) {
				if err := tx.Bucket([]byte(category)).Put([]byte(peer.Node.ID), []byte{1}); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func selectPeerRetention(peers []PeerObservation, limit int) []PeerObservation {
	ordered := append([]PeerObservation(nil), peers...)
	sort.Slice(ordered, func(i, j int) bool { return peerRetentionLess(ordered[i], ordered[j]) })
	selected := make([]PeerObservation, 0, min(limit, len(ordered)))
	seen := make(map[string]struct{}, len(ordered))
	add := func(peer PeerObservation) {
		if len(selected) >= limit {
			return
		}
		if _, ok := seen[peer.Node.ID]; ok {
			return
		}
		seen[peer.Node.ID] = struct{}{}
		selected = append(selected, peer)
	}
	for _, peer := range ordered {
		if peer.Friend {
			add(peer)
		}
	}
	for _, peer := range ordered {
		if peer.UseCount > 0 || !peer.LastUsed.IsZero() {
			add(peer)
		}
	}
	for _, peer := range ordered {
		if peer.ClosestIDRank > 0 || peer.ClosestNameRank > 0 {
			add(peer)
		}
	}
	covered := make(map[string]struct{})
	for _, peer := range ordered {
		if !peer.OfflineSince.IsZero() {
			continue
		}
		keys := peerDiversityKeys(peer.Node.Addr)
		addsCoverage := false
		for _, key := range keys {
			if _, exists := covered[key]; !exists {
				addsCoverage = true
			}
		}
		if addsCoverage {
			add(peer)
			for _, key := range keys {
				covered[key] = struct{}{}
			}
		}
	}
	for _, peer := range ordered {
		if peer.OfflineSince.IsZero() {
			add(peer)
		}
	}
	for _, peer := range ordered {
		if !peer.ProbationUntil.IsZero() {
			add(peer)
		}
	}
	for _, peer := range ordered {
		if !peer.OfflineSince.IsZero() {
			add(peer)
		}
	}
	for _, peer := range ordered {
		add(peer)
	}
	return selected
}

func (s *PeerStore) loadAll() ([]PeerObservation, error) {
	var peers []PeerObservation
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(peerBucketName)).ForEach(func(_, value []byte) error {
			var peer PeerObservation
			if json.Unmarshal(value, &peer) == nil {
				peers = append(peers, peer)
			}
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("read DHT peer history: %w", err)
	}
	return peers, nil
}

func peerCategories(peer PeerObservation, now time.Time) []string {
	var categories []string
	if peer.Friend {
		categories = append(categories, peerFriendIndexName)
	}
	if peer.UseCount >= 3 || !peer.LastUsed.IsZero() {
		categories = append(categories, peerUsedIndexName)
	}
	if peer.ClosestIDRank > 0 {
		categories = append(categories, peerClosestIDIndex)
	}
	if peer.ClosestNameRank > 0 {
		categories = append(categories, peerClosestNameIndex)
	}
	if peer.OfflineSince.IsZero() {
		categories = append(categories, peerActiveIndexName)
	} else {
		categories = append(categories, peerInactiveIndexName)
	}
	if !peer.ProbationUntil.IsZero() && now.Before(peer.ProbationUntil) {
		categories = append(categories, peerProbationIndexName)
	}
	return categories
}

func trimPeerRows(tx *bolt.Tx, now time.Time) error {
	bucket := tx.Bucket([]byte(peerBucketName))
	var peers []PeerObservation
	if err := bucket.ForEach(func(_, raw []byte) error {
		var peer PeerObservation
		if json.Unmarshal(raw, &peer) == nil {
			peers = append(peers, peer)
		}
		return nil
	}); err != nil {
		return err
	}
	if len(peers) <= peerCacheHotLimit {
		return nil
	}
	sort.Slice(peers, func(i, j int) bool { return peerRetentionLess(peers[i], peers[j]) })
	nameIndex := tx.Bucket([]byte(peerNameIndexName))
	for _, peer := range peers[peerCacheHotLimit:] {
		if err := bucket.Delete([]byte(peer.Node.ID)); err != nil {
			return err
		}
		if hash := peerNameHash(peer.Node); hash != "" {
			if err := nameIndex.Delete([]byte(hash + "/" + peer.Node.ID)); err != nil {
				return err
			}
		}
		for _, category := range peerCategoryIndexNames {
			if err := tx.Bucket([]byte(category)).Delete([]byte(peer.Node.ID)); err != nil {
				return err
			}
		}
		diversity := tx.Bucket([]byte(peerDiversityIndexName))
		cursor := diversity.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			if string(value) == peer.Node.ID {
				if err := cursor.Delete(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func peerNameHash(node proto.NodeInfo) string {
	if node.NameHash != "" {
		return node.NameHash
	}
	if node.Name != "" {
		return NodeNameHash(node.Name)
	}
	return ""
}

func (s *PeerStore) LoadCandidates(now time.Time, limit int) ([]PeerObservation, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if limit <= 0 || limit > peerCacheHotLimit {
		limit = peerCacheHotLimit
	}
	var peers []PeerObservation
	byID := make(map[string]PeerObservation)
	var indexedIDs [][]string
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte(peerBucketName)).ForEach(func(_, value []byte) error {
			var peer PeerObservation
			if err := json.Unmarshal(value, &peer); err != nil {
				return nil // Ignore a damaged row without losing the rest of the cache.
			}
			tooOldOffline := !peer.OfflineSince.IsZero() && now.Sub(peer.OfflineSince) > peerHistoryTTL
			staleUnclassified := peer.OfflineSince.IsZero() && !peer.LastSeen.IsZero() && now.Sub(peer.LastSeen) > peerAddressHintTTL
			if peer.Node.ID == "" || peer.Node.Addr == "" || (!peer.Pinned && !peer.Friend && (tooOldOffline || staleUnclassified)) {
				return nil
			}
			byID[peer.Node.ID] = peer
			return nil
		}); err != nil {
			return err
		}
		for _, name := range []string{peerFriendIndexName, peerUsedIndexName, peerClosestIDIndex,
			peerClosestNameIndex, peerDiversityIndexName, peerActiveIndexName,
			peerProbationIndexName, peerInactiveIndexName} {
			ids := make([]string, 0)
			if err := tx.Bucket([]byte(name)).ForEach(func(key, value []byte) error {
				id := string(key)
				if name == peerDiversityIndexName {
					id = string(value)
				}
				ids = append(ids, id)
				return nil
			}); err != nil {
				return err
			}
			indexedIDs = append(indexedIDs, ids)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read DHT peer store: %w", err)
	}
	for _, ids := range indexedIDs {
		members := make([]PeerObservation, 0, len(ids))
		for _, id := range ids {
			if peer, ok := byID[id]; ok {
				members = append(members, peer)
			}
		}
		sort.Slice(members, func(i, j int) bool { return peerRetentionLess(members[i], members[j]) })
		for _, peer := range members {
			if _, exists := byID[peer.Node.ID]; !exists {
				continue
			}
			peers = append(peers, peer)
			delete(byID, peer.Node.ID)
			if len(peers) == limit {
				return peers, nil
			}
		}
	}
	remaining := make([]PeerObservation, 0, len(byID))
	for _, peer := range byID {
		remaining = append(remaining, peer)
	}
	sort.Slice(remaining, func(i, j int) bool { return peerRetentionLess(remaining[i], remaining[j]) })
	for _, peer := range remaining {
		peers = append(peers, peer)
		if len(peers) == limit {
			break
		}
	}
	return peers, nil
}

func peerRetentionLess(a, b PeerObservation) bool {
	if a.Friend != b.Friend {
		return a.Friend
	}
	if a.Pinned != b.Pinned {
		return a.Pinned
	}
	aUsed, bUsed := a.UseCount > 0 || !a.LastUsed.IsZero(), b.UseCount > 0 || !b.LastUsed.IsZero()
	if aUsed != bUsed {
		return aUsed
	}
	if !a.LastUsed.Equal(b.LastUsed) {
		return a.LastUsed.After(b.LastUsed)
	}
	if a.UseCount != b.UseCount {
		return a.UseCount > b.UseCount
	}
	aClosest, bClosest := a.ClosestIDRank > 0 || a.ClosestNameRank > 0, b.ClosestIDRank > 0 || b.ClosestNameRank > 0
	if aClosest != bClosest {
		return aClosest
	}
	if a.ClosestIDRank > 0 && b.ClosestIDRank > 0 && a.ClosestIDRank != b.ClosestIDRank {
		return a.ClosestIDRank < b.ClosestIDRank
	}
	if a.ClosestNameRank > 0 && b.ClosestNameRank > 0 && a.ClosestNameRank != b.ClosestNameRank {
		return a.ClosestNameRank < b.ClosestNameRank
	}
	if a.OfflineSince.IsZero() != b.OfflineSince.IsZero() {
		return a.OfflineSince.IsZero()
	}
	if !a.FirstSeen.Equal(b.FirstSeen) {
		if a.FirstSeen.IsZero() {
			return false
		}
		if b.FirstSeen.IsZero() {
			return true
		}
		return a.FirstSeen.Before(b.FirstSeen)
	}
	if a.SuccessCount != b.SuccessCount {
		return a.SuccessCount > b.SuccessCount
	}
	return a.LastSuccess.After(b.LastSuccess)
}

// SetFriend adds or removes a local retention preference keyed by cryptographic
// NodeID. The advertised name is display metadata, never a global name claim.
func (s *PeerStore) SetFriend(node proto.NodeInfo, friend bool, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	if node.ID == "" || node.Addr == "" {
		return fmt.Errorf("friend record requires node ID and address")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		peers := tx.Bucket([]byte(peerBucketName))
		var peer PeerObservation
		if raw := peers.Get([]byte(node.ID)); len(raw) > 0 {
			if err := json.Unmarshal(raw, &peer); err != nil {
				return err
			}
		}
		peer.Node = node
		peer.Friend = friend
		if peer.FirstSeen.IsZero() {
			peer.FirstSeen = now
		}
		if peer.LastSeen.IsZero() {
			peer.LastSeen = now
		}
		data, err := json.Marshal(peer)
		if err != nil {
			return err
		}
		if err := peers.Put([]byte(node.ID), data); err != nil {
			return err
		}
		bucket := tx.Bucket([]byte(peerFriendIndexName))
		if friend {
			if err := bucket.Put([]byte(node.ID), []byte{1}); err != nil {
				return err
			}
		} else if err := bucket.Delete([]byte(node.ID)); err != nil {
			return err
		}
		return trimPeerRows(tx, now)
	})
}

func (s *PeerStore) SetFriendByID(nodeID string, friend bool) error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		peers := tx.Bucket([]byte(peerBucketName))
		raw := peers.Get([]byte(nodeID))
		if len(raw) == 0 {
			return fmt.Errorf("peer %s is not in the local peer index", nodeID)
		}
		var peer PeerObservation
		if err := json.Unmarshal(raw, &peer); err != nil {
			return err
		}
		peer.Friend = friend
		data, err := json.Marshal(peer)
		if err != nil {
			return err
		}
		if err := peers.Put([]byte(nodeID), data); err != nil {
			return err
		}
		bucket := tx.Bucket([]byte(peerFriendIndexName))
		if friend {
			return bucket.Put([]byte(nodeID), []byte{1})
		}
		return bucket.Delete([]byte(nodeID))
	})
}

// RecordUse persists a successfully established service connection, even when
// the CLI and daemon are separate processes sharing the same bbolt database.
func (s *PeerStore) RecordUse(node proto.NodeInfo, now time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	if node.ID == "" || node.Addr == "" {
		return fmt.Errorf("service-use record requires node ID and address")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		peers := tx.Bucket([]byte(peerBucketName))
		var peer PeerObservation
		if raw := peers.Get([]byte(node.ID)); len(raw) > 0 {
			if err := json.Unmarshal(raw, &peer); err != nil {
				return err
			}
		}
		peer.Node = node
		peer.LastUsed = now
		peer.LastSeen = now
		if peer.UseCount < ^uint32(0) {
			peer.UseCount++
		}
		if peer.FirstSeen.IsZero() {
			peer.FirstSeen = now
		}
		data, err := json.Marshal(peer)
		if err != nil {
			return err
		}
		if err := peers.Put([]byte(node.ID), data); err != nil {
			return err
		}
		if err := tx.Bucket([]byte(peerUsedIndexName)).Put([]byte(node.ID), []byte{1}); err != nil {
			return err
		}
		return trimPeerRows(tx, now)
	})
}
