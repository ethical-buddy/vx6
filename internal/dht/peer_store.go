package dht

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/vx6/vx6/internal/proto"
	bolt "go.etcd.io/bbolt"
)

const (
	peerBucketName    = "peers-v1"
	peerNameIndexName = "name-hash-v1"
	maxPersistedPeers = 10000
	peerStoreFileMode = 0o600
	peerStoreDirMode  = 0o700
	peerHistoryTTL    = 30 * 24 * time.Hour
)

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
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize DHT peer store: %w", err)
	}
	return &PeerStore{db: db}, nil
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
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Pinned != peers[j].Pinned {
			return peers[i].Pinned
		}
		return peers[i].LastSuccess.After(peers[j].LastSuccess)
	})
	selected := make([]PeerObservation, 0, min(len(peers), maxPersistedPeers))
	for _, peer := range peers {
		if peer.Node.ID == "" || peer.Node.Addr == "" || (!peer.Pinned && !peer.LastSeen.IsZero() && now.Sub(peer.LastSeen) > peerHistoryTTL) {
			continue
		}
		if len(selected) == maxPersistedPeers {
			if peer.Pinned {
				return fmt.Errorf("DHT peer store limit (%d) reached by pinned peers", maxPersistedPeers)
			}
			continue
		}
		selected = append(selected, peer)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		peersBucket := tx.Bucket([]byte(peerBucketName))
		nameBucket := tx.Bucket([]byte(peerNameIndexName))
		keep := make(map[string]struct{}, len(selected))
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
			if bytes.Equal(oldData, data) {
				continue
			}
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
		return nil
	})
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
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(peerBucketName)).ForEach(func(_, value []byte) error {
			var peer PeerObservation
			if err := json.Unmarshal(value, &peer); err != nil {
				return nil // Ignore a damaged row without losing the rest of the cache.
			}
			if peer.Node.ID == "" || peer.Node.Addr == "" || (!peer.Pinned && !peer.LastSeen.IsZero() && now.Sub(peer.LastSeen) > peerAddressHintTTL) {
				return nil
			}
			peers = append(peers, peer)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("read DHT peer store: %w", err)
	}
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Pinned != peers[j].Pinned {
			return peers[i].Pinned
		}
		return peers[i].LastSuccess.After(peers[j].LastSuccess)
	})
	if len(peers) > limit {
		peers = peers[:limit]
	}
	return peers, nil
}
