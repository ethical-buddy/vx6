package dht

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"sort"
	"strings"
	"sync"

	"github.com/vx6/vx6/internal/proto"
)

const K = 20 // K-bucket size

const (
	replacementCacheSize  = 20
	staleFailureThreshold = 2
)

type bucketEntry struct {
	Node      proto.NodeInfo
	FailCount int
}

type RoutingTable struct {
	SelfID  string
	mu      sync.RWMutex
	Buckets [256][]bucketEntry // Full bit length of SHA-256
	Spare   [256][]proto.NodeInfo
	Pending [256][]proto.NodeInfo
}

func NewRoutingTable(selfID string) *RoutingTable {
	return &RoutingTable{SelfID: selfID}
}

// AddNode inserts or updates a node in the routing table
func (rt *RoutingTable) AddNode(node proto.NodeInfo) {
	if node.ID == rt.SelfID {
		return
	}

	bucketIdx := rt.bucketIndex(node.ID)

	rt.mu.Lock()
	defer rt.mu.Unlock()

	bucket := rt.Buckets[bucketIdx]
	for i, existing := range bucket {
		if existing.Node.ID == node.ID {
			// Update existing entry (move to end)
			rt.Buckets[bucketIdx] = append(bucket[:i], bucket[i+1:]...)
			rt.Buckets[bucketIdx] = append(rt.Buckets[bucketIdx], bucketEntry{Node: node})
			return
		}
	}

	if len(bucket) < K {
		rt.Buckets[bucketIdx] = append(bucket, bucketEntry{Node: node})
		return
	}

	rt.rememberReplacementLocked(bucketIdx, node)
}

// AddCandidate keeps a signed referral out of the active routing table until
// a query to that identity succeeds over the authenticated peer tunnel.
func (rt *RoutingTable) AddCandidate(node proto.NodeInfo) {
	if node.ID == "" || node.ID == rt.SelfID || node.Addr == "" {
		return
	}
	bucketIdx := rt.bucketIndex(node.ID)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, bucket := range rt.Buckets {
		for _, entry := range bucket {
			if entry.Node.ID == node.ID {
				return
			}
		}
	}
	for i, existing := range rt.Pending[bucketIdx] {
		if existing.ID == node.ID {
			rt.Pending[bucketIdx] = append(rt.Pending[bucketIdx][:i], rt.Pending[bucketIdx][i+1:]...)
			break
		}
	}
	rt.Pending[bucketIdx] = append(rt.Pending[bucketIdx], node)
	if len(rt.Pending[bucketIdx]) > replacementCacheSize {
		rt.Pending[bucketIdx] = rt.Pending[bucketIdx][1:]
	}
}

func (rt *RoutingTable) PromoteCandidate(nodeID string) {
	var found proto.NodeInfo
	rt.mu.Lock()
	for i := range rt.Pending {
		for j, node := range rt.Pending[i] {
			if node.ID != nodeID {
				continue
			}
			found = node
			rt.Pending[i] = append(rt.Pending[i][:j], rt.Pending[i][j+1:]...)
			break
		}
		if found.ID != "" {
			break
		}
	}
	rt.mu.Unlock()
	if found.ID != "" {
		rt.AddNode(found)
	}
}

func (rt *RoutingTable) DiscardCandidate(nodeID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for i := range rt.Pending {
		for j, node := range rt.Pending[i] {
			if node.ID == nodeID {
				rt.Pending[i] = append(rt.Pending[i][:j], rt.Pending[i][j+1:]...)
				return
			}
		}
	}
}

func (rt *RoutingTable) NoteFailure(nodeID string) bool {
	if nodeID == "" || nodeID == rt.SelfID {
		return false
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	for bucketIdx, bucket := range rt.Buckets {
		for i, entry := range bucket {
			if entry.Node.ID != nodeID {
				continue
			}
			entry.FailCount++
			if entry.FailCount < staleFailureThreshold {
				rt.Buckets[bucketIdx][i] = entry
				return false
			}

			rt.Buckets[bucketIdx] = append(bucket[:i], bucket[i+1:]...)
			rt.promoteReplacementLocked(bucketIdx)
			return true
		}
	}
	return false
}

// ClosestNodes returns the K closest nodes to the target ID
func (rt *RoutingTable) ClosestNodes(targetID string, count int) []proto.NodeInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	var all []proto.NodeInfo
	for _, b := range rt.Buckets {
		for _, entry := range b {
			all = append(all, entry.Node)
		}
	}

	sort.Slice(all, func(i, j int) bool {
		distI := rt.distance(all[i].ID, targetID)
		distJ := rt.distance(all[j].ID, targetID)
		return distI.Cmp(distJ) == -1
	})

	if len(all) > count {
		return all[:count]
	}
	return all
}

func (rt *RoutingTable) NodeByAddress(addr string) (proto.NodeInfo, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for _, bucket := range rt.Buckets {
		for _, entry := range bucket {
			if entry.Node.Addr == addr {
				return entry.Node, true
			}
		}
	}
	for _, bucket := range rt.Spare {
		for _, node := range bucket {
			if node.Addr == addr {
				return node, true
			}
		}
	}
	for _, bucket := range rt.Pending {
		for _, node := range bucket {
			if node.Addr == addr {
				return node, true
			}
		}
	}
	return proto.NodeInfo{}, false
}

func (rt *RoutingTable) ActiveNode(nodeID string) (proto.NodeInfo, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for _, bucket := range rt.Buckets {
		for _, entry := range bucket {
			if entry.Node.ID == nodeID {
				return entry.Node, true
			}
		}
	}
	return proto.NodeInfo{}, false
}

func (rt *RoutingTable) Nodes() []proto.NodeInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := make([]proto.NodeInfo, 0)
	for _, bucket := range rt.Buckets {
		for _, entry := range bucket {
			out = append(out, entry.Node)
		}
	}
	for _, bucket := range rt.Spare {
		out = append(out, bucket...)
	}
	return out
}

func (rt *RoutingTable) bucketIndex(nodeID string) int {
	dist := rt.distance(rt.SelfID, nodeID)
	bucketIdx := dist.BitLen() - 1
	if bucketIdx < 0 {
		return 0
	}
	return bucketIdx
}

func (rt *RoutingTable) rememberReplacementLocked(bucketIdx int, node proto.NodeInfo) {
	replacements := rt.Spare[bucketIdx]
	for i, existing := range replacements {
		if existing.ID != node.ID {
			continue
		}
		rt.Spare[bucketIdx] = append(replacements[:i], replacements[i+1:]...)
		rt.Spare[bucketIdx] = append(rt.Spare[bucketIdx], node)
		return
	}
	rt.Spare[bucketIdx] = append(rt.Spare[bucketIdx], node)
	if len(rt.Spare[bucketIdx]) > replacementCacheSize {
		rt.Spare[bucketIdx] = rt.Spare[bucketIdx][len(rt.Spare[bucketIdx])-replacementCacheSize:]
	}
}

func (rt *RoutingTable) promoteReplacementLocked(bucketIdx int) {
	if len(rt.Buckets[bucketIdx]) >= K {
		return
	}
	replacements := rt.Spare[bucketIdx]
	if len(replacements) == 0 {
		return
	}
	next := replacements[len(replacements)-1]
	rt.Spare[bucketIdx] = replacements[:len(replacements)-1]
	rt.Buckets[bucketIdx] = append(rt.Buckets[bucketIdx], bucketEntry{Node: next})
}

func (rt *RoutingTable) distance(id1, id2 string) *big.Int {
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
