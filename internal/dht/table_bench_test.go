package dht

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/proto"
)

func tableBenchmarkPeer(i int) proto.NodeInfo {
	name := fmt.Sprintf("BENCH-%05d", i)
	return proto.NodeInfo{
		ID:       fmt.Sprintf("vx6_%064x", i+1),
		Name:     name,
		NameHash: NodeNameHash(name),
		Addr:     fmt.Sprintf("[2001:db8:%x::%x]:4242", i/65536, i%65535+1),
	}
}

func makeBenchmarkRoutingTable(peerCount int) *RoutingTable {
	rt := NewRoutingTable("vx6_" + fmt.Sprintf("%064x", 0))
	rt.SetSelfNameHash(NodeNameHash("SELF"))
	for i := 0; i < peerCount; i++ {
		rt.AddNode(tableBenchmarkPeer(i))
	}
	return rt
}

func benchmarkRoutingTable(b *testing.B, peerCount int) *RoutingTable {
	b.Helper()
	return makeBenchmarkRoutingTable(peerCount)
}

func BenchmarkCandidateInsertBatch(b *testing.B) {
	for _, batchSize := range []int{50, 512} {
		b.Run(fmt.Sprintf("candidates=%d", batchSize), func(b *testing.B) {
			candidates := make([]proto.NodeInfo, batchSize)
			for i := range candidates {
				candidates[i] = tableBenchmarkPeer(i)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rt := NewRoutingTable("self")
				for _, candidate := range candidates {
					rt.AddCandidate(candidate)
				}
			}
		})
	}
}

func BenchmarkClosestNodeSelection(b *testing.B) {
	for _, peerCount := range []int{50, 512, 10001} {
		b.Run(fmt.Sprintf("active=%d", peerCount), func(b *testing.B) {
			rt := benchmarkRoutingTable(b, peerCount)
			target := "vx6_" + fmt.Sprintf("%064x", ^uint64(0))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = rt.ClosestNodes(target, K)
			}
		})
	}
}

func BenchmarkRefreshTargetSelection(b *testing.B) {
	for _, peerCount := range []int{50, 512, 10001} {
		b.Run(fmt.Sprintf("active=%d", peerCount), func(b *testing.B) {
			rt := benchmarkRoutingTable(b, peerCount)
			base := time.Now().Add(time.Hour)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				now := base.Add(time.Duration(i+1) * bucketRefreshInterval)
				_ = rt.RefreshTargets(now, 2)
			}
		})
	}
}

func BenchmarkRoutingChurnRecovery(b *testing.B) {
	for _, peerCount := range []int{50, 512} {
		b.Run(fmt.Sprintf("active=%d", peerCount), func(b *testing.B) {
			rt := benchmarkRoutingTable(b, peerCount)
			victim := tableBenchmarkPeer(peerCount / 2)
			base := time.Now().Add(time.Hour)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				start := base.Add(time.Duration(i) * 20 * time.Minute)
				for _, delta := range []time.Duration{0, 5 * time.Minute, 10 * time.Minute} {
					rt.RecordLivenessResult(victim.ID, start.Add(delta), false)
				}
				rt.AddCandidate(victim)
				rt.PromoteCandidate(victim.ID)
			}
		})
	}
}

func TestRoutingTableRetainedHeapReport(t *testing.T) {
	for _, peerCount := range []int{50, 512, 10001} {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		rt := makeBenchmarkRoutingTable(peerCount)
		runtime.GC()
		runtime.ReadMemStats(&after)
		retained := after.HeapAlloc - before.HeapAlloc
		t.Logf("active_peers=%d retained_heap_bytes=%d bytes_per_peer=%.1f", peerCount, retained, float64(retained)/float64(peerCount))
		runtime.KeepAlive(rt)
	}
}
