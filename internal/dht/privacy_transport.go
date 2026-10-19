package dht

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/vx6/vx6/internal/onion"
	"github.com/vx6/vx6/internal/record"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

const hiddenDescriptorRelayHopCount = 3

type HiddenDescriptorPrivacyConfig struct {
	TransportMode          string
	RelayHopCount          int
	RelayCandidates        func() []record.EndpointRecord
	ExcludeAddrs           func() []string
	PollInterval           time.Duration
	CacheWindow            time.Duration
	CoverLookups           int
	CoverInterval          time.Duration
	PollJitter             time.Duration
	FetchParallel          int
	FetchBatchSize         int
	DiversityAttempts      int
	MinRelayNetworkGroups  int
	MinRelayProviderGroups int
	MinRelayASNGroups      int
	ConsensusGroups        int
	ConsensusMinMatches    int
	BucketPeriod           time.Duration
	BucketBaseCover        []int
	AnomalyEWMAWeight      float64
	AnomalyEscalationSteps []float64
}

func (s *Server) SetHiddenDescriptorPrivacy(cfg HiddenDescriptorPrivacyConfig) {
	if cfg.RelayHopCount <= 0 {
		cfg.RelayHopCount = hiddenDescriptorRelayHopCount
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = hiddenDescriptorPollInterval
	}
	if cfg.CacheWindow <= 0 {
		cfg.CacheWindow = hiddenDescriptorCacheWindow
	}
	if cfg.CoverLookups < 0 {
		cfg.CoverLookups = 0
	}
	if cfg.CoverLookups == 0 {
		cfg.CoverLookups = hiddenDescriptorCoverLookups
	}
	if cfg.CoverInterval <= 0 {
		cfg.CoverInterval = 18 * time.Second
	}
	if cfg.PollJitter < 0 {
		cfg.PollJitter = 0
	}
	if cfg.PollJitter == 0 {
		cfg.PollJitter = 3 * time.Second
	}
	if cfg.FetchParallel <= 0 {
		cfg.FetchParallel = 2
	}
	if cfg.FetchBatchSize <= 0 {
		cfg.FetchBatchSize = 6
	}
	if cfg.FetchBatchSize < cfg.FetchParallel {
		cfg.FetchBatchSize = cfg.FetchParallel
	}
	if cfg.DiversityAttempts <= 0 {
		cfg.DiversityAttempts = 4
	}
	if cfg.MinRelayNetworkGroups <= 0 {
		cfg.MinRelayNetworkGroups = minInt(cfg.RelayHopCount, 3)
	}
	if cfg.MinRelayProviderGroups <= 0 {
		cfg.MinRelayProviderGroups = minInt(cfg.RelayHopCount, 2)
	}
	if cfg.MinRelayASNGroups < 0 {
		cfg.MinRelayASNGroups = 0
	}
	if cfg.ConsensusGroups <= 0 {
		cfg.ConsensusGroups = 3
	}
	if cfg.ConsensusMinMatches <= 0 {
		cfg.ConsensusMinMatches = 2
	}
	if cfg.ConsensusMinMatches > cfg.ConsensusGroups {
		cfg.ConsensusMinMatches = cfg.ConsensusGroups
	}
	if cfg.BucketPeriod <= 0 {
		cfg.BucketPeriod = 10 * time.Minute
	}
	if len(cfg.BucketBaseCover) == 0 {
		cfg.BucketBaseCover = []int{1, 2, 1, 3, 2, 1}
	}
	if cfg.AnomalyEWMAWeight <= 0 || cfg.AnomalyEWMAWeight >= 1 {
		cfg.AnomalyEWMAWeight = 0.2
	}
	if len(cfg.AnomalyEscalationSteps) == 0 {
		cfg.AnomalyEscalationSteps = []float64{0.20, 0.35, 0.55}
	}
	s.mu.Lock()
	s.hidden = cfg
	s.mu.Unlock()
	s.ensureHiddenCoverWorker()
}

func (s *Server) dialDHTConn(ctx context.Context, addr, key, action string) (net.Conn, error) {
	ctx = s.guardedContext(ctx)
	if conn, handled, err := s.dialHiddenDescriptorConn(ctx, addr, key, action); handled {
		return conn, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	return vxtransport.DialContext(dialCtx, vxtransport.ModeAuto, addr)
}

func (s *Server) dialHiddenDescriptorConn(ctx context.Context, targetAddr, key, action string) (net.Conn, bool, error) {
	if !stringsHasHiddenDescriptorKey(key) {
		return nil, false, nil
	}

	s.mu.RLock()
	cfg := s.hidden
	s.mu.RUnlock()
	if cfg.RelayCandidates == nil {
		return nil, false, nil
	}

	hopCount := cfg.RelayHopCount
	if hopCount <= 0 {
		hopCount = hiddenDescriptorRelayHopCount
	}

	exclude := []string{targetAddr}
	if cfg.ExcludeAddrs != nil {
		exclude = append(exclude, cfg.ExcludeAddrs()...)
	}
	relays := filterRelayCandidates(cfg.RelayCandidates(), exclude)
	if len(relays) < hopCount {
		return nil, true, fmt.Errorf("not enough relay candidates to anonymize hidden descriptor %s", action)
	}

	var (
		bestPlan   onion.CircuitPlan
		bestScore  = -1
		planErr    error
		maxAttempt = cfg.DiversityAttempts
	)
	for attempt := 0; attempt < maxAttempt; attempt++ {
		plan, err := onion.PlanAutomatedCircuit(record.ServiceRecord{Address: targetAddr}, relays, hopCount, exclude)
		if err != nil {
			planErr = err
			continue
		}
		networkGroups, providerGroups, asnGroups := circuitRelayDiversity(plan.Relays)
		score := networkGroups*100 + providerGroups*10 + asnGroups
		if score > bestScore {
			bestScore = score
			bestPlan = plan
		}
		if networkGroups >= cfg.MinRelayNetworkGroups &&
			providerGroups >= cfg.MinRelayProviderGroups &&
			(asnGroups >= cfg.MinRelayASNGroups || cfg.MinRelayASNGroups == 0) {
			bestPlan = plan
			planErr = nil
			break
		}
		planErr = fmt.Errorf("hidden descriptor circuit diversity below threshold")
	}
	if len(bestPlan.Relays) == 0 {
		if planErr != nil {
			return nil, true, planErr
		}
		return nil, true, fmt.Errorf("failed to build hidden descriptor circuit plan")
	}
	bestPlan.Purpose = "dht-hidden-desc-" + action

	opts := onion.ClientOptions{TransportMode: cfg.TransportMode}
	conn, err := onion.DialPlannedCircuit(ctx, bestPlan, opts)
	return conn, true, err
}

func filterRelayCandidates(nodes []record.EndpointRecord, excludeAddrs []string) []record.EndpointRecord {
	seenAddrs := make(map[string]struct{}, len(excludeAddrs))
	for _, addr := range excludeAddrs {
		if addr == "" {
			continue
		}
		seenAddrs[addr] = struct{}{}
	}

	filtered := make([]record.EndpointRecord, 0, len(nodes))
	seenNodeIDs := make(map[string]struct{}, len(nodes))
	for _, rec := range nodes {
		if rec.NodeID == "" || rec.Address == "" || rec.PublicKey == "" {
			continue
		}
		if _, ok := seenAddrs[rec.Address]; ok {
			continue
		}
		if _, ok := seenNodeIDs[rec.NodeID]; ok {
			continue
		}
		seenNodeIDs[rec.NodeID] = struct{}{}
		filtered = append(filtered, rec)
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].NodeID < filtered[j].NodeID
	})
	return filtered
}

func circuitRelayDiversity(relays []record.EndpointRecord) (networkGroups int, providerGroups int, asnGroups int) {
	networks := map[string]struct{}{}
	providers := map[string]struct{}{}
	asns := map[string]struct{}{}
	for _, relay := range relays {
		src := sourceObservation{addr: relay.Address}
		if n := src.networkKey(); n != "" {
			networks[n] = struct{}{}
		}
		if p := src.providerKey(); p != "" {
			providers[p] = struct{}{}
		}
		if a := src.asnKey(); a != "" {
			asns[a] = struct{}{}
		}
	}
	return len(networks), len(providers), len(asns)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
