// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package dht

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

type Server struct {
	RT            *RoutingTable
	Values        map[string]string // The decentralized database
	publisher     identity.Identity
	hidden        HiddenDescriptorPrivacyConfig
	adaptive      AdaptiveConfig
	versions      map[string]StoredValueState
	replicas      map[string]ReplicaObservation
	hiddenCache   map[string]cachedHiddenService
	hiddenWarmers map[string]struct{}
	hiddenTracked map[string]struct{}
	hiddenCoverOn bool
	hiddenRates   map[string]rateWindow
	storeRates    map[string]rateWindow
	lookupEWMA    float64
	hiddenAnomalyEWMA float64
	mu            sync.RWMutex
}

type lookupBranch struct {
	id         int
	rootNodeID string
	queue      []proto.NodeInfo
}

const (
	defaultLookupAlpha               = 3
	defaultLookupQueryBudget         = 12
	defaultReplicationFactor         = 5
	lookupAlpha                      = defaultLookupAlpha
	lookupQueryBudget                = defaultLookupQueryBudget
	replicationFactor                = defaultReplicationFactor
	hiddenDescriptorRotation         = time.Hour
	hiddenLookupDelimiter            = "#"
	hiddenDescriptorCacheWindow      = 45 * time.Second
	hiddenDescriptorPollInterval     = 12 * time.Second
	hiddenDescriptorCoverLookups     = 1
	hiddenDescriptorLookupRateWindow = 30 * time.Second
	hiddenDescriptorLookupRateLimit  = 48
	hiddenDescriptorStoreRateWindow  = 30 * time.Second
	hiddenDescriptorStoreRateLimit   = 24
)

type AdaptiveConfig struct {
	LookupAlphaBase      int
	LookupAlphaMax       int
	LookupBudgetBase     int
	LookupBudgetMax      int
	ReplicationBase      int
	ReplicationMax       int
	FailureEWMAWeight    float64
	HighFailureThreshold float64
}

type StoredVersion struct {
	Family          string
	Fingerprint     string
	PublisherNodeID string
	Version         uint64
	IssuedAt        string
	ExpiresAt       string
}

type StoredValueState struct {
	Current   StoredVersion
	Previous  []StoredVersion
	Conflicts []StoredVersion
}

type ReplicationReport struct {
	Key            string
	Desired        int
	Attempted      int
	StoredRemotely int
	LocalStored    bool
	Successful     []proto.NodeInfo
	Failed         []proto.NodeInfo
}

func NodeNameKey(name string) string {
	return "node/name/" + name
}

func NodeIDKey(nodeID string) string {
	return "node/id/" + nodeID
}

func ServiceKey(fullName string) string {
	return "service/" + fullName
}

func isTrustedLookupKey(key string) bool {
	return strings.HasPrefix(key, "node/name/") ||
		strings.HasPrefix(key, "node/id/") ||
		strings.HasPrefix(key, "service/") ||
		strings.HasPrefix(key, "hidden-desc/v1/") ||
		strings.HasPrefix(key, "private-catalog/")
}

func HiddenServiceKey(alias string) string {
	return HiddenServiceKeyAt(alias, time.Now())
}

func HiddenServiceKeyAt(alias string, now time.Time) string {
	ref, _ := ParseHiddenLookupRef(alias)
	return hiddenServiceKeyForRefEpoch(ref, hiddenDescriptorEpoch(now))
}

func HiddenServiceLookupKeys(alias string, now time.Time) []string {
	ref, _ := ParseHiddenLookupRef(alias)
	current := hiddenDescriptorEpoch(now)
	keys := []string{hiddenServiceKeyForRefEpoch(ref, current)}
	previous := current - 1
	if previous >= 0 {
		keys = append(keys, hiddenServiceKeyForRefEpoch(ref, previous))
	}
	return keys
}

func HiddenServicePublishKeys(alias, secret string, now time.Time) []string {
	ref := HiddenLookupRef{Alias: alias, Secret: secret}
	keys := hiddenServiceLookupKeysForRef(ref, now)
	out := make([]string, 0, len(keys))
	seen := map[string]struct{}{}
	for _, key := range keys {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

type HiddenLookupRef struct {
	Alias  string
	Secret string
}

func ParseHiddenLookupRef(input string) (HiddenLookupRef, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return HiddenLookupRef{}, fmt.Errorf("hidden lookup reference cannot be empty")
	}
	parts := strings.SplitN(input, hiddenLookupDelimiter, 2)
	ref := HiddenLookupRef{Alias: parts[0]}
	if err := record.ValidateHiddenAlias(ref.Alias); err != nil {
		return HiddenLookupRef{}, err
	}
	if len(parts) == 2 {
		ref.Secret = strings.TrimSpace(parts[1])
		if err := ValidateHiddenLookupSecret(ref.Secret); err != nil {
			return HiddenLookupRef{}, err
		}
	}
	return ref, nil
}

func ComposeHiddenLookupInvite(alias, secret string) string {
	if strings.TrimSpace(secret) == "" {
		return alias
	}
	return alias + hiddenLookupDelimiter + secret
}

func NewHiddenLookupSecret() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate hidden lookup secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func ValidateHiddenLookupSecret(secret string) error {
	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf("hidden lookup secret cannot be empty")
	}
	if strings.ContainsAny(secret, " \t\r\n/#") {
		return fmt.Errorf("hidden lookup secret contains unsupported characters")
	}
	if len(secret) < 16 {
		return fmt.Errorf("hidden lookup secret must be at least 16 characters")
	}
	return nil
}

func NewServer(selfID string) *Server {
	return &Server{
		RT:            NewRoutingTable(selfID),
		Values:        make(map[string]string),
		adaptive:      defaultAdaptiveConfig(),
		versions:      make(map[string]StoredValueState),
		replicas:      make(map[string]ReplicaObservation),
		hiddenCache:   make(map[string]cachedHiddenService),
		hiddenWarmers: make(map[string]struct{}),
		hiddenTracked: make(map[string]struct{}),
		hiddenRates:   make(map[string]rateWindow),
		storeRates:    make(map[string]rateWindow),
	}
}

func defaultAdaptiveConfig() AdaptiveConfig {
	return AdaptiveConfig{
		LookupAlphaBase:      defaultLookupAlpha,
		LookupAlphaMax:       6,
		LookupBudgetBase:     defaultLookupQueryBudget,
		LookupBudgetMax:      28,
		ReplicationBase:      defaultReplicationFactor,
		ReplicationMax:       8,
		FailureEWMAWeight:    0.18,
		HighFailureThreshold: 0.35,
	}
}

func hiddenDescriptorEpoch(now time.Time) int64 {
	if now.IsZero() {
		now = time.Now()
	}
	return now.UTC().Unix() / int64(hiddenDescriptorRotation/time.Second)
}

func hiddenServiceLookupKeysForRef(ref HiddenLookupRef, now time.Time) []string {
	current := hiddenDescriptorEpoch(now)
	keys := []string{hiddenServiceKeyForRefEpoch(ref, current)}
	previous := current - 1
	if previous >= 0 {
		keys = append(keys, hiddenServiceKeyForRefEpoch(ref, previous))
	}
	return keys
}

func hiddenServiceKeyForRefEpoch(ref HiddenLookupRef, epoch int64) string {
	lookupSecret := ref.Alias
	if strings.TrimSpace(ref.Secret) != "" {
		lookupSecret = ref.Secret
	}
	sum := sha256.Sum256([]byte("vx6-hidden-desc-v1\n" + ref.Alias + "\n" + lookupSecret + "\n" + strconv.FormatInt(epoch, 10)))
	return "hidden-desc/v1/" + strconv.FormatInt(epoch, 10) + "/" + base64.RawURLEncoding.EncodeToString(sum[:20])
}

func NewServerWithIdentity(id identity.Identity) *Server {
	server := NewServer(id.NodeID)
	_ = server.SetPublisherIdentity(id)
	return server
}

func (s *Server) SetPublisherIdentity(id identity.Identity) error {
	if err := id.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publisher = id
	return nil
}

func (s *Server) LookupState(key string) (StoredValueState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.versions[key]
	return state, ok
}

// HandleDHT processes an incoming DHT request from a peer.
func (s *Server) HandleDHT(ctx context.Context, conn net.Conn, req proto.DHTRequest) error {
	resp := proto.DHTResponse{}
	if stringsHasHiddenDescriptorKey(req.Target) {
		if !s.allowHiddenDescriptorRequest(conn.RemoteAddr().String(), req.Action, time.Now()) {
			payload, _ := json.Marshal(resp)
			if err := proto.WriteHeader(conn, proto.KindDHT); err != nil {
				return err
			}
			return proto.WriteLengthPrefixed(conn, payload)
		}
	}

	switch req.Action {
	case "find_node":
		resp.Nodes = s.RT.ClosestNodes(req.Target, K)
	case "find_value":
		resp.Nodes = s.RT.ClosestNodes(req.Target, K)
		s.mu.RLock()
		val, ok := s.Values[req.Target]
		s.mu.RUnlock()
		if ok {
			resp.Value = val
		}
	case "store":
		if err := s.admitStoreValue(conn.RemoteAddr().String(), req.Target, req.Data, time.Now()); err != nil {
			// Invalid or conflicting writes are ignored to keep the DHT conservative
			// under poisoning attempts.
			break
		}
		if _, _, err := s.storeValidated(req.Target, req.Data, time.Now()); err != nil {
			// Invalid or conflicting writes are ignored to keep the DHT conservative
			// under poisoning attempts.
		}
	}

	payload, _ := json.Marshal(resp)
	if err := proto.WriteHeader(conn, proto.KindDHT); err != nil {
		return err
	}
	return proto.WriteLengthPrefixed(conn, payload)
}

func (s *Server) StoreLocal(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Values[key] = value
	if validated, err := validateLookupValue(key, value, time.Now()); err == nil {
		s.versions[key] = StoredValueState{Current: storedVersionFromValidated(validated)}
	}
}

// RecursiveFindNode searches the network for a specific NodeID.
func (s *Server) RecursiveFindNode(ctx context.Context, targetID string) ([]proto.NodeInfo, error) {
	visited := make(map[string]bool)
	candidates := s.RT.ClosestNodes(targetID, K)

	for {
		foundNew := false
		newCandidates := []proto.NodeInfo{}
		for _, node := range candidates {
			if visited[node.ID] {
				continue
			}
			visited[node.ID] = true

			newNodes, err := s.QueryNode(ctx, node.Addr, targetID)
			if err != nil {
				s.RT.NoteFailure(node.ID)
				continue
			}
			s.RT.AddNode(node)
			for _, n := range newNodes {
				if !visited[n.ID] {
					s.RT.AddNode(n)
					newCandidates = append(newCandidates, n)
					foundNew = true
				}
			}
		}
		candidates = append(candidates, newCandidates...)

		if !foundNew {
			break
		}
	}

	return s.RT.ClosestNodes(targetID, K), nil
}

// Store saves a value on a bounded set of the closest nodes to the target key.
func (s *Server) Store(ctx context.Context, targetID, value string) error {
	_, err := s.MaintainReplicas(ctx, targetID, value)
	return err
}

// MaintainReplicas stores a validated value locally and then repairs the remote
// replica set by walking bounded backup candidates until the desired replica
// count is reached or no more candidates remain.
func (s *Server) MaintainReplicas(ctx context.Context, targetID, value string) (ReplicationReport, error) {
	report := ReplicationReport{Key: targetID}

	wrapped, err := s.prepareStoreValue(targetID, value, time.Now())
	if err != nil {
		return report, err
	}
	if _, _, err := s.storeValidated(targetID, wrapped, time.Now()); err != nil {
		return report, err
	}
	report.LocalStored = true

	candidates := selectReplicationNodes(s.RT.ClosestNodes(targetID, K), K)
	desired := s.adaptiveReplicationTarget()
	if len(candidates) < desired {
		report.Desired = len(candidates)
	} else {
		report.Desired = desired
	}

	for offset := 0; offset < len(candidates) && report.StoredRemotely < report.Desired; {
		remaining := report.Desired - report.StoredRemotely
		end := offset + remaining
		if end > len(candidates) {
			end = len(candidates)
		}
		batch := candidates[offset:end]
		offset = end

		type batchResult struct {
			node proto.NodeInfo
			err  error
		}
		results := make(chan batchResult, len(batch))
		for _, node := range batch {
			node := node
			go func() {
				results <- batchResult{node: node, err: s.sendStore(ctx, node.Addr, targetID, wrapped)}
			}()
		}

		for range batch {
			result := <-results
			report.Attempted++
			if result.err != nil {
				s.RT.NoteFailure(result.node.ID)
				report.Failed = append(report.Failed, result.node)
				continue
			}
			s.RT.AddNode(result.node)
			report.StoredRemotely++
			report.Successful = append(report.Successful, result.node)
		}
	}

	return report, nil
}

func (s *Server) adaptiveLookupParams() (int, int) {
	s.mu.RLock()
	cfg := s.adaptive
	failure := s.lookupEWMA
	s.mu.RUnlock()

	alpha := cfg.LookupAlphaBase
	budget := cfg.LookupBudgetBase
	if failure >= cfg.HighFailureThreshold {
		alpha += 2
		budget += 10
	} else if failure >= cfg.HighFailureThreshold/2 {
		alpha++
		budget += 5
	}

	if alpha < 1 {
		alpha = 1
	}
	if alpha > cfg.LookupAlphaMax {
		alpha = cfg.LookupAlphaMax
	}
	if budget < alpha {
		budget = alpha
	}
	if budget > cfg.LookupBudgetMax {
		budget = cfg.LookupBudgetMax
	}
	return alpha, budget
}

func (s *Server) adaptiveReplicationTarget() int {
	s.mu.RLock()
	cfg := s.adaptive
	failure := s.lookupEWMA
	s.mu.RUnlock()

	target := cfg.ReplicationBase
	if failure >= cfg.HighFailureThreshold {
		target += 2
	} else if failure >= cfg.HighFailureThreshold/2 {
		target++
	}
	if target < 1 {
		target = 1
	}
	if target > cfg.ReplicationMax {
		target = cfg.ReplicationMax
	}
	return target
}

func (s *Server) noteLookupResult(success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	weight := s.adaptive.FailureEWMAWeight
	if weight <= 0 || weight >= 1 {
		weight = 0.18
	}
	sample := 1.0
	if success {
		sample = 0.0
	}
	s.lookupEWMA = (1.0-weight)*s.lookupEWMA + weight*sample
}

func (s *Server) prepareStoreValue(key, value string, now time.Time) (string, error) {
	info, err := validateInnerLookupValue(key, value, now)
	if err != nil {
		return "", err
	}
	if !info.verified {
		return value, nil
	}

	s.mu.RLock()
	publisher := s.publisher
	s.mu.RUnlock()
	if err := publisher.Validate(); err != nil {
		return value, nil
	}
	return wrapSignedEnvelope(publisher, key, value, info, now)
}

func (s *Server) admitStoreValue(remoteAddr, key, value string, now time.Time) error {
	trusted := isTrustedLookupKey(key)
	if err := s.allowStoreRequest(remoteAddr, key, trusted, now); err != nil {
		return err
	}
	if trusted {
		incomingValue, err := validateLookupValue(key, value, now)
		if err != nil {
			return err
		}
		if incomingValue.verified && incomingValue.enveloped && !incomingValue.authoritativePublisher {
			return fmt.Errorf("trusted store rejected for non-authoritative publisher on key %q", key)
		}
		if err := s.rejectStaleStoreValue(key, value, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) allowStoreRequest(remoteAddr, key string, trusted bool, now time.Time) error {
	var (
		window time.Duration
		limit  int
	)
	if trusted {
		window = hiddenDescriptorStoreRateWindow
		limit = hiddenDescriptorStoreRateLimit
	} else {
		window = hiddenDescriptorStoreRateWindow
		limit = hiddenDescriptorStoreRateLimit * 2
	}

	host := remoteAddr
	if parsedHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	keyClass := "store\n" + host + "\n" + key
	familyKey := "store-family\n" + host + "\n" + storeFamily(key)

	s.mu.Lock()
	defer s.mu.Unlock()
	for existing, counter := range s.storeRates {
		if now.Sub(counter.WindowStart) > window*2 {
			delete(s.storeRates, existing)
		}
	}
	if !s.allowRateWindowLocked(keyClass, now, window, limit) {
		return fmt.Errorf("store rate limit exceeded for key %q from %s", key, host)
	}
	if !s.allowRateWindowLocked(familyKey, now, window, limit*2) {
		return fmt.Errorf("store family rate limit exceeded for key %q from %s", key, host)
	}
	return nil
}

func (s *Server) allowRateWindowLocked(key string, now time.Time, window time.Duration, limit int) bool {
	counter := s.storeRates[key]
	if counter.WindowStart.IsZero() || now.Sub(counter.WindowStart) >= window {
		s.storeRates[key] = rateWindow{WindowStart: now, Count: 1}
		return true
	}
	if counter.Count >= limit {
		return false
	}
	counter.Count++
	s.storeRates[key] = counter
	return true
}

func (s *Server) rejectStaleStoreValue(key, value string, now time.Time) error {
	incomingValue, err := validateLookupValue(key, value, now)
	if err != nil {
		return err
	}
	s.mu.RLock()
	current := s.Values[key]
	s.mu.RUnlock()
	if current == "" {
		return nil
	}
	currentValue, err := validateLookupValue(key, current, now)
	if err != nil || !currentValue.verified || !incomingValue.verified {
		return nil
	}
	if currentValue.family != incomingValue.family {
		return nil
	}
	if !isNewerValue(incomingValue, currentValue) {
		return fmt.Errorf("stale store rejected for key %q", key)
	}
	return nil
}

func storeFamily(key string) string {
	switch {
	case strings.HasPrefix(key, "node/name/"):
		return "node"
	case strings.HasPrefix(key, "node/id/"):
		return "node"
	case strings.HasPrefix(key, "service/"):
		return "service"
	case strings.HasPrefix(key, "private-catalog/"):
		return "private-catalog"
	case strings.HasPrefix(key, "hidden-desc/v1/"):
		return "hidden-desc"
	default:
		return "other"
	}
}

func (s *Server) storeValidated(key, value string, now time.Time) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current := s.Values[key]
	chosen, changed, previousValue, incomingValue, err := chooseStoredValue(key, current, value, now)
	if err != nil {
		if incomingValue.raw != "" {
			s.recordConflictLocked(key, incomingValue)
		}
		return current, false, err
	}
	if changed {
		s.Values[key] = chosen
	}
	s.recordVersionLocked(key, previousValue, incomingValue, changed)
	return chosen, changed, nil
}

func (s *Server) sendStore(ctx context.Context, addr, key, value string) error {
	conn, err := s.dialDHTConn(ctx, addr, key, "store")
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	req := proto.DHTRequest{Action: "store", Target: key, Data: value}
	if err := proto.WriteHeader(conn, proto.KindDHT); err != nil {
		return err
	}
	payload, _ := json.Marshal(req)
	if err := proto.WriteLengthPrefixed(conn, payload); err != nil {
		return err
	}

	kind, err := proto.ReadHeader(conn)
	if err != nil {
		return err
	}
	if kind != proto.KindDHT {
		return fmt.Errorf("invalid response")
	}
	_, err = proto.ReadLengthPrefixed(conn, 1024*1024)
	return err
}

// RecursiveFindValue searches for a value in the network.
func (s *Server) RecursiveFindValue(ctx context.Context, key string) (string, error) {
	result, err := s.RecursiveFindValueDetailed(ctx, key)
	if err != nil {
		return "", err
	}
	return result.Value, nil
}

func (s *Server) RecursiveFindValueDetailed(ctx context.Context, key string) (LookupResult, error) {
	visited := make(map[string]bool)
	candidates := s.RT.ClosestNodes(key, K)
	collector := newLookupCollector(key, time.Now())
	queried := 0
	alpha, budget := s.adaptiveLookupParams()

	s.mu.RLock()
	if local, ok := s.Values[key]; ok && local != "" {
		collector.Observe(sourceObservation{nodeID: "local:" + s.RT.SelfID, trust: 3, branch: 0}, local)
	}
	s.mu.RUnlock()

	branches, spares, nextBranchID := buildLookupBranches(candidates, alpha)
	for len(branches) > 0 && queried < budget {
		type branchQuery struct {
			branchID int
			node     proto.NodeInfo
		}
		batch := make([]branchQuery, 0, len(branches))
		active := make([]lookupBranch, 0, len(branches))
		for _, branch := range branches {
			node, ok := nextBranchCandidate(branch.queue, visited)
			if !ok {
				if len(spares) > 0 {
					branch.id = nextBranchID
					nextBranchID++
					branch.rootNodeID = spares[0].ID
					branch.queue = []proto.NodeInfo{spares[0]}
					spares = spares[1:]
					node, ok = nextBranchCandidate(branch.queue, visited)
				}
			}
			if !ok {
				continue
			}
			visited[node.ID] = true
			batch = append(batch, branchQuery{branchID: branch.id, node: node})
			active = append(active, branch)
		}
		branches = active
		if len(batch) == 0 {
			break
		}

		type queryResult struct {
			branchID int
			node     proto.NodeInfo
			value    string
			next     []proto.NodeInfo
			err      error
		}

		resultsCh := make(chan queryResult, len(batch))
		for _, item := range batch {
			item := item
			go func() {
				val, nextNodes, err := s.QueryValue(ctx, item.node.Addr, key)
				resultsCh <- queryResult{branchID: item.branchID, node: item.node, value: val, next: nextNodes, err: err}
			}()
		}

		for i := 0; i < len(batch); i++ {
			result := <-resultsCh
			queried++
			if result.err != nil {
				s.noteLookupResult(false)
				s.RT.NoteFailure(result.node.ID)
				continue
			}
			s.noteLookupResult(true)
			s.RT.AddNode(result.node)
			if result.value != "" {
				collector.Observe(sourceObservation{nodeID: result.node.ID, addr: result.node.Addr, trust: 1, branch: result.branchID}, result.value)
			}
			for idx := range branches {
				if branches[idx].id != result.branchID {
					continue
				}
				branches[idx].queue = mergeBranchCandidates(branches[idx].queue, result.next, visited, key, s.RT)
				break
			}
		}

		if collector.IsConfirmed() {
			break
		}
	}

	res, err := collector.Resolve(queried)
	if err != nil {
		s.noteLookupResult(false)
		return res, err
	}
	s.noteLookupResult(true)
	return res, nil
}

func (s *Server) QueryNode(ctx context.Context, addr, targetID string) ([]proto.NodeInfo, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	conn, err := vxtransport.DialContext(dialCtx, vxtransport.ModeAuto, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	req := proto.DHTRequest{Action: "find_node", Target: targetID}
	if err := proto.WriteHeader(conn, proto.KindDHT); err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(req)
	if err := proto.WriteLengthPrefixed(conn, payload); err != nil {
		return nil, err
	}

	kind, err := proto.ReadHeader(conn)
	if err != nil || kind != proto.KindDHT {
		return nil, fmt.Errorf("invalid response")
	}

	resPayload, err := proto.ReadLengthPrefixed(conn, 1024*1024)
	if err != nil {
		return nil, err
	}
	var resp proto.DHTResponse
	if err := json.Unmarshal(resPayload, &resp); err != nil {
		return nil, err
	}
	return resp.Nodes, nil
}

func (s *Server) QueryValue(ctx context.Context, addr, key string) (string, []proto.NodeInfo, error) {
	conn, err := s.dialDHTConn(ctx, addr, key, "lookup")
	if err != nil {
		return "", nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	req := proto.DHTRequest{Action: "find_value", Target: key}
	if err := proto.WriteHeader(conn, proto.KindDHT); err != nil {
		return "", nil, err
	}
	payload, _ := json.Marshal(req)
	if err := proto.WriteLengthPrefixed(conn, payload); err != nil {
		return "", nil, err
	}

	kind, err := proto.ReadHeader(conn)
	if err != nil || kind != proto.KindDHT {
		return "", nil, fmt.Errorf("invalid response")
	}

	resPayload, err := proto.ReadLengthPrefixed(conn, 1024*1024)
	if err != nil {
		return "", nil, err
	}
	var resp proto.DHTResponse
	if err := json.Unmarshal(resPayload, &resp); err != nil {
		return "", nil, err
	}
	return resp.Value, resp.Nodes, nil
}

func nextCandidateBatch(candidates []proto.NodeInfo, visited map[string]bool, max int) []proto.NodeInfo {
	out := make([]proto.NodeInfo, 0, max)
	for _, node := range candidates {
		if visited[node.ID] {
			continue
		}
		out = append(out, node)
		if len(out) == max {
			break
		}
	}
	return out
}

func buildLookupBranches(candidates []proto.NodeInfo, limit int) ([]lookupBranch, []proto.NodeInfo, int) {
	if limit <= 0 || len(candidates) == 0 {
		return nil, nil, 1
	}
	roots := selectReplicationNodes(candidates, limit)
	branches := make([]lookupBranch, 0, len(roots))
	used := make(map[string]struct{}, len(roots))
	for i, node := range roots {
		branches = append(branches, lookupBranch{id: i + 1, rootNodeID: node.ID, queue: []proto.NodeInfo{node}})
		used[node.ID] = struct{}{}
	}
	spares := make([]proto.NodeInfo, 0, len(candidates))
	for _, node := range candidates {
		if _, ok := used[node.ID]; ok {
			continue
		}
		spares = append(spares, node)
	}
	return branches, spares, len(roots) + 1
}

func nextBranchCandidate(queue []proto.NodeInfo, visited map[string]bool) (proto.NodeInfo, bool) {
	for _, node := range queue {
		if visited[node.ID] {
			continue
		}
		return node, true
	}
	return proto.NodeInfo{}, false
}

func mergeBranchCandidates(existing, incoming []proto.NodeInfo, visited map[string]bool, target string, rt *RoutingTable) []proto.NodeInfo {
	merged := mergeCandidateNodes(existing, incoming, map[string]bool{}, target, rt)
	out := make([]proto.NodeInfo, 0, len(merged))
	for _, node := range merged {
		if visited[node.ID] {
			continue
		}
		out = append(out, node)
	}
	return out
}

func mergeCandidateNodes(existing, incoming []proto.NodeInfo, visited map[string]bool, target string, rt *RoutingTable) []proto.NodeInfo {
	all := append([]proto.NodeInfo(nil), existing...)
	all = append(all, incoming...)

	seen := make(map[string]struct{}, len(all))
	dedup := make([]proto.NodeInfo, 0, len(all))
	for _, node := range all {
		if node.ID == "" || node.Addr == "" {
			continue
		}
		if visited[node.ID] {
			continue
		}
		if _, ok := seen[node.ID]; ok {
			continue
		}
		seen[node.ID] = struct{}{}
		dedup = append(dedup, node)
	}

	sort.Slice(dedup, func(i, j int) bool {
		distI := rt.distance(dedup[i].ID, target)
		distJ := rt.distance(dedup[j].ID, target)
		return distI.Cmp(distJ) < 0
	})
	return dedup
}

func selectReplicationNodes(nodes []proto.NodeInfo, limit int) []proto.NodeInfo {
	if len(nodes) <= limit {
		return append([]proto.NodeInfo(nil), nodes...)
	}

	out := make([]proto.NodeInfo, 0, limit)
	remaining := make([]proto.NodeInfo, 0, len(nodes))
	seenASNs := map[string]struct{}{}
	seenProviders := map[string]struct{}{}
	seenNetworks := map[string]struct{}{}
	selected := map[string]struct{}{}

	appendNode := func(node proto.NodeInfo) bool {
		if _, ok := selected[node.ID]; ok {
			return false
		}
		selected[node.ID] = struct{}{}
		out = append(out, node)
		if asn := (sourceObservation{addr: node.Addr}).asnKey(); asn != "" {
			seenASNs[asn] = struct{}{}
		}
		if provider := (sourceObservation{addr: node.Addr}).providerKey(); provider != "" {
			seenProviders[provider] = struct{}{}
		}
		if network := (sourceObservation{addr: node.Addr}).networkKey(); network != "" {
			seenNetworks[network] = struct{}{}
		}
		return len(out) == limit
	}

	for _, node := range nodes {
		asn := (sourceObservation{addr: node.Addr}).asnKey()
		if asn == "" {
			remaining = append(remaining, node)
			continue
		}
		if _, ok := seenASNs[asn]; ok {
			remaining = append(remaining, node)
			continue
		}
		if appendNode(node) {
			return out
		}
	}

	secondPass := remaining
	remaining = remaining[:0]
	for _, node := range secondPass {
		provider := (sourceObservation{addr: node.Addr}).providerKey()
		if provider == "" {
			remaining = append(remaining, node)
			continue
		}
		if _, ok := seenProviders[provider]; ok {
			remaining = append(remaining, node)
			continue
		}
		if appendNode(node) {
			return out
		}
	}

	thirdPass := remaining
	remaining = remaining[:0]
	for _, node := range thirdPass {
		network := (sourceObservation{addr: node.Addr}).networkKey()
		if network == "" {
			remaining = append(remaining, node)
			continue
		}
		if _, ok := seenNetworks[network]; ok {
			remaining = append(remaining, node)
			continue
		}
		if appendNode(node) {
			return out
		}
	}

	for _, node := range remaining {
		if appendNode(node) {
			return out
		}
	}
	return out
}

func storedVersionFromValidated(value validatedValue) StoredVersion {
	return StoredVersion{
		Family:          value.family,
		Fingerprint:     value.fingerprint,
		PublisherNodeID: value.publisherNodeID,
		Version:         value.version,
		IssuedAt:        value.issuedAt.UTC().Format(time.RFC3339),
		ExpiresAt:       value.expiresAt.UTC().Format(time.RFC3339),
	}
}

func (s *Server) recordVersionLocked(key string, previous, incoming validatedValue, changed bool) {
	if incoming.raw == "" {
		return
	}
	state := s.versions[key]
	if changed {
		if previous.raw != "" {
			state.Previous = appendBoundedVersion(state.Previous, storedVersionFromValidated(previous))
		}
		state.Current = storedVersionFromValidated(incoming)
		s.versions[key] = state
		return
	}
	if state.Current.Fingerprint == "" {
		state.Current = storedVersionFromValidated(incoming)
		s.versions[key] = state
	}
}

func (s *Server) recordConflictLocked(key string, incoming validatedValue) {
	if incoming.raw == "" {
		return
	}
	state := s.versions[key]
	state.Conflicts = appendBoundedVersion(state.Conflicts, storedVersionFromValidated(incoming))
	s.versions[key] = state
}

func appendBoundedVersion(values []StoredVersion, incoming StoredVersion) []StoredVersion {
	for _, existing := range values {
		if existing.Fingerprint == incoming.Fingerprint && existing.Version == incoming.Version && existing.PublisherNodeID == incoming.PublisherNodeID {
			return values
		}
	}
	values = append(values, incoming)
	const maxTrackedVersions = 6
	if len(values) > maxTrackedVersions {
		values = values[len(values)-maxTrackedVersions:]
	}
	return values
}
