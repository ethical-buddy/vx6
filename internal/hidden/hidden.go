// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package hidden

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/onion"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/secure"
	"github.com/vx6/vx6/internal/serviceproxy"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

const (
	activeIntroCount  = 3
	standbyIntroCount = 2
	guardCount        = 2

	hiddenDialParallelAttempts = 3
	maxHiddenDialAttempts      = 8
	maxActiveRendezvous        = 512
	rendezvousJoinTimeout      = 8 * time.Second
	maxControlReplayEntries    = 8192

	hiddenIntroRequestWindow   = 10 * time.Second
	hiddenIntroRequestLimit    = 48
	hiddenRendezvousJoinWindow = 10 * time.Second
	hiddenRendezvousJoinLimit  = 64
	hiddenControlActionWindow  = 30 * time.Second
	hiddenControlActionLimit   = 96
	hiddenFailureCooldownBase  = 5 * time.Second

	IntroModeRandom = "random"
	IntroModeManual = "manual"
	IntroModeHybrid = "hybrid"
)

var (
	hiddenControlEpochDuration = 30 * time.Second
	hiddenControlPingInterval  = 10 * time.Second
	hiddenControlReadTimeout   = 25 * time.Second
	hiddenControlLeaseDuration = 30 * time.Second

	errHiddenControlLeaseExpired = errors.New("hidden control lease expired")
)

type Message struct {
	Action               string   `json:"action"`
	Service              string   `json:"service,omitempty"`
	NotifyAddrs          []string `json:"notify_addrs,omitempty"`
	RendezvousID         string   `json:"rendezvous_id,omitempty"`
	RendezvousCandidates []string `json:"rendezvous_candidates,omitempty"`
	HopCount             int      `json:"hop_count,omitempty"`
	RelayExcludes        []string `json:"relay_excludes,omitempty"`
	CallbackID           string   `json:"callback_id,omitempty"`
	SenderNodeID         string   `json:"sender_node_id,omitempty"`
	Epoch                int64    `json:"epoch,omitempty"`
	Nonce                string   `json:"nonce,omitempty"`
}

type HandlerConfig struct {
	Identity      identity.Identity
	AdvertiseAddr string
	TransportMode string
	Services      map[string]string
	HiddenAliases map[string]string
	Registry      *discovery.Registry
}

type Topology struct {
	ActiveIntros  []string
	StandbyIntros []string
	Guards        []string
}

type DialOptions struct {
	SelfAddr      string
	Identity      identity.Identity
	TransportMode string
}

type ControlOptions struct {
	Identity      identity.Identity
	Registry      *discovery.Registry
	SelfAddr      string
	TransportMode string
	RelayHopCount int
	RelayExcludes []string
	RequireRelay  bool
}

type rendezvousWait struct {
	peerCh    chan net.Conn
	doneCh    chan struct{}
	createdAt time.Time
	expiresAt time.Time
}

type introRegistration struct {
	NotifyAddrs []string
	Conn        net.Conn
}

type guardRegistration struct {
	CallbackID string
	Conn       net.Conn
	writeMu    sync.Mutex
}

type registrationLease struct {
	Fingerprint string
	Cancel      context.CancelFunc
}

type OwnerRegistrationTarget struct {
	LookupKey  string
	GuardAddrs []string
	IntroAddrs []string
}

type peerScore struct {
	Addr      string
	NodeName  string
	Prefix    string
	RTT       time.Duration
	Healthy   bool
	Failures  int
	Preferred bool
}

type healthEntry struct {
	Healthy       bool
	RTT           time.Duration
	LastChecked   time.Time
	Failures      int
	CooldownUntil time.Time
}

type hiddenDialAttempt struct {
	introAddr       string
	rendezvousAddr  string
	rendezvousID    string
	relayExcludes   []string
	candidateOrder  []string
	plan            onion.CircuitPlan
	controlHopCount int
}

type windowCounter struct {
	WindowStart time.Time
	Count       int
}

var (
	introMu       sync.RWMutex
	introServices = map[string]introRegistration{}

	guardMu       sync.RWMutex
	guardServices = map[string]*guardRegistration{}

	rendezvousMu sync.Mutex
	rendezvouses = map[string]*rendezvousWait{}

	healthMu    sync.Mutex
	healthCache = map[string]healthEntry{}

	trackerMu    sync.Mutex
	trackersByIP = map[string]struct{}{}

	introClientMu sync.Mutex
	introClients  = map[string]registrationLease{}

	guardClientMu sync.Mutex
	guardClients  = map[string]registrationLease{}

	controlReplayMu sync.Mutex
	controlReplays  = map[string]time.Time{}

	hiddenRateMu       sync.Mutex
	hiddenRateCounters = map[string]windowCounter{}
)

func RegisterIntro(ctx context.Context, opts ControlOptions, introAddr, lookupKey string, notifyAddrs []string) error {
	msg := Message{
		Action:      "intro_register",
		Service:     lookupKey,
		NotifyAddrs: append([]string(nil), notifyAddrs...),
	}
	return sendControl(ctx, introAddr, msg, opts)
}

func EnsureIntroRegistration(ctx context.Context, opts ControlOptions, introAddr, lookupKey string, notifyAddrs []string) {
	key := introClientKey(opts.Identity.NodeID, introAddr, lookupKey)
	fingerprint := addressFingerprint(notifyAddrs)

	introClientMu.Lock()
	if existing, ok := introClients[key]; ok {
		if existing.Fingerprint == fingerprint {
			introClientMu.Unlock()
			return
		}
		existing.Cancel()
		delete(introClients, key)
	}
	runCtx, cancel := context.WithCancel(ctx)
	introClients[key] = registrationLease{
		Fingerprint: fingerprint,
		Cancel:      cancel,
	}
	introClientMu.Unlock()

	go func() {
		defer func() {
			introClientMu.Lock()
			current, ok := introClients[key]
			if ok && current.Fingerprint == fingerprint {
				delete(introClients, key)
			}
			introClientMu.Unlock()
		}()

		backoff := 150 * time.Millisecond
		for {
			err := maintainIntroRegistration(runCtx, opts, introAddr, lookupKey, notifyAddrs)
			if runCtx.Err() != nil {
				return
			}
			backoff = nextRegistrationBackoff(err, backoff)
			timer := time.NewTimer(backoff)
			select {
			case <-runCtx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func EnsureGuardRegistration(ctx context.Context, opts ControlOptions, guardAddr, lookupKey string, cfgFn func() HandlerConfig) {
	key := guardClientKey(opts.Identity.NodeID, guardAddr, lookupKey)

	guardClientMu.Lock()
	if _, ok := guardClients[key]; ok {
		guardClientMu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	guardClients[key] = registrationLease{Cancel: cancel}
	guardClientMu.Unlock()

	go func() {
		defer func() {
			guardClientMu.Lock()
			delete(guardClients, key)
			guardClientMu.Unlock()
		}()

		backoff := 150 * time.Millisecond
		for {
			err := maintainGuardRegistration(runCtx, opts, guardAddr, lookupKey, cfgFn)
			if runCtx.Err() != nil {
				return
			}
			backoff = nextRegistrationBackoff(err, backoff)
			timer := time.NewTimer(backoff)
			select {
			case <-runCtx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func DialHiddenService(ctx context.Context, service record.ServiceRecord, registry *discovery.Registry) (net.Conn, error) {
	return DialHiddenServiceWithOptions(ctx, service, registry, DialOptions{})
}

func DialHiddenServiceWithOptions(ctx context.Context, service record.ServiceRecord, registry *discovery.Registry, opts DialOptions) (net.Conn, error) {
	if !service.IsHidden {
		return nil, fmt.Errorf("service %s is not hidden", record.FullServiceName(service.NodeName, service.ServiceName))
	}
	if registry == nil {
		return nil, fmt.Errorf("hidden service dialing requires a local registry")
	}

	nodes, _ := registry.Snapshot()
	introPool := append([]string(nil), service.IntroPoints...)
	introPool = append(introPool, service.StandbyIntroPoints...)
	introPool = rankAddresses(ctx, introPool)
	if len(introPool) == 0 {
		return nil, fmt.Errorf("hidden service has no reachable introduction points")
	}

	excluded := append([]string(nil), introPool...)
	if opts.SelfAddr != "" {
		excluded = append(excluded, opts.SelfAddr)
	}
	excluded = sanitizeAddressList(excluded)
	rendezvousCandidates := SelectRendezvousCandidates(ctx, nodes, excluded, 3)
	if len(rendezvousCandidates) == 0 {
		return nil, fmt.Errorf("no rendezvous candidates available")
	}
	primeHealth(ctx, append(append([]string(nil), introPool...), rendezvousCandidates...))

	hopCount := hopCountForProfile(service.HiddenProfile)
	lookupKey := record.ServiceLookupKey(service)
	attempts := buildHiddenDialAttempts(ctx, service, nodes, introPool, rendezvousCandidates, excluded, hopCount)
	if len(attempts) == 0 {
		return nil, fmt.Errorf("failed to establish hidden-service circuit")
	}

	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	parallel := hiddenDialParallelAttempts
	if parallel > len(attempts) {
		parallel = len(attempts)
	}
	if parallel <= 0 {
		parallel = 1
	}

	type dialResult struct {
		conn    net.Conn
		err     error
		attempt hiddenDialAttempt
	}

	results := make(chan dialResult, len(attempts))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for _, attempt := range attempts {
		attempt := attempt
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := executeHiddenDialAttempt(attemptCtx, attempt, lookupKey, service.HiddenProfile, registry, opts)
			results <- dialResult{conn: conn, err: err, attempt: attempt}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var lastErr error
	for result := range results {
		if result.err == nil && result.conn != nil {
			cancel()
			noteHiddenPathSuccess([]string{result.attempt.introAddr, result.attempt.rendezvousAddr})
			noteHiddenPathSuccess(result.attempt.plan.RelayAddrs())
			return result.conn, nil
		}
		lastErr = result.err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("failed to establish hidden-service circuit")
	}
	return nil, lastErr
}

func HandleConn(ctx context.Context, conn net.Conn, cfg HandlerConfig) error {
	controlConn, err := secure.Server(conn, proto.KindRendezvous, cfg.Identity)
	if err != nil {
		return err
	}
	msg, err := readValidatedControl(controlConn)
	if err != nil {
		return err
	}

	switch msg.Action {
	case "intro_register":
		return holdIntroRegistration(controlConn, nodeScopedService(cfg.Identity.NodeID, msg.Service), sanitizeAddressList(msg.NotifyAddrs))
	case "guard_register":
		return holdGuardRegistration(controlConn, nodeScopedService(cfg.Identity.NodeID, msg.Service), msg.CallbackID)
	case "intro_request":
		if !allowHiddenAction(hiddenActorKey(controlConn, msg), "intro_request", hiddenIntroRequestWindow, hiddenIntroRequestLimit, time.Now()) {
			return fmt.Errorf("hidden intro request rate limited")
		}
		introMu.RLock()
		reg := introServices[nodeScopedService(cfg.Identity.NodeID, msg.Service)]
		introMu.RUnlock()
		if len(reg.NotifyAddrs) == 0 {
			return fmt.Errorf("hidden service %q is not registered on this intro point", msg.Service)
		}
		notifyAddrs := rankAddresses(ctx, reg.NotifyAddrs)
		for _, addr := range notifyAddrs {
			if err := sendControl(ctx, addr, Message{
				Action:               "guard_notify",
				Service:              msg.Service,
				RendezvousID:         msg.RendezvousID,
				RendezvousCandidates: append([]string(nil), msg.RendezvousCandidates...),
				HopCount:             msg.HopCount,
				RelayExcludes:        append([]string(nil), msg.RelayExcludes...),
			}, ControlOptions{
				Identity:      cfg.Identity,
				Registry:      cfg.Registry,
				SelfAddr:      cfg.AdvertiseAddr,
				TransportMode: cfg.TransportMode,
				RelayHopCount: controlHopCountFromData(msg.HopCount),
				RelayExcludes: msg.RelayExcludes,
				RequireRelay:  true,
			}); err == nil {
				return nil
			}
		}
		return fmt.Errorf("no reachable guard or owner for hidden service %q", msg.Service)
	case "guard_notify":
		guardMu.RLock()
		_, ok := guardServices[nodeScopedService(cfg.Identity.NodeID, msg.Service)]
		guardMu.RUnlock()
		if !ok {
			return handleIntroNotify(ctx, msg, cfg)
		}
		if err := sendGuardCallback(nodeScopedService(cfg.Identity.NodeID, msg.Service), Message{
			Action:               "intro_notify",
			Service:              msg.Service,
			RendezvousID:         msg.RendezvousID,
			RendezvousCandidates: append([]string(nil), msg.RendezvousCandidates...),
			HopCount:             msg.HopCount,
			RelayExcludes:        append([]string(nil), msg.RelayExcludes...),
		}); err != nil {
			return err
		}
		return nil
	case "intro_notify":
		return handleIntroNotify(ctx, msg, cfg)
	case "rv_join", "rv_register":
		if !allowHiddenAction(hiddenActorKey(controlConn, msg), "rendezvous_join", hiddenRendezvousJoinWindow, hiddenRendezvousJoinLimit, time.Now()) {
			return fmt.Errorf("hidden rendezvous join rate limited")
		}
		return joinRendezvous(controlConn, msg.RendezvousID)
	default:
		return fmt.Errorf("unknown hidden action %q", msg.Action)
	}
}

func handleIntroNotify(ctx context.Context, msg Message, cfg HandlerConfig) error {
	if cfg.Registry == nil {
		return fmt.Errorf("hidden service owner requires a registry")
	}

	serviceName := resolveHostedService(msg.Service, cfg)
	if serviceName == "" {
		return fmt.Errorf("hidden service %q is not hosted on this node", msg.Service)
	}

	nodes, _ := cfg.Registry.Snapshot()
	hopCount := msg.HopCount
	if hopCount <= 0 {
		hopCount = 3
	}

	rankedCandidates := sanitizeAddressList(msg.RendezvousCandidates)
	var lastErr error
	for _, candidate := range rankedCandidates {
		plan, err := onion.PlanAutomatedCircuit(record.ServiceRecord{Address: candidate}, nodes, hopCount, msg.RelayExcludes)
		if err != nil {
			noteHiddenPathFailure([]string{candidate})
			lastErr = err
			continue
		}
		plan.Purpose = "hidden-rendezvous"

		conn, err := onion.DialPlannedCircuit(ctx, plan, onion.ClientOptions{
			Identity:      cfg.Identity,
			TransportMode: cfg.TransportMode,
		})
		if err != nil {
			noteHiddenPathFailure(append([]string{candidate}, plan.RelayAddrs()...))
			lastErr = err
			continue
		}
		controlConn, err := openControlClient(conn, cfg.Identity)
		if err != nil {
			_ = conn.Close()
			noteHiddenPathFailure(append([]string{candidate}, plan.RelayAddrs()...))
			lastErr = err
			continue
		}
		if err := writeControl(controlConn, Message{
			Action:       "rv_register",
			RendezvousID: msg.RendezvousID,
		}); err != nil {
			_ = controlConn.Close()
			noteHiddenPathFailure(append([]string{candidate}, plan.RelayAddrs()...))
			lastErr = err
			continue
		}
		ready, err := readValidatedControl(controlConn)
		if err != nil {
			_ = controlConn.Close()
			noteHiddenPathFailure(append([]string{candidate}, plan.RelayAddrs()...))
			lastErr = err
			continue
		}
		if ready.Action != "rv_ready" {
			_ = controlConn.Close()
			noteHiddenPathFailure(append([]string{candidate}, plan.RelayAddrs()...))
			lastErr = fmt.Errorf("unexpected hidden rendezvous readiness %q", ready.Action)
			continue
		}

		reader := bufio.NewReader(controlConn)
		kind, err := proto.ReadHeader(reader)
		if err != nil {
			_ = controlConn.Close()
			return err
		}
		if kind != proto.KindServiceConn {
			_ = controlConn.Close()
			return fmt.Errorf("unexpected hidden-service follow-up kind %d", kind)
		}
		noteHiddenPathSuccess(append([]string{candidate}, plan.RelayAddrs()...))
		return serviceproxy.HandleInbound(&bufferedConn{Conn: controlConn, reader: reader}, cfg.Identity, cfg.Services)
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("failed to connect owner side to rendezvous")
	}
	return lastErr
}

func joinRendezvous(conn net.Conn, rendezvousID string) error {
	if rendezvousID == "" {
		return fmt.Errorf("missing rendezvous id")
	}

	rendezvousMu.Lock()
	pruneExpiredRendezvousesLocked(time.Now())
	wait, ok := rendezvouses[rendezvousID]
	if !ok {
		if len(rendezvouses) >= maxActiveRendezvous {
			rendezvousMu.Unlock()
			return fmt.Errorf("rendezvous capacity reached")
		}
		wait = &rendezvousWait{
			peerCh:    make(chan net.Conn, 1),
			doneCh:    make(chan struct{}),
			createdAt: time.Now(),
			expiresAt: time.Now().Add(rendezvousJoinTimeout),
		}
		rendezvouses[rendezvousID] = wait
		rendezvousMu.Unlock()
		timer := time.NewTimer(rendezvousJoinTimeout)
		defer timer.Stop()
		select {
		case peer := <-wait.peerCh:
			if err := writeControl(conn, Message{Action: "rv_ready"}); err != nil {
				_ = peer.Close()
				close(wait.doneCh)
				return err
			}
			if err := writeControl(peer, Message{Action: "rv_ready"}); err != nil {
				_ = peer.Close()
				close(wait.doneCh)
				return err
			}
			err := proxyDuplex(conn, peer)
			close(wait.doneCh)
			return err
		case <-timer.C:
			rendezvousMu.Lock()
			current, exists := rendezvouses[rendezvousID]
			if exists && current == wait {
				delete(rendezvouses, rendezvousID)
			}
			rendezvousMu.Unlock()
			close(wait.doneCh)
			_ = conn.Close()
			return fmt.Errorf("timed out waiting for rendezvous peer")
		}
	}
	delete(rendezvouses, rendezvousID)
	rendezvousMu.Unlock()

	timer := time.NewTimer(rendezvousJoinTimeout)
	defer timer.Stop()
	select {
	case wait.peerCh <- conn:
	case <-wait.doneCh:
		return fmt.Errorf("rendezvous expired before join")
	case <-timer.C:
		return fmt.Errorf("timed out joining rendezvous")
	}

	select {
	case <-wait.doneCh:
		return nil
	case <-timer.C:
		return fmt.Errorf("timed out waiting for rendezvous completion")
	}
}

func SelectTopology(ctx context.Context, selfAddr string, nodes []record.EndpointRecord, preferred []string, introMode, profile string) Topology {
	_ = profile // reserved for future profile-specific topology sizing.

	candidates := dedupeCandidates(nodes, map[string]struct{}{selfAddr: {}})
	if len(candidates) == 0 {
		return Topology{}
	}

	preferredAddrs := resolvePreferredAddressesOrdered(candidates, preferred)
	used := map[string]struct{}{}
	guardCandidates := scoreCandidates(ctx, candidates, nil, nil)
	guardCandidates = stabilizeScores(guardCandidates, selfAddr, guardCount)
	topology := Topology{}
	topology.Guards = pickAddresses(guardCandidates, guardCount, used)

	scored := scoreCandidates(ctx, candidates, nil, used)
	scored = prioritizeScores(scored, preferredAddrs, introMode, activeIntroCount+standbyIntroCount)
	intros := pickAddresses(scored, activeIntroCount+standbyIntroCount, used)
	if len(intros) > activeIntroCount {
		topology.ActiveIntros = append([]string(nil), intros[:activeIntroCount]...)
		topology.StandbyIntros = append([]string(nil), intros[activeIntroCount:]...)
	} else {
		topology.ActiveIntros = append([]string(nil), intros...)
	}
	return topology
}

func SelectRendezvousCandidates(ctx context.Context, nodes []record.EndpointRecord, excludeAddrs []string, count int) []string {
	exclude := make(map[string]struct{}, len(excludeAddrs))
	for _, addr := range excludeAddrs {
		if addr != "" {
			exclude[addr] = struct{}{}
		}
	}
	candidates := dedupeCandidates(nodes, exclude)
	scored := scoreCandidates(ctx, candidates, nil, exclude)
	scored = randomizeTopScores(scored, count)
	return pickAddresses(scored, count, map[string]struct{}{})
}

func NormalizeIntroMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", IntroModeRandom:
		return IntroModeRandom
	case IntroModeManual:
		return IntroModeManual
	case IntroModeHybrid:
		return IntroModeHybrid
	default:
		return ""
	}
}

func TrackAddresses(ctx context.Context, addrs []string, interval time.Duration) {
	if interval <= 0 {
		interval = 20 * time.Second
	}
	for _, addr := range sanitizeAddressList(addrs) {
		if addr == "" {
			continue
		}

		trackerMu.Lock()
		if _, ok := trackersByIP[addr]; ok {
			trackerMu.Unlock()
			continue
		}
		trackersByIP[addr] = struct{}{}
		trackerMu.Unlock()

		go func(addr string) {
			defer func() {
				trackerMu.Lock()
				delete(trackersByIP, addr)
				trackerMu.Unlock()
			}()

			primeHealth(context.Background(), []string{addr})
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					primeHealth(context.Background(), []string{addr})
				}
			}
		}(addr)
	}
}

func hopCountForProfile(profile string) int {
	if record.NormalizeHiddenProfile(profile) == "balanced" {
		return 5
	}
	return 3
}

func ControlHopCountForProfile(profile string) int {
	if record.NormalizeHiddenProfile(profile) == "balanced" {
		return 3
	}
	return 2
}

func controlHopCountFromData(hopCount int) int {
	switch {
	case hopCount >= 5:
		return 3
	case hopCount >= 3:
		return 2
	default:
		return 1
	}
}

func nodeScopedService(nodeID, service string) string {
	return nodeID + "\n" + service
}

func introClientKey(nodeID, introAddr, lookupKey string) string {
	return "intro\n" + nodeID + "\n" + lookupKey + "\n" + introAddr
}

func guardClientKey(nodeID, guardAddr, lookupKey string) string {
	return "guard\n" + nodeID + "\n" + lookupKey + "\n" + guardAddr
}

func addressFingerprint(addrs []string) string {
	normalized := append([]string(nil), sanitizeAddressList(addrs)...)
	sort.Strings(normalized)
	return strings.Join(normalized, "\n")
}

func resolveHostedService(lookup string, cfg HandlerConfig) string {
	if name := cfg.HiddenAliases[lookup]; name != "" {
		return name
	}
	if _, ok := cfg.Services[lookup]; ok {
		return lookup
	}
	if strings.Contains(lookup, ".") {
		parts := strings.Split(lookup, ".")
		name := parts[len(parts)-1]
		if _, ok := cfg.Services[name]; ok {
			return name
		}
	}
	return ""
}

func sanitizeAddressList(addrs []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func resolvePreferredAddressesOrdered(nodes []record.EndpointRecord, selectors []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		selector = strings.TrimSpace(selector)
		if selector == "" {
			continue
		}
		for _, node := range nodes {
			if node.Address == "" {
				continue
			}
			if selector == node.Address || selector == node.NodeName {
				if _, ok := seen[node.Address]; ok {
					continue
				}
				seen[node.Address] = struct{}{}
				out = append(out, node.Address)
			}
		}
	}
	return out
}

func dedupeCandidates(nodes []record.EndpointRecord, exclude map[string]struct{}) []record.EndpointRecord {
	seen := map[string]struct{}{}
	out := make([]record.EndpointRecord, 0, len(nodes))
	for _, node := range nodes {
		if node.Address == "" {
			continue
		}
		if _, ok := exclude[node.Address]; ok {
			continue
		}
		if _, ok := seen[node.Address]; ok {
			continue
		}
		seen[node.Address] = struct{}{}
		out = append(out, node)
	}
	return out
}

func scoreCandidates(ctx context.Context, nodes []record.EndpointRecord, preferred map[string]bool, exclude map[string]struct{}) []peerScore {
	scored := make([]peerScore, 0, len(nodes))
	for _, node := range nodes {
		if node.Address == "" {
			continue
		}
		if exclude != nil {
			if _, ok := exclude[node.Address]; ok {
				continue
			}
		}
		healthy, rtt, failures := measureHealth(ctx, node.Address)
		scored = append(scored, peerScore{
			Addr:      node.Address,
			NodeName:  node.NodeName,
			Prefix:    addrPrefix(node.Address),
			RTT:       rtt,
			Healthy:   healthy,
			Failures:  failures,
			Preferred: preferred[node.Address],
		})
	}

	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].Preferred != scored[j].Preferred {
			return scored[i].Preferred
		}
		if scored[i].Healthy != scored[j].Healthy {
			return scored[i].Healthy
		}
		if scored[i].Failures != scored[j].Failures {
			return scored[i].Failures < scored[j].Failures
		}
		if scored[i].RTT != scored[j].RTT {
			return scored[i].RTT < scored[j].RTT
		}
		if scored[i].NodeName != scored[j].NodeName {
			return scored[i].NodeName < scored[j].NodeName
		}
		return scored[i].Addr < scored[j].Addr
	})
	return scored
}

func prioritizeScores(scored []peerScore, preferredAddrs []string, introMode string, count int) []peerScore {
	introMode = NormalizeIntroMode(introMode)
	if introMode == "" {
		introMode = IntroModeRandom
	}
	if introMode == IntroModeRandom {
		return randomizeTopScores(scored, count)
	}

	preferred := make([]peerScore, 0, len(preferredAddrs))
	remaining := make([]peerScore, 0, len(scored))
	byAddr := make(map[string]peerScore, len(scored))
	for _, candidate := range scored {
		byAddr[candidate.Addr] = candidate
	}
	selected := map[string]struct{}{}
	for _, addr := range preferredAddrs {
		candidate, ok := byAddr[addr]
		if !ok {
			continue
		}
		preferred = append(preferred, candidate)
		selected[addr] = struct{}{}
	}
	for _, candidate := range scored {
		if _, ok := selected[candidate.Addr]; ok {
			continue
		}
		remaining = append(remaining, candidate)
	}
	if introMode == IntroModeHybrid {
		remaining = randomizeTopScores(remaining, count-len(preferred))
	}
	return append(preferred, remaining...)
}

func randomizeTopScores(scored []peerScore, count int) []peerScore {
	if len(scored) <= 1 {
		return scored
	}
	limit := count * 4
	if limit <= 0 || limit > len(scored) {
		limit = len(scored)
	}
	head := append([]peerScore(nil), scored[:limit]...)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(head), func(i, j int) {
		head[i], head[j] = head[j], head[i]
	})
	out := append([]peerScore(nil), head...)
	out = append(out, scored[limit:]...)
	return out
}

func stabilizeScores(scored []peerScore, seed string, count int) []peerScore {
	if len(scored) <= 1 {
		return scored
	}
	limit := count * 4
	if limit <= 0 || limit > len(scored) {
		limit = len(scored)
	}
	head := append([]peerScore(nil), scored[:limit]...)
	sort.SliceStable(head, func(i, j int) bool {
		hi := stableScoreSeed(seed, head[i].Addr)
		hj := stableScoreSeed(seed, head[j].Addr)
		return hi < hj
	})
	out := append([]peerScore(nil), head...)
	out = append(out, scored[limit:]...)
	return out
}

func stableScoreSeed(seed, addr string) string {
	sum := sha256.Sum256([]byte(seed + "\n" + addr))
	return fmt.Sprintf("%x", sum[:])
}

func pickAddresses(scored []peerScore, count int, used map[string]struct{}) []string {
	if count <= 0 {
		return nil
	}

	out := make([]string, 0, count)
	usedPrefixes := map[string]struct{}{}

	pick := func(requireFreshPrefix bool) {
		for _, candidate := range scored {
			if len(out) >= count {
				return
			}
			if _, ok := used[candidate.Addr]; ok {
				continue
			}
			if requireFreshPrefix && candidate.Prefix != "" {
				if _, ok := usedPrefixes[candidate.Prefix]; ok {
					continue
				}
			}
			used[candidate.Addr] = struct{}{}
			if candidate.Prefix != "" {
				usedPrefixes[candidate.Prefix] = struct{}{}
			}
			out = append(out, candidate.Addr)
		}
	}

	pick(true)
	pick(false)
	return out
}

func rankAddresses(ctx context.Context, addrs []string) []string {
	nodes := make([]record.EndpointRecord, 0, len(addrs))
	for _, addr := range sanitizeAddressList(addrs) {
		nodes = append(nodes, record.EndpointRecord{NodeName: addr, Address: addr})
	}
	scored := scoreCandidates(ctx, nodes, nil, nil)
	out := make([]string, 0, len(scored))
	for _, candidate := range scored {
		out = append(out, candidate.Addr)
	}
	return out
}

func preferAddressFirst(addrs []string, first string) []string {
	out := make([]string, 0, len(addrs))
	if first != "" {
		out = append(out, first)
	}
	for _, addr := range sanitizeAddressList(addrs) {
		if addr == first {
			continue
		}
		out = append(out, addr)
	}
	return out
}

func buildHiddenDialAttempts(ctx context.Context, service record.ServiceRecord, nodes []record.EndpointRecord, introPool, rendezvousCandidates, excluded []string, hopCount int) []hiddenDialAttempt {
	controlHopCount := ControlHopCountForProfile(service.HiddenProfile)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	attempts := make([]hiddenDialAttempt, 0, maxHiddenDialAttempts)

	for _, introAddr := range introPool {
		if len(attempts) >= maxHiddenDialAttempts {
			break
		}
		for _, rendezvousAddr := range rendezvousCandidates {
			if len(attempts) >= maxHiddenDialAttempts {
				break
			}
			plan, err := onion.PlanAutomatedCircuit(record.ServiceRecord{Address: rendezvousAddr}, nodes, hopCount, excluded)
			if err != nil {
				noteHiddenPathFailure([]string{introAddr, rendezvousAddr})
				continue
			}
			plan.Purpose = "hidden-rendezvous"
			candidateOrder := preferAddressFirst(rendezvousCandidates, rendezvousAddr)

			relayExcludes := append([]string(nil), excluded...)
			relayExcludes = append(relayExcludes, candidateOrder...)
			relayExcludes = append(relayExcludes, plan.RelayAddrs()...)
			relayExcludes = sanitizeAddressList(relayExcludes)

			attempts = append(attempts, hiddenDialAttempt{
				introAddr:       introAddr,
				rendezvousAddr:  rendezvousAddr,
				rendezvousID:    fmt.Sprintf("rv_%d", rng.Int63()),
				relayExcludes:   relayExcludes,
				candidateOrder:  candidateOrder,
				plan:            plan,
				controlHopCount: controlHopCount,
			})
		}
	}
	return attempts
}

func executeHiddenDialAttempt(ctx context.Context, attempt hiddenDialAttempt, lookupKey, profile string, registry *discovery.Registry, opts DialOptions) (net.Conn, error) {
	err := sendControl(ctx, attempt.introAddr, Message{
		Action:               "intro_request",
		Service:              lookupKey,
		RendezvousID:         attempt.rendezvousID,
		RendezvousCandidates: append([]string(nil), attempt.candidateOrder...),
		HopCount:             hopCountForProfile(profile),
		RelayExcludes:        append([]string(nil), attempt.relayExcludes...),
	}, ControlOptions{
		Identity:      opts.Identity,
		Registry:      registry,
		SelfAddr:      opts.SelfAddr,
		TransportMode: opts.TransportMode,
		RelayHopCount: attempt.controlHopCount,
		RelayExcludes: append([]string(nil), attempt.relayExcludes...),
		RequireRelay:  true,
	})
	if err != nil {
		noteHiddenPathFailure([]string{attempt.introAddr, attempt.rendezvousAddr})
		noteHiddenPathFailure(attempt.plan.RelayAddrs())
		return nil, err
	}

	conn, err := onion.DialPlannedCircuit(ctx, attempt.plan, onion.ClientOptions{
		Identity:      opts.Identity,
		TransportMode: opts.TransportMode,
	})
	if err != nil {
		noteHiddenPathFailure([]string{attempt.rendezvousAddr})
		noteHiddenPathFailure(attempt.plan.RelayAddrs())
		return nil, err
	}
	controlConn, err := openControlClient(conn, opts.Identity)
	if err != nil {
		_ = conn.Close()
		noteHiddenPathFailure([]string{attempt.rendezvousAddr})
		noteHiddenPathFailure(attempt.plan.RelayAddrs())
		return nil, err
	}
	if err := writeControl(controlConn, Message{
		Action:       "rv_join",
		RendezvousID: attempt.rendezvousID,
	}); err != nil {
		_ = controlConn.Close()
		noteHiddenPathFailure([]string{attempt.rendezvousAddr})
		noteHiddenPathFailure(attempt.plan.RelayAddrs())
		return nil, err
	}
	ready, err := readValidatedControl(controlConn)
	if err != nil {
		_ = controlConn.Close()
		noteHiddenPathFailure([]string{attempt.rendezvousAddr})
		noteHiddenPathFailure(attempt.plan.RelayAddrs())
		return nil, err
	}
	if ready.Action != "rv_ready" {
		_ = controlConn.Close()
		noteHiddenPathFailure([]string{attempt.rendezvousAddr})
		noteHiddenPathFailure(attempt.plan.RelayAddrs())
		return nil, fmt.Errorf("unexpected hidden rendezvous readiness %q", ready.Action)
	}
	return controlConn, nil
}

func addrPrefix(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%x:%x:%x:%x", ip[0:2], ip[2:4], ip[4:6], ip[6:8])
}

func primeHealth(ctx context.Context, addrs []string) {
	for _, addr := range sanitizeAddressList(addrs) {
		if addr == "" {
			continue
		}
		_, _, _ = measureHealth(ctx, addr)
	}
}

func measureHealth(ctx context.Context, addr string) (bool, time.Duration, int) {
	healthMu.Lock()
	entry, ok := healthCache[addr]
	if ok && entry.CooldownUntil.After(time.Now()) {
		healthMu.Unlock()
		return false, maxDuration(entry.RTT, 300*time.Millisecond), entry.Failures
	}
	if ok && time.Since(entry.LastChecked) < 30*time.Second {
		healthMu.Unlock()
		return entry.Healthy, entry.RTT, entry.Failures
	}
	healthMu.Unlock()

	timeout := 300 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline) / 2; remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	conn, err := vxtransport.DialContext(dialCtx, vxtransport.ModeTCP, addr)
	healthy := err == nil
	rtt := timeout
	failures := entry.Failures
	if healthy {
		rtt = time.Since(start)
		_ = conn.Close()
		failures = 0
	} else {
		failures++
	}

	healthMu.Lock()
	healthCache[addr] = healthEntry{
		Healthy:       healthy,
		RTT:           rtt,
		LastChecked:   time.Now(),
		Failures:      failures,
		CooldownUntil: hiddenFailureCooldown(time.Now(), healthy, failures),
	}
	healthMu.Unlock()
	return healthy, rtt, failures
}

func noteHiddenPathFailure(addrs []string) {
	now := time.Now()
	healthMu.Lock()
	defer healthMu.Unlock()
	for _, addr := range sanitizeAddressList(addrs) {
		entry := healthCache[addr]
		entry.Healthy = false
		entry.LastChecked = now
		entry.Failures++
		entry.CooldownUntil = hiddenFailureCooldown(now, false, entry.Failures)
		if entry.RTT <= 0 {
			entry.RTT = 300 * time.Millisecond
		}
		healthCache[addr] = entry
	}
}

func noteHiddenPathSuccess(addrs []string) {
	now := time.Now()
	healthMu.Lock()
	defer healthMu.Unlock()
	for _, addr := range sanitizeAddressList(addrs) {
		entry := healthCache[addr]
		entry.Healthy = true
		entry.Failures = 0
		entry.LastChecked = now
		entry.CooldownUntil = time.Time{}
		if entry.RTT <= 0 {
			entry.RTT = 50 * time.Millisecond
		}
		healthCache[addr] = entry
	}
}

func hiddenFailureCooldown(now time.Time, healthy bool, failures int) time.Time {
	if healthy || failures <= 0 {
		return time.Time{}
	}
	backoff := hiddenFailureCooldownBase
	for i := 1; i < failures && backoff < 30*time.Second; i++ {
		backoff *= 2
	}
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	return now.Add(backoff)
}

func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}

func maintainGuardRegistration(ctx context.Context, opts ControlOptions, guardAddr, lookupKey string, cfgFn func() HandlerConfig) error {
	conn, err := openControlConn(ctx, guardAddr, opts)
	if err != nil {
		return err
	}
	defer conn.Close()

	callbackID := fmt.Sprintf("cb_%d", time.Now().UnixNano())
	if err := writeControl(conn, Message{
		Action:     "guard_register",
		Service:    lookupKey,
		CallbackID: callbackID,
	}); err != nil {
		return err
	}
	return sustainControlRegistration(ctx, conn, func(msg Message) error {
		if msg.Action != "intro_notify" {
			return nil
		}
		go func(msg Message) {
			_ = handleIntroNotify(ctx, msg, cfgFn())
		}(msg)
		return nil
	})
}

func maintainIntroRegistration(ctx context.Context, opts ControlOptions, introAddr, lookupKey string, notifyAddrs []string) error {
	conn, err := openControlConn(ctx, introAddr, opts)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := writeControl(conn, Message{
		Action:      "intro_register",
		Service:     lookupKey,
		NotifyAddrs: append([]string(nil), notifyAddrs...),
	}); err != nil {
		return err
	}
	return sustainControlRegistration(ctx, conn, func(Message) error { return nil })
}

func holdIntroRegistration(conn net.Conn, scopedService string, notifyAddrs []string) error {
	reg := introRegistration{
		NotifyAddrs: append([]string(nil), notifyAddrs...),
		Conn:        conn,
	}

	introMu.Lock()
	if existing, ok := introServices[scopedService]; ok && existing.Conn != nil {
		_ = existing.Conn.Close()
	}
	introServices[scopedService] = reg
	introMu.Unlock()

	defer func() {
		introMu.Lock()
		current, ok := introServices[scopedService]
		if ok && current.Conn == conn {
			delete(introServices, scopedService)
		}
		introMu.Unlock()
	}()

	for {
		msg, err := readValidatedControl(conn)
		if err != nil {
			if isControlCloseError(err) {
				return nil
			}
			return err
		}
		if msg.Action == "control_ping" {
			if err := writeControl(conn, Message{Action: "control_pong"}); err != nil {
				if isControlCloseError(err) {
					return nil
				}
				return err
			}
		}
	}
}

func holdGuardRegistration(conn net.Conn, scopedService, callbackID string) error {
	reg := &guardRegistration{
		CallbackID: callbackID,
		Conn:       conn,
	}

	guardMu.Lock()
	if existing, ok := guardServices[scopedService]; ok && existing.Conn != nil {
		_ = existing.Conn.Close()
	}
	guardServices[scopedService] = reg
	guardMu.Unlock()

	defer func() {
		guardMu.Lock()
		current, ok := guardServices[scopedService]
		if ok && current != nil && current.CallbackID == callbackID {
			delete(guardServices, scopedService)
		}
		guardMu.Unlock()
	}()

	for {
		msg, err := readValidatedControl(conn)
		if err != nil {
			if isControlCloseError(err) {
				return nil
			}
			return err
		}
		if msg.Action == "control_ping" {
			reg.writeMu.Lock()
			err := writeControl(conn, Message{Action: "control_pong"})
			reg.writeMu.Unlock()
			if err != nil {
				if isControlCloseError(err) {
					return nil
				}
				return err
			}
		}
	}
}

func sendGuardCallback(scopedService string, msg Message) error {
	guardMu.RLock()
	reg, ok := guardServices[scopedService]
	guardMu.RUnlock()
	if !ok || reg.Conn == nil {
		return fmt.Errorf("no active guard callback registered for %s", scopedService)
	}

	reg.writeMu.Lock()
	defer reg.writeMu.Unlock()
	if err := writeControl(reg.Conn, msg); err != nil {
		_ = reg.Conn.Close()
		guardMu.Lock()
		current, ok := guardServices[scopedService]
		if ok && current.CallbackID == reg.CallbackID {
			delete(guardServices, scopedService)
		}
		guardMu.Unlock()
		return err
	}
	return nil
}

func PruneOwnerRegistrations(nodeID string, targets []OwnerRegistrationTarget) {
	desiredIntro := map[string]struct{}{}
	desiredGuard := map[string]struct{}{}
	for _, target := range targets {
		for _, introAddr := range sanitizeAddressList(target.IntroAddrs) {
			desiredIntro[introClientKey(nodeID, introAddr, target.LookupKey)] = struct{}{}
		}
		for _, guardAddr := range sanitizeAddressList(target.GuardAddrs) {
			desiredGuard[guardClientKey(nodeID, guardAddr, target.LookupKey)] = struct{}{}
		}
	}

	introPrefix := "intro\n" + nodeID + "\n"
	introClientMu.Lock()
	for key, lease := range introClients {
		if !strings.HasPrefix(key, introPrefix) {
			continue
		}
		if _, ok := desiredIntro[key]; ok {
			continue
		}
		lease.Cancel()
		delete(introClients, key)
	}
	introClientMu.Unlock()

	guardPrefix := "guard\n" + nodeID + "\n"
	guardClientMu.Lock()
	for key, lease := range guardClients {
		if !strings.HasPrefix(key, guardPrefix) {
			continue
		}
		if _, ok := desiredGuard[key]; ok {
			continue
		}
		lease.Cancel()
		delete(guardClients, key)
	}
	guardClientMu.Unlock()
}

func sendControl(ctx context.Context, addr string, msg Message, opts ControlOptions) error {
	if opts.Identity.NodeID == "" {
		return fmt.Errorf("hidden control requires a local identity")
	}

	conn, err := openControlConn(ctx, addr, opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	return writeControl(conn, msg)
}

func openControlConn(ctx context.Context, addr string, opts ControlOptions) (net.Conn, error) {
	if opts.Registry != nil && opts.RelayHopCount > 0 {
		nodes, _ := opts.Registry.Snapshot()
		excludeAddrs := append([]string(nil), opts.RelayExcludes...)
		if opts.SelfAddr != "" {
			excludeAddrs = append(excludeAddrs, opts.SelfAddr)
		}
		var lastErr error
		for hopCount := opts.RelayHopCount; hopCount >= 1; hopCount-- {
			plan, err := onion.PlanAutomatedCircuit(record.ServiceRecord{Address: addr}, nodes, hopCount, sanitizeAddressList(excludeAddrs))
			if err != nil {
				lastErr = err
				continue
			}
			plan.Purpose = "hidden-control"
			conn, err := onion.DialPlannedCircuit(ctx, plan, onion.ClientOptions{
				Identity:      opts.Identity,
				TransportMode: opts.TransportMode,
			})
			if err == nil {
				return openControlClient(conn, opts.Identity)
			}
			lastErr = err
		}
		if opts.RequireRelay {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("unable to open relay-backed hidden control path to %s", addr)
		}
	}

	conn, err := vxtransport.DialContext(ctx, opts.TransportMode, addr)
	if err != nil {
		return nil, err
	}
	return openControlClient(conn, opts.Identity)
}

func openControlClient(conn net.Conn, id identity.Identity) (net.Conn, error) {
	if err := proto.WriteHeader(conn, proto.KindRendezvous); err != nil {
		_ = conn.Close()
		return nil, err
	}
	secureConn, err := secure.Client(conn, proto.KindRendezvous, id)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return secureConn, nil
}

func writeControl(conn net.Conn, msg Message) error {
	stamped, err := stampControlMessage(conn, msg)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(stamped)
	if err != nil {
		return err
	}
	return proto.WriteLengthPrefixed(conn, payload)
}

func readControl(conn net.Conn) (Message, error) {
	payload, err := proto.ReadLengthPrefixed(conn, 1024*1024)
	if err != nil {
		return Message{}, err
	}
	var msg Message
	if err := json.Unmarshal(payload, &msg); err != nil {
		return Message{}, err
	}
	return msg, nil
}

func readValidatedControl(conn net.Conn) (Message, error) {
	msg, err := readControl(conn)
	if err != nil {
		return Message{}, err
	}
	if err := validateControlMessage(conn, msg); err != nil {
		return Message{}, err
	}
	return msg, nil
}

func sustainControlRegistration(ctx context.Context, conn net.Conn, handle func(Message) error) error {
	var writeMu sync.Mutex
	errCh := make(chan error, 1)

	go func() {
		for {
			if hiddenControlReadTimeout > 0 {
				if err := conn.SetReadDeadline(time.Now().Add(hiddenControlReadTimeout)); err != nil {
					errCh <- err
					return
				}
			}

			msg, err := readValidatedControl(conn)
			if err != nil {
				errCh <- err
				return
			}

			switch msg.Action {
			case "control_ping":
				writeMu.Lock()
				err = writeControl(conn, Message{Action: "control_pong"})
				writeMu.Unlock()
				if err != nil {
					errCh <- err
					return
				}
			case "control_pong":
				continue
			default:
				if err := handle(msg); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	pingTicker := time.NewTicker(hiddenControlPingInterval)
	defer pingTicker.Stop()

	leaseTimer := time.NewTimer(hiddenControlLeaseDuration)
	defer leaseTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return err
		case <-leaseTimer.C:
			return errHiddenControlLeaseExpired
		case <-pingTicker.C:
			writeMu.Lock()
			err := writeControl(conn, Message{Action: "control_ping"})
			writeMu.Unlock()
			if err != nil {
				return err
			}
		}
	}
}

func stampControlMessage(conn net.Conn, msg Message) (Message, error) {
	if msg.SenderNodeID != "" && msg.Epoch != 0 && msg.Nonce != "" {
		return msg, nil
	}

	localID, ok := controlLocalNodeID(conn)
	if !ok || localID == "" {
		return msg, nil
	}

	nonce, err := newControlNonce()
	if err != nil {
		return Message{}, err
	}

	msg.SenderNodeID = localID
	msg.Epoch = controlEpoch(time.Now())
	msg.Nonce = nonce
	return msg, nil
}

func validateControlMessage(conn net.Conn, msg Message) error {
	peerID, ok := controlPeerNodeID(conn)
	if !ok || peerID == "" {
		return nil
	}
	if msg.Action == "" {
		return fmt.Errorf("hidden control message missing action")
	}
	if msg.SenderNodeID == "" || msg.Epoch == 0 || msg.Nonce == "" {
		return fmt.Errorf("hidden control message missing envelope")
	}
	if msg.SenderNodeID != peerID {
		return fmt.Errorf("hidden control sender mismatch: got %s want %s", msg.SenderNodeID, peerID)
	}

	currentEpoch := controlEpoch(time.Now())
	if delta := currentEpoch - msg.Epoch; delta < -1 || delta > 1 {
		return fmt.Errorf("hidden control epoch outside replay window")
	}

	if err := rememberControlReplay(msg.SenderNodeID, msg.Epoch, msg.Nonce, time.Now()); err != nil {
		return err
	}
	if !allowHiddenAction("node:"+msg.SenderNodeID, "control:"+msg.Action, hiddenControlActionWindow, hiddenControlActionLimit, time.Now()) {
		return fmt.Errorf("hidden control rate limited")
	}
	return nil
}

func newControlNonce() (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(crand.Reader, raw[:]); err != nil {
		return "", fmt.Errorf("generate hidden control nonce: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func controlEpoch(now time.Time) int64 {
	duration := hiddenControlEpochDuration
	if duration <= 0 {
		duration = 30 * time.Second
	}
	return now.UnixNano() / duration.Nanoseconds()
}

func rememberControlReplay(senderNodeID string, epoch int64, nonce string, now time.Time) error {
	expiry := now.Add(hiddenControlEpochDuration * 2)
	key := fmt.Sprintf("%s\n%d\n%s", senderNodeID, epoch, nonce)

	controlReplayMu.Lock()
	defer controlReplayMu.Unlock()

	for key, expiresAt := range controlReplays {
		if !expiresAt.After(now) {
			delete(controlReplays, key)
		}
	}
	if expiresAt, ok := controlReplays[key]; ok && expiresAt.After(now) {
		return fmt.Errorf("hidden control replay detected")
	}
	if len(controlReplays) >= maxControlReplayEntries {
		evictOldestControlReplaysLocked(len(controlReplays) - maxControlReplayEntries + 1)
	}
	controlReplays[key] = expiry
	return nil
}

func evictOldestControlReplaysLocked(removeCount int) {
	if removeCount <= 0 {
		return
	}
	for removeCount > 0 && len(controlReplays) > 0 {
		var (
			oldestKey string
			oldestAt  time.Time
			seen      bool
		)
		for key, expiresAt := range controlReplays {
			if !seen || expiresAt.Before(oldestAt) {
				oldestKey = key
				oldestAt = expiresAt
				seen = true
			}
		}
		if !seen {
			return
		}
		delete(controlReplays, oldestKey)
		removeCount--
	}
}

func pruneExpiredRendezvousesLocked(now time.Time) {
	for id, wait := range rendezvouses {
		if wait == nil {
			delete(rendezvouses, id)
			continue
		}
		if wait.expiresAt.IsZero() || wait.expiresAt.After(now) {
			continue
		}
		delete(rendezvouses, id)
		select {
		case <-wait.doneCh:
		default:
			close(wait.doneCh)
		}
	}
}

func hiddenActorKey(conn net.Conn, msg Message) string {
	if msg.SenderNodeID != "" {
		return "node:" + msg.SenderNodeID
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return "addr:" + conn.RemoteAddr().String()
	}
	return "addr:" + host
}

func allowHiddenAction(actor, action string, window time.Duration, limit int, now time.Time) bool {
	if actor == "" || action == "" || window <= 0 || limit <= 0 {
		return true
	}

	hiddenRateMu.Lock()
	defer hiddenRateMu.Unlock()

	for key, counter := range hiddenRateCounters {
		if now.Sub(counter.WindowStart) > window*2 {
			delete(hiddenRateCounters, key)
		}
	}

	key := action + "\n" + actor
	counter := hiddenRateCounters[key]
	if counter.WindowStart.IsZero() || now.Sub(counter.WindowStart) >= window {
		counter = windowCounter{WindowStart: now, Count: 1}
		hiddenRateCounters[key] = counter
		return true
	}
	if counter.Count >= limit {
		return false
	}
	counter.Count++
	hiddenRateCounters[key] = counter
	return true
}

func controlLocalNodeID(conn net.Conn) (string, bool) {
	type localNoder interface {
		LocalNodeID() string
	}
	withID, ok := conn.(localNoder)
	if !ok {
		return "", false
	}
	return withID.LocalNodeID(), true
}

func controlPeerNodeID(conn net.Conn) (string, bool) {
	type peerNoder interface {
		PeerNodeID() string
	}
	withID, ok := conn.(peerNoder)
	if !ok {
		return "", false
	}
	return withID.PeerNodeID(), true
}

func isControlCloseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

func nextRegistrationBackoff(err error, current time.Duration) time.Duration {
	if errors.Is(err, errHiddenControlLeaseExpired) {
		return 25 * time.Millisecond
	}
	if current <= 0 {
		current = 150 * time.Millisecond
	}
	next := current * 2
	if next > time.Second {
		next = time.Second
	}
	return next
}

func proxyDuplex(a, b net.Conn) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	copyPipe := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if closer, ok := dst.(io.Closer); ok {
			_ = closer.Close()
		}
		if closer, ok := src.(io.Closer); ok {
			_ = closer.Close()
		}
		errCh <- err
	}

	wg.Add(2)
	go copyPipe(a, b)
	go copyPipe(b, a)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil && !isControlCloseError(err) && !strings.Contains(err.Error(), "closed pipe") {
			return err
		}
	}
	return nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
