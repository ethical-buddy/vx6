// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the VX6 terms in LICENSE-COMMERCIAL.md.
// Sole inventor, maintainer, and rights holder: Suryansh Deshwal (https://github.com/ethical-buddy).

package node

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/hidden"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/ipsec"
	"github.com/vx6/vx6/internal/liveness"
	"github.com/vx6/vx6/internal/netutil"
	"github.com/vx6/vx6/internal/onion"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/runtimectl"
	"github.com/vx6/vx6/internal/serviceproxy"
	"github.com/vx6/vx6/internal/strictjson"
	"github.com/vx6/vx6/internal/transfer"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

const (
	syncCycleInterval         = 10 * time.Second
	syncWarmupInterval        = 2 * time.Second
	syncWarmupRounds          = 4
	syncTargetTimeout         = 2 * time.Second
	syncProbeTimeout          = 1 * time.Second
	syncMaxRounds             = 3
	syncParallelTargets       = 6
	dhtRefreshLead            = 5 * time.Minute
	defaultMaxConcurrentConns = 1024
	maxConcurrentPeerAuth     = 64
	maxConcurrentDHTRequests  = 64
	peerAuthDeadline          = 10 * time.Second
	headerReadDeadline        = 10 * time.Second
	handshakeDeadline         = 30 * time.Second
	dhtPayloadDeadline        = 15 * time.Second
	discoveryDeadline         = 30 * time.Second
	relayHandshakeDeadline    = 60 * time.Second
	serviceProxyDeadline      = 30 * time.Second
	idleSessionDeadline       = 5 * time.Minute
	dhtRouteRefreshInterval   = 5 * time.Minute
	dhtRouteRefreshJitter     = time.Minute
	dhtRefreshRoundLimit      = 2
	dhtPeerStoreFlushInterval = time.Minute
)

type ServiceRefresher func() map[string]string

type PeerTunnel interface {
	PreparePeer(context.Context, record.EndpointRecord) error
	EnsurePeer(context.Context, record.EndpointRecord) error
	RegisterProbePort(context.Context, string) error
	AuthenticatePeer(context.Context, string) (record.EndpointRecord, bool)
}

type Config struct {
	Name                   string
	NodeID                 string
	ListenAddr             string
	AdvertiseAddr          string
	AdvertiseExplicit      bool
	TransportMode          string
	HideEndpoint           bool
	RelayMode              string
	RelayResourcePercent   int
	MaxConcurrentConns     int
	DataDir                string
	ReceiveDir             string
	FileReceiveMode        string
	AllowedFileSenders     []string
	ConfigPath             string
	ControlInfoPath        string
	RefreshServices        ServiceRefresher
	RefreshServicePolicies func() map[string]serviceproxy.ServicePolicy
	PeerAddrs              []string
	Services               map[string]string
	ServicePolicies        map[string]serviceproxy.ServicePolicy
	Identity               identity.Identity
	Registry               *discovery.Registry
	DHT                    *dht.Server
	IPsecTunnel            PeerTunnel
	Reload                 chan struct{}
	livenessCache          *liveness.Cache
	recordState            *endpointRecordState
}

type endpointRecordState struct {
	mu       sync.Mutex
	config   string
	sequence uint64
	name     string
	address  string
	current  record.EndpointRecord
}

func Run(ctx context.Context, log io.Writer, cfg Config) error {
	if cfg.Name == "" {
		return errors.New("node name cannot be empty")
	}
	if cfg.NodeID == "" {
		return errors.New("node id cannot be empty")
	}
	if cfg.livenessCache == nil {
		cfg.livenessCache = liveness.NewCache(20 * time.Second)
	}
	if cfg.recordState == nil {
		cfg.recordState = newEndpointRecordState(cfg.ConfigPath)
	}
	if cfg.DHT != nil && cfg.DHT.RT != nil {
		cfg.DHT.RT.SetSelfNameHash(dht.NodeNameHash(cfg.Name))
	}
	if cfg.Registry == nil {
		return errors.New("registry cannot be nil")
	}
	if cfg.DHT != nil && cfg.DHT.RT != nil {
		cfg.Registry.SetEndpointObserver(func(rec record.EndpointRecord) {
			cfg.DHT.RT.UpdateKnownNode(dht.NodeInfoFromEndpointRecord(rec))
		})
	}
	cfg = refreshAdvertiseAddress(log, cfg)
	if err := transfer.ValidateIPv6Address(cfg.ListenAddr); err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	var peerStore *dht.PeerStore
	if cfg.DHT != nil && cfg.DHT.RT != nil {
		store, err := dht.OpenPeerStore(filepath.Join(cfg.DataDir, "dht-peers.db"))
		if err != nil {
			return err
		}
		peerStore = store
		defer peerStore.Close()
		cached, err := peerStore.LoadCandidates(time.Now(), 512)
		if err != nil {
			return err
		}
		cfg.DHT.RT.RestoreCandidates(cached, time.Now())
		if err := cfg.DHT.AttachValuePersistence(peerStore, time.Now()); err != nil {
			return fmt.Errorf("restore validated DHT values: %w", err)
		}
	}
	if cfg.ReceiveDir == "" {
		cfg.ReceiveDir = defaultReceiveDir(cfg.DataDir)
	}
	if err := os.MkdirAll(cfg.ReceiveDir, 0o755); err != nil {
		return fmt.Errorf("create receive directory: %w", err)
	}
	var peerTunnel PeerTunnel = cfg.IPsecTunnel
	if peerTunnel == nil {
		localAddress := currentIPsecLocalAddress(cfg)
		client, err := ipsec.NewClient(ipsec.DefaultSocket(), localAddress, cfg.Identity)
		if err != nil {
			return fmt.Errorf("initialize Linux IPsec service client: %w", err)
		}
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := client.Check(checkCtx); err != nil {
			cancel()
			return fmt.Errorf("Linux IPsec control service is unavailable: %w", err)
		}
		cancel()
		peerTunnel = runtimePeerTunnel{
			identity: cfg.Identity,
			address:  func() string { return currentIPsecLocalAddress(cfg) },
			client: func(address string, id identity.Identity) (PeerTunnel, error) {
				return ipsec.NewClient(ipsec.DefaultSocket(), address, id)
			},
		}
	}
	cfg.IPsecTunnel = peerTunnel
	guard := func(dialCtx context.Context, addr string) error {
		var peer record.EndpointRecord
		for _, candidate := range registryRecords(cfg.Registry, cfg.DHT) {
			if candidate.Address == addr {
				peer = candidate
				break
			}
		}
		if peer.NodeID == "" && cfg.DHT != nil && cfg.DHT.RT != nil {
			if info, ok := cfg.DHT.RT.NodeByAddress(addr); ok && dht.VerifyNodeInfo(info, time.Now()) == nil {
				peer = record.EndpointRecord{
					Version: info.IdentityVersion, Sequence: info.IdentitySequence,
					NodeID: info.ID, NodeName: info.Name, Address: info.Addr,
					PublicKey: info.PublicKey, IssuedAt: info.IdentityIssuedAt,
					ExpiresAt: info.IdentityExpiresAt, Signature: info.IdentitySignature,
				}
			}
		}
		if peer.NodeID == "" {
			return fmt.Errorf("no verified signed DHT identity for endpoint")
		}
		if expected := vxtransport.ExpectedPeerID(dialCtx); expected != "" && peer.NodeID != expected {
			return fmt.Errorf("signed peer identity mismatch at %s: got %s, want %s", addr, peer.NodeID, expected)
		}
		if !cfg.livenessCache.IsAlive(addr, time.Now()) {
			if _, _, err := liveness.Probe(dialCtx, addr, false, syncProbeTimeout); err != nil {
				cfg.livenessCache.MarkFailed(addr)
				return fmt.Errorf("VX6 liveness probe failed: %w", err)
			}
			cfg.livenessCache.MarkAlive(addr, time.Now())
		}
		return peerTunnel.EnsurePeer(dialCtx, peer)
	}
	ctx = vxtransport.WithDialGuard(ctx, guard)
	for _, peer := range registryRecords(cfg.Registry, cfg.DHT) {
		if peer.NodeID == cfg.NodeID {
			continue
		}
		if err := peerTunnel.PreparePeer(ctx, peer); err != nil {
			return fmt.Errorf("prepare IPsec peer %s: %w", peer.NodeID, err)
		}
	}
	if len(cfg.Services) == 0 && cfg.RefreshServices != nil {
		cfg.Services = cfg.RefreshServices()
	}
	if cfg.Services == nil {
		cfg.Services = map[string]string{}
	}
	if cfg.DHT != nil {
		cfg.DHT.SetHiddenDescriptorPrivacy(dht.HiddenDescriptorPrivacyConfig{
			TransportMode: cfg.TransportMode,
			RelayHopCount: 3,
			RelayCandidates: func() []record.EndpointRecord {
				if cfg.Registry == nil {
					return nil
				}
				nodes, _ := cfg.Registry.Snapshot()
				return append([]record.EndpointRecord(nil), nodes...)
			},
			ExcludeAddrs: func() []string {
				exclude := make([]string, 0, 2)
				if cfg.AdvertiseAddr != "" {
					exclude = append(exclude, cfg.AdvertiseAddr)
				}
				if cfg.ListenAddr != "" && cfg.ListenAddr != cfg.AdvertiseAddr {
					exclude = append(exclude, cfg.ListenAddr)
				}
				return exclude
			},
		})
	}
	startedAt := time.Now()

	listener, err := vxtransport.Listen(cfg.TransportMode, cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
	}
	defer listener.Close()
	udpServiceAddress, err := serviceproxy.UDPServicePort(cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("configure VX6 UDP service endpoint: %w", err)
	}
	udpServiceUDPAddr, err := net.ResolveUDPAddr("udp6", udpServiceAddress)
	if err != nil {
		return fmt.Errorf("resolve VX6 UDP service endpoint: %w", err)
	}
	udpServiceConn, err := net.ListenUDP("udp6", udpServiceUDPAddr)
	if err != nil {
		return fmt.Errorf("listen on VX6 UDP service endpoint %s: %w", udpServiceAddress, err)
	}
	defer udpServiceConn.Close()
	go func() {
		if err := serviceproxy.ServeUDPServices(ctx, udpServiceConn, func() map[string]serviceproxy.ServicePolicy {
			return runtimeServicePolicies(cfg)
		}, peerTunnel.AuthenticatePeer); err != nil && ctx.Err() == nil {
			fmt.Fprintf(log, "VX6 UDP services stopped: %v\n", err)
		}
	}()
	if !cfg.HideEndpoint && cfg.AdvertiseAddr != "" {
		probeListenAddr, err := livenessListenAddress(listener.Addr().String(), cfg.AdvertiseAddr)
		if err != nil {
			return fmt.Errorf("configure VX6 liveness endpoint: %w", err)
		}
		probeUDPAddr, err := net.ResolveUDPAddr("udp6", probeListenAddr)
		if err != nil {
			return fmt.Errorf("resolve VX6 liveness endpoint %s: %w", probeListenAddr, err)
		}
		probeConn, err := net.ListenUDP("udp6", probeUDPAddr)
		if err != nil {
			return fmt.Errorf("listen on VX6 liveness endpoint %s: %w", probeListenAddr, err)
		}
		defer probeConn.Close()
		_, probePort, _ := net.SplitHostPort(probeListenAddr)
		registerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = peerTunnel.RegisterProbePort(registerCtx, probePort)
		cancel()
		if err != nil {
			return fmt.Errorf("register VX6 liveness firewall port: %w", err)
		}
		responder := liveness.NewResponder()
		identityProvider := func() (record.EndpointRecord, error) {
			return cfg.recordState.Current(cfg.Identity, cfg.Name, cfg.AdvertiseAddr)
		}
		acceptIdentity := func(ctx context.Context, caller record.EndpointRecord, _ net.IP) error {
			// Preparing an IKE credential is not DHT admission. The peer becomes
			// active only after authenticated DHT traffic succeeds.
			return peerTunnel.PreparePeer(ctx, caller)
		}
		go func() {
			if err := responder.Serve(ctx, probeConn, identityProvider, acceptIdentity); err != nil && ctx.Err() == nil {
				fmt.Fprintf(log, "VX6 liveness service stopped: %v\n", err)
			}
		}()
	}
	go maintainIPsecPeers(ctx, log, cfg, peerTunnel)
	relayGovernor := newRelayGovernor(cfg.RelayMode, cfg.RelayResourcePercent)
	serviceSessions := serviceproxy.NewSessionTracker()
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				serviceSessions.Reconcile(runtimeServicePolicies(cfg))
			}
		}
	}()
	if cfg.ControlInfoPath != "" {
		controlServer, err := runtimectl.StartWithPeerHandlers(cfg.ControlInfoPath, os.Getpid(), func() error {
			if cfg.Reload == nil {
				return fmt.Errorf("reload channel is not configured")
			}
			select {
			case cfg.Reload <- struct{}{}:
			default:
			}
			return nil
		}, func() runtimectl.Status {
			liveCfg := runtimeConfig(cfg)
			nodeCount := 0
			serviceCount := 0
			dhtSummary := dhtStatusSummary(liveCfg.DHT)
			asnStatus := dht.ASNResolverStatusSnapshot()
			if cfg.Registry != nil {
				nodes, services := cfg.Registry.Snapshot()
				nodeCount = len(nodes)
				serviceCount = len(services)
			}
			return runtimectl.Status{
				NodeName:                        liveCfg.Name,
				AdvertiseAddr:                   liveCfg.AdvertiseAddr,
				EndpointPublish:                 endpointPublishMode(liveCfg.HideEndpoint),
				TransportConfig:                 liveCfg.TransportMode,
				TransportActive:                 vxtransport.EffectiveMode(liveCfg.TransportMode),
				RelayMode:                       liveCfg.RelayMode,
				RelayPercent:                    liveCfg.RelayResourcePercent,
				RegistryNodes:                   nodeCount,
				RegistryServices:                serviceCount,
				UptimeSeconds:                   int64(time.Since(startedAt).Seconds()),
				DHTTrackedKeys:                  dhtSummary.Tracked,
				DHTHealthyKeys:                  dhtSummary.Healthy,
				DHTDegradedKeys:                 dhtSummary.Degraded,
				DHTStaleKeys:                    dhtSummary.Stale,
				HiddenDescriptorKeys:            dhtSummary.HiddenDescriptors,
				HiddenDescriptorHealthy:         dhtSummary.HiddenHealthy,
				HiddenDescriptorDegraded:        dhtSummary.HiddenDegraded,
				HiddenDescriptorStale:           dhtSummary.HiddenStale,
				DHTRefreshIntervalSeconds:       int64(dhtSummary.RefreshInterval.Seconds()),
				HiddenDescriptorRotationSeconds: int64(dhtSummary.HiddenRotation.Seconds()),
				HiddenDescriptorOverlapKeys:     dhtSummary.HiddenPublishOverlapKey,
				ASNResolverLoaded:               asnStatus.Loaded,
				ASNResolverSource:               asnStatus.Source,
				ASNResolverEntries:              asnStatus.Entries,
			}
		}, func(peer proto.NodeInfo) error {
			if err := dht.VerifyNodeInfo(peer, time.Now()); err != nil {
				return fmt.Errorf("reject invalid peer-use record: %w", err)
			}
			if cfg.DHT == nil || cfg.DHT.RT == nil || peerStore == nil {
				return errors.New("DHT peer retention is unavailable")
			}
			cfg.DHT.RT.RecordUse(peer.ID, time.Now(), 0)
			return peerStore.RecordUse(peer, time.Now())
		}, func(peer proto.NodeInfo, friend bool) error {
			if cfg.DHT == nil || cfg.DHT.RT == nil || peerStore == nil {
				return errors.New("DHT peer retention is unavailable")
			}
			if friend {
				if err := dht.VerifyNodeInfo(peer, time.Now()); err != nil {
					return fmt.Errorf("reject invalid friend record: %w", err)
				}
				cfg.DHT.RT.AddCandidate(peer)
			} else if peer.ID == "" {
				return errors.New("friend removal requires NodeID")
			}
			cfg.DHT.RT.SetFriend(peer.ID, friend)
			if friend {
				return peerStore.SetFriend(peer, true, time.Now())
			}
			return peerStore.SetFriendByID(peer.ID, false)
		})
		if err != nil {
			return err
		}
		defer controlServer.Close()
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	fmt.Fprintf(log, "vx6 node %q (%s) listening on %s\n", cfg.Name, cfg.NodeID, listener.Addr().String())

	if shouldRunPeerSyncTasks(cfg) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runPeerSyncTasks(ctx, log, cfg)
		}()
	}
	if cfg.DHT != nil && cfg.DHT.RT != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runDHTMaintenance(ctx, log, cfg, peerStore)
		}()
	}
	if cfg.AdvertiseAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runLocalDiscovery(ctx, log, cfg)
		}()
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	connCap := effectiveMaxConcurrentConns(cfg.MaxConcurrentConns)
	connSem := make(chan struct{}, connCap)
	authSem := make(chan struct{}, maxConcurrentPeerAuth)
	dhtSem := make(chan struct{}, maxConcurrentDHTRequests)
	peerLimiter := newPeerIngressLimiter()
	ingressLog := &rateLimitedLogger{writer: log, interval: time.Second, limit: 20}
	fmt.Fprintf(log, "connection cap: %d; concurrent IKE identity checks: %d\n", connCap, maxConcurrentPeerAuth)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept connection: %w", err)
		}
		if !tryAcquire(authSem) {
			_ = conn.Close()
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-authSem }()
			authCtx, cancelAuth := context.WithTimeout(ctx, peerAuthDeadline)
			peerIdentity, authenticated := peerTunnel.AuthenticatePeer(authCtx, conn.RemoteAddr().String())
			cancelAuth()
			if !authenticated {
				_ = conn.Close()
				return
			}
			if !peerLimiter.Allow(peerIdentity.NodeID, time.Now()) {
				_ = conn.Close()
				return
			}
			if !tryAcquire(connSem) {
				ingressLog.Printf("connection cap saturated (%d/%d), dropping authenticated connection from %s\n", connCap, connCap, conn.RemoteAddr().String())
				_ = conn.Close()
				return
			}
			wg.Add(1)
			go func() {
				defer func() { <-connSem }()
				defer wg.Done()
				defer conn.Close()
				done := make(chan struct{})
				defer close(done)
				go func() {
					select {
					case <-ctx.Done():
						_ = conn.Close()
					case <-done:
					}
				}()

				reader := bufio.NewReader(conn)

				if err := conn.SetReadDeadline(time.Now().Add(headerReadDeadline)); err != nil {
					ingressLog.Printf("failed to set header read deadline for %s: %v\n", conn.RemoteAddr().String(), err)
					return
				}
				kind, err := proto.ReadHeader(reader)
				if err != nil {
					if errors.Is(err, io.EOF) {
						return
					}
					ingressLog.Printf("session error from %s: %v\n", conn.RemoteAddr().String(), err)
					return
				}

				if err := conn.SetReadDeadline(time.Time{}); err != nil {
					ingressLog.Printf("failed to clear header deadline for %s: %v\n", conn.RemoteAddr().String(), err)
					return
				}

				liveCfg := runtimeConfig(cfg)
				relayGovernor.Update(liveCfg.RelayMode, liveCfg.RelayResourcePercent)

				switch kind {
				case proto.KindLiveness:
					_ = conn.SetDeadline(time.Now().Add(discoveryDeadline))
					if err := liveness.HandleTunnelConn(&bufferedConn{Conn: conn, reader: reader}); err != nil {
						ingressLog.Printf("tunnel liveness request from %s failed: %v\n", conn.RemoteAddr().String(), err)
					}
				case proto.KindFileTransfer:

					_ = conn.SetDeadline(time.Now().Add(idleSessionDeadline))
					res, err := transfer.ReceiveFileWithAuthenticatedPeer(&bufferedConn{Conn: conn, reader: reader}, liveCfg.ReceiveDir, fileReceivePolicy(liveCfg), peerIdentity.NodeName, peerIdentity.NodeID)
					if err != nil {
						ingressLog.Printf("receive error from %s: %v\n", conn.RemoteAddr().String(), err)
						return
					}
					absPath, pathErr := filepath.Abs(res.StoredPath)
					if pathErr != nil {
						absPath = res.StoredPath
					}
					ingressLog.Printf("received %q (%d bytes) from node %q into %s\n", res.FileName, res.BytesReceived, res.SenderNode, absPath)
				case proto.KindDiscoveryReq:

					_ = conn.SetDeadline(time.Now().Add(discoveryDeadline))
					if err := cfg.Registry.HandleConnFromPeer(&bufferedConn{Conn: conn, reader: reader}, peerIdentity.NodeID); err != nil {
						ingressLog.Printf("discovery error from %s: %v\n", conn.RemoteAddr().String(), err)
						return
					}
					ingressLog.Printf("processed discovery request from %s\n", conn.RemoteAddr().String())
				case proto.KindDHT:
					if !tryAcquire(dhtSem) {
						ingressLog.Printf("DHT request concurrency limit reached; dropping request from %s\n", conn.RemoteAddr().String())
						return
					}
					defer func() { <-dhtSem }()

					_ = conn.SetReadDeadline(time.Now().Add(dhtPayloadDeadline))
					payload, err := proto.ReadLengthPrefixed(reader, proto.MaxDHTFrameSize)
					if err != nil {
						ingressLog.Printf("dht read error from %s: %v\n", conn.RemoteAddr().String(), err)
						return
					}

					_ = conn.SetDeadline(time.Now().Add(discoveryDeadline))
					if cfg.DHT != nil {
						if err := cfg.DHT.HandleDHTPayload(ctx, conn, payload, peerIdentity.NodeID); err != nil {
							ingressLog.Printf("dht error from %s: %v\n", conn.RemoteAddr().String(), err)
						}
					}
				case proto.KindExtend:
					release, err := relayGovernor.Acquire(kind)
					if err != nil {
						ingressLog.Printf("relay admission denied for %s: %v\n", conn.RemoteAddr().String(), err)
						return
					}
					defer release()

					_ = conn.SetDeadline(time.Now().Add(idleSessionDeadline))
					if err := onion.HandleExtend(ctx, &bufferedConn{Conn: conn, reader: reader}, cfg.Identity); err != nil {
						ingressLog.Printf("extend error from %s: %v\n", conn.RemoteAddr().String(), err)
					}
				case proto.KindRendezvous:
					release, err := relayGovernor.Acquire(kind)
					if err != nil {
						ingressLog.Printf("relay admission denied for %s: %v\n", conn.RemoteAddr().String(), err)
						return
					}
					defer release()

					_ = conn.SetDeadline(time.Now().Add(relayHandshakeDeadline))
					liveServices := liveCfg.Services
					if err := hidden.HandleConn(ctx, &bufferedConn{Conn: conn, reader: reader}, hidden.HandlerConfig{
						Identity:      cfg.Identity,
						AdvertiseAddr: liveCfg.AdvertiseAddr,
						TransportMode: liveCfg.TransportMode,
						Services:      liveServices,
						HiddenAliases: hiddenAliasMap(cfg.ConfigPath),
						Registry:      cfg.Registry,
					}); err != nil {
						ingressLog.Printf("hidden service error from %s: %v\n", conn.RemoteAddr().String(), err)
					}
				case proto.KindServiceConn:

					_ = conn.SetDeadline(time.Now().Add(serviceProxyDeadline))
					if err := serviceproxy.HandleInboundWithPolicyAndTracker(&bufferedConn{Conn: conn, reader: reader}, runtimeServicePolicies(cfg), peerIdentity, serviceSessions); err != nil {
						ingressLog.Printf("service proxy error from %s: %v\n", conn.RemoteAddr().String(), err)
					}
				default:
					ingressLog.Printf("session error from %s: unsupported kind %d\n", conn.RemoteAddr().String(), kind)
				}
			}()
		}()
	}
}

type rateLimitedLogger struct {
	mu       sync.Mutex
	writer   io.Writer
	interval time.Duration
	limit    int
	start    time.Time
	count    int
}

func (l *rateLimitedLogger) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.start.IsZero() || now.Sub(l.start) >= l.interval {
		l.start = now
		l.count = 0
	}
	if l.count >= l.limit {
		return
	}
	l.count++
	_, _ = fmt.Fprintf(l.writer, format, args...)
}

const (
	peerIngressWindow   = 10 * time.Second
	peerIngressBurst    = 600
	peerIngressMaxPeers = 4096
	peerIngressEntryTTL = time.Minute
)

type peerIngressLimiter struct {
	mu      sync.Mutex
	entries map[string]timeWindowCount
}

type timeWindowCount struct {
	start time.Time
	count int
}

func newPeerIngressLimiter() *peerIngressLimiter {
	return &peerIngressLimiter{entries: make(map[string]timeWindowCount)}
}

func (l *peerIngressLimiter) Allow(peerID string, now time.Time) bool {
	if peerID == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, exists := l.entries[peerID]
	if !exists {
		if len(l.entries) >= peerIngressMaxPeers {
			for key, old := range l.entries {
				if now.Sub(old.start) > peerIngressEntryTTL {
					delete(l.entries, key)
				}
			}
			if len(l.entries) >= peerIngressMaxPeers {
				return false
			}
		}
		l.entries[peerID] = timeWindowCount{start: now, count: 1}
		return true
	}
	if now.Sub(entry.start) >= peerIngressWindow {
		l.entries[peerID] = timeWindowCount{start: now, count: 1}
		return true
	}
	if entry.count >= peerIngressBurst {
		return false
	}
	entry.count++
	l.entries[peerID] = entry
	return true
}

func endpointPublishMode(hidden bool) string {
	if hidden {
		return "hidden"
	}
	return "published"
}

func effectiveMaxConcurrentConns(configured int) int {
	if configured > 0 {
		return configured
	}
	return defaultMaxConcurrentConns
}

func tryAcquire(semaphore chan struct{}) bool {
	select {
	case semaphore <- struct{}{}:
		return true
	default:
		return false
	}
}

func shouldRunPeerSyncTasks(cfg Config) bool {
	if cfg.AdvertiseAddr != "" {
		return true
	}
	if len(cfg.PeerAddrs) > 0 {
		return true
	}
	if cfg.Registry == nil {
		return false
	}
	nodes, _ := cfg.Registry.Snapshot()
	return len(nodes) > 0
}

func runLocalDiscovery(ctx context.Context, log io.Writer, cfg Config) {
	const multicastAddr = "[ff02::1]:4245"
	if cfg.AdvertiseAddr != "" {
		probeAddr, err := liveness.ProbeAddress(cfg.AdvertiseAddr)
		if err == nil {
			_, probePort, _ := net.SplitHostPort(probeAddr)
			_, multicastPort, _ := net.SplitHostPort(multicastAddr)
			if probePort == multicastPort {
				return
			}
		}
	}
	addr, _ := net.ResolveUDPAddr("udp6", multicastAddr)
	conn, err := net.ListenMulticastUDP("udp6", nil, addr)
	if err != nil {
		return
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil || n == 0 {
				return
			}
			var info proto.NodeInfo
			if err := strictjson.Decode(buf[:n], &info); err == nil && info.ID != cfg.NodeID {
				rec := record.EndpointRecord{
					Version: info.IdentityVersion, Sequence: info.IdentitySequence,
					NodeID: info.ID, NodeName: info.Name, Address: info.Addr,
					PublicKey: info.PublicKey, IssuedAt: info.IdentityIssuedAt,
					ExpiresAt: info.IdentityExpiresAt, Signature: info.IdentitySignature,
				}
				if dht.VerifyNodeInfo(info, time.Now()) == nil {
					_ = cfg.Registry.Import([]record.EndpointRecord{rec}, nil)
				}
			}
		}
	}()

	ticker := time.NewTicker(15 * time.Second)
	localRecord, err := cfg.recordState.Current(cfg.Identity, cfg.Name, cfg.AdvertiseAddr)
	if err != nil {
		return
	}
	data, _ := json.Marshal(dht.NodeInfoFromEndpointRecord(localRecord))
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = conn.WriteToUDP(data, addr)
		}
	}
}

func livenessListenAddress(listenerAddress, advertisedAddress string) (string, error) {
	probeAddress, err := liveness.ProbeAddress(advertisedAddress)
	if err != nil {
		return "", err
	}
	listenHost, _, err := net.SplitHostPort(listenerAddress)
	if err != nil {
		return "", fmt.Errorf("split listener address: %w", err)
	}
	_, probePort, err := net.SplitHostPort(probeAddress)
	if err != nil {
		return "", fmt.Errorf("split advertised probe address: %w", err)
	}
	return net.JoinHostPort(listenHost, probePort), nil
}

func newEndpointRecordState(configPath string) *endpointRecordState {
	state := &endpointRecordState{config: configPath}
	if configPath == "" {
		return state
	}
	store, err := config.NewStore(configPath)
	if err != nil {
		return state
	}
	configured, err := store.Load()
	if err != nil {
		return state
	}
	state.sequence = configured.Node.RecordSequence
	state.name = configured.Node.RecordName
	state.address = configured.Node.RecordAddress
	return state
}

func (s *endpointRecordState) Current(id identity.Identity, name, address string) (record.EndpointRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.current.NodeID == id.NodeID && s.name == name && s.address == address {
		expiresAt, err := time.Parse(time.RFC3339, s.current.ExpiresAt)
		if err == nil && now.Add(5*time.Minute).Before(expiresAt) {
			return s.current, nil
		}
	}
	if s.sequence == ^uint64(0) {
		return record.EndpointRecord{}, fmt.Errorf("endpoint record sequence exhausted")
	}
	next := s.sequence + 1
	if next == 0 {
		next = 1
	}
	created, err := record.NewEndpointRecordV2(id, name, address, next, 20*time.Minute, now)
	if err != nil {
		return record.EndpointRecord{}, err
	}
	if s.config != "" {
		store, err := config.NewStore(s.config)
		if err != nil {
			return record.EndpointRecord{}, err
		}
		configured, err := store.Load()
		if err != nil {
			return record.EndpointRecord{}, err
		}
		if configured.Node.RecordSequence >= next {
			if configured.Node.RecordSequence == ^uint64(0) {
				return record.EndpointRecord{}, fmt.Errorf("endpoint record sequence exhausted")
			}
			next = configured.Node.RecordSequence + 1
			created, err = record.NewEndpointRecordV2(id, name, address, next, 20*time.Minute, now)
			if err != nil {
				return record.EndpointRecord{}, err
			}
		}
		configured.Node.RecordSequence = next
		configured.Node.RecordName = name
		configured.Node.RecordAddress = address
		if err := store.Save(configured); err != nil {
			return record.EndpointRecord{}, err
		}
	}
	s.sequence = next
	s.name = name
	s.address = address
	s.current = created
	return created, nil
}

func runPeerSyncTasks(ctx context.Context, log io.Writer, cfg Config) {
	syncOnlyLogged := false
	selfLookupDone := false
	lastEndpointSequenceByPeer := make(map[string]uint64)

	publishAndSync := func() {
		liveCfg := runtimeConfig(cfg)
		var (
			rec           record.EndpointRecord
			endpointReady bool
		)
		if liveCfg.AdvertiseAddr != "" {
			var err error
			rec, err = liveCfg.recordState.Current(liveCfg.Identity, liveCfg.Name, liveCfg.AdvertiseAddr)
			if err != nil {
				fmt.Fprintf(log, "[SYNC] Skipping endpoint publish for %s: %v\n", liveCfg.Name, err)
			} else {
				endpointReady = true
			}
		} else if !syncOnlyLogged {
			fmt.Fprintf(log, "[SYNC] Running discovery sync without a publishable advertise address for %s\n", liveCfg.Name)
			syncOnlyLogged = true
		}
		if endpointReady {
			syncOnlyLogged = false
		}
		if endpointReady && !liveCfg.HideEndpoint {
			_ = liveCfg.Registry.Import([]record.EndpointRecord{rec}, nil)
		}

		nodes, _ := liveCfg.Registry.Snapshot()
		targets := syncMesh(ctx, log, liveCfg, endpointRecordRef(endpointReady, rec), nodes, lastEndpointSequenceByPeer)
		if !selfLookupDone && liveCfg.DHT != nil && liveCfg.DHT.RT != nil && len(liveCfg.DHT.RT.Nodes()) > 0 {
			lookupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			result, err := liveCfg.DHT.RecursiveFindValueDetailed(lookupCtx, dht.NodeIDKey(liveCfg.NodeID))
			cancel()
			if result.QueriedNodes > 0 {
				selfLookupDone = true
				fmt.Fprintf(log, "[DHT] Initial self-identity lookup queried %d peers; result=%v\n", result.QueriedNodes, err)
			}
		}

		nodes, _ = liveCfg.Registry.Snapshot()
		persistKnownPeerMetadata(liveCfg.ConfigPath, nodes)
		hidden.TrackAddresses(ctx, nodeAddresses(nodes), 30*time.Second)
		if !endpointReady {
			return
		}
		serviceRecords, hiddenTopologies, hiddenLookupSecrets := buildServiceRecords(ctx, liveCfg, nodes)
		publishServicesToTargets(ctx, liveCfg, log, targets, serviceRecords)
		hiddenTargets := make([]hidden.OwnerRegistrationTarget, 0)

		for _, srec := range serviceRecords {
			if !srec.IsHidden {
				continue
			}
			topology := hiddenTopologies[record.ServiceLookupKey(srec)]
			notifyAddrs := append([]string(nil), topology.Guards...)
			if len(notifyAddrs) == 0 {
				notifyAddrs = []string{liveCfg.AdvertiseAddr}
			}
			controlOpts := hidden.ControlOptions{
				Identity:      liveCfg.Identity,
				Registry:      liveCfg.Registry,
				SelfAddr:      liveCfg.AdvertiseAddr,
				TransportMode: liveCfg.TransportMode,
				RelayHopCount: hidden.ControlHopCountForProfile(srec.HiddenProfile),
				RequireRelay:  true,
			}
			allIntros := append([]string(nil), srec.IntroPoints...)
			allIntros = append(allIntros, srec.StandbyIntroPoints...)
			hidden.TrackAddresses(ctx, append(append([]string(nil), allIntros...), topology.Guards...), 20*time.Second)
			for _, guardAddr := range topology.Guards {
				hidden.EnsureGuardRegistration(ctx, controlOpts, guardAddr, record.ServiceLookupKey(srec), func() hidden.HandlerConfig {
					current := runtimeConfig(cfg)
					return hidden.HandlerConfig{
						Identity:      cfg.Identity,
						AdvertiseAddr: current.AdvertiseAddr,
						TransportMode: current.TransportMode,
						Services:      current.Services,
						HiddenAliases: hiddenAliasMap(cfg.ConfigPath),
						Registry:      cfg.Registry,
					}
				})
			}
			for _, introAddr := range allIntros {
				hidden.EnsureIntroRegistration(ctx, controlOpts, introAddr, record.ServiceLookupKey(srec), notifyAddrs)
			}
			hiddenTargets = append(hiddenTargets, hidden.OwnerRegistrationTarget{
				LookupKey:  record.ServiceLookupKey(srec),
				GuardAddrs: append([]string(nil), topology.Guards...),
				IntroAddrs: append([]string(nil), allIntros...),
			})
		}
		hidden.PruneOwnerRegistrations(liveCfg.Identity.NodeID, hiddenTargets)

		publishRecordsToTargets(ctx, liveCfg, log, targets, rec, serviceRecords)

		publishDHTRecords(ctx, liveCfg.DHT, liveCfg.Identity, rec, serviceRecords, hiddenLookupSecrets, liveCfg.HideEndpoint)
		warnOnNodeNameConflict(ctx, log, liveCfg)
	}

	publishAndSync()
	ticker := time.NewTicker(syncWarmupInterval)
	defer ticker.Stop()
	warmupRounds := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-cfg.Reload:
			fmt.Fprintf(log, "[RELOAD] configuration refresh requested\n")
			publishAndSync()
		case <-ticker.C:
			publishAndSync()
			if warmupRounds < syncWarmupRounds {
				warmupRounds++
				if warmupRounds == syncWarmupRounds {
					ticker.Reset(syncCycleInterval)
				}
			}
		}
	}
}

func runDHTMaintenance(ctx context.Context, log io.Writer, cfg Config, store *dht.PeerStore) {
	probeMu := &sync.Mutex{}
	go runDHTLivenessChecks(ctx, log, cfg, probeMu)
	flush := func() {
		if store == nil || cfg.DHT == nil || cfg.DHT.RT == nil {
			return
		}
		now := time.Now()
		cfg.DHT.RT.PruneOffline(now)
		if err := store.SaveSnapshot(cfg.DHT.RT.SnapshotPeers(), now); err != nil {
			fmt.Fprintf(log, "[DHT] Could not persist peer observations: %v\n", err)
		}
	}
	refresh := func() {
		if cfg.DHT == nil || cfg.DHT.RT == nil {
			return
		}
		// Recheck only a small number of durable address hints. They remain
		// candidates until signed identity, IKE and in-tunnel liveness succeed.
		for _, candidate := range cfg.DHT.RT.CandidateNodes(2) {
			if ctx.Err() != nil {
				return
			}
			if !cfg.DHT.RT.ProbeAllowed(candidate.ID, time.Now()) {
				continue
			}
			probeMu.Lock()
			attemptCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := verifyAndPromoteRoutingCandidate(attemptCtx, cfg, cfg.DHT.RT, candidate)
			cancel()
			probeMu.Unlock()
			if err != nil {
				fmt.Fprintf(log, "[DHT] Candidate validation failed (%s): %v\n", candidate.ID, err)
			}
		}
		var refreshKeys []string
		bootstrap := cfg.DHT.RT.ActivePeerCount() == 0
		if bootstrap {
			refreshKeys = []string{dht.NodeIDKey(cfg.NodeID), dht.NodeNameKey(cfg.Name)}
		} else {
			refreshKeys = append(refreshKeys, dht.NodeIDKey(cfg.NodeID))
			for _, target := range cfg.DHT.RT.RefreshTargets(time.Now(), dhtRefreshRoundLimit) {
				refreshKeys = append(refreshKeys, target.Key)
			}
		}
		for _, key := range refreshKeys {
			refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			var referrals []proto.NodeInfo
			var err error
			if bootstrap {
				result, lookupErr := cfg.DHT.RecursiveBootstrapFindNodeDetailed(refreshCtx, key)
				referrals, err = result.Closest, lookupErr
			} else {
				referrals, err = cfg.DHT.RecursiveFindNode(refreshCtx, key)
			}
			cancel()
			if err != nil {
				continue
			}
			for _, referral := range referrals {
				if dht.VerifyNodeInfo(referral, time.Now()) == nil {
					cfg.DHT.RT.AddCandidate(referral)
				}
			}
		}
		flush()
	}

	flushTicker := time.NewTicker(dhtPeerStoreFlushInterval)
	defer flushTicker.Stop()
	defer flush()
	refreshTimer := time.NewTimer(jitteredDHTRefresh())
	defer refreshTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-flushTicker.C:
			flush()
		case <-refreshTimer.C:
			refresh()
			refreshTimer.Reset(jitteredDHTRefresh())
		}
	}
}

func runDHTLivenessChecks(ctx context.Context, log io.Writer, cfg Config, probeMu *sync.Mutex) {
	if cfg.DHT == nil || cfg.DHT.RT == nil {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		peer, ok := cfg.DHT.RT.BeginLivenessProbe(time.Now())
		if !ok {
			continue
		}
		probeMu.Lock()
		probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := verifyRoutingPeer(probeCtx, cfg, peer)
		cancel()
		probeMu.Unlock()
		removed := cfg.DHT.RT.RecordLivenessResult(peer.ID, time.Now(), err == nil)
		if err != nil {
			fmt.Fprintf(log, "[DHT] Peer liveness check failed (%s): %v\n", peer.ID, err)
		}
		if removed {
			fmt.Fprintf(log, "[DHT] Peer marked inactive after three spaced liveness failures: %s\n", peer.ID)
		}
	}
}

func verifyRoutingPeer(ctx context.Context, cfg Config, peer proto.NodeInfo) error {
	if err := dht.VerifyNodeInfo(peer, time.Now()); err != nil {
		return fmt.Errorf("signed peer identity is invalid: %w", err)
	}
	endpoint := record.EndpointRecord{
		Version: peer.IdentityVersion, Sequence: peer.IdentitySequence,
		NodeID: peer.ID, NodeName: peer.Name, Address: peer.Addr,
		PublicKey: peer.PublicKey, IssuedAt: peer.IdentityIssuedAt,
		ExpiresAt: peer.IdentityExpiresAt, Signature: peer.IdentitySignature,
	}
	if err := record.VerifyEndpointRecord(endpoint, time.Now()); err != nil {
		return fmt.Errorf("signed peer endpoint is invalid: %w", err)
	}
	if _, _, err := liveness.Probe(ctx, peer.Addr, false, syncProbeTimeout); err != nil {
		return fmt.Errorf("peer did not answer VX6 liveness probe: %w", err)
	}
	if cfg.IPsecTunnel == nil {
		return errors.New("IPsec peer verifier is unavailable")
	}
	if err := cfg.IPsecTunnel.EnsurePeer(ctx, endpoint); err != nil {
		return fmt.Errorf("IKE/IPsec identity check failed: %w", err)
	}
	protectedCtx := vxtransport.WithDialGuard(ctx, func(_ context.Context, target string) error {
		if target != peer.Addr {
			return fmt.Errorf("liveness context cannot dial unverified endpoint %s", target)
		}
		return nil
	})
	if err := liveness.TunnelPing(protectedCtx, cfg.TransportMode, peer.Addr, syncProbeTimeout); err != nil {
		return fmt.Errorf("authenticated IPsec tunnel check failed: %w", err)
	}
	return nil
}

func verifyAndPromoteRoutingCandidate(ctx context.Context, cfg Config, rt *dht.RoutingTable, peer proto.NodeInfo) error {
	if err := verifyRoutingPeer(ctx, cfg, peer); err != nil {
		rt.RecordLivenessResult(peer.ID, time.Now(), false)
		return err
	}
	rt.AddNode(peer)
	return nil
}

func jitteredDHTRefresh() time.Duration {
	return dhtRouteRefreshInterval - dhtRouteRefreshJitter + time.Duration(rand.Int63n(int64(2*dhtRouteRefreshJitter)+1))
}

func warnOnNodeNameConflict(ctx context.Context, log io.Writer, cfg Config) {
	if cfg.DHT == nil || cfg.Name == "" {
		return
	}
	result, err := cfg.DHT.RecursiveFindValueDetailed(ctx, dht.NodeNameKey(cfg.Name))
	if err != nil && !errors.Is(err, dht.ErrConflictingValues) {
		return
	}
	candidates := make([]record.EndpointRecord, 0, 2)
	if result.Value != "" {
		var rec record.EndpointRecord
		if err := strictjson.Decode([]byte(result.Value), &rec); err == nil && rec.NodeName == cfg.Name {
			candidates = append(candidates, rec)
		}
	}
	for _, raw := range result.ConflictValues {
		var rec record.EndpointRecord
		if err := strictjson.Decode([]byte(raw), &rec); err != nil {
			continue
		}
		if rec.NodeName != cfg.Name {
			continue
		}
		seen := false
		for _, existing := range candidates {
			if existing.NodeID == rec.NodeID && existing.Address == rec.Address {
				seen = true
				break
			}
		}
		if !seen {
			candidates = append(candidates, rec)
		}
	}
	if len(candidates) <= 1 {
		return
	}
	fmt.Fprintf(log, "[NAME-CONFLICT] node name %q is claimed by %d identities; one operator should rename\n", cfg.Name, len(candidates))
	for _, rec := range candidates {
		fmt.Fprintf(log, "[NAME-CONFLICT] candidate\tname=%s\tid=%s\taddr=%s\n", rec.NodeName, rec.NodeID, rec.Address)
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func hiddenAliasMap(configPath string) map[string]string {
	entries := loadServiceEntries(configPath)
	out := make(map[string]string, len(entries))
	for name, entry := range entries {
		if entry.IsHidden && entry.Alias != "" {
			out[entry.Alias] = name
		}
	}
	return out
}

func loadServiceEntries(configPath string) map[string]config.ServiceEntry {
	if configPath == "" {
		return nil
	}
	store, err := config.NewStore(configPath)
	if err != nil {
		return nil
	}
	cfgFile, err := store.Load()
	if err != nil {
		return nil
	}
	out := make(map[string]config.ServiceEntry, len(cfgFile.Services))
	for name, entry := range cfgFile.Services {
		out[name] = entry
	}
	return out
}

func seedDHTRouting(server *dht.Server, records []record.EndpointRecord) {
	if server == nil {
		return
	}
	for _, rec := range records {
		if record.VerifyEndpointRecord(rec, time.Now()) != nil {
			continue
		}
		server.RT.AddNode(dht.NodeInfoFromEndpointRecord(rec))
	}
}

func registryRecords(registry *discovery.Registry, server *dht.Server) []record.EndpointRecord {
	byID := make(map[string]record.EndpointRecord)
	if registry != nil {
		nodes, _ := registry.Snapshot()
		for _, rec := range nodes {
			if record.VerifyEndpointRecord(rec, time.Now()) == nil {
				preferEndpointRecord(byID, rec)
			}
		}
	}
	if server != nil && server.RT != nil {
		for _, info := range server.RT.Nodes() {
			if dht.VerifyNodeInfo(info, time.Now()) != nil {
				continue
			}
			rec := record.EndpointRecord{
				Version: info.IdentityVersion, Sequence: info.IdentitySequence,
				NodeID: info.ID, NodeName: info.Name, Address: info.Addr,
				PublicKey: info.PublicKey, IssuedAt: info.IdentityIssuedAt,
				ExpiresAt: info.IdentityExpiresAt, Signature: info.IdentitySignature,
			}
			preferEndpointRecord(byID, rec)
		}
	}
	out := make([]record.EndpointRecord, 0, len(byID))
	for _, rec := range byID {
		out = append(out, rec)
	}
	return out
}

func preferEndpointRecord(records map[string]record.EndpointRecord, candidate record.EndpointRecord) {
	current, exists := records[candidate.NodeID]
	if !exists || record.EndpointRecordNewer(candidate, current) {
		records[candidate.NodeID] = candidate
	}
}

func maintainIPsecPeers(ctx context.Context, log io.Writer, cfg Config, manager PeerTunnel) {
	prepare := func() {
		for _, peer := range registryRecords(cfg.Registry, cfg.DHT) {
			if peer.NodeID == cfg.NodeID {
				continue
			}
			if err := manager.PreparePeer(ctx, peer); err != nil && ctx.Err() == nil {
				fmt.Fprintf(log, "[IPSEC] prepare peer %s failed: %v\n", peer.NodeID, err)
			}
		}
	}
	prepare()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prepare()
		}
	}
}

func publishDHTRecords(ctx context.Context, server *dht.Server, signer identity.Identity, endpoint record.EndpointRecord, services []record.ServiceRecord, hiddenLookupSecrets map[string]string, hideEndpoint bool) {
	if server == nil {
		return
	}
	now := time.Now()

	if !hideEndpoint {
		if data, err := json.Marshal(endpoint); err == nil {
			payload := string(data)
			publishDHTRecord(ctx, server, dht.NodeNameKey(endpoint.NodeName), payload, dht.ReplicaKindNodeName, endpoint.NodeName, now, endpoint.ExpiresAt)
			publishDHTRecord(ctx, server, dht.NodeIDKey(endpoint.NodeID), payload, dht.ReplicaKindNodeID, endpoint.NodeID, now, endpoint.ExpiresAt)
		}
	}

	for _, svc := range services {
		if svc.IsPrivate {
			continue
		}
		if svc.IsHidden && svc.Alias != "" {
			lookupSecret := hiddenLookupSecrets[svc.ServiceName]
			server.TrackHiddenLookupInvite(dht.ComposeHiddenLookupInvite(svc.Alias, lookupSecret))
			for _, key := range dht.HiddenServicePublishKeys(svc.Alias, lookupSecret, now) {
				payload, err := dht.EncodeHiddenServiceDescriptor(svc, key, lookupSecret)
				if err != nil {
					continue
				}
				publishDHTRecord(ctx, server, key, payload, dht.ReplicaKindHiddenDescriptor, svc.Alias, now, svc.ExpiresAt)
			}
			continue
		}
		if data, err := json.Marshal(svc); err == nil {
			payload := string(data)
			publishDHTRecord(ctx, server, dht.ServiceKey(record.FullServiceName(svc.NodeName, svc.ServiceName)), payload, dht.ReplicaKindPublicService, record.FullServiceName(svc.NodeName, svc.ServiceName), now, svc.ExpiresAt)
		}
	}

	privateServices := privateCatalogServices(services)
	if len(privateServices) > 0 {
		catalog, err := dht.NewPrivateServiceCatalog(signer, endpoint.NodeName, privateServices, 20*time.Minute, now)
		if err == nil {
			if data, err := json.Marshal(catalog); err == nil {
				publishDHTRecord(ctx, server, dht.PrivateCatalogKey(endpoint.NodeName), string(data), dht.ReplicaKindPrivateCatalog, "private:"+endpoint.NodeName, now, catalog.ExpiresAt)
			}
		}
	}
}

func privateCatalogServices(services []record.ServiceRecord) []record.ServiceRecord {
	out := make([]record.ServiceRecord, 0, len(services))
	for _, svc := range services {
		if svc.IsPrivate && !svc.IsHidden {
			out = append(out, svc)
		}
	}
	return out
}

func publishDHTRecord(ctx context.Context, server *dht.Server, key, payload string, kind dht.ReplicaKind, subject string, publishedAt time.Time, expiresAtRaw string) {
	if server == nil {
		return
	}
	report, err := server.MaintainReplicas(ctx, key, payload)
	observation := dht.ReplicaObservation{
		Key:            key,
		Kind:           kind,
		Subject:        subject,
		Desired:        report.Desired,
		Attempted:      report.Attempted,
		StoredRemotely: report.StoredRemotely,
		LocalStored:    report.LocalStored,
		PublishedAt:    publishedAt,
		RefreshBy:      dhtRefreshDeadline(publishedAt, expiresAtRaw),
		LastError:      errString(err),
	}
	if epoch, ok := dht.HiddenDescriptorEpochFromKey(key); ok {
		observation.Epoch = epoch
	}
	if expiresAtRaw != "" {
		if expiresAt, err := time.Parse(time.RFC3339, expiresAtRaw); err == nil {
			observation.ExpiresAt = expiresAt
		}
	}
	server.RecordReplicaObservation(observation)
}

func dhtRefreshDeadline(publishedAt time.Time, expiresAtRaw string) time.Time {
	refreshBy := publishedAt.Add(syncCycleInterval)
	if expiresAtRaw == "" {
		return refreshBy
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresAtRaw)
	if err != nil {
		return refreshBy
	}
	lead := expiresAt.Add(-dhtRefreshLead)
	if lead.Before(refreshBy) {
		return lead
	}
	return refreshBy
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func dhtStatusSummary(server *dht.Server) dht.ReplicaSummary {
	if server == nil {
		return dht.ReplicaSummary{
			RefreshInterval:         syncCycleInterval,
			HiddenRotation:          dht.HiddenDescriptorRotationInterval(),
			HiddenPublishOverlapKey: dht.HiddenDescriptorPublishOverlap(),
		}
	}
	return server.ReplicaSummary(time.Now(), syncCycleInterval)
}

func buildServiceRecords(ctx context.Context, cfg Config, nodes []record.EndpointRecord) ([]record.ServiceRecord, map[string]hidden.Topology, map[string]string) {
	serviceRecords := make([]record.ServiceRecord, 0, len(cfg.Services))
	topologies := make(map[string]hidden.Topology)
	hiddenLookupSecrets := make(map[string]string)
	entries := loadServiceEntries(cfg.ConfigPath)

	for name := range cfg.Services {
		entry := entries[name]
		isHidden := entry.IsHidden
		svcAddr := cfg.AdvertiseAddr
		if isHidden {
			svcAddr = ""
		}
		srec, err := record.NewServiceRecord(cfg.Identity, cfg.Name, name, svcAddr, 20*time.Minute, time.Now())
		if err != nil {
			continue
		}
		srec.Protocol = record.NormalizeServiceProtocol(entry.Protocol)

		srec.IsHidden = isHidden
		srec.IsPrivate = entry.IsPrivate
		if isHidden {
			topology := hidden.SelectTopology(ctx, cfg.AdvertiseAddr, nodes, entry.IntroNodes, entry.IntroMode, entry.HiddenProfile)
			srec.Alias = entry.Alias
			if srec.Alias == "" {
				srec.Alias = name
			}
			srec.HiddenProfile = record.NormalizeHiddenProfile(entry.HiddenProfile)
			srec.IntroPoints = append([]string(nil), topology.ActiveIntros...)
			srec.StandbyIntroPoints = append([]string(nil), topology.StandbyIntros...)
			topologies[record.ServiceLookupKey(srec)] = topology
			hiddenLookupSecrets[srec.ServiceName] = entry.HiddenLookupSecret
		}
		_ = record.SignServiceRecord(cfg.Identity, &srec)
		if !srec.IsPrivate && !srec.IsHidden {
			_ = cfg.Registry.Import(nil, []record.ServiceRecord{srec})
		}
		serviceRecords = append(serviceRecords, srec)
	}

	return serviceRecords, topologies, hiddenLookupSecrets
}

func nodeAddresses(nodes []record.EndpointRecord) []string {
	out := make([]string, 0, len(nodes))
	for _, nodeRec := range nodes {
		if nodeRec.Address == "" {
			continue
		}
		out = append(out, nodeRec.Address)
	}
	return out
}

func endpointRecordRef(ok bool, rec record.EndpointRecord) *record.EndpointRecord {
	if !ok {
		return nil
	}
	out := rec
	return &out
}

func syncMesh(ctx context.Context, log io.Writer, cfg Config, rec *record.EndpointRecord, initialNodes []record.EndpointRecord, lastEndpointSequenceByPeer map[string]uint64) map[string]struct{} {
	targets := map[string]struct{}{}
	reachable := map[string]struct{}{}
	for _, addr := range cfg.PeerAddrs {
		addSyncTarget(targets, cfg.AdvertiseAddr, addr)
	}
	for _, nodeRec := range initialNodes {
		if nodeRec.NodeID == cfg.NodeID {
			continue
		}
		addSyncTarget(targets, cfg.AdvertiseAddr, nodeRec.Address)
	}

	synced := map[string]struct{}{}
	for round := 0; round < syncMaxRounds; round++ {
		pending := pendingSyncTargets(targets, synced)
		if len(pending) == 0 {
			break
		}
		eligible := pending[:0]
		for _, addr := range pending {
			if rec != nil && !cfg.HideEndpoint && lastEndpointSequenceByPeer[addr] < rec.Sequence {
				eligible = append(eligible, addr)
				continue
			}
			if cfg.DHT != nil && cfg.DHT.RT != nil {
				peer, known := cfg.DHT.RT.NodeByAddress(addr)
				if known && !cfg.DHT.RT.ProbeAllowed(peer.ID, time.Now()) {
					synced[addr] = struct{}{}
					continue
				}
			}
			eligible = append(eligible, addr)
		}
		pending = eligible
		if len(pending) == 0 {
			continue
		}
		results := syncTargetBatch(ctx, log, cfg, rec, pending)
		for _, result := range results {
			synced[result.addr] = struct{}{}
			if result.err != nil {
				if cfg.DHT != nil && cfg.DHT.RT != nil && result.nodeID != "" {
					cfg.DHT.RT.NoteFailure(result.nodeID)
				}
				continue
			}
			reachable[result.addr] = struct{}{}
			if rec != nil && !cfg.HideEndpoint && rec.Sequence > 0 {
				lastEndpointSequenceByPeer[result.addr] = rec.Sequence
			}
			if result.peer != nil {
				_ = cfg.Registry.Import([]record.EndpointRecord{*result.peer}, nil)
				seedDHTRouting(cfg.DHT, []record.EndpointRecord{*result.peer})
			}
			_ = cfg.Registry.Import(result.records, result.services)
			for _, nodeRec := range result.records {
				if nodeRec.NodeID == cfg.NodeID {
					continue
				}
				addSyncTarget(targets, cfg.AdvertiseAddr, nodeRec.Address)
			}
		}

		nodes, _ := cfg.Registry.Snapshot()
		for _, nodeRec := range nodes {
			if nodeRec.NodeID == cfg.NodeID {
				continue
			}
			addSyncTarget(targets, cfg.AdvertiseAddr, nodeRec.Address)
		}
	}

	return reachable
}

type syncResult struct {
	addr     string
	records  []record.EndpointRecord
	services []record.ServiceRecord
	peer     *record.EndpointRecord
	nodeID   string
	err      error
}

func syncTargetBatch(ctx context.Context, log io.Writer, cfg Config, rec *record.EndpointRecord, targets []string) []syncResult {
	results := make([]syncResult, 0, len(targets))
	if len(targets) == 0 {
		return results
	}

	sem := make(chan struct{}, syncParallelTargets)
	resultsCh := make(chan syncResult, len(targets))
	var wg sync.WaitGroup

	for _, addr := range targets {
		addr := addr
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				resultsCh <- syncResult{addr: addr, err: ctx.Err()}
				return
			}
			defer func() { <-sem }()
			resultsCh <- syncTarget(ctx, log, cfg, rec, addr)
		}()
	}

	wg.Wait()
	close(resultsCh)

	for result := range resultsCh {
		results = append(results, result)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].addr < results[j].addr
	})
	return results
}

func syncTarget(ctx context.Context, log io.Writer, cfg Config, rec *record.EndpointRecord, addr string) syncResult {
	result := syncResult{addr: addr}
	if addr == "" {
		return result
	}
	if cfg.DHT != nil && cfg.DHT.RT != nil {
		if candidate, ok := cfg.DHT.RT.NodeByAddress(addr); ok {
			result.nodeID = candidate.ID
		}
	}
	peer, known := endpointRecordByAddress(cfg, addr)
	wantIdentity := !known
	var identityRecord *record.EndpointRecord
	var err error
	if wantIdentity {
		if rec == nil {
			result.err = fmt.Errorf("first contact requires this node's signed endpoint identity")
			return result
		}
		identityRecord, _, err = liveness.ExchangeIdentity(ctx, addr, *rec, syncProbeTimeout)
	} else {
		identityRecord, _, err = liveness.Probe(ctx, addr, false, syncProbeTimeout)
	}
	if err != nil {
		fmt.Fprintf(log, "[SYNC] Skipping target without a VX6 PONG: %s: %v\n", addr, err)
		result.err = fmt.Errorf("VX6 liveness probe failed: %w", err)
		if known {
			result.nodeID = peer.NodeID
		}
		return result
	}
	if !known {
		if identityRecord == nil {
			result.err = fmt.Errorf("peer answered liveness probe without an identity record")
			return result
		}
		if err := record.VerifyEndpointRecord(*identityRecord, time.Now()); err != nil {
			result.err = fmt.Errorf("peer supplied an invalid signed identity record: %w", err)
			return result
		}
		if identityRecord.Address != addr {
			result.err = fmt.Errorf("peer identity endpoint %s does not match contacted endpoint %s", identityRecord.Address, addr)
			return result
		}
		peer = *identityRecord
	}
	result.nodeID = peer.NodeID
	result.peer = &peer
	if cfg.IPsecTunnel == nil {
		result.err = fmt.Errorf("IPsec peer verifier is unavailable")
		return result
	}
	if err := cfg.IPsecTunnel.EnsurePeer(ctx, peer); err != nil {
		result.err = fmt.Errorf("IKE/IPsec peer authentication failed: %w", err)
		return result
	}
	if cfg.livenessCache != nil {
		cfg.livenessCache.MarkAlive(addr, time.Now())
	}
	protectedCtx := vxtransport.WithDialGuard(ctx, func(_ context.Context, target string) error {
		if target != addr {
			return fmt.Errorf("tunnel liveness context cannot dial unverified endpoint %s", target)
		}
		return nil
	})
	if err := liveness.TunnelPing(protectedCtx, cfg.TransportMode, addr, syncProbeTimeout); err != nil {
		result.err = fmt.Errorf("authenticated IPsec tunnel health check failed: %w", err)
		return result
	}

	fmt.Fprintf(log, "[SYNC] Connecting to target: %s\n", addr)
	if rec != nil && !cfg.HideEndpoint {
		publishCtx, cancel := withSyncTimeout(protectedCtx)
		_, err := discovery.Publish(publishCtx, addr, *rec)
		cancel()
		if err != nil {
			fmt.Fprintf(log, "[SYNC] Publish to %s failed: %v\n", addr, err)
			result.err = fmt.Errorf("publish signed endpoint update: %w", err)
			return result
		}
	}

	snapshotCtx, cancel := withSyncTimeout(protectedCtx)
	recs, svcs, err := discovery.Snapshot(snapshotCtx, addr)
	cancel()
	if err != nil {
		fmt.Fprintf(log, "[SYNC] Snapshot from %s failed: %v\n", addr, err)
		result.err = err
		return result
	}

	result.records = recs
	result.services = svcs
	fmt.Fprintf(log, "[SYNC] Successfully linked with %s. Received %d records.\n", addr, len(recs)+len(svcs))
	return result
}

func publishServicesToTargets(ctx context.Context, cfg Config, log io.Writer, targets map[string]struct{}, serviceRecords []record.ServiceRecord) {
	for _, addr := range pendingSyncTargets(targets, nil) {
		for _, srec := range serviceRecords {
			if srec.IsPrivate || srec.IsHidden {
				continue
			}
			publishCtx, cancel := withSyncTimeout(ctx)
			_, err := discovery.PublishService(publishCtx, addr, srec)
			cancel()
			if err != nil {
				fmt.Fprintf(log, "[SYNC] Service publish to %s failed: %v\n", addr, err)
			}
		}
	}
}

func publishRecordsToTargets(ctx context.Context, cfg Config, log io.Writer, targets map[string]struct{}, rec record.EndpointRecord, serviceRecords []record.ServiceRecord) {
	for _, addr := range pendingSyncTargets(targets, nil) {
		if !cfg.HideEndpoint {
			publishCtx, cancel := withSyncTimeout(ctx)
			_, err := discovery.Publish(publishCtx, addr, rec)
			cancel()
			if err != nil {
				fmt.Fprintf(log, "[SYNC] Publish to %s failed: %v\n", addr, err)
			}
		}
		for _, srec := range serviceRecords {
			if srec.IsPrivate || srec.IsHidden {
				continue
			}
			publishCtx, cancel := withSyncTimeout(ctx)
			_, err := discovery.PublishService(publishCtx, addr, srec)
			cancel()
			if err != nil {
				fmt.Fprintf(log, "[SYNC] Service publish to %s failed: %v\n", addr, err)
			}
		}
	}
}

func pendingSyncTargets(targets map[string]struct{}, synced map[string]struct{}) []string {
	out := make([]string, 0, len(targets))
	for addr := range targets {
		if addr == "" {
			continue
		}
		if synced != nil {
			if _, ok := synced[addr]; ok {
				continue
			}
		}
		out = append(out, addr)
	}
	sort.Strings(out)
	return out
}

func addSyncTarget(targets map[string]struct{}, selfAddr, addr string) {
	if addr == "" || addr == selfAddr {
		return
	}
	targets[addr] = struct{}{}
}

func endpointRecordByAddress(cfg Config, addr string) (record.EndpointRecord, bool) {
	for _, candidate := range registryRecords(cfg.Registry, cfg.DHT) {
		if candidate.Address == addr {
			return candidate, true
		}
	}
	return record.EndpointRecord{}, false
}

func withSyncTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, syncTargetTimeout)
}

func runtimeConfig(base Config) Config {
	live := base
	if base.ConfigPath == "" {
		if len(live.Services) == 0 && base.RefreshServices != nil {
			live.Services = base.RefreshServices()
		}
		if updated, _, err := netutil.RefreshAdvertiseAddressWithAddrsAndTargets(live.AdvertiseAddr, live.ListenAddr, currentInterfaceAddrs(), advertiseTargets(live), live.AdvertiseExplicit); err == nil {
			live.AdvertiseAddr = updated
		}
		return live
	}

	store, err := config.NewStore(base.ConfigPath)
	if err != nil {
		return live
	}
	cfgFile, err := store.Load()
	if err != nil {
		return live
	}

	if cfgFile.Node.Name != "" {
		live.Name = cfgFile.Node.Name
	}
	if cfgFile.Node.AdvertiseAddr != "" {
		live.AdvertiseAddr = cfgFile.Node.AdvertiseAddr
	}
	live.AdvertiseExplicit = cfgFile.Node.AdvertiseAddr != ""
	live.TransportMode = cfgFile.Node.TransportMode
	live.HideEndpoint = cfgFile.Node.HideEndpoint
	live.RelayMode = cfgFile.Node.RelayMode
	live.RelayResourcePercent = cfgFile.Node.RelayResourcePercent
	live.MaxConcurrentConns = cfgFile.Node.MaxConcurrentConns
	live.PeerAddrs = config.ConfiguredPeerAddresses(cfgFile)
	live.FileReceiveMode = cfgFile.Node.FileReceiveMode
	live.AllowedFileSenders = append([]string(nil), cfgFile.Node.AllowedFileSenders...)
	live.Services = serviceTargets(cfgFile.Services)
	if len(live.Services) == 0 && base.RefreshServices != nil {
		live.Services = base.RefreshServices()
	}
	live.ReceiveDir = cfgFile.Node.DownloadDir
	if updated, _, err := netutil.RefreshAdvertiseAddressWithAddrsAndTargets(live.AdvertiseAddr, live.ListenAddr, currentInterfaceAddrs(), advertiseTargets(live), live.AdvertiseExplicit); err == nil {
		live.AdvertiseAddr = updated
	}
	return live
}

type runtimePeerTunnel struct {
	identity identity.Identity
	address  func() string
	client   func(string, identity.Identity) (PeerTunnel, error)
}

func (t runtimePeerTunnel) withClient(run func(PeerTunnel) error) error {
	address := t.address()
	if address == "" {
		return errors.New("no current local IPv6 endpoint is available for IPsec")
	}
	client, err := t.client(address, t.identity)
	if err != nil {
		return fmt.Errorf("initialize IPsec control client for %s: %w", address, err)
	}
	return run(client)
}

func (t runtimePeerTunnel) PreparePeer(ctx context.Context, peer record.EndpointRecord) error {
	return t.withClient(func(client PeerTunnel) error { return client.PreparePeer(ctx, peer) })
}

func (t runtimePeerTunnel) EnsurePeer(ctx context.Context, peer record.EndpointRecord) error {
	return t.withClient(func(client PeerTunnel) error { return client.EnsurePeer(ctx, peer) })
}

func (t runtimePeerTunnel) RegisterProbePort(ctx context.Context, port string) error {
	return t.withClient(func(client PeerTunnel) error { return client.RegisterProbePort(ctx, port) })
}

func (t runtimePeerTunnel) AuthenticatePeer(ctx context.Context, remote string) (record.EndpointRecord, bool) {
	var peer record.EndpointRecord
	var authenticated bool
	err := t.withClient(func(client PeerTunnel) error {
		peer, authenticated = client.AuthenticatePeer(ctx, remote)
		return nil
	})
	return peer, authenticated && err == nil
}

func currentIPsecLocalAddress(cfg Config) string {
	updated, _, err := netutil.RefreshAdvertiseAddressWithAddrsAndTargets(
		cfg.AdvertiseAddr,
		cfg.ListenAddr,
		currentInterfaceAddrs(),
		advertiseTargets(cfg),
		cfg.AdvertiseExplicit,
	)
	if err == nil && updated != "" {
		return updated
	}
	return cfg.AdvertiseAddr
}

func runtimeServices(base Config) map[string]string {
	return runtimeConfig(base).Services
}

func runtimeServicePolicies(base Config) map[string]serviceproxy.ServicePolicy {
	if base.RefreshServicePolicies != nil {
		if policies := base.RefreshServicePolicies(); policies != nil {
			return policies
		}
	}
	if base.ServicePolicies != nil {
		return base.ServicePolicies
	}
	policies := make(map[string]serviceproxy.ServicePolicy, len(base.Services))
	for name, target := range base.Services {
		policies[name] = serviceproxy.ServicePolicy{Target: target, Protocol: record.ServiceProtocolTCP}
	}
	return policies
}

func persistKnownPeerMetadata(configPath string, records []record.EndpointRecord) {
	if configPath == "" || len(records) == 0 {
		return
	}
	store, err := config.NewStore(configPath)
	if err != nil {
		return
	}
	for _, rec := range records {
		if rec.NodeID == "" || rec.NodeName == "" || rec.Address == "" {
			continue
		}
		_ = store.UpsertKnownPeerRecord(rec)
	}
}

func fileReceivePolicy(cfg Config) transfer.ReceivePolicy {
	allowed := make(map[string]struct{}, len(cfg.AllowedFileSenders))
	for _, sender := range cfg.AllowedFileSenders {
		allowed[sender] = struct{}{}
	}
	return transfer.ReceivePolicy{
		Mode:           cfg.FileReceiveMode,
		AllowedSenders: allowed,
	}
}

func serviceTargets(entries map[string]config.ServiceEntry) map[string]string {
	out := make(map[string]string, len(entries))
	for name, entry := range entries {
		out[name] = entry.Target
	}
	return out
}

func refreshAdvertiseAddress(log io.Writer, cfg Config) Config {
	updated, changed, err := netutil.RefreshAdvertiseAddressWithAddrsAndTargets(cfg.AdvertiseAddr, cfg.ListenAddr, currentInterfaceAddrs(), advertiseTargets(cfg), cfg.AdvertiseExplicit)
	if err != nil || updated == "" {
		return cfg
	}
	if changed {
		if cfg.AdvertiseAddr == "" {
			fmt.Fprintf(log, "auto-detected advertise address %s\n", updated)
		} else {
			fmt.Fprintf(log, "advertise address updated from %s to %s\n", cfg.AdvertiseAddr, updated)
		}
	}
	cfg.AdvertiseAddr = updated
	return cfg
}

func advertiseTargets(cfg Config) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(cfg.PeerAddrs)+8)
	add := func(addr string) {
		if addr == "" || addr == cfg.ListenAddr {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	for _, addr := range cfg.PeerAddrs {
		add(addr)
	}
	if cfg.Registry != nil {
		nodes, _ := cfg.Registry.Snapshot()
		for _, rec := range nodes {
			add(rec.Address)
		}
	}
	return out
}

func currentInterfaceAddrs() []net.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	return addrs
}

func defaultReceiveDir(dataDir string) string {
	if path, err := config.DefaultDownloadDir(); err == nil {
		return path
	}
	if dataDir != "" {
		return dataDir
	}
	return filepath.Join(".", "Downloads")
}
