package node

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/vx6/vx6/internal/netutil"
	"github.com/vx6/vx6/internal/onion"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/runtimectl"
	"github.com/vx6/vx6/internal/secure"
	"github.com/vx6/vx6/internal/serviceproxy"
	"github.com/vx6/vx6/internal/transfer"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

const (
	syncCycleInterval   = 10 * time.Second
	syncWarmupInterval  = 2 * time.Second
	syncWarmupRounds    = 4
	syncTargetTimeout   = 2 * time.Second
	syncProbeTimeout    = 1 * time.Second
	syncMaxRounds       = 3
	syncParallelTargets = 6
	dhtRefreshLead      = 5 * time.Minute
	maxConcurrentConns  = 1024
)

type ServiceRefresher func() map[string]string

type Config struct {
	Name                 string
	NodeID               string
	ListenAddr           string
	AdvertiseAddr        string
	AdvertiseExplicit    bool
	TransportMode        string
	HideEndpoint         bool
	RelayMode            string
	RelayResourcePercent int
	DataDir              string
	ReceiveDir           string
	FileReceiveMode      string
	AllowedFileSenders   []string
	ConfigPath           string
	ControlInfoPath      string
	RefreshServices      ServiceRefresher
	PeerAddrs            []string
	Services             map[string]string
	Identity             identity.Identity
	Registry             *discovery.Registry
	DHT                  *dht.Server
	Reload               chan struct{}
}

func Run(ctx context.Context, log io.Writer, cfg Config) error {
	if cfg.Name == "" {
		return errors.New("node name cannot be empty")
	}
	if cfg.NodeID == "" {
		return errors.New("node id cannot be empty")
	}
	if cfg.Registry == nil {
		return errors.New("registry cannot be nil")
	}
	cfg = refreshAdvertiseAddress(log, cfg)
	if err := transfer.ValidateIPv6Address(cfg.ListenAddr); err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	if cfg.ReceiveDir == "" {
		cfg.ReceiveDir = defaultReceiveDir(cfg.DataDir)
	}
	if err := os.MkdirAll(cfg.ReceiveDir, 0o755); err != nil {
		return fmt.Errorf("create receive directory: %w", err)
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
	relayGovernor := newRelayGovernor(cfg.RelayMode, cfg.RelayResourcePercent)
	if cfg.ControlInfoPath != "" {
		controlServer, err := runtimectl.Start(cfg.ControlInfoPath, os.Getpid(), func() error {
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
	connSem := make(chan struct{}, maxConcurrentConns)

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

		select {
		case connSem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
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
			//bug: after listener.Accept() the goroutine immediately calls proto.ReadHeader(reader) with no timeout
			//a malicious peer can open thousands of tcp connections without sending data each holding a goroutine+file descriptor forever
			reader := bufio.NewReader(conn)
			//fix:add a read deadline immediately after the reader is created
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			kind, err := proto.ReadHeader(reader)
			//after successful read clear the deadline
			conn.SetReadDeadline(time.Time{})
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				fmt.Fprintf(log, "session error from %s: %v\n", conn.RemoteAddr().String(), err)
				return
			}
			liveCfg := runtimeConfig(cfg)
			relayGovernor.Update(liveCfg.RelayMode, liveCfg.RelayResourcePercent)

			switch kind {
			case proto.KindFileTransfer:
				secureConn, err := secure.Server(&bufferedConn{Conn: conn, reader: reader}, proto.KindFileTransfer, cfg.Identity)
				if err != nil {
					fmt.Fprintf(log, "secure receive error from %s: %v\n", conn.RemoteAddr().String(), err)
					return
				}
				res, err := transfer.ReceiveFileWithPolicy(secureConn, liveCfg.ReceiveDir, fileReceivePolicy(liveCfg))
				if err != nil {
					fmt.Fprintf(log, "receive error from %s: %v\n", conn.RemoteAddr().String(), err)
					return
				}
				absPath, pathErr := filepath.Abs(res.StoredPath)
				if pathErr != nil {
					absPath = res.StoredPath
				}
				fmt.Fprintf(log, "received %q (%d bytes) from node %q into %s\n", res.FileName, res.BytesReceived, res.SenderNode, absPath)
			case proto.KindDiscoveryReq:
				if err := cfg.Registry.HandleConn(&bufferedConn{Conn: conn, reader: reader}); err != nil {
					fmt.Fprintf(log, "discovery error from %s: %v\n", conn.RemoteAddr().String(), err)
					return
				}
				fmt.Fprintf(log, "processed discovery request from %s\n", conn.RemoteAddr().String())
			case proto.KindDHT:
				payload, err := proto.ReadLengthPrefixed(reader, 1024*1024)
				if err != nil {
					fmt.Fprintf(log, "dht read error from %s: %v\n", conn.RemoteAddr().String(), err)
					return
				}
				var dr proto.DHTRequest
				if err := json.Unmarshal(payload, &dr); err != nil {
					fmt.Fprintf(log, "dht decode error from %s: %v\n", conn.RemoteAddr().String(), err)
					return
				}
				if cfg.DHT != nil {
					if err := cfg.DHT.HandleDHT(ctx, conn, dr); err != nil {
						fmt.Fprintf(log, "dht error from %s: %v\n", conn.RemoteAddr().String(), err)
					}
				}
			case proto.KindExtend:
				release, err := relayGovernor.Acquire(kind)
				if err != nil {
					fmt.Fprintf(log, "relay admission denied for %s: %v\n", conn.RemoteAddr().String(), err)
					return
				}
				defer release()
				secureConn, err := secure.Server(&bufferedConn{Conn: conn, reader: reader}, proto.KindExtend, cfg.Identity)
				if err != nil {
					fmt.Fprintf(log, "extend secure handshake error from %s: %v\n", conn.RemoteAddr().String(), err)
					return
				}
				if err := onion.HandleExtend(ctx, secureConn, cfg.Identity); err != nil {
					fmt.Fprintf(log, "extend error from %s: %v\n", conn.RemoteAddr().String(), err)
				}
			case proto.KindRendezvous:
				release, err := relayGovernor.Acquire(kind)
				if err != nil {
					fmt.Fprintf(log, "relay admission denied for %s: %v\n", conn.RemoteAddr().String(), err)
					return
				}
				defer release()
				liveServices := liveCfg.Services
				if err := hidden.HandleConn(ctx, &bufferedConn{Conn: conn, reader: reader}, hidden.HandlerConfig{
					Identity:      cfg.Identity,
					AdvertiseAddr: liveCfg.AdvertiseAddr,
					TransportMode: liveCfg.TransportMode,
					Services:      liveServices,
					HiddenAliases: hiddenAliasMap(cfg.ConfigPath),
					Registry:      cfg.Registry,
				}); err != nil {
					fmt.Fprintf(log, "hidden service error from %s: %v\n", conn.RemoteAddr().String(), err)
				}
			case proto.KindServiceConn:
				if err := serviceproxy.HandleInbound(&bufferedConn{Conn: conn, reader: reader}, cfg.Identity, runtimeServices(cfg)); err != nil {
					fmt.Fprintf(log, "service proxy error from %s: %v\n", conn.RemoteAddr().String(), err)
				}
			default:
				fmt.Fprintf(log, "session error from %s: unsupported kind %d\n", conn.RemoteAddr().String(), kind)
			}
		}()
	}
}

func endpointPublishMode(hidden bool) string {
	if hidden {
		return "hidden"
	}
	return "published"
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
	const multicastAddr = "[ff02::1]:4243"
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
			if err := json.Unmarshal(buf[:n], &info); err == nil && info.ID != cfg.NodeID {
				rec := record.EndpointRecord{NodeID: info.ID, NodeName: info.Name, Address: info.Addr}
				_ = cfg.Registry.Import([]record.EndpointRecord{rec}, nil)
			}
		}
	}()

	ticker := time.NewTicker(15 * time.Second)
	data, _ := json.Marshal(proto.NodeInfo{ID: cfg.NodeID, Name: cfg.Name, Addr: cfg.AdvertiseAddr})
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = conn.WriteToUDP(data, addr)
		}
	}
}

func runPeerSyncTasks(ctx context.Context, log io.Writer, cfg Config) {
	syncOnlyLogged := false

	publishAndSync := func() {
		liveCfg := runtimeConfig(cfg)
		var (
			rec           record.EndpointRecord
			endpointReady bool
		)
		if liveCfg.AdvertiseAddr != "" {
			var err error
			rec, err = record.NewEndpointRecord(liveCfg.Identity, liveCfg.Name, liveCfg.AdvertiseAddr, 20*time.Minute, time.Now())
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
		seedDHTRouting(liveCfg.DHT, liveCfg.PeerAddrs, nodes)
		targets := syncMesh(ctx, log, liveCfg, endpointRecordRef(endpointReady, rec), nodes)

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
		if err := json.Unmarshal([]byte(result.Value), &rec); err == nil && rec.NodeName == cfg.Name {
			candidates = append(candidates, rec)
		}
	}
	for _, raw := range result.ConflictValues {
		var rec record.EndpointRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
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

func seedDHTRouting(server *dht.Server, seedAddrs []string, records []record.EndpointRecord) {
	if server == nil {
		return
	}

	for _, addr := range seedAddrs {
		if addr == "" {
			continue
		}
		server.RT.AddNode(proto.NodeInfo{ID: "seed:" + addr, Addr: addr})
	}
	for _, rec := range records {
		if rec.NodeID == "" || rec.Address == "" {
			continue
		}
		server.RT.AddNode(proto.NodeInfo{ID: rec.NodeID, Addr: rec.Address})
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

func syncMesh(ctx context.Context, log io.Writer, cfg Config, rec *record.EndpointRecord, initialNodes []record.EndpointRecord) map[string]struct{} {
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

		results := syncTargetBatch(ctx, log, cfg, rec, pending)
		for _, result := range results {
			synced[result.addr] = struct{}{}
			if result.err != nil {
				continue
			}
			reachable[result.addr] = struct{}{}
			_ = cfg.Registry.Import(result.records, result.services)
			seedDHTRouting(cfg.DHT, nil, result.records)
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

	if !probeSyncTarget(ctx, addr) {
		fmt.Fprintf(log, "[SYNC] Skipping unreachable target: %s\n", addr)
		result.err = fmt.Errorf("unreachable")
		return result
	}

	fmt.Fprintf(log, "[SYNC] Connecting to target: %s\n", addr)
	if rec != nil && !cfg.HideEndpoint {
		publishCtx, cancel := withSyncTimeout(ctx)
		_, err := discovery.Publish(publishCtx, addr, *rec)
		cancel()
		if err != nil {
			fmt.Fprintf(log, "[SYNC] Publish to %s failed: %v\n", addr, err)
		}
	}

	snapshotCtx, cancel := withSyncTimeout(ctx)
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

func probeSyncTarget(ctx context.Context, addr string) bool {
	dialCtx, cancel := context.WithTimeout(ctx, syncProbeTimeout)
	defer cancel()
	return vxtransport.ProbeContext(dialCtx, vxtransport.ModeTCP, addr)
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

func runtimeServices(base Config) map[string]string {
	return runtimeConfig(base).Services
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
