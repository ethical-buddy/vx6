// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/hidden"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/node"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/transfer"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

// Client exposes VX6 protocol capabilities for app/tool developers.
// It keeps protocol behavior aligned with the built-in CLI implementation.
type Client struct {
	store *config.Store
}

type InitOptions struct {
	Name            string
	ListenAddr      string
	AdvertiseAddr   string
	TransportMode   string
	HideEndpoint    bool
	RelayMode       string
	RelayPercent    int
	DataDir         string
	DownloadsDir    string
	Peers           []string
	FileReceiveMode string
}

type StartOptions struct {
	Name         string
	ListenAddr   string
	DataDir      string
	DownloadsDir string
}

// New creates an SDK client. If configPath is empty, default VX6 path is used.
func New(configPath string) (*Client, error) {
	store, err := config.NewStore(configPath)
	if err != nil {
		return nil, err
	}
	return &Client{store: store}, nil
}

func (c *Client) ConfigPath() string {
	return c.store.Path()
}

func (c *Client) Init(ctx context.Context, opts InitOptions) (identity.Identity, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return identity.Identity{}, errors.New("init requires non-empty name")
	}
	if err := record.ValidateNodeName(opts.Name); err != nil {
		return identity.Identity{}, err
	}

	listen := opts.ListenAddr
	if listen == "" {
		listen = "[::]:4242"
	}
	if err := transfer.ValidateIPv6Address(listen); err != nil {
		return identity.Identity{}, fmt.Errorf("invalid listen address: %w", err)
	}
	if strings.TrimSpace(opts.AdvertiseAddr) != "" {
		if err := transfer.ValidateIPv6Address(opts.AdvertiseAddr); err != nil {
			return identity.Identity{}, fmt.Errorf("invalid advertise address: %w", err)
		}
	}
	for _, p := range opts.Peers {
		if err := transfer.ValidateIPv6Address(p); err != nil {
			return identity.Identity{}, fmt.Errorf("invalid peer address %q: %w", p, err)
		}
	}

	cfg, err := c.store.Load()
	if err != nil {
		return identity.Identity{}, err
	}
	cfg.Node.Name = opts.Name
	cfg.Node.ListenAddr = listen
	cfg.Node.AdvertiseAddr = strings.TrimSpace(opts.AdvertiseAddr)
	cfg.Node.HideEndpoint = opts.HideEndpoint

	mode := vxtransport.NormalizeMode(opts.TransportMode)
	if mode == "" {
		mode = vxtransport.ModeAuto
	}
	cfg.Node.TransportMode = mode
	relayMode := config.NormalizeRelayMode(opts.RelayMode)
	if relayMode == "" {
		relayMode = config.RelayModeOn
	}
	cfg.Node.RelayMode = relayMode
	cfg.Node.RelayResourcePercent = config.NormalizeRelayResourcePercent(opts.RelayPercent)
	if opts.FileReceiveMode != "" {
		cfg.Node.FileReceiveMode = config.NormalizeFileReceiveMode(opts.FileReceiveMode)
	}
	if opts.DataDir != "" {
		cfg.Node.DataDir = opts.DataDir
	}
	if opts.DownloadsDir != "" {
		cfg.Node.DownloadDir = opts.DownloadsDir
	}
	if len(opts.Peers) > 0 {
		cfg.Node.KnownPeers = nil
		cfg.Node.KnownPeerAddrs = append([]string(nil), opts.Peers...)
		cfg.Node.Bootstraps = nil
		cfg.Node.BootstrapAddrs = nil
	}

	idStore, err := identity.NewStoreForConfig(c.store.Path())
	if err != nil {
		return identity.Identity{}, err
	}
	id, _, err := idStore.Ensure()
	if err != nil {
		return identity.Identity{}, err
	}

	// Lightweight distributed clash probe before accepting the name.
	if err := c.waitForNameAvailability(ctx, cfg, opts.Name, id.NodeID, 10*time.Second); err != nil {
		return identity.Identity{}, err
	}

	if err := c.store.Save(cfg); err != nil {
		return identity.Identity{}, err
	}
	return id, nil
}

func (c *Client) StartNode(ctx context.Context, log io.Writer, opts StartOptions) error {
	cfgFile, err := c.store.Load()
	if err != nil {
		return err
	}
	idStore, err := identity.NewStoreForConfig(c.store.Path())
	if err != nil {
		return err
	}
	id, err := idStore.Load()
	if err != nil {
		return err
	}

	name := opts.Name
	if name == "" {
		name = cfgFile.Node.Name
	}
	listenAddr := opts.ListenAddr
	if listenAddr == "" {
		listenAddr = cfgFile.Node.ListenAddr
	}
	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir = cfgFile.Node.DataDir
	}
	downloads := opts.DownloadsDir
	if downloads == "" {
		downloads = cfgFile.Node.DownloadDir
	}

	services := make(map[string]string, len(cfgFile.Services))
	for name, svc := range cfgFile.Services {
		services[name] = svc.Target
	}
	registry, err := discovery.NewRegistry(filepath.Join(dataDir, "registry.json"))
	if err != nil {
		return err
	}
	controlInfoPath, err := config.RuntimeControlPath(c.store.Path())
	if err != nil {
		return err
	}

	runCfg := node.Config{
		Name:                 name,
		NodeID:               id.NodeID,
		ListenAddr:           listenAddr,
		AdvertiseAddr:        cfgFile.Node.AdvertiseAddr,
		AdvertiseExplicit:    cfgFile.Node.AdvertiseAddr != "",
		TransportMode:        cfgFile.Node.TransportMode,
		HideEndpoint:         cfgFile.Node.HideEndpoint,
		RelayMode:            cfgFile.Node.RelayMode,
		RelayResourcePercent: cfgFile.Node.RelayResourcePercent,
		DataDir:              dataDir,
		ReceiveDir:           downloads,
		ConfigPath:           c.store.Path(),
		ControlInfoPath:      controlInfoPath,
		Identity:             id,
		FileReceiveMode:      cfgFile.Node.FileReceiveMode,
		AllowedFileSenders:   append([]string(nil), cfgFile.Node.AllowedFileSenders...),
		DHT:                  dht.NewServerWithIdentity(id),
		PeerAddrs:            config.ConfiguredPeerAddresses(cfgFile),
		Services:             services,
		Registry:             registry,
		Reload:               make(chan struct{}, 1),
		RefreshServices: func() map[string]string {
			cf, err := c.store.Load()
			if err != nil {
				return nil
			}
			out := make(map[string]string, len(cf.Services))
			for k, v := range cf.Services {
				out[k] = v.Target
			}
			return out
		},
	}
	return node.Run(ctx, log, runCfg)
}

func (c *Client) AddPeer(name, addr string) error {
	if name == "" {
		return c.store.AddKnownPeerAddress(addr)
	}
	return c.store.AddPeer(name, addr)
}

func (c *Client) AddService(name string, entry config.ServiceEntry) error {
	return c.store.SetService(name, entry)
}

func (c *Client) RemoveService(name string) error {
	return c.store.RemoveService(name)
}

func (c *Client) ListServices() (map[string]config.ServiceEntry, error) {
	cfg, err := c.store.Load()
	if err != nil {
		return nil, err
	}
	out := make(map[string]config.ServiceEntry, len(cfg.Services))
	for k, v := range cfg.Services {
		out[k] = v
	}
	return out, nil
}

func (c *Client) ResolveService(ctx context.Context, service string) (record.ServiceRecord, error) {
	cfg, err := c.store.Load()
	if err != nil {
		return record.ServiceRecord{}, err
	}
	// local registry first
	if reg, err := discovery.NewRegistry(filepath.Join(cfg.Node.DataDir, "registry.json")); err == nil {
		if rec, err := reg.ResolveServiceLocal(service); err == nil {
			return rec, nil
		}
	}

	client, err := c.newDHTClient(cfg)
	if err == nil && client != nil {
		if strings.Contains(service, ".") {
			result, err := client.RecursiveFindValueDetailed(ctx, dht.ServiceKey(service))
			if err == nil && result.Value != "" {
				var rec record.ServiceRecord
				if json.Unmarshal([]byte(result.Value), &rec) == nil && record.VerifyServiceRecord(rec, time.Now()) == nil {
					return rec, nil
				}
			}
		} else {
			if rec, err := client.ResolveHiddenService(ctx, service, time.Now()); err == nil {
				return rec, nil
			}
		}
	}

	for _, addr := range config.ConfiguredPeerAddresses(cfg) {
		rec, err := discovery.ResolveService(ctx, addr, service)
		if err == nil {
			return rec, nil
		}
	}
	return record.ServiceRecord{}, errors.New("service not found")
}

func (c *Client) newDHTClient(cfg config.File) (*dht.Server, error) {
	_, _ = dht.ConfigureASNResolver(c.store.Path())
	client := dht.NewServer("sdk-observer")
	var registryNodes []record.EndpointRecord

	for _, addr := range config.ConfiguredPeerAddresses(cfg) {
		if addr != "" {
			client.RT.AddNode(proto.NodeInfo{ID: "seed:" + addr, Addr: addr})
		}
	}
	if registry, err := discovery.NewRegistry(filepath.Join(cfg.Node.DataDir, "registry.json")); err == nil {
		nodes, _ := registry.Snapshot()
		registryNodes = append(registryNodes, nodes...)
		for _, rec := range nodes {
			if rec.NodeID != "" && rec.Address != "" {
				client.RT.AddNode(proto.NodeInfo{ID: rec.NodeID, Addr: rec.Address})
			}
		}
	}
	client.SetHiddenDescriptorPrivacy(dht.HiddenDescriptorPrivacyConfig{
		TransportMode: cfg.Node.TransportMode,
		RelayHopCount: 3,
		RelayCandidates: func() []record.EndpointRecord {
			return append([]record.EndpointRecord(nil), registryNodes...)
		},
		ExcludeAddrs: func() []string {
			exclude := make([]string, 0, 2)
			if cfg.Node.AdvertiseAddr != "" {
				exclude = append(exclude, cfg.Node.AdvertiseAddr)
			}
			if cfg.Node.ListenAddr != "" && cfg.Node.ListenAddr != cfg.Node.AdvertiseAddr {
				exclude = append(exclude, cfg.Node.ListenAddr)
			}
			return exclude
		},
	})
	return client, nil
}

func (c *Client) waitForNameAvailability(ctx context.Context, cfg config.File, name, ownNodeID string, wait time.Duration) error {
	client, err := c.newDHTClient(cfg)
	if err != nil || client == nil {
		return nil
	}
	deadline := time.Now().Add(wait)
	for {
		result, err := client.RecursiveFindValueDetailed(ctx, dht.NodeNameKey(name))
		if err == nil && result.Value != "" {
			var rec record.EndpointRecord
			if json.Unmarshal([]byte(result.Value), &rec) == nil && rec.NodeID != ownNodeID {
				return fmt.Errorf("node name %q is already in use", name)
			}
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func NormalizeHiddenServiceEntry(entry config.ServiceEntry) (config.ServiceEntry, error) {
	if entry.IsPrivate && entry.IsHidden {
		return entry, errors.New("service cannot be both hidden and private")
	}
	if !entry.IsHidden {
		entry.Alias = ""
		entry.HiddenLookupSecret = ""
		entry.HiddenProfile = ""
		entry.IntroMode = ""
		entry.IntroNodes = nil
		return entry, nil
	}
	if entry.Alias == "" {
		return entry, errors.New("hidden service requires alias")
	}
	if entry.HiddenLookupSecret == "" {
		secret, err := dht.NewHiddenLookupSecret()
		if err != nil {
			return entry, err
		}
		entry.HiddenLookupSecret = secret
	}
	entry.HiddenProfile = record.NormalizeHiddenProfile(entry.HiddenProfile)
	if entry.HiddenProfile == "" {
		entry.HiddenProfile = "fast"
	}
	entry.IntroMode = hidden.NormalizeIntroMode(entry.IntroMode)
	if entry.IntroMode == "" {
		if len(entry.IntroNodes) > 0 {
			entry.IntroMode = hidden.IntroModeManual
		} else {
			entry.IntroMode = hidden.IntroModeRandom
		}
	}
	return entry, nil
}
