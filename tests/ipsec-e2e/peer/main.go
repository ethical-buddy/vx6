package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/node"
	"github.com/vx6/vx6/internal/record"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}
	idStore, err := identity.NewStoreForConfig(store.Path())
	if err != nil {
		return err
	}
	id, err := idStore.Load()
	if err != nil {
		return err
	}
	registry, err := discovery.NewRegistry(filepath.Join(cfg.Node.DataDir, "registry.json"))
	if err != nil {
		return err
	}
	peers := make([]record.EndpointRecord, 0, len(cfg.Node.KnownPeers))
	for _, peer := range cfg.Node.KnownPeers {
		endpoint := record.EndpointRecord{
			NodeID: peer.NodeID, NodeName: peer.NodeName, Address: peer.Address,
			PublicKey: peer.PublicKey, IssuedAt: peer.IdentityIssuedAt,
			ExpiresAt: peer.IdentityExpiresAt, Signature: peer.IdentitySignature,
		}
		if err := record.VerifyEndpointRecord(endpoint, time.Now()); err != nil {
			return fmt.Errorf("invalid signed test peer %s: %w", endpoint.NodeID, err)
		}
		peers = append(peers, endpoint)
	}
	if err := registry.Import(peers, nil); err != nil {
		return err
	}
	services := make(map[string]string, len(cfg.Services))
	for name, service := range cfg.Services {
		services[name] = service.Target
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return node.Run(ctx, os.Stdout, node.Config{
		Name: cfg.Node.Name, NodeID: id.NodeID, ListenAddr: cfg.Node.ListenAddr,
		AdvertiseAddr: cfg.Node.AdvertiseAddr, AdvertiseExplicit: cfg.Node.AdvertiseAddr != "",
		TransportMode: cfg.Node.TransportMode, RelayMode: cfg.Node.RelayMode,
		RelayResourcePercent: cfg.Node.RelayResourcePercent, DataDir: cfg.Node.DataDir,
		ReceiveDir: cfg.Node.DownloadDir, FileReceiveMode: cfg.Node.FileReceiveMode,
		AllowedFileSenders: cfg.Node.AllowedFileSenders, Identity: id,
		Registry: registry, Services: services,
	})
}
