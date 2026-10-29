package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/ipsec"
	"github.com/vx6/vx6/internal/node"
	"github.com/vx6/vx6/internal/record"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

func main() {
	if len(os.Args) == 3 && (os.Args[1] == "ensure-peer" || os.Args[1] == "prepare-peer" || os.Args[1] == "guarded-dial") {
		if err := setupPeer(os.Args[1], os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func setupPeer(action, recordPath string) error {
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
	data, err := os.ReadFile(recordPath)
	if err != nil {
		return err
	}
	var peer record.EndpointRecord
	if err := json.Unmarshal(data, &peer); err != nil {
		return fmt.Errorf("decode expected peer record: %w", err)
	}
	if err := record.VerifyEndpointRecord(peer, time.Now()); err != nil {
		return fmt.Errorf("verify expected peer record: %w", err)
	}
	if cfg.Node.AdvertiseAddr == "" {
		return fmt.Errorf("test peer needs an explicit advertised IPv6 address")
	}
	tunnel, err := ipsec.NewClient(ipsec.DefaultSocket(), cfg.Node.AdvertiseAddr, id)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if action == "ensure-peer" {
		if err := tunnel.EnsurePeer(ctx, peer); err != nil {
			return err
		}
	} else if action == "guarded-dial" {
		guardedCtx := vxtransport.WithDialGuard(ctx, func(ctx context.Context, addr string) error {
			if addr != peer.Address {
				return fmt.Errorf("unexpected guarded endpoint %s", addr)
			}
			return tunnel.EnsurePeer(ctx, peer)
		})
		conn, err := vxtransport.DialContext(guardedCtx, vxtransport.ModeTCP, peer.Address)
		if err == nil {
			_ = conn.Close()
			return fmt.Errorf("unexpectedly opened VX6 application socket to %s", peer.Address)
		}
		if !strings.Contains(err.Error(), "IPsec peer gate rejected") {
			return fmt.Errorf("dial failed outside the IPsec peer gate: %w", err)
		}
		return err
	} else if err := tunnel.PreparePeer(ctx, peer); err != nil {
		return err
	}
	fmt.Printf("peer_%s\t%s\n", strings.TrimSuffix(action, "-peer"), peer.NodeID)
	return nil
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
