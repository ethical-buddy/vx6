package sdk

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/ipsec"
	"github.com/vx6/vx6/internal/netutil"
	"github.com/vx6/vx6/internal/record"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

func (c *Client) peerDialGuard(cfg config.File, id identity.Identity, registry *discovery.Registry, routing *dht.RoutingTable) (vxtransport.DialGuard, error) {
	localAddress := cfg.Node.AdvertiseAddr
	if localAddress == "" {
		_, port, err := net.SplitHostPort(cfg.Node.ListenAddr)
		if err != nil {
			return nil, fmt.Errorf("resolve local IPv6 endpoint for IPsec: %w", err)
		}
		localAddress, err = netutil.DetectAdvertiseAddress(port)
		if err != nil {
			return nil, err
		}
	}
	tunnel, err := ipsec.NewClient(ipsec.DefaultSocket(), localAddress, id)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, address string) error {
		if registry != nil {
			nodes, _ := registry.Snapshot()
			for _, peer := range nodes {
				if peer.Address == address && record.VerifyEndpointRecord(peer, time.Now()) == nil {
					return tunnel.EnsurePeer(ctx, peer)
				}
			}
		}
		if routing != nil {
			info, ok := routing.NodeByAddress(address)
			if ok && dht.VerifyNodeInfo(info, time.Now()) == nil {
				peer := record.EndpointRecord{
					NodeID: info.ID, NodeName: info.Name, Address: info.Addr,
					PublicKey: info.PublicKey, IssuedAt: info.IdentityIssuedAt,
					ExpiresAt: info.IdentityExpiresAt, Signature: info.IdentitySignature,
				}
				return tunnel.EnsurePeer(ctx, peer)
			}
		}
		return fmt.Errorf("no verified signed peer identity for endpoint %s", address)
	}, nil
}

func (c *Client) guardedPeerContext(ctx context.Context, cfg config.File, id identity.Identity, registry *discovery.Registry) (context.Context, error) {
	var routing *dht.RoutingTable
	client, err := c.newDHTClient(cfg)
	if err != nil {
		return nil, err
	}
	if client != nil {
		routing = client.RT
	}
	guard, err := c.peerDialGuard(cfg, id, registry, routing)
	if err != nil {
		return nil, err
	}
	return vxtransport.WithDialGuard(ctx, guard), nil
}
