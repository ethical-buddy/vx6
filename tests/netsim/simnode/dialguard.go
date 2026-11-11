// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/liveness"
	"github.com/vx6/vx6/internal/record"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

// lookupProbeTimeout mirrors internal/node's syncProbeTimeout.
const lookupProbeTimeout = time.Second

// peerPreparer is the part of the node's peer tunnel the dial guard uses.
type peerPreparer interface {
	EnsurePeer(context.Context, record.EndpointRecord) error
}

// newLookupDialGuard returns a dial guard with the same rules internal/node
// installs on its own context: the address must belong to a verified signed
// identity from the registry or the DHT table, it must match any expected
// peer ID, an unknown-liveness peer must answer a plain VX6 liveness probe,
// and the tunnel must accept the peer. Admin-API lookups run on the HTTP
// request context, which carries no guard; without one the transport refuses
// every peer dial, so simulated lookups could only ever be answered from the
// requester's own table.
func newLookupDialGuard(registry *discovery.Registry, srv *dht.Server, tunnel peerPreparer, cache *liveness.Cache) vxtransport.DialGuard {
	return func(ctx context.Context, addr string) error {
		peer, ok := verifiedEndpoint(registry, srv, addr)
		if !ok {
			return errors.New("no verified signed DHT identity for endpoint")
		}
		if expected := vxtransport.ExpectedPeerID(ctx); expected != "" && peer.NodeID != expected {
			return fmt.Errorf("signed peer identity mismatch at %s: got %s, want %s", addr, peer.NodeID, expected)
		}
		if !cache.IsAlive(addr, time.Now()) {
			if _, _, err := liveness.Probe(ctx, addr, false, lookupProbeTimeout); err != nil {
				cache.MarkFailed(addr)
				return fmt.Errorf("VX6 liveness probe failed: %w", err)
			}
			cache.MarkAlive(addr, time.Now())
		}
		return tunnel.EnsurePeer(ctx, peer)
	}
}

func verifiedEndpoint(registry *discovery.Registry, srv *dht.Server, addr string) (record.EndpointRecord, bool) {
	now := time.Now()
	if registry != nil {
		nodes, _ := registry.Snapshot()
		for _, rec := range nodes {
			if rec.Address == addr && record.VerifyEndpointRecord(rec, now) == nil {
				return rec, true
			}
		}
	}
	if srv != nil && srv.RT != nil {
		if info, ok := srv.RT.NodeByAddress(addr); ok && dht.VerifyNodeInfo(info, now) == nil {
			return record.EndpointRecord{
				Version: info.IdentityVersion, Sequence: info.IdentitySequence,
				NodeID: info.ID, NodeName: info.Name, Address: info.Addr,
				PublicKey: info.PublicKey, IssuedAt: info.IdentityIssuedAt,
				ExpiresAt: info.IdentityExpiresAt, Signature: info.IdentitySignature,
			}, true
		}
	}
	return record.EndpointRecord{}, false
}
