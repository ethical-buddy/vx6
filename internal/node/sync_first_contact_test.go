package node

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/liveness"
	"github.com/vx6/vx6/internal/record"
)

// stopAfterProbeTunnel ends syncTarget right after the liveness step.
type stopAfterProbeTunnel struct{}

var errStopAfterProbe = errors.New("stop after liveness step")

func (stopAfterProbeTunnel) PreparePeer(context.Context, record.EndpointRecord) error { return nil }
func (stopAfterProbeTunnel) EnsurePeer(context.Context, record.EndpointRecord) error {
	return errStopAfterProbe
}
func (stopAfterProbeTunnel) RegisterProbePort(context.Context, string) error { return nil }
func (stopAfterProbeTunnel) AuthenticatePeer(context.Context, string) (record.EndpointRecord, bool) {
	return record.EndpointRecord{}, false
}

type knownSeed struct {
	seed     record.EndpointRecord
	self     record.EndpointRecord
	selfID   string
	registry *discovery.Registry
	prepared chan record.EndpointRecord
}

// startKnownSeed runs a liveness responder for a seed whose signed record is
// already imported into our registry (as a bootstrap seed file does). The
// responder reports every caller identity it prepares.
func startKnownSeed(t *testing.T, ctx context.Context) knownSeed {
	t.Helper()
	seedID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	selfID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	seedPort := udp.LocalAddr().(*net.UDPAddr).Port - 1
	if seedPort < 1 {
		t.Fatal("allocated UDP port cannot provide an adjacent endpoint port")
	}
	now := time.Now()
	seedRecord, err := record.NewEndpointRecordV2(seedID, "SEED", net.JoinHostPort("::1", strconv.Itoa(seedPort)), 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	selfRecord, err := record.NewEndpointRecordV2(selfID, "SELF", "[::1]:4242", 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared := make(chan record.EndpointRecord, 8)
	go func() {
		_ = liveness.NewResponder().Serve(ctx, udp, func() (record.EndpointRecord, error) { return seedRecord, nil },
			func(_ context.Context, caller record.EndpointRecord, _ net.IP) error {
				prepared <- caller
				return nil
			})
	}()
	registry, err := discovery.NewRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Import([]record.EndpointRecord{seedRecord}, nil); err != nil {
		t.Fatal(err)
	}
	return knownSeed{seed: seedRecord, self: selfRecord, selfID: selfID.NodeID, registry: registry, prepared: prepared}
}

// A bootstrap seed is "known" (its signed record was imported), but the seed
// does not know us. First contact must still send our signed identity, or the
// seed never prepares us and rejects the following authenticated tunnel ping.
func TestSyncFirstContactWithKnownSeedSendsOurIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := startKnownSeed(t, ctx)
	cfg := Config{NodeID: s.selfID, Registry: s.registry, IPsecTunnel: stopAfterProbeTunnel{}}
	if _, known := endpointRecordByAddress(cfg, s.seed.Address); !known {
		t.Fatal("test setup: the imported seed must count as a known record")
	}

	result := syncTarget(ctx, &bytes.Buffer{}, cfg, &s.self, s.seed.Address)

	select {
	case caller := <-s.prepared:
		if caller.NodeID != s.selfID {
			t.Fatalf("seed prepared %s, want our node %s", caller.NodeID, s.selfID)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("seed never received our signed identity on first contact (result err: %v)", result.err)
	}
	if !errors.Is(result.err, errStopAfterProbe) {
		t.Fatalf("syncTarget should pass the liveness step and stop at the tunnel; got %v", result.err)
	}
}

// Hidden-endpoint nodes keep the plain probe for peers they already know, so
// they do not hand their signed endpoint record to every peer they sync with.
func TestSyncHiddenEndpointDoesNotSendIdentityToKnownPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := startKnownSeed(t, ctx)
	cfg := Config{NodeID: s.selfID, Registry: s.registry, IPsecTunnel: stopAfterProbeTunnel{}, HideEndpoint: true}

	result := syncTarget(ctx, &bytes.Buffer{}, cfg, &s.self, s.seed.Address)

	if !errors.Is(result.err, errStopAfterProbe) {
		t.Fatalf("plain probe should pass the liveness step; got %v", result.err)
	}
	select {
	case caller := <-s.prepared:
		t.Fatalf("hidden-endpoint node revealed its identity %s to a known peer", caller.NodeID)
	case <-time.After(500 * time.Millisecond):
	}
}

// Failures after the liveness step used to be silent; they must be logged
// once, because the failed target is then backed off without further logs.
func TestSyncMeshLogsSilentTargetFailures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := startKnownSeed(t, ctx)
	cfg := Config{NodeID: s.selfID, AdvertiseAddr: s.self.Address, PeerAddrs: []string{s.seed.Address},
		Registry: s.registry, IPsecTunnel: stopAfterProbeTunnel{}}

	var log bytes.Buffer
	syncMesh(ctx, &log, cfg, &s.self, nil, map[string]uint64{})

	want := "[SYNC] Target " + s.seed.Address + " failed:"
	if got := log.String(); strings.Count(got, want) != 1 || !strings.Contains(got, errStopAfterProbe.Error()) {
		t.Fatalf("expected exactly one failure log for %s, got:\n%s", s.seed.Address, got)
	}
}
