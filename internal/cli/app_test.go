package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/runtimectl"
)

func TestExtractLeadingConnectService(t *testing.T) {
	t.Parallel()

	service, rest := extractLeadingConnectService([]string{"bob.ssh", "--listen", "127.0.0.1:3333"})
	if service != "bob.ssh" {
		t.Fatalf("unexpected service %q", service)
	}
	if len(rest) != 2 || rest[0] != "--listen" || rest[1] != "127.0.0.1:3333" {
		t.Fatalf("unexpected remaining args: %#v", rest)
	}
}

func TestExtractLeadingConnectServiceKeepsFlagFirstForm(t *testing.T) {
	t.Parallel()

	service, rest := extractLeadingConnectService([]string{"--listen", "127.0.0.1:3333", "bob.ssh"})
	if service != "" {
		t.Fatalf("unexpected service %q", service)
	}
	if len(rest) != 3 || rest[0] != "--listen" || rest[2] != "bob.ssh" {
		t.Fatalf("unexpected remaining args: %#v", rest)
	}
}

func TestFriendlyRelayPathErrorForProxy(t *testing.T) {
	t.Parallel()

	err := friendlyRelayPathError(errors.New("not enough peers in registry to build a 5-hop chain (need 5, have 2)"), "proxy mode")
	if err == nil {
		t.Fatal("expected wrapped error")
	}
	if !strings.Contains(err.Error(), "proxy mode requires more reachable VX6 nodes") {
		t.Fatalf("unexpected error %q", err.Error())
	}
}

func TestFriendlyRelayPathErrorForHiddenService(t *testing.T) {
	t.Parallel()

	err := friendlyRelayPathError(errors.New("no rendezvous candidates available"), "hidden-service mode")
	if err == nil {
		t.Fatal("expected wrapped error")
	}
	if !strings.Contains(err.Error(), "hidden-service mode requires more reachable VX6 nodes") {
		t.Fatalf("unexpected error %q", err.Error())
	}
}

func TestAcquireNodeLockPreventsSecondNodeStart(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "config.json")

	lock, err := acquireNodeLock(configPath)
	if err != nil {
		t.Fatalf("acquire first node lock: %v", err)
	}
	defer lock.Close()

	_, err = acquireNodeLock(configPath)
	if err == nil {
		t.Fatal("expected second node start to fail")
	}
	if !strings.Contains(err.Error(), "already running in the background") {
		t.Fatalf("unexpected error %q", err.Error())
	}
}

func TestPrintUsageHidesAddressRevealFlags(t *testing.T) {
	var usage bytes.Buffer
	printUsage(&usage)
	if strings.Contains(usage.String(), "show-addresses") {
		t.Fatalf("usage leaked address-reveal flag: %q", usage.String())
	}

	var debugUsage bytes.Buffer
	printDebugUsage(&debugUsage)
	if strings.Contains(debugUsage.String(), "show-addresses") {
		t.Fatalf("debug usage leaked address-reveal flag: %q", debugUsage.String())
	}
}

func TestRunPeerRedactsStoredPeerAddresses(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("VX6_CONFIG_PATH", configPath)

	store, err := config.NewStore("")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.AddPeer("alice", "[2001:db8::10]:4242"); err != nil {
		t.Fatalf("add peer: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runPeer(nil); err != nil {
			t.Fatalf("run peer: %v", err)
		}
	})
	if !strings.Contains(output, "alice") || !strings.Contains(output, "configured") {
		t.Fatalf("unexpected peer output %q", output)
	}
	if strings.Contains(output, "[2001:db8::10]:4242") {
		t.Fatalf("peer output leaked address: %q", output)
	}
}

func TestSignedEndpointRecordCanBeExportedAndUsedAsBootstrap(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	t.Setenv("VX6_CONFIG_PATH", configPath)
	store, err := config.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Node.Name = "bootstrap"
	cfg.Node.DataDir = filepath.Join(root, "data")
	cfg.Node.AdvertiseAddr = "[2001:db8::10]:4242"
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	idStore, err := identity.NewStoreForConfig(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := idStore.Ensure(); err != nil {
		t.Fatal(err)
	}
	endpointPath := filepath.Join(root, "endpoint.json")
	if err := runIdentityExportEndpoint([]string{"--out", endpointPath}); err != nil {
		t.Fatalf("export signed endpoint: %v", err)
	}
	if err := runPeer([]string{"add", "--record", endpointPath}); err != nil {
		t.Fatalf("import signed bootstrap endpoint: %v", err)
	}
	registry, err := loadLocalRegistry(cfg.Node.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	peers, _ := registry.Snapshot()
	if len(peers) != 1 || peers[0].NodeName != "bootstrap" || peers[0].Address != cfg.Node.AdvertiseAddr {
		t.Fatalf("signed endpoint was not imported into local registry: %+v", peers)
	}
	updated, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Node.KnownPeers) != 1 || updated.Node.KnownPeers[0].PublicKey != peers[0].PublicKey {
		t.Fatalf("signed public key was not persisted in known peers: %+v", updated.Node.KnownPeers)
	}
}

func TestPrintRuntimeStatusOmitsAddresses(t *testing.T) {
	output := captureStdout(t, func() {
		printRuntimeStatus("ONLINE", runtimectl.Status{
			NodeName:                        "alpha",
			EndpointPublish:                 "hidden",
			TransportConfig:                 "auto",
			TransportActive:                 "tcp",
			RelayMode:                       "on",
			RelayPercent:                    33,
			RegistryNodes:                   4,
			RegistryServices:                2,
			DHTTrackedKeys:                  6,
			DHTHealthyKeys:                  5,
			DHTDegradedKeys:                 1,
			HiddenDescriptorKeys:            2,
			HiddenDescriptorHealthy:         2,
			DHTRefreshIntervalSeconds:       10,
			HiddenDescriptorRotationSeconds: 3600,
			HiddenDescriptorOverlapKeys:     2,
		})
	})
	if strings.Contains(output, "listen_addr") || strings.Contains(output, "advertise_addr") || strings.Contains(output, "probe_addr") {
		t.Fatalf("runtime status leaked raw address fields: %q", output)
	}
	if !strings.Contains(output, "endpoint_publish\thidden") {
		t.Fatalf("runtime status missing endpoint publish mode: %q", output)
	}
	if !strings.Contains(output, "dht_refresh_interval_seconds\t10") || !strings.Contains(output, "hidden_descriptor_keys\t2") {
		t.Fatalf("runtime status missing dht summary: %q", output)
	}
}

func TestRunIdentityOmitsAddresses(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("VX6_CONFIG_PATH", configPath)

	store, err := config.NewStore("")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	cfg.Node.Name = "alpha"
	cfg.Node.ListenAddr = "[::]:4242"
	cfg.Node.AdvertiseAddr = "[2001:db8::10]:4242"
	cfg.Node.HideEndpoint = true
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	idStore, err := identity.NewStoreForConfig(store.Path())
	if err != nil {
		t.Fatalf("new identity store: %v", err)
	}
	if _, _, err := idStore.Ensure(); err != nil {
		t.Fatalf("ensure identity: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runIdentity(context.Background(), nil); err != nil {
			t.Fatalf("run identity: %v", err)
		}
	})
	if strings.Contains(output, "listen_addr") || strings.Contains(output, "advertise_addr") || strings.Contains(output, "[2001:db8::10]:4242") {
		t.Fatalf("identity output leaked addresses: %q", output)
	}
	if !strings.Contains(output, "endpoint_publish\thidden") {
		t.Fatalf("identity output missing endpoint publish mode: %q", output)
	}
}

func TestRunDebugRegistryRedactsDiscoveredAddresses(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	dataDir := filepath.Join(root, "data")
	t.Setenv("VX6_CONFIG_PATH", configPath)

	store, err := config.NewStore("")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	cfg.Node.Name = "alpha"
	cfg.Node.DataDir = dataDir
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	now := time.Now()
	nodeRec, err := record.NewEndpointRecord(id, "alice", "[2001:db8::10]:4242", 10*time.Minute, now)
	if err != nil {
		t.Fatalf("new endpoint record: %v", err)
	}
	publicSvc, err := record.NewServiceRecord(id, "alice", "ssh", "[2001:db8::10]:4242", 10*time.Minute, now)
	if err != nil {
		t.Fatalf("new public service record: %v", err)
	}
	hiddenSvc, err := record.NewServiceRecord(id, "alice", "admin", "", 10*time.Minute, now)
	if err != nil {
		t.Fatalf("new hidden service record: %v", err)
	}
	hiddenSvc.IsHidden = true
	hiddenSvc.Alias = "ghost-admin"
	hiddenSvc.HiddenProfile = "fast"
	if err := record.SignServiceRecord(id, &hiddenSvc); err != nil {
		t.Fatalf("sign hidden service record: %v", err)
	}

	reg, err := discovery.NewRegistry(filepath.Join(dataDir, "registry.json"))
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	if err := reg.Import([]record.EndpointRecord{nodeRec}, []record.ServiceRecord{publicSvc, hiddenSvc}); err != nil {
		t.Fatalf("import registry snapshot: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runDebugRegistry(nil); err != nil {
			t.Fatalf("run debug registry: %v", err)
		}
	})
	if strings.Contains(output, "[2001:db8::10]:4242") || strings.Contains(output, "addr=") {
		t.Fatalf("registry output leaked address: %q", output)
	}
	if !strings.Contains(output, "node\talice") || !strings.Contains(output, "endpoint=sealed") {
		t.Fatalf("registry node output missing redacted summary: %q", output)
	}
	if !strings.Contains(output, "service\tkey=alice.ssh") {
		t.Fatalf("registry service output missing public summary: %q", output)
	}
	if strings.Contains(output, "ghost-admin") || strings.Contains(output, "hidden=true") {
		t.Fatalf("registry output should not include hidden services from shared registry snapshots: %q", output)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	defer r.Close()

	os.Stdout = w
	defer func() {
		os.Stdout = orig
	}()

	outputCh := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outputCh <- buf.String()
	}()

	fn()
	_ = w.Close()
	return <-outputCh
}
