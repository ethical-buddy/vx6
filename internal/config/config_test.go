package config

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/record"
)

func TestStoreRoundTrip(t *testing.T) {
	t.Parallel()

	store, err := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}
	cfg.Node.Name = "alpha"
	cfg.Peers["beta"] = PeerEntry{Address: "[2001:db8::2]:4242"}

	if err := store.Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.Node.Name != "alpha" {
		t.Fatalf("unexpected node name %q", loaded.Node.Name)
	}
	if loaded.Peers["beta"].Address != "[2001:db8::2]:4242" {
		t.Fatalf("unexpected peer address %q", loaded.Peers["beta"].Address)
	}
}

func TestRuntimePIDPathUsesConfigDirectory(t *testing.T) {
	t.Parallel()

	path, err := RuntimePIDPath("/tmp/vx6/config.json")
	if err != nil {
		t.Fatalf("runtime pid path: %v", err)
	}
	if path != "/tmp/vx6/node.pid" {
		t.Fatalf("unexpected pid path %q", path)
	}
}

func TestRuntimeLockPathUsesConfigDirectory(t *testing.T) {
	t.Parallel()

	path, err := RuntimeLockPath("/tmp/vx6/config.json")
	if err != nil {
		t.Fatalf("runtime lock path: %v", err)
	}
	if path != "/tmp/vx6/node.lock" {
		t.Fatalf("unexpected lock path %q", path)
	}
}

func TestRuntimeControlPathUsesConfigDirectory(t *testing.T) {
	t.Parallel()

	path, err := RuntimeControlPath("/tmp/vx6/config.json")
	if err != nil {
		t.Fatalf("runtime control path: %v", err)
	}
	if path != "/tmp/vx6/node.control.json" {
		t.Fatalf("unexpected control path %q", path)
	}
}

func TestDefaultPathsUseHomeDirectory(t *testing.T) {
	t.Setenv("HOME", "/tmp/vx6-home")

	configPath, err := DefaultPath()
	if err != nil {
		t.Fatalf("default config path: %v", err)
	}
	if configPath != "/tmp/vx6-home/.config/vx6/config.json" {
		t.Fatalf("unexpected config path %q", configPath)
	}

	dataDir, err := DefaultDataDir()
	if err != nil {
		t.Fatalf("default data dir: %v", err)
	}
	if dataDir != "/tmp/vx6-home/.local/share/vx6" {
		t.Fatalf("unexpected data dir %q", dataDir)
	}

	downloadDir, err := DefaultDownloadDir()
	if err != nil {
		t.Fatalf("default download dir: %v", err)
	}
	if downloadDir != "/tmp/vx6-home/Downloads" {
		t.Fatalf("unexpected download dir %q", downloadDir)
	}
}

func TestStoreNormalizesTrustedFileReceiveSettings(t *testing.T) {
	t.Parallel()

	store, err := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}
	cfg.Node.FileReceiveMode = "TRUSTED"
	cfg.Node.AllowedFileSenders = []string{"beta", "", "alpha", "beta"}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if loaded.Node.FileReceiveMode != FileReceiveTrusted {
		t.Fatalf("unexpected receive mode %q", loaded.Node.FileReceiveMode)
	}
	if want := []string{"alpha", "beta"}; !reflect.DeepEqual(loaded.Node.AllowedFileSenders, want) {
		t.Fatalf("unexpected allowed senders %#v", loaded.Node.AllowedFileSenders)
	}
}

func TestStoreClearsAllowListOutsideTrustedMode(t *testing.T) {
	t.Parallel()

	store, err := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}
	cfg.Node.FileReceiveMode = FileReceiveOpen
	cfg.Node.AllowedFileSenders = []string{"alpha"}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if loaded.Node.FileReceiveMode != FileReceiveOpen {
		t.Fatalf("unexpected receive mode %q", loaded.Node.FileReceiveMode)
	}
	if loaded.Node.AllowedFileSenders != nil {
		t.Fatalf("expected allow list to be cleared, got %#v", loaded.Node.AllowedFileSenders)
	}
}

func TestStoreNormalizesTransportAndRelayDefaults(t *testing.T) {
	t.Parallel()

	store, err := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}
	cfg.Node.TransportMode = "AUTO"
	cfg.Node.RelayMode = ""
	cfg.Node.RelayResourcePercent = 0
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if loaded.Node.TransportMode != "auto" {
		t.Fatalf("unexpected transport mode %q", loaded.Node.TransportMode)
	}
	if loaded.Node.RelayMode != RelayModeOn {
		t.Fatalf("unexpected relay mode %q", loaded.Node.RelayMode)
	}
	if loaded.Node.RelayResourcePercent != 33 {
		t.Fatalf("unexpected relay resource percent %d", loaded.Node.RelayResourcePercent)
	}
}

func TestAddPeerValidatesNameAndAddress(t *testing.T) {
	t.Parallel()

	store, err := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	if err := store.AddPeer("Alpha", "[2001:db8::2]:4242"); err == nil {
		t.Fatal("expected invalid peer name to fail")
	}
	if err := store.AddPeer("beta", "127.0.0.1:4242"); err == nil {
		t.Fatal("expected invalid peer address to fail")
	}
	if err := store.AddPeer("beta", "[2001:db8::2]:4242"); err != nil {
		t.Fatalf("expected valid peer add to succeed, got %v", err)
	}
}

func TestStoreNormalizesKnownPeerEntriesAndAddresses(t *testing.T) {
	t.Parallel()

	store, err := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	cfg.Node.KnownPeerAddrs = []string{
		"[2001:db8::2]:4242",
		"[2001:db8::4]:4242",
		"[2001:db8::2]:4242",
	}
	cfg.Node.KnownPeers = []KnownPeerEntry{
		{NodeID: "vx6_boot1", NodeName: "bootstrap", Address: "[2001:db8::1]:4242"},
		{NodeID: "vx6_boot2", NodeName: "relay-seed", Address: "[2001:db8::3]:4242"},
		{NodeID: "vx6_boot1", NodeName: "bootstrap", Address: "[2001:db8::1]:4242"},
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if want := []string{
		"[2001:db8::1]:4242",
		"[2001:db8::2]:4242",
		"[2001:db8::3]:4242",
		"[2001:db8::4]:4242",
	}; !reflect.DeepEqual(KnownPeerAddresses(loaded.Node), want) {
		t.Fatalf("unexpected known peer address list %#v", KnownPeerAddresses(loaded.Node))
	}

	entries, err := store.ListKnownPeerEntries()
	if err != nil {
		t.Fatalf("list known peer entries: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 normalized known peer entries, got %d", len(entries))
	}
}

func TestUpsertKnownPeerRecordRefreshesAddressByNodeIdentity(t *testing.T) {
	t.Parallel()

	store, err := NewStore(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	cfg.Node.KnownPeers = []KnownPeerEntry{
		{
			NodeID:   id.NodeID,
			NodeName: "bootstrap",
			Address:  "[2001:db8::10]:4242",
		},
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	rec, err := record.NewEndpointRecord(id, "bootstrap", "[2001:db8::99]:4242", 20*time.Minute, time.Now())
	if err != nil {
		t.Fatalf("new endpoint record: %v", err)
	}
	if err := store.UpsertKnownPeerRecord(rec); err != nil {
		t.Fatalf("upsert known peer record: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if len(loaded.Node.KnownPeers) != 1 {
		t.Fatalf("expected 1 known peer entry, got %d", len(loaded.Node.KnownPeers))
	}
	entry := loaded.Node.KnownPeers[0]
	if entry.Address != rec.Address {
		t.Fatalf("expected known peer address %q, got %q", rec.Address, entry.Address)
	}
	if entry.NodeID != rec.NodeID {
		t.Fatalf("expected known peer node id %q, got %q", rec.NodeID, entry.NodeID)
	}
	if entry.NodeName != rec.NodeName {
		t.Fatalf("expected known peer node name %q, got %q", rec.NodeName, entry.NodeName)
	}
	if entry.PublicKey != rec.PublicKey || entry.IdentityIssuedAt != rec.IssuedAt || entry.IdentityExpiresAt != rec.ExpiresAt || entry.IdentitySignature != rec.Signature {
		t.Fatal("known peer config did not preserve the signed public-key identity")
	}
}
