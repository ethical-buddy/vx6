package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreEnsureRoundTrip(t *testing.T) {
	t.Parallel()

	store, err := NewStore(filepath.Join(t.TempDir(), "identity.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	first, created, err := store.Ensure()
	if err != nil {
		t.Fatalf("ensure first identity: %v", err)
	}
	if !created {
		t.Fatal("expected first ensure to create identity")
	}

	second, created, err := store.Ensure()
	if err != nil {
		t.Fatalf("ensure second identity: %v", err)
	}
	if created {
		t.Fatal("expected second ensure to reuse identity")
	}
	if first.NodeID != second.NodeID {
		t.Fatalf("unexpected node id mismatch %q != %q", first.NodeID, second.NodeID)
	}
}

func TestStoreSaveReplacesOverlyPermissiveIdentityFile(t *testing.T) {
	if !identityFilePermissionsEnforced {
		t.Skip("POSIX permission bits are not enforced on this platform")
	}
	store, err := NewStore(filepath.Join(t.TempDir(), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.Path(), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(id); err != nil {
		t.Fatalf("save identity over existing file: %v", err)
	}
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("identity mode = %o, want 600", got)
	}
	if _, err := store.Load(); err != nil {
		t.Fatalf("load saved identity: %v", err)
	}
}

func TestStoreLoadRejectsOverlyPermissiveIdentityFile(t *testing.T) {
	if !identityFilePermissionsEnforced {
		t.Skip("POSIX permission bits are not enforced on this platform")
	}
	store, err := NewStore(filepath.Join(t.TempDir(), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(id); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.Path(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("loaded a world-readable identity file")
	}
}

func TestIdentityReplacementCreatesNewNodeIdentity(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldIdentity, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(oldIdentity); err != nil {
		t.Fatal(err)
	}
	newIdentity, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if newIdentity.NodeID == oldIdentity.NodeID {
		t.Fatal("replacement key unexpectedly retained the old node ID")
	}
	if err := store.Save(newIdentity); err != nil {
		t.Fatalf("replace identity: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.NodeID != newIdentity.NodeID || loaded.NodeID == oldIdentity.NodeID {
		t.Fatalf("replacement identity node ID = %q, want new ID %q (old %q)", loaded.NodeID, newIdentity.NodeID, oldIdentity.NodeID)
	}
}

func TestNewStoreForConfigUsesDistinctIdentityFilesForCustomConfigs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	firstStore, err := NewStoreForConfig(filepath.Join(dir, "bootstrap.json"))
	if err != nil {
		t.Fatalf("new first store: %v", err)
	}
	secondStore, err := NewStoreForConfig(filepath.Join(dir, "client.json"))
	if err != nil {
		t.Fatalf("new second store: %v", err)
	}

	if firstStore.Path() == secondStore.Path() {
		t.Fatalf("expected distinct identity paths, got %s", firstStore.Path())
	}

	first, _, err := firstStore.Ensure()
	if err != nil {
		t.Fatalf("ensure first identity: %v", err)
	}
	second, _, err := secondStore.Ensure()
	if err != nil {
		t.Fatalf("ensure second identity: %v", err)
	}

	if first.NodeID == second.NodeID {
		t.Fatalf("expected distinct node ids, both were %s", first.NodeID)
	}

	if _, err := os.Stat(firstStore.Path()); err != nil {
		t.Fatalf("stat first identity path: %v", err)
	}
	if _, err := os.Stat(secondStore.Path()); err != nil {
		t.Fatalf("stat second identity path: %v", err)
	}
}

func TestDefaultPathUsesHomeConfigDirectory(t *testing.T) {
	t.Setenv("HOME", "/tmp/vx6-home")

	path, err := DefaultPath()
	if err != nil {
		t.Fatalf("default path: %v", err)
	}
	if path != "/tmp/vx6-home/.config/vx6/identity.json" {
		t.Fatalf("unexpected default identity path %q", path)
	}
}
