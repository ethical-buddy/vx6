package dht

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
)

func TestValidatedDHTValuesSurviveRestartAndAreRevalidated(t *testing.T) {
	now := time.Now().UTC()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	key := ServiceKey("owner.api")
	record := mustServiceRecordForIdentity(t, id, "owner", "api", "[2001:db8::20]:4242", false, "", now)
	value := mustSignedValue(t, id, key, mustJSON(t, record), now)

	path := filepath.Join(t.TempDir(), "dht-peers.db")
	store, err := OpenPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	first := NewServerWithIdentity(id)
	if err := first.AttachValuePersistence(store, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.storeValidated(key, value, now); err != nil {
		t.Fatalf("store signed DHT value: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = OpenPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	restarted := NewServerWithIdentity(id)
	if err := restarted.AttachValuePersistence(store, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := restarted.Values[key]; got != value {
		t.Fatalf("restored DHT value = %q, want persisted signed value", got)
	}
	if _, ok := restarted.LookupState(key); !ok {
		t.Fatal("restored DHT value did not rebuild its version state")
	}
}

func TestPersistedDHTValuesRejectInvalidAndExpiredRows(t *testing.T) {
	now := time.Now().UTC()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dht-peers.db")
	store, err := OpenPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	key := ServiceKey("owner.api")
	expired := mustServiceRecordForIdentity(t, id, "owner", "api", "[2001:db8::21]:4242", false, "", now.Add(-2*time.Hour))
	if err := store.PutValue(key, mustSignedValue(t, id, key, mustJSON(t, expired), now.Add(-2*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := store.PutValue("service/owner.other", "not a signed service record"); err != nil {
		t.Fatal(err)
	}
	server := NewServerWithIdentity(id)
	if err := server.AttachValuePersistence(store, now); err != nil {
		t.Fatal(err)
	}
	if len(server.Values) != 0 {
		t.Fatalf("restored invalid values: %#v", server.Values)
	}
	rows, err := store.LoadValues()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("invalid rows were not removed from persistence: %#v", rows)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}
