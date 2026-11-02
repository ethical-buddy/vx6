package node

import (
	"testing"
	"time"

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/record"
)

func TestEndpointRecordStatePersistsSequenceAndReusesCurrentRecord(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/config.json"
	store, err := config.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(config.File{Node: config.NodeConfig{Name: "ALPHA"}}); err != nil {
		t.Fatal(err)
	}

	state := newEndpointRecordState(path)
	first, err := state.Current(id, "ALPHA", "[2001:db8::1]:4242")
	if err != nil {
		t.Fatal(err)
	}
	reused, err := state.Current(id, "ALPHA", "[2001:db8::1]:4242")
	if err != nil || reused.Sequence != first.Sequence || reused.Signature != first.Signature {
		t.Fatalf("unchanged endpoint record was not reused: %+v, %v", reused, err)
	}

	changed, err := state.Current(id, "ALPHA", "[2001:db8::2]:4242")
	if err != nil {
		t.Fatal(err)
	}
	if changed.Sequence <= first.Sequence {
		t.Fatalf("address change did not advance sequence: %d -> %d", first.Sequence, changed.Sequence)
	}

	restarted := newEndpointRecordState(path)
	recovered, err := restarted.Current(id, "ALPHA", "[2001:db8::2]:4242")
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Sequence <= changed.Sequence {
		t.Fatalf("restart reused a prior sequence: %d -> %d", changed.Sequence, recovered.Sequence)
	}
	if err := record.VerifyEndpointRecord(recovered, time.Now()); err != nil {
		t.Fatalf("persisted sequence record failed verification: %v", err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Node.RecordSequence != recovered.Sequence || cfg.Node.RecordAddress != recovered.Address {
		t.Fatalf("record sequence state was not persisted: %+v", cfg.Node)
	}
}
