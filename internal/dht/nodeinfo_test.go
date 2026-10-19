package dht

import (
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
)

func TestNodeInfoFromEndpointRecordPreservesAndVerifiesIdentity(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	rec, err := record.NewEndpointRecord(id, "peer", "[2001:db8::2]:4242", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}

	info := NodeInfoFromEndpointRecord(rec)
	if err := VerifyNodeInfo(info, now); err != nil {
		t.Fatalf("verify converted identity: %v", err)
	}
	if info.PublicKey != rec.PublicKey || info.IdentitySignature != rec.Signature {
		t.Fatal("converted NodeInfo did not preserve the signed identity")
	}

	info.Addr = "[2001:db8::3]:4242"
	if err := VerifyNodeInfo(info, now); err == nil {
		t.Fatal("accepted NodeInfo with a changed endpoint")
	}
}

func TestVerifyNodeInfoRejectsMissingAndExpiredIdentity(t *testing.T) {
	if err := VerifyNodeInfo(proto.NodeInfo{ID: "peer", Name: "peer", Addr: "[2001:db8::2]:4242"}, time.Now()); err == nil {
		t.Fatal("accepted keyless NodeInfo")
	}

	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second)
	rec, err := record.NewEndpointRecord(id, "peer", "[2001:db8::2]:4242", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyNodeInfo(NodeInfoFromEndpointRecord(rec), time.Now()); err == nil {
		t.Fatal("accepted expired identity")
	}
}
