package dht

import (
	"encoding/json"
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
	if info.NameHash != NodeNameHash(rec.NodeName) {
		t.Fatalf("cached name hash %q does not match canonical name", info.NameHash)
	}
	if err := VerifyNodeInfo(info, now); err != nil {
		t.Fatalf("verify converted identity: %v", err)
	}
	badNameHash := info
	badNameHash.NameHash = NodeNameHash("OTHER")
	if err := VerifyNodeInfo(badNameHash, now); err == nil {
		t.Fatal("accepted NodeInfo with a mismatched name hash")
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

func TestV2EndpointRecordMatchesSeparateNameAndIdentityIndexes(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rec, err := record.NewEndpointRecordV2(id, "PEER-7", "[2001:db8::7]:4242", 12, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	rawBytes, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(rawBytes)
	nameValue, err := validateInnerLookupValue(NodeNameKey("peer-7"), raw, now)
	if err != nil {
		t.Fatalf("name index rejected signed endpoint record: %v", err)
	}
	identityKey, err := NodePublicKeyKey(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	identityValue, err := validateInnerLookupValue(identityKey, raw, now)
	if err != nil {
		t.Fatalf("identity index rejected signed endpoint record: %v", err)
	}
	if nameValue.originNodeID != id.NodeID || identityValue.originNodeID != id.NodeID || nameValue.fingerprint != identityValue.fingerprint {
		t.Fatal("name and identity indexes did not resolve to the same signed identity record")
	}
	if _, err := validateInnerLookupValue(NodeNameKey("other"), raw, now); err == nil {
		t.Fatal("name index accepted a record for a different canonical name")
	}
	if _, err := validateInnerLookupValue(NodeIDKey("vx6_wrong"), raw, now); err == nil {
		t.Fatal("identity index accepted a record for a different NodeID")
	}
}
