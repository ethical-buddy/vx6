package record

import (
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
)

func TestEndpointRecordRoundTrip(t *testing.T) {
	t.Parallel()

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	now := time.Date(2026, 4, 19, 10, 0, 0, 0, time.UTC)
	rec, err := NewEndpointRecord(id, "alpha", "[2001:db8::1]:4242", 10*time.Minute, now)
	if err != nil {
		t.Fatalf("new endpoint record: %v", err)
	}

	if err := VerifyEndpointRecord(rec, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("verify endpoint record: %v", err)
	}
}

func TestVerifyEndpointReturnsBoundVerifiedRecord(t *testing.T) {
	t.Parallel()

	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	rec, err := NewEndpointRecord(id, "alpha", "[2001:db8::1]:4242", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := VerifyEndpoint(rec, now)
	if err != nil {
		t.Fatalf("verify endpoint: %v", err)
	}
	if verified.Endpoint().NodeID != id.NodeID || !verified.PublicKey().Equal(id.PublicKey) {
		t.Fatal("verified endpoint did not preserve the key-to-NodeID binding")
	}

	key := verified.PublicKey()
	key[0] ^= 0xff
	if !verified.PublicKey().Equal(id.PublicKey) {
		t.Fatal("mutating the returned public key changed the verified value")
	}

	rec.Address = "[2001:db8::9]:4242"
	if verified.Endpoint().Address != "[2001:db8::1]:4242" {
		t.Fatal("mutating the input record changed the verified value")
	}

	if _, err := VerifyEndpoint(verified.Endpoint(), now.Add(2*time.Hour)); err == nil {
		t.Fatal("verified an expired endpoint record")
	}
}

func TestEndpointRecordExpiry(t *testing.T) {
	t.Parallel()

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	now := time.Date(2026, 4, 19, 10, 0, 0, 0, time.UTC)
	rec, err := NewEndpointRecord(id, "alpha", "[2001:db8::1]:4242", time.Minute, now)
	if err != nil {
		t.Fatalf("new endpoint record: %v", err)
	}

	if err := VerifyEndpointRecord(rec, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expected expired record to fail verification")
	}
}

func TestEndpointRecordV2UsesSignedSequenceNotIssueTimeForOrdering(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	first, err := NewEndpointRecordV2(id, "alpha", "[2001:db8::1]:4242", 7, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewEndpointRecordV2(id, "alpha", "[2001:db8::2]:4242", 8, 2*time.Hour, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !EndpointRecordNewer(second, first) {
		t.Fatal("higher signed sequence was not considered newer")
	}
	if err := VerifyEndpointRecord(second, now); err != nil {
		t.Fatalf("future-independent sequence record was rejected: %v", err)
	}
	second.Sequence++
	if err := VerifyEndpointRecord(second, now); err == nil {
		t.Fatal("accepted a sequence changed without a new signature")
	}
}

func TestEndpointRecordV2ExpiryDoesNotUseIssueTimeAsIdentityProof(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rec, err := NewEndpointRecordV2(id, "alpha", "[2001:db8::1]:4242", 1, time.Hour, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEndpointRecord(rec, now); err != nil {
		t.Fatalf("issue time incorrectly acted as a verification timestamp: %v", err)
	}
	if err := VerifyEndpointRecord(rec, now.Add(26*time.Hour)); err == nil {
		t.Fatal("expired endpoint record was accepted")
	}
}
