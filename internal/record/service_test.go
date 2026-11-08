package record

import (
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
)

func TestServiceRecordRoundTrip(t *testing.T) {
	t.Parallel()

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	now := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	rec, err := NewServiceRecord(id, "surya", "ssh", "[2001:db8::1]:4242", 10*time.Minute, now)
	if err != nil {
		t.Fatalf("new service record: %v", err)
	}

	if err := VerifyServiceRecord(rec, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("verify service record: %v", err)
	}
}

func TestHiddenServiceRecordRoundTrip(t *testing.T) {
	t.Parallel()

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	now := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	rec, err := NewServiceRecord(id, "surya", "ghost", "", 10*time.Minute, now)
	if err != nil {
		t.Fatalf("new hidden service record: %v", err)
	}
	rec.IsHidden = true
	rec.Alias = "hs-ghost"
	rec.HiddenProfile = "fast"
	rec.IntroPoints = []string{"[2001:db8::10]:4242", "[2001:db8::11]:4242", "[2001:db8::12]:4242"}
	rec.StandbyIntroPoints = []string{"[2001:db8::13]:4242", "[2001:db8::14]:4242"}
	if err := SignServiceRecord(id, &rec); err != nil {
		t.Fatalf("sign hidden service record: %v", err)
	}

	if got := ServiceLookupKey(rec); got != "hs-ghost" {
		t.Fatalf("unexpected lookup key %q", got)
	}
	if err := VerifyServiceRecord(rec, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("verify hidden service record: %v", err)
	}
}

func TestPrivateServiceRecordRoundTrip(t *testing.T) {
	t.Parallel()

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	now := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	rec, err := NewServiceRecord(id, "surya", "admin", "[2001:db8::55]:4242", 10*time.Minute, now)
	if err != nil {
		t.Fatalf("new private service record: %v", err)
	}
	rec.IsPrivate = true
	if err := SignServiceRecord(id, &rec); err != nil {
		t.Fatalf("sign private service record: %v", err)
	}
	if err := VerifyServiceRecord(rec, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("verify private service record: %v", err)
	}
}

func TestUDPServiceProtocolIsSigned(t *testing.T) {
	t.Parallel()

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	now := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	rec, err := NewServiceRecord(id, "surya", "media", "[2001:db8::1]:4242", 10*time.Minute, now)
	if err != nil {
		t.Fatalf("new service record: %v", err)
	}
	rec.Protocol = ServiceProtocolUDP
	if err := SignServiceRecord(id, &rec); err != nil {
		t.Fatalf("sign UDP service record: %v", err)
	}
	if err := VerifyServiceRecord(rec, now.Add(time.Minute)); err != nil {
		t.Fatalf("verify UDP service record: %v", err)
	}
	rec.Protocol = ServiceProtocolTCP
	if err := VerifyServiceRecord(rec, now.Add(time.Minute)); err == nil {
		t.Fatal("accepted service protocol changed after signing")
	}
}
