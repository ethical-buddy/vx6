package discovery

import (
	"testing"
	"time"

	"github.com/vx6/vx6/internal/record"
)

func TestDiscoveryRequestActionSchemas(t *testing.T) {
	valid := []request{
		{Action: "publish", Record: record.EndpointRecord{NodeID: "id"}},
		{Action: "resolve", Name: "NODE-A"},
		{Action: "resolve", NodeID: "vx6_0123456789abcdef"},
		{Action: "resolve_service", Service: "NODE-A.web"},
		{Action: "snapshot"},
	}
	for _, req := range valid {
		if err := req.validate(); err != nil {
			t.Errorf("rejected valid %q request: %v", req.Action, err)
		}
	}
	invalid := []request{
		{Action: "resolve", Name: "NODE-A", NodeID: "vx6_id"},
		{Action: "snapshot", Service: "NODE-A.web"},
		{Action: "publish", Record: record.EndpointRecord{NodeID: "id"}, NodeID: "vx6_id"},
		{Action: "unknown"},
	}
	for _, req := range invalid {
		if err := req.validate(); err == nil {
			t.Errorf("accepted invalid %q request: %+v", req.Action, req)
		}
	}
}

func TestDiscoveryIngressBudgetIsBoundedPerPeer(t *testing.T) {
	registry, err := NewRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < requestRateBurst; i++ {
		if !registry.allowRequest("peer-a", now) {
			t.Fatalf("limited peer before request %d", i+1)
		}
	}
	if registry.allowRequest("peer-a", now) {
		t.Fatal("accepted discovery request above peer budget")
	}
	if !registry.allowRequest("peer-b", now) {
		t.Fatal("peer-a discovery budget affected peer-b")
	}
}
