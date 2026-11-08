package proto

import (
	"strings"
	"testing"
)

func TestDHTRequestRequiresMatchingTypedPayload(t *testing.T) {
	tests := []struct {
		name string
		req  DHTRequest
		bad  bool
	}{
		{
			name: "valid name lookup",
			req: DHTRequest{
				Version: DHTWireVersion, Type: DHTTypeLookupName, Action: "find_value",
				Target: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
		{
			name: "bootstrap by name hash",
			req:  DHTRequest{Version: DHTWireVersion, Type: DHTTypeBootstrap, Action: "find_node", Target: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
		{
			name: "bootstrap by NodeID",
			req:  DHTRequest{Version: DHTWireVersion, Type: DHTTypeBootstrap, Action: "find_node", Target: "vx6_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		},
		{
			name: "wrong operation type",
			req: DHTRequest{
				Version: DHTWireVersion, Type: DHTTypeLookupKey, Action: "find_value",
				Target: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			bad: true,
		},
		{
			name: "short name hash",
			req:  DHTRequest{Version: DHTWireVersion, Type: DHTTypeLookupName, Action: "find_value", Target: "abcd"},
			bad:  true,
		},
		{
			name: "unknown action",
			req:  DHTRequest{Version: DHTWireVersion, Type: DHTTypeLookupOther, Action: "delete", Target: "app/key"},
			bad:  true,
		},
		{
			name: "lookup cannot smuggle data",
			req:  DHTRequest{Version: DHTWireVersion, Type: DHTTypeLookupOther, Action: "find_value", Target: "app/key", Data: "unexpected"},
			bad:  true,
		},
		{
			name: "unknown lookup keyspace rejected",
			req:  DHTRequest{Version: DHTWireVersion, Type: DHTTypeLookupOther, Action: "find_value", Target: "app/key"},
			bad:  true,
		},
		{
			name: "unsupported store keyspace rejected",
			req:  DHTRequest{Version: DHTWireVersion, Type: DHTTypeUpdate, Action: "store", Target: "app/key", Data: "value"},
			bad:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate()
			if tc.bad && err == nil {
				t.Fatal("expected validation error")
			}
			if !tc.bad && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestDHTRequestAcceptsOnlyTypedEndpointUpdate(t *testing.T) {
	target := "node/id/vx6_" + strings.Repeat("a", 64)
	request := DHTRequest{Version: DHTWireVersion, Type: DHTTypeUpdateIP, Action: "update_ip", Target: target, Data: "signed-endpoint-record"}
	if err := request.Validate(); err != nil {
		t.Fatalf("valid endpoint update rejected: %v", err)
	}
	request.Target = "service/owner.api"
	if err := request.Validate(); err == nil {
		t.Fatal("endpoint update accepted an unrelated target key")
	}
	request.Target = target
	request.Action = "store"
	if err := request.Validate(); err == nil {
		t.Fatal("endpoint update accepted a generic store action")
	}
}

func TestDHTWireVersionAndCanonicalHashValidation(t *testing.T) {
	request := DHTRequest{Version: DHTWireVersion, Type: DHTTypeLookupName, Action: "find_node", Target: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := request.Validate(); err != nil {
		t.Fatalf("valid v1 request rejected: %v", err)
	}
	request.Version++
	if err := request.Validate(); err == nil {
		t.Fatal("unsupported wire version accepted")
	}
	request.Version = DHTWireVersion
	request.Target = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := request.Validate(); err == nil {
		t.Fatal("uppercase non-canonical hash accepted")
	}
}
