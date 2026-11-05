package proto

import "testing"

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
