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
				Type: DHTTypeLookupName, Action: "find_value",
				Target: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
		{
			name: "wrong operation type",
			req: DHTRequest{
				Type: DHTTypeLookupKey, Action: "find_value",
				Target: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			bad: true,
		},
		{
			name: "short name hash",
			req:  DHTRequest{Type: DHTTypeLookupName, Action: "find_value", Target: "abcd"},
			bad:  true,
		},
		{
			name: "unknown action",
			req:  DHTRequest{Type: DHTTypeLookupOther, Action: "delete", Target: "app/key"},
			bad:  true,
		},
		{
			name: "lookup cannot smuggle data",
			req:  DHTRequest{Type: DHTTypeLookupOther, Action: "find_value", Target: "app/key", Data: "unexpected"},
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
