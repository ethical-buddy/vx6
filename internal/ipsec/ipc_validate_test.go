package ipsec

import (
	"testing"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/strictjson"
)

func TestIPsecIPCStrictRequestSchema(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	req := ipcRequest{Action: "check", NodeID: id.NodeID, PublicKey: id.PublicKey, PrivateKey: id.PrivateKey, LocalAddress: "[2001:db8::1]:4242"}
	if err := req.validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if err := strictjson.Decode([]byte(`{"action":"check","unknown":true}`), &req); err == nil {
		t.Fatal("accepted unknown IPC field")
	}
}

func FuzzIPsecIPCRequest(f *testing.F) {
	f.Add([]byte(`{"action":"check"}`))
	f.Add([]byte(`{"action":"authenticate","remote":"x","action":"revoke"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var req ipcRequest
		if strictjson.Decode(data, &req) == nil {
			_ = req.validate()
		}
	})
}
