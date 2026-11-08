package hidden

import (
	"testing"

	"github.com/vx6/vx6/internal/strictjson"
)

func TestHiddenControlSchemaRejectsUnknownActionAndFields(t *testing.T) {
	for _, msg := range []Message{
		{Action: "execute"},
		{Action: "rv_join", RendezvousID: "rv", Service: "unexpected"},
		{Action: "intro_request", Service: "svc", RendezvousID: "rv", RendezvousCandidates: []string{"[2001:db8::1]:4242"}, HopCount: 9},
		{Action: "guard_register", Service: "svc", CallbackID: "cb", NotifyAddrs: make([]string, 17)},
	} {
		if err := msg.validate(); err == nil {
			t.Fatalf("accepted invalid control message: %+v", msg)
		}
	}
}

func FuzzHiddenControlSchema(f *testing.F) {
	f.Add([]byte(`{"action":"control_ping"}`))
	f.Add([]byte(`{"action":"rv_join","rendezvous_id":"rv","action":"rv_register"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg Message
		if strictjson.Decode(data, &msg) == nil {
			_ = msg.validate()
		}
	})
}

func TestHiddenControlSchemaAcceptsKnownMessages(t *testing.T) {
	for _, msg := range []Message{
		{Action: "intro_register", Service: "svc", NotifyAddrs: []string{"[2001:db8::1]:4242"}},
		{Action: "guard_register", Service: "svc", CallbackID: "cb"},
		{Action: "intro_request", Service: "svc", RendezvousID: "rv", RendezvousCandidates: []string{"[2001:db8::1]:4242"}, HopCount: 1},
		{Action: "rv_join", RendezvousID: "rv"},
		{Action: "control_ping"},
	} {
		if err := msg.validate(); err != nil {
			t.Fatalf("rejected valid control message %+v: %v", msg, err)
		}
	}
}
