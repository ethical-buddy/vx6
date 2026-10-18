package main

import (
	"encoding/json"
	"testing"
)

func TestInviteRoundTrip(t *testing.T) {
	link := inviteLink("node-a", "alice", "[::1]:4242", "secret-1")
	req, err := parseInviteLink(link)
	if err != nil {
		t.Fatalf("parse invite: %v", err)
	}
	if req.FromID != "node-a" || req.FromName != "alice" || req.Secret != "secret-1" {
		t.Fatalf("unexpected invite fields: %#v", req)
	}
}

func TestSealAndOpenMessage(t *testing.T) {
	env, err := sealMessage("s3", chatMessage{Text: "hello"}, "node-a", "node-b", "msg", 1)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	msg, err := openMessage("s3", env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if msg.Text != "hello" {
		t.Fatalf("unexpected text: %q", msg.Text)
	}
}

func TestAckMessage(t *testing.T) {
	ack := makeAckMessage("m1", "node-a", "node-b")
	if ack.Type != "ack" || ack.AckFor != "m1" {
		t.Fatalf("unexpected ack payload: %#v", ack)
	}
}

func TestLocalStateJSON(t *testing.T) {
	st := localState{
		Unread:      map[string]int{"node-a": 2},
		SeenMessage: map[string]bool{"m1": true},
		Pending:     map[string]bool{"m2": true},
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out localState
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Unread["node-a"] != 2 || !out.SeenMessage["m1"] || !out.Pending["m2"] {
		t.Fatalf("unexpected roundtrip: %#v", out)
	}
}
