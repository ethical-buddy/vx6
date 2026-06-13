// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package chat

import (
	"context"
	"testing"
)

type memDHT struct {
	values map[string][]byte
}

func (m *memDHT) DHTGet(ctx context.Context, key string) ([]byte, error) {
	return m.values[key], nil
}

func (m *memDHT) DHTPut(ctx context.Context, key string, payload []byte) error {
	m.values[key] = append([]byte(nil), payload...)
	return nil
}

func TestInviteRoundTrip(t *testing.T) {
	link := BuildInvite("node-a", "alice", "[::1]:4242", "secret-1")
	req, err := ParseInvite(link)
	if err != nil {
		t.Fatalf("parse invite: %v", err)
	}
	if req.FromID != "node-a" || req.FromName != "alice" || req.Secret != "secret-1" {
		t.Fatalf("unexpected invite fields: %#v", req)
	}
}

func TestSealAndOpenMessage(t *testing.T) {
	env, err := SealMessage("s3", Message{Text: "hello"}, "node-a", "node-b", "msg", 1)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	msg, err := OpenMessage("s3", env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if msg.Text != "hello" {
		t.Fatalf("unexpected text: %q", msg.Text)
	}
}

func TestClientPublishesDesktopCompatibleLedger(t *testing.T) {
	dht := &memDHT{values: map[string][]byte{}}
	client := NewClient(dht)
	contact := Contact{NodeID: "node-b", NodeName: "bob", Address: "[::1]:4243", Secret: "s3", Accepted: true}
	env, err := client.SendText(context.Background(), "node-a", contact, "hello", 1)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	raw := dht.values[PairKey("node-a", "node-b")]
	if len(raw) == 0 {
		t.Fatal("ledger was not written")
	}
	msgs, err := client.FetchMessages(context.Background(), "node-a", contact)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(msgs) != 1 || msgs[0].ID != env.ID || msgs[0].Text != "hello" {
		t.Fatalf("unexpected messages: %#v", msgs)
	}
}
