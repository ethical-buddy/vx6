// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package chat

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vx6/vx6/sdk"
)

type VX6Client interface {
	DHTGet(ctx context.Context, key string) ([]byte, error)
	DHTPut(ctx context.Context, key string, payload []byte) error
}

type Client struct {
	vx6 VX6Client
}

func NewClient(vx6 VX6Client) *Client {
	return &Client{vx6: vx6}
}

func (c *Client) PublishEnvelope(ctx context.Context, selfNodeID string, contact Contact, env Envelope) error {
	key := PairKey(selfNodeID, contact.NodeID)
	var ledger Ledger
	if raw, err := c.vx6.DHTGet(ctx, key); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &ledger)
	}
	for _, existing := range ledger.Messages {
		if existing.ID == env.ID {
			return nil
		}
	}
	ledger.PairKey = key
	ledger.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	ledger.Messages = append(ledger.Messages, env)
	if len(ledger.Messages) > 800 {
		ledger.Messages = ledger.Messages[len(ledger.Messages)-800:]
	}
	return c.vx6.DHTPut(ctx, key, MarshalJSON(ledger))
}

func (c *Client) SendText(ctx context.Context, selfNodeID string, contact Contact, text string, seq uint64) (Envelope, error) {
	env, err := SealMessage(contact.Secret, Message{Text: text}, selfNodeID, contact.NodeID, "msg", seq)
	if err != nil {
		return Envelope{}, err
	}
	if err := c.PublishEnvelope(ctx, selfNodeID, contact, env); err != nil {
		return env, err
	}
	return env, nil
}

func (c *Client) FetchMessages(ctx context.Context, selfNodeID string, contact Contact) ([]PlainMessage, error) {
	raw, err := c.vx6.DHTGet(ctx, PairKey(selfNodeID, contact.NodeID))
	if err != nil {
		return nil, err
	}
	var ledger Ledger
	if err := json.Unmarshal(raw, &ledger); err != nil {
		return nil, err
	}
	out := make([]PlainMessage, 0, len(ledger.Messages))
	for _, env := range ledger.Messages {
		pm := PlainMessage{
			ID:        env.ID,
			Type:      env.Type,
			Seq:       env.Seq,
			From:      env.From,
			To:        env.To,
			CreatedAt: env.CreatedAt,
			MediaName: env.MediaName,
			MediaSize: env.MediaSize,
			MediaSHA:  env.MediaSHA,
		}
		if env.Type == "msg" {
			msg, err := OpenMessage(contact.Secret, env)
			if err != nil {
				continue
			}
			pm.Text = msg.Text
		}
		out = append(out, pm)
	}
	return out, nil
}

func AddInvitePeer(client *sdk.Client, req FriendRequest) error {
	return client.AddPeer(req.FromName, req.Address)
}
