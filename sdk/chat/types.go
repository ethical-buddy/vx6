// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package chat

import (
	"encoding/json"
	"sort"
)

type Contact struct {
	NodeID    string `json:"node_id"`
	NodeName  string `json:"node_name"`
	Address   string `json:"address"`
	Secret    string `json:"secret"`
	AddedAt   string `json:"added_at"`
	Accepted  bool   `json:"accepted"`
	RequestID string `json:"request_id"`
}

type Envelope struct {
	Version   int    `json:"version"`
	ID        string `json:"id"`
	Type      string `json:"type"`
	Seq       uint64 `json:"seq,omitempty"`
	AckFor    string `json:"ack_for,omitempty"`
	MediaName string `json:"media_name,omitempty"`
	MediaSize int64  `json:"media_size,omitempty"`
	MediaSHA  string `json:"media_sha,omitempty"`
	GroupID   string `json:"group_id,omitempty"`
	From      string `json:"from"`
	To        string `json:"to"`
	CreatedAt string `json:"created_at"`
	Nonce     string `json:"nonce"`
	Cipher    string `json:"cipher"`
}

type Ledger struct {
	PairKey   string     `json:"pair_key"`
	UpdatedAt string     `json:"updated_at"`
	Messages  []Envelope `json:"messages"`
}

type Message struct {
	Text string `json:"text"`
}

type FriendRequest struct {
	Version   int    `json:"version"`
	RequestID string `json:"request_id"`
	FromID    string `json:"from_id"`
	FromName  string `json:"from_name"`
	Address   string `json:"address"`
	Secret    string `json:"secret"`
	CreatedAt string `json:"created_at"`
}

type PlainMessage struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Seq       uint64 `json:"seq,omitempty"`
	From      string `json:"from"`
	To        string `json:"to"`
	CreatedAt string `json:"created_at"`
	Text      string `json:"text,omitempty"`
	MediaName string `json:"media_name,omitempty"`
	MediaSize int64  `json:"media_size,omitempty"`
	MediaSHA  string `json:"media_sha,omitempty"`
}

func PairKey(a, b string) string {
	ids := []string{a, b}
	sort.Strings(ids)
	return "vx6chat/conv/" + ids[0] + "/" + ids[1]
}

func RequestKey(toNodeID string) string {
	return "vx6chat/request/" + toNodeID
}

func MarshalJSON(v any) []byte {
	out, _ := json.Marshal(v)
	return out
}
