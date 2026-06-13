// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package chat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func RandomSecret() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func BuildInvite(nodeID, nodeName, addr, secret string) string {
	req := FriendRequest{
		Version:   1,
		RequestID: base64.RawURLEncoding.EncodeToString([]byte(nodeID))[:8] + fmt.Sprintf("%d", time.Now().UnixNano()%100000),
		FromID:    nodeID,
		FromName:  nodeName,
		Address:   addr,
		Secret:    secret,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return "vx6chat://invite/" + base64.RawURLEncoding.EncodeToString(MarshalJSON(req))
}

func ParseInvite(link string) (FriendRequest, error) {
	const p = "vx6chat://invite/"
	if !strings.HasPrefix(strings.TrimSpace(link), p) {
		return FriendRequest{}, fmt.Errorf("invalid invite")
	}
	raw := strings.TrimPrefix(strings.TrimSpace(link), p)
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return FriendRequest{}, err
	}
	var req FriendRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return FriendRequest{}, err
	}
	if req.FromID == "" || req.Address == "" || req.Secret == "" {
		return FriendRequest{}, fmt.Errorf("invite missing fields")
	}
	return req, nil
}

func SealMessage(secret string, plain Message, from, to, kind string, seq uint64) (Envelope, error) {
	raw, err := json.Marshal(plain)
	if err != nil {
		return Envelope{}, err
	}
	key := deriveMessageKey(secret, from, to, seq)
	return sealWithKey(key, raw, from, to, kind, seq)
}

func OpenMessage(secret string, env Envelope) (Message, error) {
	key := deriveMessageKey(secret, env.From, env.To, env.Seq)
	raw, err := openWithKey(key, env)
	if err != nil {
		return Message{}, err
	}
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		return Message{}, err
	}
	return msg, nil
}

func MakeAckMessage(ackedID, from, to string) Envelope {
	return Envelope{
		Version:   1,
		ID:        base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("ack-%s-%d", ackedID, time.Now().UnixNano()))),
		Type:      "ack",
		AckFor:    ackedID,
		From:      from,
		To:        to,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func deriveMessageKey(secret, from, to string, seq uint64) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("vx6-ratchet-v1\n%s\n%s\n%s\n%d", secret, from, to, seq)))
	return sum[:]
}

func sealWithKey(msgKey []byte, raw []byte, from, to, kind string, seq uint64) (Envelope, error) {
	block, err := aes.NewCipher(msgKey[:32])
	if err != nil {
		return Envelope{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	ciphertext := gcm.Seal(nil, nonce, raw, []byte(from+"\n"+to))
	sum := sha256.Sum256(append(nonce, ciphertext...))
	return Envelope{
		Version:   1,
		ID:        base64.RawURLEncoding.EncodeToString(sum[:12]),
		Type:      kind,
		Seq:       seq,
		From:      from,
		To:        to,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
		Cipher:    base64.RawURLEncoding.EncodeToString(ciphertext),
	}, nil
}

func openWithKey(msgKey []byte, env Envelope) ([]byte, error) {
	block, err := aes.NewCipher(msgKey[:32])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(env.Cipher)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, []byte(env.From+"\n"+env.To))
}
