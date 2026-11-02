// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package liveness

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/vx6/vx6/internal/proto"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

const maxTunnelMessage = 128

type tunnelMessage struct {
	Version int    `json:"version"`
	Type    string `json:"type"`
	Nonce   string `json:"nonce"`
}

// TunnelPing checks the VX6 application path after the caller has established
// the peer's IKE/ESP association. Its TCP connection is protected by ESP.
func TunnelPing(ctx context.Context, mode, endpoint string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := vxtransport.DialContext(dialCtx, mode, endpoint)
	if err != nil {
		return fmt.Errorf("dial tunnel health RPC: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("create tunnel health nonce: %w", err)
	}
	challenge := hex.EncodeToString(nonce[:])
	if err := writeTunnelMessage(conn, tunnelMessage{Version: 1, Type: "ping", Nonce: challenge}); err != nil {
		return err
	}
	kind, err := proto.ReadHeader(conn)
	if err != nil {
		return err
	}
	if kind != proto.KindLiveness {
		return fmt.Errorf("unexpected tunnel health response kind %d", kind)
	}
	payload, err := proto.ReadLengthPrefixed(conn, maxTunnelMessage)
	if err != nil {
		return err
	}
	var response tunnelMessage
	if err := json.Unmarshal(payload, &response); err != nil {
		return fmt.Errorf("decode tunnel health response: %w", err)
	}
	if response.Version != 1 || response.Type != "pong" || response.Nonce != challenge {
		return errors.New("tunnel health response did not match the outstanding challenge")
	}
	return nil
}

// HandleTunnelConn is called only after the node's IPsec accept gate has
// confirmed the sender's installed peer association.
func HandleTunnelConn(conn net.Conn) error {
	payload, err := proto.ReadLengthPrefixed(conn, maxTunnelMessage)
	if err != nil {
		return err
	}
	var request tunnelMessage
	if err := json.Unmarshal(payload, &request); err != nil {
		return fmt.Errorf("decode tunnel health request: %w", err)
	}
	if request.Version != 1 || request.Type != "ping" || !validNonce(request.Nonce) {
		return errors.New("invalid tunnel health request")
	}
	return writeTunnelMessage(conn, tunnelMessage{Version: 1, Type: "pong", Nonce: request.Nonce})
}

func writeTunnelMessage(conn net.Conn, msg tunnelMessage) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encode tunnel health message: %w", err)
	}
	if len(payload) > maxTunnelMessage {
		return errors.New("tunnel health message is too large")
	}
	if err := proto.WriteHeader(conn, proto.KindLiveness); err != nil {
		return err
	}
	return proto.WriteLengthPrefixed(conn, payload)
}

func validNonce(value string) bool {
	if len(value) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}
