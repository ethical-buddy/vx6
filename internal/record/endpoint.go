// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package record

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/transfer"
)

type EndpointRecord struct {
	NodeID    string `json:"node_id"`
	NodeName  string `json:"node_name"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	Signature string `json:"signature"`
}

func NewEndpointRecord(id identity.Identity, nodeName, address string, ttl time.Duration, now time.Time) (EndpointRecord, error) {
	if err := ValidateNodeName(nodeName); err != nil {
		return EndpointRecord{}, err
	}
	if err := transfer.ValidateIPv6Address(address); err != nil {
		return EndpointRecord{}, err
	}
	if ttl <= 0 {
		return EndpointRecord{}, fmt.Errorf("ttl must be greater than zero")
	}
	if err := id.Validate(); err != nil {
		return EndpointRecord{}, err
	}

	record := EndpointRecord{
		NodeID:    id.NodeID,
		NodeName:  nodeName,
		Address:   address,
		PublicKey: base64.StdEncoding.EncodeToString(id.PublicKey),
		IssuedAt:  now.UTC().Format(time.RFC3339),
		ExpiresAt: now.UTC().Add(ttl).Format(time.RFC3339),
	}

	signature := ed25519.Sign(id.PrivateKey, signingPayload(record))
	record.Signature = base64.StdEncoding.EncodeToString(signature)
	return record, nil
}

func VerifyEndpointRecord(record EndpointRecord, now time.Time) error {
	if record.NodeID == "" || record.NodeName == "" || record.Address == "" {
		return fmt.Errorf("record missing required fields")
	}
	if err := ValidateNodeName(record.NodeName); err != nil {
		return err
	}
	if err := transfer.ValidateIPv6Address(record.Address); err != nil {
		return err
	}

	publicKey, err := base64.StdEncoding.DecodeString(record.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(record.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("record contains invalid public key")
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("record contains invalid signature")
	}

	issuedAt, err := time.Parse(time.RFC3339, record.IssuedAt)
	if err != nil {
		return fmt.Errorf("parse issued_at: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, record.ExpiresAt)
	if err != nil {
		return fmt.Errorf("parse expires_at: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return fmt.Errorf("record expiry must be after issue time")
	}
	if now.UTC().After(expiresAt) {
		return fmt.Errorf("record has expired")
	}

	if want := identity.NodeIDFromPublicKey(ed25519.PublicKey(publicKey)); want != record.NodeID {
		return fmt.Errorf("record node id does not match public key")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), signingPayload(record), signature) {
		return fmt.Errorf("record signature verification failed")
	}

	return nil
}

func Fingerprint(record EndpointRecord) string {
	sum := sha256.Sum256(signingPayload(record))
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

func JSON(record EndpointRecord) ([]byte, error) {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode endpoint record: %w", err)
	}
	return append(data, '\n'), nil
}

func signingPayload(record EndpointRecord) []byte {
	return []byte(
		record.NodeID + "\n" +
			record.NodeName + "\n" +
			record.Address + "\n" +
			record.PublicKey + "\n" +
			record.IssuedAt + "\n" +
			record.ExpiresAt + "\n",
	)
}
