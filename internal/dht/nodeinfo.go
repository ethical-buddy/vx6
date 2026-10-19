// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package dht

import (
	"fmt"
	"time"

	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
)

func NodeInfoFromEndpointRecord(rec record.EndpointRecord) proto.NodeInfo {
	return proto.NodeInfo{
		ID:                rec.NodeID,
		Name:              rec.NodeName,
		Addr:              rec.Address,
		PublicKey:         rec.PublicKey,
		IdentityIssuedAt:  rec.IssuedAt,
		IdentityExpiresAt: rec.ExpiresAt,
		IdentitySignature: rec.Signature,
	}
}

func VerifyNodeInfo(info proto.NodeInfo, now time.Time) error {
	if info.ID == "" || info.Name == "" || info.Addr == "" || info.PublicKey == "" ||
		info.IdentityIssuedAt == "" || info.IdentityExpiresAt == "" || info.IdentitySignature == "" {
		return fmt.Errorf("node info is missing signed identity fields")
	}
	rec := record.EndpointRecord{
		NodeID:    info.ID,
		NodeName:  info.Name,
		Address:   info.Addr,
		PublicKey: info.PublicKey,
		IssuedAt:  info.IdentityIssuedAt,
		ExpiresAt: info.IdentityExpiresAt,
		Signature: info.IdentitySignature,
	}
	return record.VerifyEndpointRecord(rec, now)
}
