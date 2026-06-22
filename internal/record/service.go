// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package record

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/transfer"
)

type ServiceRecord struct {
	NodeID             string   `json:"node_id"`
	NodeName           string   `json:"node_name"`
	ServiceName        string   `json:"service_name"`
	Alias              string   `json:"alias,omitempty"`
	Address            string   `json:"address,omitempty"` // Empty if hidden
	IsHidden           bool     `json:"is_hidden"`         // If true, IP is masked
	IsPrivate          bool     `json:"is_private,omitempty"`
	HiddenProfile      string   `json:"hidden_profile,omitempty"`
	IntroPoints        []string `json:"intro_points,omitempty"`         // Active intro points
	StandbyIntroPoints []string `json:"standby_intro_points,omitempty"` // Spare intro points
	PublicKey          string   `json:"public_key"`
	IssuedAt           string   `json:"issued_at"`
	ExpiresAt          string   `json:"expires_at"`
	Signature          string   `json:"signature"`
}

func NewServiceRecord(id identity.Identity, nodeName, serviceName, address string, ttl time.Duration, now time.Time) (ServiceRecord, error) {
	if err := ValidateNodeName(nodeName); err != nil {
		return ServiceRecord{}, err
	}
	if err := ValidateServiceName(serviceName); err != nil {
		return ServiceRecord{}, err
	}
	if address != "" {
		if err := transfer.ValidateIPv6Address(address); err != nil {
			return ServiceRecord{}, err
		}
	}
	if ttl <= 0 {
		return ServiceRecord{}, fmt.Errorf("ttl must be greater than zero")
	}
	if err := id.Validate(); err != nil {
		return ServiceRecord{}, err
	}

	rec := ServiceRecord{
		NodeID:      id.NodeID,
		NodeName:    nodeName,
		ServiceName: serviceName,
		Address:     address,
		PublicKey:   base64.StdEncoding.EncodeToString(id.PublicKey),
		IssuedAt:    now.UTC().Format(time.RFC3339),
		ExpiresAt:   now.UTC().Add(ttl).Format(time.RFC3339),
	}
	rec.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(id.PrivateKey, serviceSigningPayload(rec)))

	return rec, nil
}

func SignServiceRecord(id identity.Identity, rec *ServiceRecord) error {
	sig := ed25519.Sign(id.PrivateKey, serviceSigningPayload(*rec))
	rec.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

func VerifyServiceRecord(rec ServiceRecord, now time.Time) error {
	if rec.NodeID == "" || rec.NodeName == "" || rec.ServiceName == "" {
		return fmt.Errorf("service record missing required fields")
	}
	if err := ValidateNodeName(rec.NodeName); err != nil {
		return err
	}
	if rec.Alias != "" {
		if err := ValidateHiddenAlias(rec.Alias); err != nil {
			return err
		}
	}
	if !rec.IsHidden && rec.Address == "" {
		return fmt.Errorf("non-hidden service requires an address")
	}
	if !rec.IsHidden {
		if err := transfer.ValidateIPv6Address(rec.Address); err != nil {
			return err
		}
	}
	if rec.IsHidden && rec.IsPrivate {
		return fmt.Errorf("service cannot be both hidden and private")
	}
	if rec.IsHidden {
		if rec.Alias == "" {
			return fmt.Errorf("hidden service requires an alias")
		}
		if NormalizeHiddenProfile(rec.HiddenProfile) == "" {
			return fmt.Errorf("hidden service contains invalid profile %q", rec.HiddenProfile)
		}
	}

	publicKey, err := base64.StdEncoding.DecodeString(rec.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(rec.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("service record contains invalid public key")
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("service record contains invalid signature")
	}

	issuedAt, err := time.Parse(time.RFC3339, rec.IssuedAt)
	if err != nil {
		return fmt.Errorf("parse issued_at: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, rec.ExpiresAt)
	if err != nil {
		return fmt.Errorf("parse expires_at: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return fmt.Errorf("service record expiry must be after issue time")
	}
	if now.UTC().After(expiresAt) {
		return fmt.Errorf("service record has expired")
	}
	if want := identity.NodeIDFromPublicKey(ed25519.PublicKey(publicKey)); want != rec.NodeID {
		return fmt.Errorf("service record node id does not match public key")
	}

	if !ed25519.Verify(ed25519.PublicKey(publicKey), serviceSigningPayload(rec), signature) {
		return fmt.Errorf("service record signature verification failed")
	}

	return nil
}

func FullServiceName(nodeName, serviceName string) string {
	return nodeName + "." + serviceName
}

func ServiceLookupKey(rec ServiceRecord) string {
	if rec.IsHidden && rec.Alias != "" {
		return rec.Alias
	}
	return FullServiceName(rec.NodeName, rec.ServiceName)
}

func ValidateServiceName(name string) error {
	if name == "" {
		return fmt.Errorf("service name cannot be empty")
	}
	if strings.Contains(name, ".") {
		return fmt.Errorf("service name %q cannot contain dots", name)
	}
	return nil
}

func ValidateHiddenAlias(alias string) error {
	if alias == "" {
		return fmt.Errorf("hidden alias cannot be empty")
	}
	if strings.ContainsAny(alias, " \t\r\n/#") {
		return fmt.Errorf("hidden alias %q contains unsupported characters", alias)
	}
	return nil
}

func NormalizeHiddenProfile(profile string) string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", "fast":
		return "fast"
	case "balanced":
		return "balanced"
	default:
		return ""
	}
}

func serviceSigningPayload(rec ServiceRecord) []byte {
	// We include the hidden routing metadata in the signed payload to prevent descriptor spoofing.
	intros := strings.Join(rec.IntroPoints, ",")
	standbys := strings.Join(rec.StandbyIntroPoints, ",")
	hiddenStr := "false"
	if rec.IsHidden {
		hiddenStr = "true"
	}
	privateStr := "false"
	if rec.IsPrivate {
		privateStr = "true"
	}

	return []byte(
		rec.NodeID + "\n" +
			rec.NodeName + "\n" +
			rec.ServiceName + "\n" +
			rec.Alias + "\n" +
			rec.Address + "\n" +
			hiddenStr + "\n" +
			privateStr + "\n" +
			rec.HiddenProfile + "\n" +
			intros + "\n" +
			standbys + "\n" +
			rec.PublicKey + "\n" +
			rec.IssuedAt + "\n" +
			rec.ExpiresAt + "\n",
	)
}
