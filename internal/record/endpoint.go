// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the VX6 terms in LICENSE-COMMERCIAL.md.
// Sole inventor, maintainer, and rights holder: Suryansh Deshwal (https://github.com/ethical-buddy).

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
	Version   uint8  `json:"record_version,omitempty"`
	Sequence  uint64 `json:"record_sequence,omitempty"`
	NodeID    string `json:"node_id"`
	NodeName  string `json:"node_name"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	Signature string `json:"signature"`
}

// VerifiedEndpointRecord is an endpoint record whose signature, key-to-NodeID
// binding, and expiry have been checked. It does not prove DHT membership,
// network-wide uniqueness, or that the record came from an honest DHT quorum.
type VerifiedEndpointRecord struct {
	record    EndpointRecord
	publicKey ed25519.PublicKey
}

// Endpoint returns the signed endpoint fields that were verified.
func (v VerifiedEndpointRecord) Endpoint() EndpointRecord {
	return v.record
}

// PublicKey returns a copy of the key verified against the record signature
// and NodeID.
func (v VerifiedEndpointRecord) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), v.publicKey...)
}

func NewEndpointRecord(id identity.Identity, nodeName, address string, ttl time.Duration, now time.Time) (EndpointRecord, error) {
	return newEndpointRecord(id, nodeName, address, ttl, now, 0)
}

// NewEndpointRecordV2 creates a versioned endpoint record. Sequence is a
// persistent per-identity counter and must increase when signed metadata changes.
func NewEndpointRecordV2(id identity.Identity, nodeName, address string, sequence uint64, ttl time.Duration, now time.Time) (EndpointRecord, error) {
	if sequence == 0 {
		return EndpointRecord{}, fmt.Errorf("record sequence must be greater than zero")
	}
	return newEndpointRecord(id, nodeName, address, ttl, now, sequence)
}

func newEndpointRecord(id identity.Identity, nodeName, address string, ttl time.Duration, now time.Time, sequence uint64) (EndpointRecord, error) {
	canonicalName, err := NormalizeNodeName(nodeName)
	if err != nil {
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
		Version:   1,
		NodeID:    id.NodeID,
		NodeName:  canonicalName,
		Address:   address,
		PublicKey: base64.StdEncoding.EncodeToString(id.PublicKey),
		IssuedAt:  now.UTC().Format(time.RFC3339),
		ExpiresAt: now.UTC().Add(ttl).Format(time.RFC3339),
	}
	if sequence > 0 {
		record.Version = 2
		record.Sequence = sequence
	}

	signature := ed25519.Sign(id.PrivateKey, signingPayload(record))
	record.Signature = base64.StdEncoding.EncodeToString(signature)
	return record, nil
}

func VerifyEndpointRecord(record EndpointRecord, now time.Time) error {
	_, err := VerifyEndpoint(record, now)
	return err
}

// VerifyEndpoint checks an endpoint record and returns a value suitable for
// security-sensitive consumers such as the IPsec peer-key pinning path.
// Verification proves only that the record is internally valid and signed
// by the key it names; membership and uniqueness are separate trust decisions.
func VerifyEndpoint(record EndpointRecord, now time.Time) (VerifiedEndpointRecord, error) {
	if record.NodeID == "" || record.NodeName == "" || record.Address == "" {
		return VerifiedEndpointRecord{}, fmt.Errorf("record missing required fields")
	}
	if err := ValidateCanonicalNodeName(record.NodeName); err != nil {
		return VerifiedEndpointRecord{}, err
	}
	if err := transfer.ValidateIPv6Address(record.Address); err != nil {
		return VerifiedEndpointRecord{}, err
	}

	publicKey, err := base64.StdEncoding.DecodeString(record.PublicKey)
	if err != nil {
		return VerifiedEndpointRecord{}, fmt.Errorf("decode public key: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(record.Signature)
	if err != nil {
		return VerifiedEndpointRecord{}, fmt.Errorf("decode signature: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return VerifiedEndpointRecord{}, fmt.Errorf("record contains invalid public key")
	}
	if len(signature) != ed25519.SignatureSize {
		return VerifiedEndpointRecord{}, fmt.Errorf("record contains invalid signature")
	}

	expiresAt, err := time.Parse(time.RFC3339, record.ExpiresAt)
	if err != nil {
		return VerifiedEndpointRecord{}, fmt.Errorf("parse expires_at: %w", err)
	}
	if record.Version > 2 {
		return VerifiedEndpointRecord{}, fmt.Errorf("unsupported endpoint record version %d", record.Version)
	}
	if record.Version == 2 && record.Sequence == 0 {
		return VerifiedEndpointRecord{}, fmt.Errorf("version 2 endpoint record has no sequence")
	}
	if record.Version < 2 && record.Sequence != 0 {
		return VerifiedEndpointRecord{}, fmt.Errorf("legacy endpoint record unexpectedly contains a sequence")
	}
	if record.Version < 2 {
		issuedAt, err := time.Parse(time.RFC3339, record.IssuedAt)
		if err != nil {
			return VerifiedEndpointRecord{}, fmt.Errorf("parse issued_at: %w", err)
		}
		if !expiresAt.After(issuedAt) {
			return VerifiedEndpointRecord{}, fmt.Errorf("record expiry must be after issue time")
		}
	}
	if now.UTC().After(expiresAt) {
		return VerifiedEndpointRecord{}, fmt.Errorf("record has expired")
	}

	if want := identity.NodeIDFromPublicKey(ed25519.PublicKey(publicKey)); want != record.NodeID {
		return VerifiedEndpointRecord{}, fmt.Errorf("record node id does not match public key")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), signingPayload(record), signature) {
		return VerifiedEndpointRecord{}, fmt.Errorf("record signature verification failed")
	}

	return VerifiedEndpointRecord{
		record:    record,
		publicKey: append(ed25519.PublicKey(nil), publicKey...),
	}, nil
}

func Fingerprint(record EndpointRecord) string {
	sum := sha256.Sum256(signingPayload(record))
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

// EndpointRecordNewer compares records for the same identity. Version 2 uses
// its signed sequence; legacy records fall back to their historical issue time.
func EndpointRecordNewer(candidate, current EndpointRecord) bool {
	if candidate.Version != current.Version {
		return candidate.Version > current.Version
	}
	if candidate.Version >= 2 {
		return candidate.Sequence > current.Sequence
	}
	candidateTime, candidateErr := time.Parse(time.RFC3339, candidate.IssuedAt)
	currentTime, currentErr := time.Parse(time.RFC3339, current.IssuedAt)
	return candidateErr == nil && currentErr == nil && candidateTime.After(currentTime)
}

// EndpointRecordSequenceVersion returns the version used to compare records
// inside the signed endpoint family.
func EndpointRecordSequenceVersion(rec EndpointRecord) uint64 {
	if rec.Version >= 2 {
		return rec.Sequence
	}
	issuedAt, err := time.Parse(time.RFC3339, rec.IssuedAt)
	if err != nil {
		return 0
	}
	return uint64(issuedAt.UTC().Unix())
}

func JSON(record EndpointRecord) ([]byte, error) {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode endpoint record: %w", err)
	}
	return append(data, '\n'), nil
}

func signingPayload(record EndpointRecord) []byte {
	if record.Version >= 2 {
		return []byte(fmt.Sprintf("vx6/endpoint-record/v2\n%d\n%d\n%s\n%s\n%s\n%s\n%s\n%s\n",
			record.Version, record.Sequence, record.NodeID, record.NodeName, record.Address,
			record.PublicKey, record.IssuedAt, record.ExpiresAt))
	}
	return []byte(
		record.NodeID + "\n" +
			record.NodeName + "\n" +
			record.Address + "\n" +
			record.PublicKey + "\n" +
			record.IssuedAt + "\n" +
			record.ExpiresAt + "\n",
	)
}
