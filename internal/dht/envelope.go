package dht

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/strictjson"
)

type SignedEnvelope struct {
	Key                string `json:"key"`
	Value              string `json:"value"`
	OriginNodeID       string `json:"origin_node_id,omitempty"`
	PublisherNodeID    string `json:"publisher_node_id"`
	PublisherPublicKey string `json:"publisher_public_key"`
	Version            uint64 `json:"version"`
	IssuedAt           string `json:"issued_at"`
	ExpiresAt          string `json:"expires_at"`
	ObservedAt         string `json:"observed_at"`
	Signature          string `json:"signature"`
}

func maybeDecodeEnvelope(raw string) (SignedEnvelope, bool, error) {
	var env SignedEnvelope
	if err := strictjson.Decode([]byte(raw), &env); err != nil {
		return SignedEnvelope{}, false, nil
	}
	if env.Key == "" && env.Value == "" && env.PublisherNodeID == "" && env.Signature == "" {
		return SignedEnvelope{}, false, nil
	}
	if env.Key == "" || env.Value == "" || env.PublisherNodeID == "" || env.PublisherPublicKey == "" || env.Signature == "" || env.IssuedAt == "" || env.ExpiresAt == "" || env.ObservedAt == "" || env.Version == 0 {
		return SignedEnvelope{}, true, fmt.Errorf("incomplete dht envelope")
	}
	return env, true, nil
}

func wrapSignedEnvelope(id identity.Identity, key, value string, info validatedValue, now time.Time) (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	if !info.verified {
		return "", fmt.Errorf("cannot wrap unverified value for key %q", key)
	}

	observedAt := now.UTC()
	if observedAt.Before(info.issuedAt.UTC()) {
		observedAt = info.issuedAt.UTC()
	}

	env := SignedEnvelope{
		Key:                key,
		Value:              value,
		OriginNodeID:       info.originNodeID,
		PublisherNodeID:    id.NodeID,
		PublisherPublicKey: base64.StdEncoding.EncodeToString(id.PublicKey),
		Version:            info.version,
		IssuedAt:           info.issuedAt.UTC().Format(time.RFC3339),
		ExpiresAt:          info.expiresAt.UTC().Format(time.RFC3339),
		ObservedAt:         observedAt.Format(time.RFC3339),
	}
	env.Signature = signEnvelope(id, env)

	data, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("marshal dht envelope: %w", err)
	}
	return string(data), nil
}

func verifyEnvelope(key string, env SignedEnvelope, now time.Time) error {
	if env.Key != key {
		return fmt.Errorf("envelope key %q does not match lookup key %q", env.Key, key)
	}
	publicKey, err := base64.StdEncoding.DecodeString(env.PublisherPublicKey)
	if err != nil {
		return fmt.Errorf("decode envelope public key: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return fmt.Errorf("decode envelope signature: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("envelope contains invalid public key")
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("envelope contains invalid signature")
	}
	if want := identity.NodeIDFromPublicKey(ed25519.PublicKey(publicKey)); want != env.PublisherNodeID {
		return fmt.Errorf("envelope publisher node id does not match public key")
	}

	issuedAt, err := time.Parse(time.RFC3339, env.IssuedAt)
	if err != nil {
		return fmt.Errorf("parse envelope issued_at: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, env.ExpiresAt)
	if err != nil {
		return fmt.Errorf("parse envelope expires_at: %w", err)
	}
	observedAt, err := time.Parse(time.RFC3339, env.ObservedAt)
	if err != nil {
		return fmt.Errorf("parse envelope observed_at: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return fmt.Errorf("envelope expiry must be after issue time")
	}
	if observedAt.Before(issuedAt) {
		return fmt.Errorf("envelope observed_at cannot be before issued_at")
	}
	if now.UTC().After(expiresAt) {
		return fmt.Errorf("envelope has expired")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), envelopeSigningPayload(env), signature) {
		return fmt.Errorf("envelope signature verification failed")
	}
	return nil
}

func signEnvelope(id identity.Identity, env SignedEnvelope) string {
	sig := ed25519.Sign(id.PrivateKey, envelopeSigningPayload(env))
	return base64.StdEncoding.EncodeToString(sig)
}

func envelopeSigningPayload(env SignedEnvelope) []byte {
	return []byte(
		env.Key + "\n" +
			env.Value + "\n" +
			env.OriginNodeID + "\n" +
			env.PublisherNodeID + "\n" +
			env.PublisherPublicKey + "\n" +
			strconv.FormatUint(env.Version, 10) + "\n" +
			env.IssuedAt + "\n" +
			env.ExpiresAt + "\n" +
			env.ObservedAt + "\n",
	)
}
