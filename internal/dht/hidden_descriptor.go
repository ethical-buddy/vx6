package dht

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/strictjson"
)

const hiddenDescriptorPayloadTargetSize = 1024

type HiddenDescriptor struct {
	NodeID     string `json:"node_id"`
	ServiceTag string `json:"service_tag"`
	IssuedAt   string `json:"issued_at"`
	ExpiresAt  string `json:"expires_at"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type hiddenDescriptorPayload struct {
	Record  record.ServiceRecord `json:"record"`
	Padding string               `json:"padding"`
}

func EncodeHiddenServiceDescriptor(rec record.ServiceRecord, lookupKey, lookupSecret string) (string, error) {
	if !rec.IsHidden || rec.Alias == "" {
		return "", fmt.Errorf("hidden descriptor requires a hidden service record with alias")
	}
	epoch, err := parseHiddenDescriptorEpoch(lookupKey)
	if err != nil {
		return "", err
	}
	key := hiddenDescriptorCipherKey(rec.Alias, lookupSecret, epoch)
	plaintext, err := marshalHiddenDescriptorPayload(rec)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("init hidden descriptor cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("init hidden descriptor AEAD: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("read hidden descriptor nonce: %w", err)
	}
	serviceTag := hiddenServiceTag(rec)
	aad := hiddenDescriptorAAD(lookupKey, serviceTag, rec.NodeID)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	desc := HiddenDescriptor{
		NodeID:     rec.NodeID,
		ServiceTag: serviceTag,
		IssuedAt:   rec.IssuedAt,
		ExpiresAt:  rec.ExpiresAt,
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	}
	data, err := json.Marshal(desc)
	if err != nil {
		return "", fmt.Errorf("marshal hidden descriptor: %w", err)
	}
	return string(data), nil
}

func DecodeHiddenServiceRecord(lookupKey, storedValue, alias string, now time.Time) (record.ServiceRecord, error) {
	desc, err := extractHiddenDescriptor(lookupKey, storedValue, now)
	if err != nil {
		if legacy, legacyErr := decodeLegacyHiddenServiceRecord(lookupKey, storedValue, alias, now); legacyErr == nil {
			return legacy, nil
		}
		return record.ServiceRecord{}, err
	}
	ref, err := ParseHiddenLookupRef(alias)
	if err != nil {
		return record.ServiceRecord{}, err
	}
	epoch, err := parseHiddenDescriptorEpoch(lookupKey)
	if err != nil {
		return record.ServiceRecord{}, err
	}
	key := hiddenDescriptorCipherKey(ref.Alias, ref.Secret, epoch)
	nonce, err := base64.RawURLEncoding.DecodeString(desc.Nonce)
	if err != nil {
		return record.ServiceRecord{}, fmt.Errorf("decode hidden descriptor nonce: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(desc.Ciphertext)
	if err != nil {
		return record.ServiceRecord{}, fmt.Errorf("decode hidden descriptor ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return record.ServiceRecord{}, fmt.Errorf("init hidden descriptor cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return record.ServiceRecord{}, fmt.Errorf("init hidden descriptor AEAD: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, hiddenDescriptorAAD(lookupKey, desc.ServiceTag, desc.NodeID))
	if err != nil {
		return record.ServiceRecord{}, fmt.Errorf("decrypt hidden descriptor: %w", err)
	}

	var rec record.ServiceRecord
	if payload, err := decodeHiddenDescriptorPayload(plaintext); err == nil {
		rec = payload.Record
	} else if err := strictjson.Decode(plaintext, &rec); err != nil {
		return record.ServiceRecord{}, fmt.Errorf("decode decrypted hidden record: %w", err)
	}
	if err := record.VerifyServiceRecord(rec, now); err != nil {
		return record.ServiceRecord{}, err
	}
	if !rec.IsHidden || rec.Alias != ref.Alias {
		return record.ServiceRecord{}, fmt.Errorf("decrypted hidden service alias %q does not match requested alias %q", rec.Alias, ref.Alias)
	}
	if rec.NodeID != desc.NodeID {
		return record.ServiceRecord{}, fmt.Errorf("hidden descriptor node id %q does not match decrypted record %q", desc.NodeID, rec.NodeID)
	}
	if rec.IssuedAt != desc.IssuedAt || rec.ExpiresAt != desc.ExpiresAt {
		return record.ServiceRecord{}, fmt.Errorf("hidden descriptor times do not match decrypted record")
	}
	if hiddenServiceTag(rec) != desc.ServiceTag {
		return record.ServiceRecord{}, fmt.Errorf("hidden descriptor service tag does not match decrypted record")
	}
	return rec, nil
}

func extractHiddenDescriptor(lookupKey, storedValue string, now time.Time) (HiddenDescriptor, error) {
	payload, err := extractLookupPayload(lookupKey, storedValue, now)
	if err != nil {
		return HiddenDescriptor{}, err
	}
	return parseHiddenDescriptor(payload)
}

func parseHiddenDescriptor(raw string) (HiddenDescriptor, error) {
	var desc HiddenDescriptor
	if err := strictjson.Decode([]byte(raw), &desc); err != nil {
		return HiddenDescriptor{}, fmt.Errorf("decode hidden descriptor: %w", err)
	}
	if desc.NodeID == "" || desc.ServiceTag == "" || desc.IssuedAt == "" || desc.ExpiresAt == "" || desc.Nonce == "" || desc.Ciphertext == "" {
		return HiddenDescriptor{}, fmt.Errorf("hidden descriptor missing required fields")
	}
	if _, err := time.Parse(time.RFC3339, desc.IssuedAt); err != nil {
		return HiddenDescriptor{}, fmt.Errorf("parse hidden descriptor issued_at: %w", err)
	}
	if _, err := time.Parse(time.RFC3339, desc.ExpiresAt); err != nil {
		return HiddenDescriptor{}, fmt.Errorf("parse hidden descriptor expires_at: %w", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(desc.Nonce); err != nil {
		return HiddenDescriptor{}, fmt.Errorf("decode hidden descriptor nonce: %w", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(desc.Ciphertext); err != nil {
		return HiddenDescriptor{}, fmt.Errorf("decode hidden descriptor ciphertext: %w", err)
	}
	return desc, nil
}

func extractLookupPayload(lookupKey, storedValue string, now time.Time) (string, error) {
	if env, ok, err := maybeDecodeEnvelope(storedValue); err != nil {
		return "", err
	} else if ok {
		if err := verifyEnvelope(lookupKey, env, now); err != nil {
			return "", err
		}
		return env.Value, nil
	}
	return storedValue, nil
}

func decodeLegacyHiddenServiceRecord(lookupKey, storedValue, alias string, now time.Time) (record.ServiceRecord, error) {
	payload, err := extractLookupPayload(lookupKey, storedValue, now)
	if err != nil {
		return record.ServiceRecord{}, err
	}

	var rec record.ServiceRecord
	if err := strictjson.Decode([]byte(payload), &rec); err != nil {
		return record.ServiceRecord{}, fmt.Errorf("decode legacy hidden descriptor: %w", err)
	}
	if err := record.VerifyServiceRecord(rec, now); err != nil {
		return record.ServiceRecord{}, err
	}
	if !rec.IsHidden || rec.Alias != alias {
		return record.ServiceRecord{}, fmt.Errorf("legacy hidden service alias %q does not match requested alias %q", rec.Alias, alias)
	}
	if stringsHasHiddenDescriptorKey(lookupKey) {
		epoch, err := parseHiddenDescriptorEpoch(lookupKey)
		if err != nil {
			return record.ServiceRecord{}, err
		}
		if expected := hiddenServiceKeyForRefEpoch(HiddenLookupRef{Alias: rec.Alias}, epoch); expected != lookupKey {
			return record.ServiceRecord{}, fmt.Errorf("legacy hidden descriptor key %q does not match alias-derived blinded key %q", lookupKey, expected)
		}
	}
	return rec, nil
}

func hiddenDescriptorCipherKey(alias, secret string, epoch int64) [32]byte {
	lookupSecret := alias
	if secret != "" {
		lookupSecret = secret
	}
	return sha256.Sum256([]byte("vx6-hidden-desc-v1-key\n" + alias + "\n" + lookupSecret + "\n" + strconv.FormatInt(epoch, 10)))
}

func hiddenServiceTag(rec record.ServiceRecord) string {
	sum := sha256.Sum256([]byte("vx6-hidden-service-tag\n" + rec.NodeID + "\n" + rec.ServiceName + "\n" + rec.Alias))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func hiddenDescriptorFingerprint(desc HiddenDescriptor) string {
	sum := sha256.Sum256([]byte(desc.NodeID + "\n" + desc.ServiceTag + "\n" + desc.IssuedAt + "\n" + desc.ExpiresAt + "\n" + desc.Nonce + "\n" + desc.Ciphertext))
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

func hiddenDescriptorAAD(lookupKey, serviceTag, nodeID string) []byte {
	return []byte("vx6-hidden-desc-v1\n" + lookupKey + "\n" + serviceTag + "\n" + nodeID + "\n")
}

func stringsHasHiddenDescriptorKey(key string) bool {
	return len(key) >= len("hidden-desc/v1/") && key[:len("hidden-desc/v1/")] == "hidden-desc/v1/"
}

func marshalHiddenDescriptorPayload(rec record.ServiceRecord) ([]byte, error) {
	payload := hiddenDescriptorPayload{Record: rec, Padding: ""}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal hidden descriptor payload: %w", err)
	}
	target := hiddenDescriptorPayloadTargetSize
	for len(raw) > target {
		target += 256
	}
	payload.Padding = strings.Repeat("x", target-len(raw))
	raw, err = json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal hidden descriptor payload: %w", err)
	}
	if len(raw) < target {
		payload.Padding += strings.Repeat("x", target-len(raw))
		raw, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal hidden descriptor payload: %w", err)
		}
	}
	return raw, nil
}

func decodeHiddenDescriptorPayload(plaintext []byte) (hiddenDescriptorPayload, error) {
	var payload hiddenDescriptorPayload
	if err := strictjson.Decode(plaintext, &payload); err != nil {
		return hiddenDescriptorPayload{}, err
	}
	if payload.Record.NodeID == "" || payload.Record.ServiceName == "" {
		return hiddenDescriptorPayload{}, fmt.Errorf("hidden descriptor payload missing wrapped record")
	}
	return payload, nil
}
