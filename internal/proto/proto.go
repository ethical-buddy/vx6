// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package proto

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

var magic = [4]byte{'V', 'X', '6', '1'}

const (
	KindFileTransfer byte = 1
	KindDiscoveryReq byte = 2
	KindDiscoveryRes byte = 3
	KindServiceConn  byte = 4
	KindOnion        byte = 5
	KindExtend       byte = 6
	KindRendezvous   byte = 7
	KindDHT          byte = 8 // New: Distributed Hash Table
	KindLiveness     byte = 9
)

type DHTRequest struct {
	Type   DHTRequestType `json:"type"`
	Action string         `json:"action"` // "find_node", "find_value", "store"
	Target string         `json:"target"` // NodeID or Service Name we are looking for
	Data   string         `json:"data"`   // The value to store (e.g. a signed record)
}

type DHTRequestType string

const (
	DHTTypeBootstrap   DHTRequestType = "bootstrap"
	DHTTypeUpdate      DHTRequestType = "update"
	DHTTypeLookupName  DHTRequestType = "lookup_name"
	DHTTypeLookupKey   DHTRequestType = "lookup_key"
	DHTTypeLookupSvc   DHTRequestType = "lookup_service"
	DHTTypeLookupPriv  DHTRequestType = "lookup_private"
	DHTTypeLookupHid   DHTRequestType = "lookup_hidden"
	DHTTypeLookupOther DHTRequestType = "lookup_other"
)

type DHTResponse struct {
	Type  DHTRequestType `json:"type"`
	Nodes []NodeInfo     `json:"nodes"` // Closest nodes to the target
	Value string         `json:"value"` // Found address/descriptor (if any)
}

func DHTTypeFor(action, target string) DHTRequestType {
	if action == "store" {
		return DHTTypeUpdate
	}
	switch {
	case strings.HasPrefix(target, "node/name/"):
		return DHTTypeLookupName
	case strings.HasPrefix(target, "node/id/"):
		return DHTTypeLookupKey
	case strings.HasPrefix(target, "service/"):
		return DHTTypeLookupSvc
	case strings.HasPrefix(target, "private-catalog/"):
		return DHTTypeLookupPriv
	case strings.HasPrefix(target, "hidden-desc/v1/"):
		return DHTTypeLookupHid
	case action == "find_node":
		return DHTTypeBootstrap
	default:
		return DHTTypeLookupOther
	}
}

func (r DHTRequest) Validate() error {
	if r.Target == "" || len(r.Target) > 512 {
		return fmt.Errorf("DHT request target is empty or too long")
	}
	if len(r.Data) > 1024*1024 {
		return fmt.Errorf("DHT request data is too large")
	}
	switch r.Type {
	case DHTTypeLookupName:
		if (r.Action != "find_value" && r.Action != "find_node") || !isSHA256Hex(r.Target) {
			return fmt.Errorf("name lookup target must be a full SHA-256 digest")
		}
	case DHTTypeLookupKey:
		if (r.Action != "find_value" && r.Action != "find_node") || !strings.HasPrefix(r.Target, "vx6_") || !isSHA256Hex(strings.TrimPrefix(r.Target, "vx6_")) {
			return fmt.Errorf("identity lookup target must contain a full NodeID")
		}
	case DHTTypeBootstrap:
		if r.Action != "find_node" || !(isSHA256Hex(r.Target) || (strings.HasPrefix(r.Target, "vx6_") && isSHA256Hex(strings.TrimPrefix(r.Target, "vx6_")))) {
			return fmt.Errorf("bootstrap target must be a full name hash or NodeID")
		}
	case DHTTypeUpdate, DHTTypeLookupSvc, DHTTypeLookupPriv, DHTTypeLookupHid, DHTTypeLookupOther:
	default:
		return fmt.Errorf("unsupported DHT request type %q", r.Type)
	}
	if r.Type != DHTTypeLookupName && r.Type != DHTTypeLookupKey && r.Type != DHTTypeBootstrap &&
		r.Type != DHTTypeFor(r.Action, r.Target) {
		return fmt.Errorf("DHT request type %q does not match action %q and target", r.Type, r.Action)
	}
	switch r.Action {
	case "find_node", "find_value":
		if r.Data != "" {
			return fmt.Errorf("DHT lookup request must not contain update data")
		}
	case "store":
		if r.Data == "" {
			return fmt.Errorf("DHT update request has no data")
		}
	default:
		return fmt.Errorf("unsupported DHT action %q", r.Action)
	}
	return nil
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

type NodeInfo struct {
	IdentityVersion   uint8  `json:"identity_version,omitempty"`
	IdentitySequence  uint64 `json:"identity_sequence,omitempty"`
	ID                string `json:"id"`
	Name              string `json:"name,omitempty"`
	NameHash          string `json:"name_hash,omitempty"`
	Addr              string `json:"addr"`
	PublicKey         string `json:"public_key,omitempty"`
	IdentityIssuedAt  string `json:"identity_issued_at,omitempty"`
	IdentityExpiresAt string `json:"identity_expires_at,omitempty"`
	IdentitySignature string `json:"identity_signature,omitempty"`
}

type ExtendRequest struct {
	NextHop   string `json:"next_hop"`   // The address of the next node to add to the chain
	CircuitID string `json:"circuit_id"` // Unique ID for this specific tunnel
}

type OnionHeader struct {
	HopCount int       `json:"hop_count"` // Current hop (0-4)
	Hops     [5]string `json:"hops"`      // IPv6 addresses of the 5 nodes
	FinalDst string    `json:"final_dst"` // The ultimate destination (e.g., 127.0.0.1:8000)
	Payload  []byte    `json:"payload"`   // The actual encrypted data
}

func WriteHeader(w io.Writer, kind byte) error {
	var header [5]byte
	copy(header[:4], magic[:])
	header[4] = kind
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("write protocol header: %w", err)
	}
	return nil
}

func ReadHeader(r io.Reader) (byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, fmt.Errorf("read protocol header: %w", err)
	}
	if header[0] != magic[0] || header[1] != magic[1] || header[2] != magic[2] || header[3] != magic[3] {
		return 0, fmt.Errorf("invalid protocol magic")
	}
	return header[4], nil
}

func WriteLengthPrefixed(w io.Writer, payload []byte) error {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(payload)))
	if _, err := w.Write(size[:]); err != nil {
		return fmt.Errorf("write payload size: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

func ReadLengthPrefixed(r io.Reader, maxSize uint32) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, fmt.Errorf("read payload size: %w", err)
	}

	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > maxSize {
		return nil, fmt.Errorf("invalid payload size %d", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	return payload, nil
}
