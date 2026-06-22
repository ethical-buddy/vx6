// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package proto

import (
	"encoding/binary"
	"fmt"
	"io"
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
)

type DHTRequest struct {
	Action string `json:"action"` // "find_node", "find_value", "store"
	Target string `json:"target"` // NodeID or Service Name we are looking for
	Data   string `json:"data"`   // The value to store (e.g. a signed record)
}

type DHTResponse struct {
	Nodes []NodeInfo `json:"nodes"` // Closest nodes to the target
	Value string     `json:"value"` // Found address/descriptor (if any)
}

type NodeInfo struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Addr string `json:"addr"`
}

type ExtendRequest struct {
	NextHop    string `json:"next_hop"`    // The address of the next node to add to the chain
	CircuitID  string `json:"circuit_id"`  // Unique ID for this specific tunnel
}

type OnionHeader struct {
	HopCount int      `json:"hop_count"` // Current hop (0-4)
	Hops     [5]string `json:"hops"`      // IPv6 addresses of the 5 nodes
	FinalDst string   `json:"final_dst"` // The ultimate destination (e.g., 127.0.0.1:8000)
	Payload  []byte   `json:"payload"`   // The actual encrypted data
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
