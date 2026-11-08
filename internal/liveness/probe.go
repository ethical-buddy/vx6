// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the VX6 terms in LICENSE-COMMERCIAL.md.
// Sole inventor, maintainer, and rights holder: Suryansh Deshwal (https://github.com/ethical-buddy).

package liveness

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/strictjson"
)

const (
	probePortOffset = 1
	maxPacketSize   = 512
	headerSize      = 25
	version         = 1
	kindPing        = 1
	kindPong        = 2
)

var wireMagic = [4]byte{'V', '6', 'L', 'P'}

type message struct {
	kind           byte
	wantIdentity   bool
	nonce          [16]byte
	identityRecord []byte
}

type Cache struct {
	mu     sync.Mutex
	alive  map[string]time.Time
	maxAge time.Duration
}

func NewCache(maxAge time.Duration) *Cache {
	if maxAge <= 0 {
		maxAge = 20 * time.Second
	}
	return &Cache{alive: make(map[string]time.Time), maxAge: maxAge}
}

func (c *Cache) IsAlive(endpoint string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen, ok := c.alive[endpoint]
	if !ok {
		return false
	}
	if now.Sub(seen) >= c.maxAge {
		delete(c.alive, endpoint)
		return false
	}
	return true
}

func (c *Cache) MarkAlive(endpoint string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.alive) >= 4096 {
		for addr, seen := range c.alive {
			if now.Sub(seen) >= c.maxAge {
				delete(c.alive, addr)
			}
		}
		if len(c.alive) >= 4096 {
			for addr := range c.alive {
				delete(c.alive, addr)
				break
			}
		}
	}
	c.alive[endpoint] = now
}

func (c *Cache) MarkFailed(endpoint string) {
	c.mu.Lock()
	delete(c.alive, endpoint)
	c.mu.Unlock()
}

// ProbeAddress maps the advertised VX6 TCP/QUIC endpoint to the adjacent UDP
// port reserved for the small, pre-IKE liveness probe.
func ProbeAddress(endpoint string) (string, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid VX6 endpoint: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		return "", errors.New("liveness probe requires an IPv6 endpoint")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port+probePortOffset > 65535 {
		return "", errors.New("VX6 endpoint port cannot be used for liveness probing")
	}
	return net.JoinHostPort(host, strconv.Itoa(port+probePortOffset)), nil
}

// Probe sends one unauthenticated, fixed-format UDP challenge. A PONG is only
// a reachability hint; callers must still authenticate the peer with IKE.
func Probe(ctx context.Context, endpoint string, wantIdentity bool, timeout time.Duration) (*record.EndpointRecord, time.Duration, error) {
	return probe(ctx, endpoint, nil, wantIdentity, timeout)
}

// ExchangeIdentity gives the first-contact peer our signed endpoint record
// and asks it to return its own. IKE subsequently proves both private keys.
func ExchangeIdentity(ctx context.Context, endpoint string, own record.EndpointRecord, timeout time.Duration) (*record.EndpointRecord, time.Duration, error) {
	return probe(ctx, endpoint, &own, true, timeout)
}

// DecodeIdentity decodes a first-contact identity carried by the fixed-size
// probe. The caller must verify its signature and bind its address to source.
func DecodeIdentity(data []byte) (record.EndpointRecord, error) {
	var endpoint record.EndpointRecord
	if len(data) == 0 {
		return endpoint, errors.New("identity probe has no sender identity")
	}
	if err := strictjson.Decode(data, &endpoint); err != nil {
		return endpoint, fmt.Errorf("decode sender identity record: %w", err)
	}
	return endpoint, nil
}

func probe(ctx context.Context, endpoint string, own *record.EndpointRecord, wantIdentity bool, timeout time.Duration) (*record.EndpointRecord, time.Duration, error) {
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	probeAddr, err := ProbeAddress(endpoint)
	if err != nil {
		return nil, 0, err
	}
	remote, err := net.ResolveUDPAddr("udp6", probeAddr)
	if err != nil {
		return nil, 0, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp6", remote.String())
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, 0, fmt.Errorf("create liveness nonce: %w", err)
	}
	var ownRecord []byte
	if own != nil {
		ownRecord, err = json.Marshal(own)
		if err != nil {
			return nil, 0, fmt.Errorf("encode local peer identity: %w", err)
		}
	}
	request := encode(message{kind: kindPing, wantIdentity: wantIdentity, nonce: nonce, identityRecord: ownRecord})
	started := time.Now()
	if _, err := conn.Write(request); err != nil {
		return nil, 0, err
	}
	buffer := make([]byte, maxPacketSize+1)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, time.Since(started), err
	}
	response, err := decode(buffer[:n])
	if err != nil {
		return nil, time.Since(started), err
	}
	if response.kind != kindPong || response.nonce != nonce {
		return nil, time.Since(started), errors.New("liveness response did not match the outstanding challenge")
	}
	if wantIdentity {
		if len(response.identityRecord) == 0 {
			return nil, time.Since(started), errors.New("peer is live but did not provide its signed identity record")
		}
		var endpointRecord record.EndpointRecord
		if err := strictjson.Decode(response.identityRecord, &endpointRecord); err != nil {
			return nil, time.Since(started), fmt.Errorf("decode peer identity record: %w", err)
		}
		return &endpointRecord, time.Since(started), nil
	}
	if len(response.identityRecord) != 0 {
		return nil, time.Since(started), errors.New("unexpected identity data in compact liveness response")
	}
	return nil, time.Since(started), nil
}

func encode(msg message) []byte {
	out := make([]byte, headerSize)
	copy(out[:4], wireMagic[:])
	out[4] = version
	out[5] = msg.kind
	if msg.wantIdentity {
		out[6] = 1
	}
	copy(out[7:headerSize], msg.nonce[:])
	if len(msg.identityRecord) > maxPacketSize-headerSize {
		return nil
	}
	binary.BigEndian.PutUint16(out[23:25], uint16(len(msg.identityRecord)))
	if msg.kind == kindPing && msg.wantIdentity {
		out = append(out, msg.identityRecord...)
		out = append(out, make([]byte, maxPacketSize-len(out))...)
	}
	if msg.kind == kindPong && len(msg.identityRecord) > 0 {
		out = append(out, msg.identityRecord...)
	}
	return out
}

func decode(data []byte) (message, error) {
	if len(data) < headerSize || len(data) > maxPacketSize {
		return message{}, errors.New("invalid liveness packet length")
	}
	if string(data[:4]) != string(wireMagic[:]) || data[4] != version {
		return message{}, errors.New("invalid liveness packet header")
	}
	msg := message{kind: data[5], wantIdentity: data[6] == 1}
	if data[6] > 1 {
		return message{}, errors.New("invalid liveness packet flags")
	}
	copy(msg.nonce[:], data[7:headerSize])
	payloadLen := int(binary.BigEndian.Uint16(data[23:25]))
	if payloadLen > len(data)-headerSize {
		return message{}, errors.New("invalid liveness identity payload length")
	}
	if msg.nonce == [16]byte{} {
		return message{}, errors.New("empty liveness nonce")
	}
	switch msg.kind {
	case kindPing:
		if msg.wantIdentity {
			if len(data) != maxPacketSize {
				return message{}, errors.New("identity probe must use the fixed padded request size")
			}
			msg.identityRecord = append([]byte(nil), data[headerSize:headerSize+payloadLen]...)
			for _, b := range data[headerSize+payloadLen:] {
				if b != 0 {
					return message{}, errors.New("invalid identity probe padding")
				}
			}
		} else if len(data) != headerSize || payloadLen != 0 {
			return message{}, errors.New("compact probe has unexpected payload")
		}
	case kindPong:
		if msg.wantIdentity {
			return message{}, errors.New("PONG must not set request flags")
		}
		if len(data) != headerSize+payloadLen {
			return message{}, errors.New("unexpected data after liveness identity payload")
		}
		msg.identityRecord = append([]byte(nil), data[headerSize:]...)
	default:
		return message{}, errors.New("invalid liveness packet type")
	}
	return msg, nil
}
