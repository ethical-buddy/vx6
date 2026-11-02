// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package liveness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vx6/vx6/internal/record"
)

type IdentityProvider func() (record.EndpointRecord, error)
type IdentityHandler func(context.Context, record.EndpointRecord, net.IP) error

type sourceBucket struct {
	tokens  float64
	updated time.Time
	seen    time.Time
}

// Responder serves only bounded VX6 liveness messages. It has a global limit
// plus a per-source limit; the response never exceeds the 512-byte request.
type Responder struct {
	mu      sync.Mutex
	global  sourceBucket
	sources map[string]sourceBucket
}

func NewResponder() *Responder {
	now := time.Now()
	return &Responder{
		global:  sourceBucket{tokens: 400, updated: now},
		sources: make(map[string]sourceBucket),
	}
}

func (r *Responder) Serve(ctx context.Context, conn *net.UDPConn, identity IdentityProvider, acceptIdentity IdentityHandler) error {
	closeDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-closeDone:
		}
	}()
	defer close(closeDone)
	buffer := make([]byte, maxPacketSize+1)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, source, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("read liveness datagram: %w", err)
		}
		request, err := decode(buffer[:n])
		if err != nil || request.kind != kindPing || !r.allow(source.IP.String(), time.Now()) {
			continue
		}
		response := message{kind: kindPong, nonce: request.nonce}
		if request.wantIdentity && identity != nil {
			if len(request.identityRecord) > 0 {
				caller, decodeErr := DecodeIdentity(request.identityRecord)
				if decodeErr != nil || record.VerifyEndpointRecord(caller, time.Now()) != nil || !endpointIPMatches(caller.Address, source.IP) {
					continue
				}
				if acceptIdentity != nil && acceptIdentity(ctx, caller, source.IP) != nil {
					continue
				}
				responseEndpoint, err := identity()
				if err == nil {
					response.identityRecord, _ = json.Marshal(responseEndpoint)
				}
			}
		}
		packet := encode(response)
		if len(packet) > n {
			continue
		}
		if _, err := conn.WriteToUDP(packet, source); err != nil && ctx.Err() == nil {
			return fmt.Errorf("write liveness response: %w", err)
		}
	}
}

func endpointIPMatches(address string, source net.IP) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil && ip.Equal(source)
}

func (r *Responder) allow(source string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !takeToken(&r.global, now, 200, 400) {
		return false
	}
	if bucket, ok := r.sources[source]; ok {
		if !takeToken(&bucket, now, 5, 10) {
			r.sources[source] = bucket
			return false
		}
		bucket.seen = now
		r.sources[source] = bucket
		return true
	}
	if len(r.sources) >= 2048 {
		oldestKey := ""
		var oldest time.Time
		for key, bucket := range r.sources {
			if now.Sub(bucket.seen) > time.Minute {
				delete(r.sources, key)
				continue
			}
			if oldestKey == "" || bucket.seen.Before(oldest) {
				oldestKey, oldest = key, bucket.seen
			}
		}
		if len(r.sources) >= 2048 && oldestKey != "" {
			delete(r.sources, oldestKey)
		}
	}
	bucket := sourceBucket{tokens: 10, updated: now, seen: now}
	if !takeToken(&bucket, now, 5, 10) {
		return false
	}
	r.sources[source] = bucket
	return true
}

func takeToken(bucket *sourceBucket, now time.Time, rate, burst float64) bool {
	if bucket.updated.IsZero() {
		bucket.tokens = burst
		bucket.updated = now
	}
	elapsed := now.Sub(bucket.updated).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * rate
		if bucket.tokens > burst {
			bucket.tokens = burst
		}
		bucket.updated = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}
