// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package onion

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/secure"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

type CircuitPlan struct {
	CircuitID  string
	Relays     []record.EndpointRecord
	TargetAddr string
	Purpose    string
}

type TraceEvent struct {
	CircuitID  string
	RelayNames []string
	RelayAddrs []string
	TargetAddr string
	Purpose    string
}

type InspectEvent struct {
	NodeID     string
	CircuitID  string
	Command    string
	NextHop    string
	TargetAddr string
	Bytes      int
}

type ClientOptions struct {
	Identity      identity.Identity
	TransportMode string
}

type extendCommand struct {
	NextHop         string `json:"next_hop"`
	ExpectedNodeID  string `json:"expected_node_id"`
	ClientPublicKey string `json:"client_public_key"`
}

type beginCommand struct {
	TargetAddr string `json:"target_addr"`
}

type errorCommand struct {
	Message string `json:"message"`
}

type clientHop struct {
	relay record.EndpointRecord
	keys  *circuitKeyState
}

type clientCircuitConn struct {
	base      net.Conn
	circuitID [16]byte
	hops      []clientHop

	writeMu   sync.Mutex
	closeOnce sync.Once

	readBuf []byte
	readCh  chan []byte
	errCh   chan error
}

var (
	traceMu   sync.RWMutex
	traceHook func(TraceEvent)

	inspectMu   sync.RWMutex
	inspectHook func(InspectEvent)
)

func SetTraceHook(fn func(TraceEvent)) func() {
	traceMu.Lock()
	prev := traceHook
	traceHook = fn
	traceMu.Unlock()
	return func() {
		traceMu.Lock()
		traceHook = prev
		traceMu.Unlock()
	}
}

func SetInspectHook(fn func(InspectEvent)) func() {
	inspectMu.Lock()
	prev := inspectHook
	inspectHook = fn
	inspectMu.Unlock()
	return func() {
		inspectMu.Lock()
		inspectHook = prev
		inspectMu.Unlock()
	}
}

func (p CircuitPlan) RelayAddrs() []string {
	out := make([]string, 0, len(p.Relays))
	for _, relay := range p.Relays {
		out = append(out, relay.Address)
	}
	return out
}

func PlanAutomatedCircuit(finalTarget record.ServiceRecord, allPeers []record.EndpointRecord, hopCount int, excludeAddrs []string) (CircuitPlan, error) {
	if hopCount <= 0 {
		return CircuitPlan{}, fmt.Errorf("hop count must be greater than zero")
	}

	targetAddr := finalTarget.Address
	if finalTarget.IsHidden && len(finalTarget.IntroPoints) > 0 {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		targetAddr = finalTarget.IntroPoints[rng.Intn(len(finalTarget.IntroPoints))]
	}
	if targetAddr == "" {
		return CircuitPlan{}, fmt.Errorf("service does not expose a reachable address for proxy mode")
	}

	seen := map[string]struct{}{targetAddr: {}}
	for _, addr := range excludeAddrs {
		if addr != "" {
			seen[addr] = struct{}{}
		}
	}

	filtered := make([]record.EndpointRecord, 0, len(allPeers))
	for _, peer := range allPeers {
		if peer.Address == "" {
			continue
		}
		if _, ok := seen[peer.Address]; ok {
			continue
		}
		seen[peer.Address] = struct{}{}
		filtered = append(filtered, peer)
	}

	if len(filtered) < hopCount {
		return CircuitPlan{}, fmt.Errorf("not enough peers in registry to build a %d-hop chain (need %d, have %d)", hopCount, hopCount, len(filtered))
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(filtered), func(i, j int) { filtered[i], filtered[j] = filtered[j], filtered[i] })
	relays := append([]record.EndpointRecord(nil), filtered[:hopCount]...)

	_, label, err := randomCircuitID()
	if err != nil {
		return CircuitPlan{}, err
	}

	return CircuitPlan{
		CircuitID:  label,
		Relays:     relays,
		TargetAddr: targetAddr,
		Purpose:    "relay",
	}, nil
}

func BuildAutomatedCircuit(ctx context.Context, finalTarget record.ServiceRecord, allPeers []record.EndpointRecord, opts ...ClientOptions) (net.Conn, error) {
	plan, err := PlanAutomatedCircuit(finalTarget, allPeers, 5, nil)
	if err != nil {
		return nil, err
	}
	return DialPlannedCircuit(ctx, plan, opts...)
}

func BuildAutomatedCircuitWithExclude(ctx context.Context, finalTarget record.ServiceRecord, allPeers []record.EndpointRecord, excludeAddrs []string, opts ...ClientOptions) (net.Conn, error) {
	plan, err := PlanAutomatedCircuit(finalTarget, allPeers, 5, excludeAddrs)
	if err != nil {
		return nil, err
	}
	return DialPlannedCircuit(ctx, plan, opts...)
}

func DialPlannedCircuit(ctx context.Context, plan CircuitPlan, opts ...ClientOptions) (net.Conn, error) {
	if len(plan.Relays) == 0 {
		return nil, fmt.Errorf("circuit plan has no relays")
	}

	circuitID := circuitIDFromString(plan.CircuitID)
	if plan.CircuitID == "" {
		_, label, err := randomCircuitID()
		if err != nil {
			return nil, err
		}
		plan.CircuitID = label
		circuitID = circuitIDFromString(plan.CircuitID)
	}

	clientOpts, err := resolveClientOptions(opts)
	if err != nil {
		return nil, err
	}

	fmt.Printf("[CIRCUIT] Building automated circuit via: ")
	for _, relay := range plan.Relays {
		fmt.Printf("%s -> ", relay.NodeName)
	}
	fmt.Printf("TARGET\n")
	notifyTrace(plan)

	firstConn, err := dialRelayConn(ctx, plan.Relays[0].Address, clientOpts, plan.Relays[0].NodeID)
	if err != nil {
		return nil, fmt.Errorf("first hop connection failed: %w", err)
	}

	hops := make([]clientHop, 0, len(plan.Relays))
	if err := establishFirstHop(firstConn, circuitID, plan.Relays[0], &hops); err != nil {
		_ = firstConn.Close()
		return nil, err
	}

	for i := 1; i < len(plan.Relays); i++ {
		hop, err := extendCircuit(firstConn, circuitID, plan.Relays[i], hops)
		if err != nil {
			_ = firstConn.Close()
			return nil, err
		}
		hops = append(hops, hop)
	}

	if plan.TargetAddr != "" {
		if err := beginCircuit(firstConn, circuitID, plan.TargetAddr, hops); err != nil {
			_ = firstConn.Close()
			return nil, err
		}
	}

	cc := &clientCircuitConn{
		base:      firstConn,
		circuitID: circuitID,
		hops:      hops,
		readCh:    make(chan []byte, 16),
		errCh:     make(chan error, 1),
	}
	go cc.readPump()
	return cc, nil
}

func establishFirstHop(conn net.Conn, circuitID [16]byte, relay record.EndpointRecord, hops *[]clientHop) error {
	clientPriv, clientPub, err := createClientKey()
	if err != nil {
		return err
	}
	if err := writeCell(conn, cell{Type: cellTypeCreate, CircuitID: circuitID, Payload: clientPub[:]}); err != nil {
		return err
	}
	resp, err := readCell(conn)
	if err != nil {
		return err
	}
	if resp.Type != cellTypeCreated {
		return fmt.Errorf("expected created cell from first hop, got %d", resp.Type)
	}
	keys, err := deriveClientHopKeys(clientPriv, resp.Payload, relay, circuitID, clientPub)
	if err != nil {
		return err
	}
	*hops = append(*hops, clientHop{relay: relay, keys: keys})
	return nil
}

func extendCircuit(conn net.Conn, circuitID [16]byte, relay record.EndpointRecord, hops []clientHop) (clientHop, error) {
	clientPriv, clientPub, err := createClientKey()
	if err != nil {
		return clientHop{}, err
	}
	body, err := json.Marshal(extendCommand{
		NextHop:         relay.Address,
		ExpectedNodeID:  relay.NodeID,
		ClientPublicKey: base64.StdEncoding.EncodeToString(clientPub[:]),
	})
	if err != nil {
		return clientHop{}, fmt.Errorf("encode extend command: %w", err)
	}
	if err := sendRelayCommand(conn, circuitID, hops, relayCmdExtend, body); err != nil {
		return clientHop{}, err
	}
	cmd, payload, err := readRelayResponse(conn, circuitID, hops)
	if err != nil {
		return clientHop{}, err
	}
	if cmd == relayCmdError {
		var e errorCommand
		if json.Unmarshal(payload, &e) == nil && e.Message != "" {
			return clientHop{}, fmt.Errorf(e.Message)
		}
		return clientHop{}, fmt.Errorf("relay extend failed")
	}
	if cmd != relayCmdExtended {
		return clientHop{}, fmt.Errorf("expected extended response, got %d", cmd)
	}
	keys, err := deriveClientHopKeys(clientPriv, payload, relay, circuitID, clientPub)
	if err != nil {
		return clientHop{}, err
	}
	return clientHop{relay: relay, keys: keys}, nil
}

func beginCircuit(conn net.Conn, circuitID [16]byte, targetAddr string, hops []clientHop) error {
	body, err := json.Marshal(beginCommand{TargetAddr: targetAddr})
	if err != nil {
		return fmt.Errorf("encode begin command: %w", err)
	}
	if err := sendRelayCommand(conn, circuitID, hops, relayCmdBegin, body); err != nil {
		return err
	}
	cmd, payload, err := readRelayResponse(conn, circuitID, hops)
	if err != nil {
		return err
	}
	if cmd == relayCmdError {
		var e errorCommand
		if json.Unmarshal(payload, &e) == nil && e.Message != "" {
			return fmt.Errorf(e.Message)
		}
		return fmt.Errorf("relay begin failed")
	}
	if cmd != relayCmdConnected {
		return fmt.Errorf("expected connected response, got %d", cmd)
	}
	return nil
}

func sendRelayCommand(conn net.Conn, circuitID [16]byte, hops []clientHop, command byte, body []byte) error {
	payload, err := encodeRelayEnvelope(command, body)
	if err != nil {
		return err
	}
	for i := len(hops) - 1; i >= 0; i-- {
		payload = hops[i].keys.sealForward(payload)
	}
	return writeCell(conn, cell{
		Type:      cellTypeRelay,
		CircuitID: circuitID,
		Payload:   payload,
	})
}

func readRelayResponse(conn net.Conn, circuitID [16]byte, hops []clientHop) (byte, []byte, error) {
	for {
		resp, err := readCell(conn)
		if err != nil {
			return 0, nil, err
		}
		if resp.CircuitID != circuitID {
			return 0, nil, fmt.Errorf("mismatched circuit id in relay response")
		}
		switch resp.Type {
		case cellTypeRelay:
			payload := resp.Payload
			for i := 0; i < len(hops); i++ {
				payload, err = hops[i].keys.openBackward(payload)
				if err != nil {
					return 0, nil, err
				}
			}
			cmd, body, recognized, err := decodeRelayEnvelope(payload)
			if err != nil {
				return 0, nil, err
			}
			if !recognized {
				return 0, nil, fmt.Errorf("relay response remained opaque after full unwrap")
			}
			return cmd, body, nil
		case cellTypeDestroy:
			return relayCmdEnd, nil, io.EOF
		default:
			return 0, nil, fmt.Errorf("unexpected relay response cell type %d", resp.Type)
		}
	}
}

func deriveClientHopKeys(priv *ecdh.PrivateKey, payload []byte, relay record.EndpointRecord, circuitID [16]byte, clientPub [32]byte) (*circuitKeyState, error) {
	serverPub, err := verifyCreatedPayload(payload, relay.PublicKey, circuitID, clientPub)
	if err != nil {
		return nil, err
	}
	serverKey, err := ecdh.X25519().NewPublicKey(serverPub[:])
	if err != nil {
		return nil, fmt.Errorf("parse relay response public key: %w", err)
	}
	shared, err := priv.ECDH(serverKey)
	if err != nil {
		return nil, fmt.Errorf("derive client relay key: %w", err)
	}
	return deriveCircuitKeys(shared, circuitID)
}

func resolveClientOptions(opts []ClientOptions) (ClientOptions, error) {
	if len(opts) > 0 {
		if err := opts[0].Identity.Validate(); err == nil {
			return opts[0], nil
		}
	}
	id, err := identity.Generate()
	if err != nil {
		return ClientOptions{}, fmt.Errorf("generate transient onion identity: %w", err)
	}
	if len(opts) > 0 {
		opts[0].Identity = id
		return opts[0], nil
	}
	return ClientOptions{Identity: id}, nil
}

func dialRelayConn(ctx context.Context, addr string, opts ClientOptions, expectedNodeID string) (net.Conn, error) {
	mode := opts.TransportMode
	if mode == "" {
		mode = vxtransport.ModeAuto
	}
	conn, err := vxtransport.DialContext(ctx, mode, addr)
	if err != nil {
		return nil, err
	}
	if err := proto.WriteHeader(conn, proto.KindExtend); err != nil {
		_ = conn.Close()
		return nil, err
	}
	secureConn, err := secure.Client(conn, proto.KindExtend, opts.Identity)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if expectedNodeID != "" && secureConn.PeerNodeID() != expectedNodeID {
		_ = secureConn.Close()
		return nil, fmt.Errorf("relay identity mismatch: got %s want %s", secureConn.PeerNodeID(), expectedNodeID)
	}
	return secureConn, nil
}

func notifyTrace(plan CircuitPlan) {
	traceMu.RLock()
	hook := traceHook
	traceMu.RUnlock()
	if hook == nil {
		return
	}

	event := TraceEvent{
		CircuitID:  plan.CircuitID,
		RelayNames: make([]string, 0, len(plan.Relays)),
		RelayAddrs: make([]string, 0, len(plan.Relays)),
		TargetAddr: plan.TargetAddr,
		Purpose:    plan.Purpose,
	}
	for _, relay := range plan.Relays {
		event.RelayNames = append(event.RelayNames, relay.NodeName)
		event.RelayAddrs = append(event.RelayAddrs, relay.Address)
	}
	hook(event)
}

func notifyInspect(ev InspectEvent) {
	inspectMu.RLock()
	hook := inspectHook
	inspectMu.RUnlock()
	if hook != nil {
		hook(ev)
	}
}

func commandName(cmd byte) string {
	switch cmd {
	case relayCmdExtend:
		return "extend"
	case relayCmdExtended:
		return "extended"
	case relayCmdBegin:
		return "begin"
	case relayCmdConnected:
		return "connected"
	case relayCmdData:
		return "data"
	case relayCmdEnd:
		return "end"
	case relayCmdError:
		return "error"
	default:
		return fmt.Sprintf("unknown-%d", cmd)
	}
}

func (c *clientCircuitConn) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		select {
		case chunk := <-c.readCh:
			if len(chunk) == 0 {
				continue
			}
			c.readBuf = chunk
		case err := <-c.errCh:
			if err == nil {
				err = io.EOF
			}
			return 0, err
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *clientCircuitConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxRelayDataPayload {
			n = maxRelayDataPayload
		}
		if err := sendRelayCommand(c.base, c.circuitID, c.hops, relayCmdData, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *clientCircuitConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.writeMu.Lock()
		_ = sendRelayCommand(c.base, c.circuitID, c.hops, relayCmdEnd, nil)
		_ = writeCell(c.base, cell{Type: cellTypeDestroy, CircuitID: c.circuitID})
		c.writeMu.Unlock()
		err = c.base.Close()
	})
	return err
}

func (c *clientCircuitConn) LocalAddr() net.Addr  { return c.base.LocalAddr() }
func (c *clientCircuitConn) RemoteAddr() net.Addr { return c.base.RemoteAddr() }
func (c *clientCircuitConn) SetDeadline(t time.Time) error {
	return c.base.SetDeadline(t)
}
func (c *clientCircuitConn) SetReadDeadline(t time.Time) error {
	return c.base.SetReadDeadline(t)
}
func (c *clientCircuitConn) SetWriteDeadline(t time.Time) error {
	return c.base.SetWriteDeadline(t)
}

func (c *clientCircuitConn) readPump() {
	for {
		cell, err := readCell(c.base)
		if err != nil {
			c.errCh <- err
			return
		}
		switch cell.Type {
		case cellTypeRelay:
			payload := cell.Payload
			for i := 0; i < len(c.hops); i++ {
				payload, err = c.hops[i].keys.openBackward(payload)
				if err != nil {
					c.errCh <- err
					return
				}
			}
			cmd, body, recognized, err := decodeRelayEnvelope(payload)
			if err != nil {
				c.errCh <- err
				return
			}
			if !recognized {
				c.errCh <- fmt.Errorf("received opaque relay payload after full unwrap")
				return
			}
			switch cmd {
			case relayCmdData:
				c.readCh <- body
			case relayCmdEnd:
				c.errCh <- io.EOF
				return
			case relayCmdError:
				var e errorCommand
				if json.Unmarshal(body, &e) == nil && e.Message != "" {
					c.errCh <- fmt.Errorf(e.Message)
				} else {
					c.errCh <- fmt.Errorf("relay circuit closed with error")
				}
				return
			default:
				continue
			}
		case cellTypeDestroy:
			c.errCh <- io.EOF
			return
		default:
			c.errCh <- fmt.Errorf("unexpected onion cell type %d", cell.Type)
			return
		}
	}
}
