package onion

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/strictjson"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

type relayCircuit struct {
	nodeID    string
	identity  identity.Identity
	circuitID [16]byte
	label     string
	inbound   net.Conn
	keys      *circuitKeyState

	outbound   net.Conn
	targetConn net.Conn

	writeMu sync.Mutex
	mu      sync.Mutex
}

func HandleExtend(ctx context.Context, inbound net.Conn, id identity.Identity) error {
	firstCell, err := readCell(inbound)
	if err != nil {
		return err
	}
	if firstCell.Type != cellTypeCreate {
		return fmt.Errorf("expected create cell, got %d", firstCell.Type)
	}
	clientPub, err := parseCreatePayload(firstCell.Payload)
	if err != nil {
		return err
	}
	relayPriv, _, err := createClientKey()
	if err != nil {
		return err
	}
	created, shared, err := buildCreatedPayload(firstCell.CircuitID, clientPub, relayPriv, id.PrivateKey)
	if err != nil {
		return err
	}
	keys, err := deriveCircuitKeys(shared, firstCell.CircuitID)
	if err != nil {
		return err
	}
	circuit := &relayCircuit{
		nodeID:    id.NodeID,
		identity:  id,
		circuitID: firstCell.CircuitID,
		label:     fmt.Sprintf("%x", firstCell.CircuitID[:]),
		inbound:   inbound,
		keys:      keys,
	}
	if err := writeCell(inbound, cell{
		Type:      cellTypeCreated,
		CircuitID: firstCell.CircuitID,
		Payload:   marshalCreatedPayload(created),
	}); err != nil {
		return err
	}
	notifyInspect(InspectEvent{
		NodeID:    id.NodeID,
		CircuitID: circuit.label,
		Command:   "create",
	})
	return circuit.serve(ctx)
}

func (c *relayCircuit) serve(ctx context.Context) error {
	defer c.closeAll()
	for {
		nextCell, err := readCell(c.inbound)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if nextCell.CircuitID != c.circuitID {
			return fmt.Errorf("unexpected circuit id on relay segment")
		}
		switch nextCell.Type {
		case cellTypeRelay:
			if err := c.handleRelayCell(ctx, nextCell.Payload); err != nil {
				return err
			}
		case cellTypeDestroy:
			if out := c.getOutbound(); out != nil {
				_ = writeCell(out, cell{Type: cellTypeDestroy, CircuitID: c.circuitID})
			}
			return nil
		default:
			return fmt.Errorf("unexpected onion cell type %d", nextCell.Type)
		}
	}
}

func (c *relayCircuit) handleRelayCell(ctx context.Context, payload []byte) error {
	inner, err := c.keys.openForward(payload)
	if err != nil {
		return err
	}
	cmd, body, recognized, err := decodeRelayEnvelope(inner)
	if err != nil {
		return err
	}
	if !recognized {
		out := c.getOutbound()
		if out == nil {
			return fmt.Errorf("opaque relay payload arrived before outbound hop existed")
		}
		return writeCell(out, cell{
			Type:      cellTypeRelay,
			CircuitID: c.circuitID,
			Payload:   inner,
		})
	}

	switch cmd {
	case relayCmdExtend:
		var req extendCommand
		if err := strictjson.Decode(body, &req); err != nil {
			return c.sendBackwardError(fmt.Errorf("decode extend command: %w", err))
		}
		if len(req.NextHop) > 128 || len(req.ExpectedNodeID) > 80 || len(req.ClientPublicKey) != 44 {
			return c.sendBackwardError(fmt.Errorf("invalid extend command field sizes"))
		}
		notifyInspect(InspectEvent{
			NodeID:    c.nodeID,
			CircuitID: c.label,
			Command:   commandName(cmd),
			NextHop:   req.NextHop,
		})
		return c.handleExtendCommand(ctx, req)
	case relayCmdBegin:
		var req beginCommand
		if err := strictjson.Decode(body, &req); err != nil {
			return c.sendBackwardError(fmt.Errorf("decode begin command: %w", err))
		}
		if req.TargetAddr == "" || len(req.TargetAddr) > 512 {
			return c.sendBackwardError(fmt.Errorf("invalid begin target"))
		}
		notifyInspect(InspectEvent{
			NodeID:     c.nodeID,
			CircuitID:  c.label,
			Command:    commandName(cmd),
			TargetAddr: req.TargetAddr,
		})
		return c.handleBeginCommand(ctx, req)
	case relayCmdData:
		target := c.getTarget()
		if target == nil {
			return c.sendBackwardError(fmt.Errorf("circuit has no target connection"))
		}
		notifyInspect(InspectEvent{
			NodeID:    c.nodeID,
			CircuitID: c.label,
			Command:   commandName(cmd),
			Bytes:     len(body),
		})
		_, err := target.Write(body)
		return err
	case relayCmdEnd:
		notifyInspect(InspectEvent{
			NodeID:    c.nodeID,
			CircuitID: c.label,
			Command:   commandName(cmd),
		})
		c.closeTarget()
		return c.sendBackwardPlain(relayCmdEnd, nil)
	default:
		return c.sendBackwardError(fmt.Errorf("unsupported relay command %d", cmd))
	}
}

func (c *relayCircuit) handleExtendCommand(ctx context.Context, req extendCommand) error {
	if req.NextHop == "" {
		return c.sendBackwardError(fmt.Errorf("extend command missing next hop"))
	}
	clientPubRaw, err := base64.StdEncoding.DecodeString(req.ClientPublicKey)
	if err != nil {
		return c.sendBackwardError(fmt.Errorf("decode extend client key: %w", err))
	}
	if len(clientPubRaw) != 32 {
		return c.sendBackwardError(fmt.Errorf("invalid extend client key size"))
	}

	c.mu.Lock()
	if c.outbound != nil {
		c.mu.Unlock()
		return c.sendBackwardError(fmt.Errorf("circuit already extended"))
	}
	c.mu.Unlock()

	outbound, err := dialRelayConn(ctx, req.NextHop, ClientOptions{Identity: c.identity, TransportMode: vxtransport.ModeAuto}, req.ExpectedNodeID)
	if err != nil {
		return c.sendBackwardError(fmt.Errorf("dial next relay %s: %w", req.NextHop, err))
	}

	if err := writeCell(outbound, cell{
		Type:      cellTypeCreate,
		CircuitID: c.circuitID,
		Payload:   append([]byte(nil), clientPubRaw...),
	}); err != nil {
		_ = outbound.Close()
		return c.sendBackwardError(fmt.Errorf("forward create to next relay: %w", err))
	}
	created, err := readCell(outbound)
	if err != nil {
		_ = outbound.Close()
		return c.sendBackwardError(fmt.Errorf("read created from next relay: %w", err))
	}
	if created.Type != cellTypeCreated {
		_ = outbound.Close()
		return c.sendBackwardError(fmt.Errorf("expected created from next relay, got %d", created.Type))
	}

	c.mu.Lock()
	c.outbound = outbound
	c.mu.Unlock()
	go c.pumpOutbound(outbound)
	return c.sendBackwardPlain(relayCmdExtended, created.Payload)
}

func (c *relayCircuit) handleBeginCommand(ctx context.Context, req beginCommand) error {
	if req.TargetAddr == "" {
		return c.sendBackwardError(fmt.Errorf("begin command missing target"))
	}

	c.mu.Lock()
	if c.targetConn != nil {
		c.mu.Unlock()
		return c.sendBackwardError(fmt.Errorf("circuit already has a target"))
	}
	c.mu.Unlock()

	target, err := vxtransport.DialContext(ctx, vxtransport.ModeAuto, req.TargetAddr)
	if err != nil {
		return c.sendBackwardError(fmt.Errorf("dial circuit target %s: %w", req.TargetAddr, err))
	}
	c.mu.Lock()
	c.targetConn = target
	c.mu.Unlock()
	go c.pumpTarget(target)
	return c.sendBackwardPlain(relayCmdConnected, nil)
}

func (c *relayCircuit) pumpOutbound(outbound net.Conn) {
	defer func() {
		_ = outbound.Close()
		c.mu.Lock()
		if c.outbound == outbound {
			c.outbound = nil
		}
		c.mu.Unlock()
	}()

	for {
		nextCell, err := readCell(outbound)
		if err != nil {
			_ = c.sendBackwardPlain(relayCmdEnd, nil)
			return
		}
		switch nextCell.Type {
		case cellTypeRelay:
			sealed := c.keys.sealBackward(nextCell.Payload)
			if err := c.writeInbound(cell{
				Type:      cellTypeRelay,
				CircuitID: c.circuitID,
				Payload:   sealed,
			}); err != nil {
				return
			}
		case cellTypeDestroy:
			_ = c.writeInbound(cell{Type: cellTypeDestroy, CircuitID: c.circuitID})
			return
		default:
			_ = c.sendBackwardError(fmt.Errorf("unexpected downstream cell type %d", nextCell.Type))
			return
		}
	}
}

func (c *relayCircuit) pumpTarget(target net.Conn) {
	defer func() {
		_ = target.Close()
		c.mu.Lock()
		if c.targetConn == target {
			c.targetConn = nil
		}
		c.mu.Unlock()
	}()

	buf := make([]byte, maxRelayDataPayload)
	for {
		n, err := target.Read(buf)
		if n > 0 {
			if sendErr := c.sendBackwardPlain(relayCmdData, append([]byte(nil), buf[:n]...)); sendErr != nil {
				return
			}
		}
		if err != nil {
			_ = c.sendBackwardPlain(relayCmdEnd, nil)
			return
		}
	}
}

func (c *relayCircuit) sendBackwardPlain(command byte, body []byte) error {
	payload, err := encodeRelayEnvelope(command, body)
	if err != nil {
		return err
	}
	sealed := c.keys.sealBackward(payload)
	return c.writeInbound(cell{
		Type:      cellTypeRelay,
		CircuitID: c.circuitID,
		Payload:   sealed,
	})
}

func (c *relayCircuit) sendBackwardError(err error) error {
	body, marshalErr := json.Marshal(errorCommand{Message: err.Error()})
	if marshalErr != nil {
		return err
	}
	return c.sendBackwardPlain(relayCmdError, body)
}

func (c *relayCircuit) writeInbound(msg cell) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeCell(c.inbound, msg)
}

func (c *relayCircuit) getOutbound() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.outbound
}

func (c *relayCircuit) getTarget() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.targetConn
}

func (c *relayCircuit) closeTarget() {
	c.mu.Lock()
	target := c.targetConn
	c.targetConn = nil
	c.mu.Unlock()
	if target != nil {
		_ = target.Close()
	}
}

func (c *relayCircuit) closeAll() {
	c.closeTarget()
	c.mu.Lock()
	outbound := c.outbound
	c.outbound = nil
	c.mu.Unlock()
	if outbound != nil {
		_ = outbound.Close()
	}
	_ = c.inbound.Close()
}
