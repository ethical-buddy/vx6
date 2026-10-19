// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package ipsec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/record"
	"golang.org/x/sys/unix"
)

const maxIPCMessage = 1 << 20

type ipcRequest struct {
	Action       string                `json:"action"`
	NodeID       string                `json:"node_id"`
	TargetPeer   record.EndpointRecord `json:"target_peer,omitempty"`
	PublicKey    []byte                `json:"public_key"`
	PrivateKey   []byte                `json:"private_key"`
	LocalAddress string                `json:"local_address"`
	Peer         record.EndpointRecord `json:"peer,omitempty"`
	Remote       string                `json:"remote,omitempty"`
}

type ipcResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Allow bool   `json:"allow,omitempty"`
}

// Client calls the narrowly scoped local IPsec service. It intentionally has
// no method that accepts a command, config fragment, or filesystem path.
type Client struct {
	socket       string
	localAddress string
	identity     identity.Identity
}

func NewClient(socket, localAddress string, id identity.Identity) (*Client, error) {
	if socket == "" {
		return nil, errors.New("IPsec service socket is required")
	}
	if err := id.Validate(); err != nil {
		return nil, fmt.Errorf("invalid local identity: %w", err)
	}
	if err := validateLocalAddress(localAddress); err != nil {
		return nil, err
	}
	return &Client{socket: socket, localAddress: localAddress, identity: id}, nil
}

func DefaultSocket() string {
	return "/run/vx6/ipsecd.sock"
}

func (c *Client) PreparePeer(ctx context.Context, peer record.EndpointRecord) error {
	_, err := c.call(ctx, ipcRequest{Action: "prepare", Peer: peer})
	return err
}

func (c *Client) EnsurePeer(ctx context.Context, peer record.EndpointRecord) error {
	_, err := c.call(ctx, ipcRequest{Action: "ensure", Peer: peer})
	return err
}

func (c *Client) RevokePeer(ctx context.Context, peer record.EndpointRecord) error {
	_, err := c.call(ctx, ipcRequest{Action: "revoke", TargetPeer: peer})
	return err
}

func (c *Client) AcceptPeer(ctx context.Context, remote string) bool {
	resp, err := c.call(ctx, ipcRequest{Action: "accept", Remote: remote})
	return err == nil && resp.Allow
}

func (c *Client) Check(ctx context.Context) error {
	_, err := c.call(ctx, ipcRequest{Action: "check"})
	return err
}

func (c *Client) call(ctx context.Context, request ipcRequest) (ipcResponse, error) {
	request.NodeID = c.identity.NodeID
	request.PublicKey = append([]byte(nil), c.identity.PublicKey...)
	request.PrivateKey = append([]byte(nil), c.identity.PrivateKey...)
	request.LocalAddress = c.localAddress
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", c.socket)
	if err != nil {
		return ipcResponse{}, fmt.Errorf("connect to VX6 IPsec service: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(20 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return ipcResponse{}, fmt.Errorf("send IPsec service request: %w", err)
	}
	var response ipcResponse
	if err := json.NewDecoder(io.LimitReader(conn, maxIPCMessage)).Decode(&response); err != nil {
		return ipcResponse{}, fmt.Errorf("read IPsec service response: %w", err)
	}
	if !response.OK {
		return response, errors.New(response.Error)
	}
	return response, nil
}

// Serve runs the privileged control plane. Only listed Unix UIDs may use it.
// StrongSwan commands are generated internally from the verified peer record.
func Serve(ctx context.Context, socket, stateRoot string, allowedUIDs []uint32, socketGID uint32) error {
	if os.Geteuid() != 0 {
		return errors.New("vx6-ipsecd must run with administrator privileges")
	}
	allowed := make(map[uint32]struct{}, len(allowedUIDs))
	for _, uid := range allowedUIDs {
		allowed[uid] = struct{}{}
	}
	if len(allowed) == 0 {
		return errors.New("at least one authorized local UID is required")
	}
	if _, err := exec.LookPath("swanctl"); err != nil {
		return errors.New("strongSwan swanctl is missing; install the VX6 Linux IPsec package dependencies")
	}
	checkCtx, cancelCheck := context.WithTimeout(ctx, 5*time.Second)
	checkCmd := exec.CommandContext(checkCtx, "swanctl", "--list-sas")
	checkOut, checkErr := checkCmd.CombinedOutput()
	cancelCheck()
	if checkErr != nil {
		return fmt.Errorf("strongSwan VICI is unavailable: %w: %s", checkErr, strings.TrimSpace(string(checkOut)))
	}
	parent := filepath.Dir(socket)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create service socket directory: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("IPsec service socket parent must be a real directory")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != 0 {
		return errors.New("IPsec service socket parent must be owned by root")
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to replace non-socket IPsec service path")
		}
		if err := os.Remove(socket); err != nil {
			return fmt.Errorf("remove stale service socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("listen on IPsec service socket: %w", err)
	}
	defer func() { _ = listener.Close(); _ = os.Remove(socket) }()
	if err := os.Chmod(socket, 0o660); err != nil {
		return fmt.Errorf("restrict IPsec service socket: %w", err)
	}
	if err := os.Chown(socket, 0, int(socketGID)); err != nil {
		return fmt.Errorf("set IPsec service socket ownership: %w", err)
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return fmt.Errorf("create IPsec service state: %w", err)
	}
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		return fmt.Errorf("restrict IPsec service state: %w", err)
	}
	firewall, err := NewFirewall(stateRoot)
	if err != nil {
		return err
	}
	if err := firewall.Restore(ctx); err != nil {
		return fmt.Errorf("restore VX6 firewall policy: %w", err)
	}
	managers := &managerCache{items: make(map[string]*Manager)}
	active := make(chan struct{}, 64)
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept IPsec service client: %w", err)
		}
		select {
		case active <- struct{}{}:
			go func() {
				defer func() { <-active }()
				serveIPCConn(ctx, conn, allowed, stateRoot, managers, firewall)
			}()
		default:
			_ = conn.Close()
		}
	}
}

type managerCache struct {
	sync.Mutex
	items map[string]*Manager
}

func serveIPCConn(ctx context.Context, conn net.Conn, allowed map[uint32]struct{}, stateRoot string, managers *managerCache, firewall *Firewall) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return
	}
	var cred *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || controlErr != nil || cred == nil {
		writeIPCError(conn, "cannot authenticate local caller")
		return
	}
	if _, ok := allowed[cred.Uid]; !ok {
		writeIPCError(conn, "local caller is not authorized")
		return
	}
	decoder := json.NewDecoder(io.LimitReader(conn, maxIPCMessage))
	var req ipcRequest
	if err := decoder.Decode(&req); err != nil {
		writeIPCError(conn, "invalid request")
		return
	}
	id := identity.Identity{NodeID: req.NodeID, PublicKey: req.PublicKey, PrivateKey: req.PrivateKey}
	if err := id.Validate(); err != nil {
		writeIPCError(conn, "invalid local identity")
		return
	}
	if err := validateLocalAddress(req.LocalAddress); err != nil {
		writeIPCError(conn, "invalid local IPv6 endpoint")
		return
	}
	key := fmt.Sprintf("%d/%s/%s", cred.Uid, id.NodeID, req.LocalAddress)
	managers.Lock()
	manager := managers.items[key]
	if manager == nil {
		endpointHash := sha256.Sum256([]byte(req.LocalAddress))
		root := filepath.Join(stateRoot, strconv.FormatUint(uint64(cred.Uid), 10), id.NodeID, hex.EncodeToString(endpointHash[:8]), "swanctl")
		manager, err = NewManager(root, req.LocalAddress, id)
		if err != nil {
			managers.Unlock()
			writeIPCError(conn, "cannot initialize peer tunnel manager")
			return
		}
		manager.firewall = firewall
		for nodeID, revoked := range manager.revoked {
			if err := firewall.Revoke(ctx, nodeID, revoked.Address); err != nil {
				managers.Unlock()
				writeIPCError(conn, "cannot restore peer revocation firewall policy")
				return
			}
		}
		managers.items[key] = manager
	}
	managers.Unlock()
	if err := firewall.RegisterPort(ctx, localPort(req.LocalAddress)); err != nil {
		writeIPCError(conn, "cannot enforce VX6 firewall policy")
		return
	}
	var response ipcResponse
	requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	switch req.Action {
	case "check":
		response.OK = true
		_ = json.NewEncoder(conn).Encode(response)
		return
	case "prepare":
		err = manager.PreparePeer(requestCtx, req.Peer)
	case "ensure":
		err = manager.EnsurePeer(requestCtx, req.Peer)
	case "revoke":
		err = manager.RevokePeer(requestCtx, req.TargetPeer)
	case "accept":
		response.Allow = manager.AcceptPeer(requestCtx, req.Remote)
	default:
		err = errors.New("unsupported operation")
	}
	if err != nil {
		response.Error = err.Error()
		response.OK = false
	} else {
		response.OK = true
	}
	_ = json.NewEncoder(conn).Encode(response)
}

func localPort(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	return port
}

func writeIPCError(conn net.Conn, message string) {
	_ = json.NewEncoder(conn).Encode(ipcResponse{Error: message})
}

func validateLocalAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid local IPv6 endpoint: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		return errors.New("local endpoint must be IPv6")
	}
	return nil
}
