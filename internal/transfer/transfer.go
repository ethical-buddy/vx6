// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package transfer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/secure"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

const maxHeaderSize = 4 * 1024

type SendRequest struct {
	NodeName string
	FilePath string
	Address  string
	Identity identity.Identity
}

type SendResult struct {
	NodeName   string
	FileName   string
	BytesSent  int64
	RemoteAddr string
}

type ReceiveResult struct {
	SenderNode    string
	FileName      string
	BytesReceived int64
	StoredPath    string
}

type ReceivePolicy struct {
	Mode           string
	AllowedSenders map[string]struct{}
}

const (
	ReceiveModeOff     = "off"
	ReceiveModeTrusted = "trusted"
	ReceiveModeOpen    = "open"
)

func SendFile(ctx context.Context, req SendRequest) (SendResult, error) {
	conn, err := vxtransport.DialContext(ctx, vxtransport.ModeAuto, req.Address)
	if err != nil {
		return SendResult{}, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	return SendFileWithConn(ctx, conn, req)
}

func SendFileWithConn(ctx context.Context, conn net.Conn, req SendRequest) (SendResult, error) {
	if req.NodeName == "" {
		return SendResult{}, fmt.Errorf("node name cannot be empty")
	}
	if err := req.Identity.Validate(); err != nil {
		return SendResult{}, err
	}
	if req.Address != "" {
		if err := ValidateIPv6Address(req.Address); err != nil {
			return SendResult{}, err
		}
	}

	file, err := os.Open(req.FilePath)
	if err != nil {
		return SendResult{}, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return SendResult{}, fmt.Errorf("stat file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return SendResult{}, fmt.Errorf("%q is not a regular file", req.FilePath)
	}

	meta := metadata{
		NodeName: req.NodeName,
		FileName: filepath.Base(req.FilePath),
		FileSize: info.Size(),
	}

	if err := proto.WriteHeader(conn, proto.KindFileTransfer); err != nil {
		return SendResult{}, err
	}
	secureConn, err := secure.Client(conn, proto.KindFileTransfer, req.Identity)
	if err != nil {
		return SendResult{}, err
	}

	if err := writeMetadata(secureConn, meta); err != nil {
		return SendResult{}, err
	}

	state, err := readResumeState(secureConn)
	if err != nil {
		return SendResult{}, err
	}
	if state.Offset < 0 || state.Offset > info.Size() {
		return SendResult{}, fmt.Errorf("receiver requested invalid resume offset %d", state.Offset)
	}
	if state.Offset > 0 {
		if _, err := file.Seek(state.Offset, io.SeekStart); err != nil {
			return SendResult{}, fmt.Errorf("seek file for resume: %w", err)
		}
	}

	written, err := io.Copy(secureConn, file)
	if err != nil {
		return SendResult{}, fmt.Errorf("stream file: %w", err)
	}

	return SendResult{
		NodeName:   req.NodeName,
		FileName:   meta.FileName,
		BytesSent:  written,
		RemoteAddr: conn.RemoteAddr().String(),
	}, nil
}

func sanitizeReceiverDirName(nodeName, nodeID string) string {
	if nodeName == "" {
		nodeName = "unknown"
	}
	if nodeID == "" {
		nodeID = "unknownid"
	}
	cleanName := strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ', '\t', '\n', '\r':
			return '_'
		default:
			return r
		}
	}, nodeName)
	cleanID := strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ', '\t', '\n', '\r':
			return '_'
		default:
			return r
		}
	}, nodeID)
	return fmt.Sprintf("%s_%s_vx6", cleanName, cleanID)
}

func ReceiveFile(conn net.Conn, dataDir string) (ReceiveResult, error) {
	return ReceiveFileWithPolicy(conn, dataDir, ReceivePolicy{Mode: ReceiveModeOpen})
}

func ReceiveFileWithPolicy(conn net.Conn, dataDir string, policy ReceivePolicy) (ReceiveResult, error) {
	meta, err := readMetadata(conn)
	if err != nil {
		return ReceiveResult{}, err
	}
	if err := policy.authorize(meta.NodeName); err != nil {
		_ = writeResumeState(conn, resumeState{Denied: err.Error()})
		return ReceiveResult{}, err
	}

	senderID := "unknownid"
	if secureConn, ok := conn.(*secure.Conn); ok {
		senderID = secureConn.PeerNodeID()
	}
	receiverDir := filepath.Join(dataDir, sanitizeReceiverDirName(meta.NodeName, senderID))
	if err := os.MkdirAll(receiverDir, 0755); err != nil {
		return ReceiveResult{}, fmt.Errorf("create receiver directory: %w", err)
	}

	filePath := filepath.Join(receiverDir, filepath.Base(meta.FileName))
	offset := int64(0)
	if info, err := os.Stat(filePath); err == nil {
		switch {
		case info.Size() == meta.FileSize:
			offset = info.Size()
		case info.Size() > 0 && info.Size() < meta.FileSize:
			offset = info.Size()
		}
	}
	if offset > meta.FileSize {
		offset = 0
	}
	if err := writeResumeState(conn, resumeState{Offset: offset}); err != nil {
		return ReceiveResult{}, err
	}

	flags := os.O_CREATE | os.O_WRONLY
	if offset == 0 {
		flags |= os.O_TRUNC
	}
	file, err := os.OpenFile(filePath, flags, 0o644)
	if err != nil {
		return ReceiveResult{}, fmt.Errorf("create file: %w", err)
	}
	defer file.Close()
	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return ReceiveResult{}, fmt.Errorf("seek receive file: %w", err)
		}
	}

	n, err := io.CopyN(file, conn, meta.FileSize-offset)
	if err != nil {
		return ReceiveResult{}, fmt.Errorf("receive stream: %w", err)
	}

	return ReceiveResult{
		SenderNode:    meta.NodeName,
		FileName:      meta.FileName,
		BytesReceived: offset + n,
		StoredPath:    filePath,
	}, nil
}

func (p ReceivePolicy) authorize(sender string) error {
	switch p.Mode {
	case ReceiveModeOpen:
		return nil
	case ReceiveModeTrusted:
		if _, ok := p.AllowedSenders[sender]; ok {
			return nil
		}
		return fmt.Errorf("file transfer from %q is not allowed", sender)
	default:
		return fmt.Errorf("file receiving is disabled")
	}
}

type metadata struct {
	NodeName string `json:"node_name"`
	FileName string `json:"file_name"`
	FileSize int64  `json:"file_size"`
}

type resumeState struct {
	Offset int64  `json:"offset"`
	Denied string `json:"denied,omitempty"`
}

func writeMetadata(w io.Writer, meta metadata) error {
	payload, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if len(payload) > maxHeaderSize {
		return fmt.Errorf("metadata too large")
	}
	return proto.WriteLengthPrefixed(w, payload)
}

func readMetadata(r io.Reader) (metadata, error) {
	payload, err := proto.ReadLengthPrefixed(r, maxHeaderSize)
	if err != nil {
		return metadata{}, err
	}
	var meta metadata
	if err := json.Unmarshal(payload, &meta); err != nil {
		return metadata{}, err
	}
	if meta.NodeName == "" {
		return metadata{}, fmt.Errorf("metadata missing node_name")
	}
	if meta.FileName == "" {
		return metadata{}, fmt.Errorf("metadata missing file_name")
	}
	if meta.FileSize < 0 {
		return metadata{}, fmt.Errorf("metadata contains invalid file_size")
	}
	return meta, nil
}

func writeResumeState(w io.Writer, state resumeState) error {
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return proto.WriteLengthPrefixed(w, payload)
}

func readResumeState(r io.Reader) (resumeState, error) {
	payload, err := proto.ReadLengthPrefixed(r, maxHeaderSize)
	if err != nil {
		return resumeState{}, err
	}
	var state resumeState
	if err := json.Unmarshal(payload, &state); err != nil {
		return resumeState{}, err
	}
	if state.Denied != "" {
		return resumeState{}, fmt.Errorf("transfer rejected: %s", state.Denied)
	}
	if state.Offset < 0 {
		return resumeState{}, fmt.Errorf("resume state contains invalid offset")
	}
	return state, nil
}

func ValidateIPv6Address(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", address, err)
	}

	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		return fmt.Errorf("address %q is not an IPv6 endpoint", address)
	}

	return nil
}
