// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package mobile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vx6/vx6/sdk"
	vxchat "github.com/vx6/vx6/sdk/chat"
)

type Engine struct {
	mu       sync.Mutex
	client   *sdk.Client
	chat     *vxchat.Client
	cancel   context.CancelFunc
	done     chan struct{}
	logs     lockedBuffer
	sendSeq  map[string]uint64
	contacts map[string]vxchat.Contact
}

func NewEngine(configPath string) (*Engine, error) {
	client, err := sdk.New(configPath)
	if err != nil {
		return nil, err
	}
	return &Engine{
		client:   client,
		chat:     vxchat.NewClient(client),
		sendSeq:  map[string]uint64{},
		contacts: map[string]vxchat.Contact{},
	}, nil
}

func (e *Engine) Init(name, listenAddr, advertiseAddr, dataDir, downloadsDir string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id, err := e.client.Init(ctx, sdk.InitOptions{
		Name:          name,
		ListenAddr:    listenAddr,
		AdvertiseAddr: advertiseAddr,
		DataDir:       dataDir,
		DownloadsDir:  downloadsDir,
	})
	if err != nil {
		return "", err
	}
	return jsonString(map[string]string{"node_id": id.NodeID})
}

func (e *Engine) StartNode() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.done = make(chan struct{})
	go func() {
		defer close(e.done)
		err := e.client.StartNode(ctx, &e.logs, sdk.StartOptions{})
		if err != nil && ctx.Err() == nil {
			_, _ = e.logs.WriteString(err.Error() + "\n")
		}
	}()
	return nil
}

func (e *Engine) StopNode() {
	e.mu.Lock()
	cancel := e.cancel
	done := e.done
	e.cancel = nil
	e.done = nil
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (e *Engine) AddPeer(name, addr string) error {
	return e.client.AddPeer(name, addr)
}

func (e *Engine) LocalNodeInfoJSON() (string, error) {
	info, err := e.client.LocalNodeInfo()
	if err != nil {
		return "", err
	}
	return jsonString(info)
}

func (e *Engine) GenerateChatInvite() (string, error) {
	info, err := e.client.LocalNodeInfo()
	if err != nil {
		return "", err
	}
	secret, err := vxchat.RandomSecret()
	if err != nil {
		return "", err
	}
	if info.AdvertiseAddr == "" {
		return "", errors.New("advertise address is required to build a mobile chat invite")
	}
	return vxchat.BuildInvite(info.NodeID, info.NodeName, info.AdvertiseAddr, secret), nil
}

func (e *Engine) AcceptChatInvite(invite string) (string, error) {
	req, err := vxchat.ParseInvite(invite)
	if err != nil {
		return "", err
	}
	contact := vxchat.Contact{
		NodeID: req.FromID, NodeName: req.FromName, Address: req.Address, Secret: req.Secret,
		AddedAt: time.Now().UTC().Format(time.RFC3339), Accepted: true, RequestID: req.RequestID,
	}
	e.mu.Lock()
	e.contacts[contact.NodeID] = contact
	e.mu.Unlock()
	_ = e.client.AddPeer(contact.NodeName, contact.Address)
	return jsonString(contact)
}

func (e *Engine) AddChatContactJSON(contactJSON string) error {
	var contact vxchat.Contact
	if err := json.Unmarshal([]byte(contactJSON), &contact); err != nil {
		return err
	}
	if contact.NodeID == "" || contact.Secret == "" {
		return errors.New("contact requires node_id and secret")
	}
	e.mu.Lock()
	e.contacts[contact.NodeID] = contact
	e.mu.Unlock()
	if contact.Address != "" {
		_ = e.client.AddPeer(contact.NodeName, contact.Address)
	}
	return nil
}

func (e *Engine) SendText(toNodeID, text string) (string, error) {
	info, err := e.client.LocalNodeInfo()
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	contact, ok := e.contacts[toNodeID]
	if !ok {
		e.mu.Unlock()
		return "", fmt.Errorf("unknown contact %q", toNodeID)
	}
	e.sendSeq[toNodeID]++
	seq := e.sendSeq[toNodeID]
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	env, err := e.chat.SendText(ctx, info.NodeID, contact, text, seq)
	if err != nil {
		return "", err
	}
	return jsonString(env)
}

func (e *Engine) MessagesJSON(contactNodeID string) (string, error) {
	info, err := e.client.LocalNodeInfo()
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	contact, ok := e.contacts[contactNodeID]
	e.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("unknown contact %q", contactNodeID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	messages, err := e.chat.FetchMessages(ctx, info.NodeID, contact)
	if err != nil {
		return "", err
	}
	return jsonString(messages)
}

func (e *Engine) Logs() string {
	return e.logs.String()
}

func jsonString(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) WriteString(s string) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.WriteString(s)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}
