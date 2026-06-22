// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Identity struct {
	NodeID     string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

type fileFormat struct {
	NodeID     string `json:"node_id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type Store struct {
	path string
}

func NewStore(path string) (*Store, error) {
	if path == "" {
		defaultPath, err := DefaultPath()
		if err != nil {
			return nil, err
		}
		path = defaultPath
	}

	return &Store{path: path}, nil
}

func NewStoreForConfig(configPath string) (*Store, error) {
	if configPath == "" {
		return NewStore("")
	}

	dir := filepath.Dir(configPath)
	base := filepath.Base(configPath)
	if base == "" || base == "." || base == "config.json" {
		return &Store{path: filepath.Join(dir, "identity.json")}, nil
	}

	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	if name == "" {
		name = "identity"
	}
	return &Store{path: filepath.Join(dir, name+".identity.json")}, nil
}

func DefaultPath() (string, error) {
	configRoot, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve config directory: %w", err)
	}

	return filepath.Join(configRoot, "vx6", "identity.json"), nil
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) Load() (Identity, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return Identity{}, fmt.Errorf("read identity: %w", err)
	}

	var raw fileFormat
	if err := json.Unmarshal(data, &raw); err != nil {
		return Identity{}, fmt.Errorf("decode identity: %w", err)
	}

	publicKey, err := base64.StdEncoding.DecodeString(raw.PublicKey)
	if err != nil {
		return Identity{}, fmt.Errorf("decode public key: %w", err)
	}
	privateKey, err := base64.StdEncoding.DecodeString(raw.PrivateKey)
	if err != nil {
		return Identity{}, fmt.Errorf("decode private key: %w", err)
	}

	id := Identity{
		NodeID:     raw.NodeID,
		PublicKey:  ed25519.PublicKey(publicKey),
		PrivateKey: ed25519.PrivateKey(privateKey),
	}

	if err := id.Validate(); err != nil {
		return Identity{}, err
	}

	return id, nil
}

func (s *Store) Save(id Identity) error {
	if err := id.Validate(); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create identity directory: %w", err)
	}

	raw := fileFormat{
		NodeID:     id.NodeID,
		PublicKey:  base64.StdEncoding.EncodeToString(id.PublicKey),
		PrivateKey: base64.StdEncoding.EncodeToString(id.PrivateKey),
	}

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("encode identity: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}

	return nil
}

func (s *Store) Ensure() (Identity, bool, error) {
	id, err := s.Load()
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Identity{}, false, err
	}

	id, err = Generate()
	if err != nil {
		return Identity{}, false, err
	}
	if err := s.Save(id); err != nil {
		return Identity{}, false, err
	}

	return id, true, nil
}

func Generate() (Identity, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("generate ed25519 keypair: %w", err)
	}

	nodeID := NodeIDFromPublicKey(publicKey)
	return Identity{
		NodeID:     nodeID,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func NodeIDFromPublicKey(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "vx6_" + hex.EncodeToString(sum[:8])
}

func (id Identity) Validate() error {
	if id.NodeID == "" {
		return fmt.Errorf("identity missing node id")
	}
	if len(id.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("identity contains invalid public key")
	}
	if len(id.PrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("identity contains invalid private key")
	}
	if got := NodeIDFromPublicKey(id.PublicKey); got != id.NodeID {
		return fmt.Errorf("identity node id does not match public key")
	}
	if !id.PublicKey.Equal(id.PrivateKey.Public()) {
		return fmt.Errorf("identity public and private keys do not match")
	}

	return nil
}
