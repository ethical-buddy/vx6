// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/transfer"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

const defaultListenAddress = "[::]:4242"

const (
	FileReceiveOff     = "off"
	FileReceiveTrusted = "trusted"
	FileReceiveOpen    = "open"

	RelayModeOn  = "on"
	RelayModeOff = "off"
)

type File struct {
	Node     NodeConfig              `json:"node"`
	Peers    map[string]PeerEntry    `json:"peers"`
	Services map[string]ServiceEntry `json:"services"`
}

type NodeConfig struct {
	Name                 string           `json:"name"`
	RecordSequence       uint64           `json:"record_sequence,omitempty"`
	RecordName           string           `json:"record_name,omitempty"`
	RecordAddress        string           `json:"record_address,omitempty"`
	ListenAddr           string           `json:"listen_addr"`
	AdvertiseAddr        string           `json:"advertise_addr"`
	TransportMode        string           `json:"transport_mode,omitempty"`
	HideEndpoint         bool             `json:"hide_endpoint"`
	RelayMode            string           `json:"relay_mode,omitempty"`
	RelayResourcePercent int              `json:"relay_resource_percent,omitempty"`
	MaxConcurrentConns   int              `json:"max_concurrent_conns,omitempty"`
	DataDir              string           `json:"data_dir"`
	DownloadDir          string           `json:"download_dir"`
	KnownPeerAddrs       []string         `json:"known_peer_addrs,omitempty"`
	KnownPeers           []KnownPeerEntry `json:"known_peers,omitempty"`
	PinnedPeers          []PinnedPeer     `json:"pinned_peers,omitempty"`
	BootstrapAddrs       []string         `json:"bootstrap_addrs,omitempty"`
	Bootstraps           []KnownPeerEntry `json:"bootstraps,omitempty"`
	FileReceiveMode      string           `json:"file_receive_mode,omitempty"`
	AllowedFileSenders   []string         `json:"allowed_file_senders,omitempty"`
}

// PinnedPeer is a local trust decision for one NodeID/public key. NodeName is
// display metadata only and is not a network-wide name reservation.
type PinnedPeer struct {
	NodeID    string `json:"node_id"`
	NodeName  string `json:"node_name"`
	PublicKey string `json:"public_key"`
}

type KnownPeerEntry struct {
	NodeID            string `json:"node_id,omitempty"`
	NodeName          string `json:"node_name,omitempty"`
	Address           string `json:"address"`
	RecordVersion     uint8  `json:"record_version,omitempty"`
	RecordSequence    uint64 `json:"record_sequence,omitempty"`
	PublicKey         string `json:"public_key,omitempty"`
	IdentityIssuedAt  string `json:"identity_issued_at,omitempty"`
	IdentityExpiresAt string `json:"identity_expires_at,omitempty"`
	IdentitySignature string `json:"identity_signature,omitempty"`
}

type PeerEntry struct {
	Address string `json:"address"`
}

type ServiceEntry struct {
	Target             string   `json:"target"`
	Protocol           string   `json:"protocol,omitempty"`
	IsHidden           bool     `json:"is_hidden"`
	IsPrivate          bool     `json:"is_private,omitempty"`
	AllowedNodeIDs     []string `json:"allowed_node_ids,omitempty"`
	Alias              string   `json:"alias,omitempty"`
	HiddenLookupSecret string   `json:"hidden_lookup_secret,omitempty"`
	HiddenProfile      string   `json:"hidden_profile,omitempty"`
	IntroMode          string   `json:"intro_mode,omitempty"`
	IntroNodes         []string `json:"intro_nodes,omitempty"`
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

func RuntimePIDPath(configPath string) (string, error) {
	if configPath == "" {
		var err error
		configPath, err = DefaultPath()
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(filepath.Dir(configPath), "node.pid"), nil
}

func RuntimeLockPath(configPath string) (string, error) {
	if configPath == "" {
		var err error
		configPath, err = DefaultPath()
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(filepath.Dir(configPath), "node.lock"), nil
}

func RuntimeControlPath(configPath string) (string, error) {
	if configPath == "" {
		var err error
		configPath, err = DefaultPath()
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(filepath.Dir(configPath), "node.control.json"), nil
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) Load() (File, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return defaultFile(), nil
		}
		return File{}, fmt.Errorf("read config: %w", err)
	}

	var cfg File
	if err := json.Unmarshal(data, &cfg); err != nil {
		return File{}, fmt.Errorf("decode config: %w", err)
	}
	if err := validatePinnedPeers(cfg.Node.PinnedPeers); err != nil {
		return File{}, fmt.Errorf("validate pinned peers: %w", err)
	}
	if err := validateServicePolicies(cfg.Services); err != nil {
		return File{}, err
	}
	normalize(&cfg)
	return cfg, nil
}

func (s *Store) Save(cfg File) error {
	if err := validatePinnedPeers(cfg.Node.PinnedPeers); err != nil {
		return fmt.Errorf("validate pinned peers: %w", err)
	}
	if err := validateServicePolicies(cfg.Services); err != nil {
		return err
	}
	normalize(&cfg)

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(s.path, data, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

func (s *Store) AddPeer(name, address string) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	canonicalName, err := record.NormalizeNodeName(name)
	if err != nil {
		return err
	}
	if err := transfer.ValidateIPv6Address(address); err != nil {
		return err
	}

	cfg.Peers[canonicalName] = PeerEntry{Address: address}
	return s.Save(cfg)
}

func (s *Store) ResolvePeer(name string) (PeerEntry, error) {
	cfg, err := s.Load()
	if err != nil {
		return PeerEntry{}, err
	}

	canonicalName, normalizeErr := record.NormalizeNodeName(name)
	if normalizeErr != nil {
		return PeerEntry{}, normalizeErr
	}
	peer, ok := cfg.Peers[canonicalName]
	if !ok {
		return PeerEntry{}, fmt.Errorf("peer %q not found in %s", name, s.path)
	}

	return peer, nil
}

func (s *Store) ListPeers() ([]string, map[string]PeerEntry, error) {
	cfg, err := s.Load()
	if err != nil {
		return nil, nil, err
	}

	names := make([]string, 0, len(cfg.Peers))
	for name := range cfg.Peers {
		names = append(names, name)
	}
	sort.Strings(names)

	return names, cfg.Peers, nil
}

func (s *Store) AddKnownPeerAddress(address string) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	if err := transfer.ValidateIPv6Address(address); err != nil {
		return err
	}

	cfg.Node.KnownPeers = upsertKnownPeerEntry(cfg.Node.KnownPeers, KnownPeerEntry{Address: address})
	cfg.Node.BootstrapAddrs = nil
	cfg.Node.Bootstraps = nil
	return s.Save(cfg)
}

func (s *Store) ListKnownPeerAddresses() ([]string, error) {
	cfg, err := s.Load()
	if err != nil {
		return nil, err
	}

	out := KnownPeerAddresses(cfg.Node)
	return out, nil
}

func (s *Store) ListKnownPeerEntries() ([]KnownPeerEntry, error) {
	cfg, err := s.Load()
	if err != nil {
		return nil, err
	}
	out := append([]KnownPeerEntry(nil), cfg.Node.KnownPeers...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].NodeName != out[j].NodeName {
			return out[i].NodeName < out[j].NodeName
		}
		if out[i].NodeID != out[j].NodeID {
			return out[i].NodeID < out[j].NodeID
		}
		return out[i].Address < out[j].Address
	})
	return out, nil
}

func (s *Store) UpsertKnownPeerRecord(rec record.EndpointRecord) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	updated, changed := mergeKnownPeerRecord(cfg.Node.KnownPeers, rec)
	if !changed {
		return nil
	}
	cfg.Node.KnownPeers = updated
	cfg.Node.KnownPeerAddrs = nil
	cfg.Node.BootstrapAddrs = nil
	cfg.Node.Bootstraps = nil
	return s.Save(cfg)
}

func (s *Store) PinPeer(rec record.EndpointRecord, now time.Time) error {
	verified, err := record.VerifyEndpoint(rec, now)
	if err != nil {
		return fmt.Errorf("cannot pin invalid peer record: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(verified.PublicKey())
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	found := false
	for _, pin := range cfg.Node.PinnedPeers {
		if pin.NodeID == rec.NodeID {
			if pin.PublicKey != key {
				return fmt.Errorf("peer ID %s is already pinned to a different public key", rec.NodeID)
			}
			cfg.Node.PinnedPeers = append([]PinnedPeer(nil), cfg.Node.PinnedPeers...)
			for i := range cfg.Node.PinnedPeers {
				if cfg.Node.PinnedPeers[i].NodeID == rec.NodeID {
					cfg.Node.PinnedPeers[i].NodeName = rec.NodeName
				}
			}
			found = true
			continue
		}
		// Local identity pins are keyed by NodeID. Different identities may
		// legitimately advertise the same display name; the pin is not a global
		// name reservation and must not hide such conflicts.
	}
	if !found {
		cfg.Node.PinnedPeers = append(cfg.Node.PinnedPeers, PinnedPeer{NodeID: rec.NodeID, NodeName: rec.NodeName, PublicKey: key})
	}
	cfg.Node.KnownPeers, _ = mergeKnownPeerRecord(cfg.Node.KnownPeers, rec)
	cfg.Node.KnownPeerAddrs = nil
	cfg.Node.BootstrapAddrs = nil
	cfg.Node.Bootstraps = nil
	sort.Slice(cfg.Node.PinnedPeers, func(i, j int) bool { return cfg.Node.PinnedPeers[i].NodeName < cfg.Node.PinnedPeers[j].NodeName })
	return s.Save(cfg)
}

func (s *Store) PinnedPeerByName(name string) (PinnedPeer, bool, error) {
	canonical, err := record.NormalizeNodeName(name)
	if err != nil {
		return PinnedPeer{}, false, err
	}
	cfg, err := s.Load()
	if err != nil {
		return PinnedPeer{}, false, err
	}
	for _, pin := range cfg.Node.PinnedPeers {
		if pin.NodeName == canonical {
			return pin, true, nil
		}
	}
	return PinnedPeer{}, false, nil
}

func (s *Store) UnpinPeer(nodeID string) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	kept := cfg.Node.PinnedPeers[:0]
	for _, pin := range cfg.Node.PinnedPeers {
		if pin.NodeID != nodeID {
			kept = append(kept, pin)
		}
	}
	if len(kept) == len(cfg.Node.PinnedPeers) {
		return fmt.Errorf("no pinned peer with node ID %s", nodeID)
	}
	cfg.Node.PinnedPeers = kept
	return s.Save(cfg)
}

func (s *Store) AddService(name, target string, isHidden bool) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}

	cfg.Services[name] = ServiceEntry{Target: target, IsHidden: isHidden}
	return s.Save(cfg)
}

func (s *Store) RemoveService(name string) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	delete(cfg.Services, name)
	return s.Save(cfg)
}

func (s *Store) SetService(name string, entry ServiceEntry) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}

	cfg.Services[name] = entry
	return s.Save(cfg)
}

func (s *Store) ResolveService(name string) (ServiceEntry, error) {
	cfg, err := s.Load()
	if err != nil {
		return ServiceEntry{}, err
	}

	service, ok := cfg.Services[name]
	if !ok {
		return ServiceEntry{}, fmt.Errorf("service %q not found in %s", name, s.path)
	}

	return service, nil
}

func (s *Store) ListServices() ([]string, map[string]ServiceEntry, error) {
	cfg, err := s.Load()
	if err != nil {
		return nil, nil, err
	}

	names := make([]string, 0, len(cfg.Services))
	for name := range cfg.Services {
		names = append(names, name)
	}
	sort.Strings(names)

	return names, cfg.Services, nil
}

func defaultFile() File {
	return File{
		Node: NodeConfig{
			ListenAddr:           defaultListenAddress,
			TransportMode:        vxtransport.ModeAuto,
			RelayMode:            RelayModeOn,
			RelayResourcePercent: 33,
			DataDir:              defaultDataDirValue(),
			DownloadDir:          defaultDownloadDirValue(),
		},
		Peers:    map[string]PeerEntry{},
		Services: map[string]ServiceEntry{},
	}
}

func normalize(cfg *File) {
	if canonical, err := record.NormalizeNodeName(cfg.Node.Name); err == nil {
		cfg.Node.Name = canonical
	}
	if len(cfg.Peers) > 0 {
		canonicalPeers := make(map[string]PeerEntry, len(cfg.Peers))
		for name, peer := range cfg.Peers {
			canonical, err := record.NormalizeNodeName(name)
			if err != nil {
				canonicalPeers[name] = peer
				continue
			}
			if _, exists := canonicalPeers[canonical]; !exists {
				canonicalPeers[canonical] = peer
			}
		}
		cfg.Peers = canonicalPeers
	}
	sort.Slice(cfg.Node.PinnedPeers, func(i, j int) bool { return cfg.Node.PinnedPeers[i].NodeName < cfg.Node.PinnedPeers[j].NodeName })
	if cfg.Node.ListenAddr == "" {
		cfg.Node.ListenAddr = defaultListenAddress
	}
	if normalized := vxtransport.NormalizeMode(cfg.Node.TransportMode); normalized != "" {
		cfg.Node.TransportMode = normalized
	} else {
		cfg.Node.TransportMode = vxtransport.ModeAuto
	}
	if normalized := NormalizeRelayMode(cfg.Node.RelayMode); normalized != "" {
		cfg.Node.RelayMode = normalized
	} else {
		cfg.Node.RelayMode = RelayModeOn
	}
	cfg.Node.RelayResourcePercent = NormalizeRelayResourcePercent(cfg.Node.RelayResourcePercent)
	cfg.Node.MaxConcurrentConns = NormalizeMaxConcurrentConns(cfg.Node.MaxConcurrentConns)
	if cfg.Node.DataDir == "" || cfg.Node.DataDir == "./data/inbox" {
		cfg.Node.DataDir = defaultDataDirValue()
	}
	if cfg.Node.DownloadDir == "" {
		cfg.Node.DownloadDir = defaultDownloadDirValue()
	}
	cfg.Node.KnownPeers = normalizeKnownPeerEntries(cfg.Node.KnownPeers, cfg.Node.KnownPeerAddrs, cfg.Node.Bootstraps, cfg.Node.BootstrapAddrs)
	cfg.Node.KnownPeerAddrs = KnownPeerAddresses(cfg.Node)
	cfg.Node.Bootstraps = nil
	cfg.Node.BootstrapAddrs = nil
	cfg.Node.FileReceiveMode = NormalizeFileReceiveMode(cfg.Node.FileReceiveMode)
	cfg.Node.AllowedFileSenders = uniqueSortedStrings(cfg.Node.AllowedFileSenders)
	if cfg.Node.FileReceiveMode != FileReceiveTrusted {
		cfg.Node.AllowedFileSenders = nil
	}
	if cfg.Peers == nil {
		cfg.Peers = map[string]PeerEntry{}
	}
	if cfg.Services == nil {
		cfg.Services = map[string]ServiceEntry{}
	}
	for name, svc := range cfg.Services {
		svc.Protocol = record.NormalizeServiceProtocol(svc.Protocol)
		svc.AllowedNodeIDs = uniqueSortedStrings(svc.AllowedNodeIDs)
		if svc.IntroNodes == nil {
			svc.IntroNodes = []string{}
		}
		if svc.IsHidden && svc.IsPrivate {
			svc.IsPrivate = false
		}
		if svc.IsHidden {
			if svc.HiddenProfile == "" {
				svc.HiddenProfile = "fast"
			}
			if svc.IntroMode == "" {
				if len(svc.IntroNodes) > 0 {
					svc.IntroMode = "manual"
				} else {
					svc.IntroMode = "random"
				}
			}
		}
		if svc.IsPrivate {
			svc.Alias = ""
			svc.HiddenLookupSecret = ""
			svc.HiddenProfile = ""
			svc.IntroMode = ""
			svc.IntroNodes = nil
		}
		if !svc.IsHidden {
			svc.HiddenLookupSecret = ""
		}
		cfg.Services[name] = svc
	}
}

func validateServicePolicies(services map[string]ServiceEntry) error {
	for name, service := range services {
		if record.NormalizeServiceProtocol(service.Protocol) == "" {
			return fmt.Errorf("service %q: protocol must be tcp or udp", name)
		}
		host, portText, err := net.SplitHostPort(service.Target)
		port, portErr := strconv.Atoi(portText)
		if err != nil || host == "" || portErr != nil || port < 1 || port > 65535 {
			return fmt.Errorf("service %q: target must be host:port", name)
		}
		if service.IsHidden && service.Protocol == record.ServiceProtocolUDP {
			return fmt.Errorf("service %q: hidden services currently require TCP", name)
		}
		if service.IsHidden && len(service.AllowedNodeIDs) > 0 {
			return fmt.Errorf("service %q: hidden-service authorization is not changed by the standard service policy", name)
		}
		for _, nodeID := range service.AllowedNodeIDs {
			if len(nodeID) != 68 || !strings.HasPrefix(nodeID, "vx6_") || strings.ToLower(nodeID) != nodeID {
				return fmt.Errorf("service %q: invalid allowed NodeID %q", name, nodeID)
			}
			if _, err := hex.DecodeString(strings.TrimPrefix(nodeID, "vx6_")); err != nil {
				return fmt.Errorf("service %q: invalid allowed NodeID %q", name, nodeID)
			}
		}
	}
	return nil
}

func validatePinnedPeers(pins []PinnedPeer) error {
	seenIDs := make(map[string]struct{}, len(pins))
	for _, pin := range pins {
		if err := record.ValidateCanonicalNodeName(pin.NodeName); err != nil {
			return fmt.Errorf("invalid pinned peer name: %w", err)
		}
		publicKey, err := base64.StdEncoding.DecodeString(pin.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("pinned peer %s has invalid Ed25519 public key", pin.NodeID)
		}
		if identity.NodeIDFromPublicKey(ed25519.PublicKey(publicKey)) != pin.NodeID {
			return fmt.Errorf("pinned peer NodeID does not match its public key")
		}
		if _, ok := seenIDs[pin.NodeID]; ok {
			return fmt.Errorf("duplicate pinned peer NodeID %s", pin.NodeID)
		}
		seenIDs[pin.NodeID] = struct{}{}
	}
	return nil
}

func KnownPeerAddresses(node NodeConfig) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(node.KnownPeers)+len(node.KnownPeerAddrs)+len(node.Bootstraps)+len(node.BootstrapAddrs))
	add := func(addr string) {
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	for _, entry := range node.KnownPeers {
		add(strings.TrimSpace(entry.Address))
	}
	for _, addr := range node.KnownPeerAddrs {
		add(strings.TrimSpace(addr))
	}
	for _, entry := range node.Bootstraps {
		add(strings.TrimSpace(entry.Address))
	}
	for _, addr := range node.BootstrapAddrs {
		add(strings.TrimSpace(addr))
	}
	sort.Strings(out)
	return out
}

func ConfiguredPeerAddresses(cfg File) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(cfg.Peers)+len(cfg.Node.KnownPeers)+len(cfg.Node.KnownPeerAddrs))
	add := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	for _, addr := range KnownPeerAddresses(cfg.Node) {
		add(addr)
	}
	for _, peer := range cfg.Peers {
		add(peer.Address)
	}
	sort.Strings(out)
	return out
}

func normalizeKnownPeerEntries(entries []KnownPeerEntry, addrs []string, legacyEntries []KnownPeerEntry, legacyAddrs []string) []KnownPeerEntry {
	out := make([]KnownPeerEntry, 0, len(entries)+len(addrs)+len(legacyEntries)+len(legacyAddrs))
	for _, entry := range entries {
		if normalized, ok := normalizeKnownPeerEntry(entry); ok {
			out = upsertKnownPeerEntry(out, normalized)
		}
	}
	for _, addr := range addrs {
		if normalized, ok := normalizeKnownPeerEntry(KnownPeerEntry{Address: addr}); ok {
			out = upsertKnownPeerEntry(out, normalized)
		}
	}
	for _, entry := range legacyEntries {
		if normalized, ok := normalizeKnownPeerEntry(entry); ok {
			out = upsertKnownPeerEntry(out, normalized)
		}
	}
	for _, addr := range legacyAddrs {
		if normalized, ok := normalizeKnownPeerEntry(KnownPeerEntry{Address: addr}); ok {
			out = upsertKnownPeerEntry(out, normalized)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NodeName != out[j].NodeName {
			return out[i].NodeName < out[j].NodeName
		}
		if out[i].NodeID != out[j].NodeID {
			return out[i].NodeID < out[j].NodeID
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func normalizeKnownPeerEntry(entry KnownPeerEntry) (KnownPeerEntry, bool) {
	entry.NodeID = strings.TrimSpace(entry.NodeID)
	entry.NodeName = strings.TrimSpace(entry.NodeName)
	entry.Address = strings.TrimSpace(entry.Address)
	entry.PublicKey = strings.TrimSpace(entry.PublicKey)
	entry.IdentityIssuedAt = strings.TrimSpace(entry.IdentityIssuedAt)
	entry.IdentityExpiresAt = strings.TrimSpace(entry.IdentityExpiresAt)
	entry.IdentitySignature = strings.TrimSpace(entry.IdentitySignature)
	if entry.Address == "" {
		return KnownPeerEntry{}, false
	}
	if err := transfer.ValidateIPv6Address(entry.Address); err != nil {
		return KnownPeerEntry{}, false
	}
	if entry.NodeName != "" && record.ValidateNodeName(entry.NodeName) != nil {
		entry.NodeName = ""
	}
	return entry, true
}

func upsertKnownPeerEntry(entries []KnownPeerEntry, entry KnownPeerEntry) []KnownPeerEntry {
	if normalized, ok := normalizeKnownPeerEntry(entry); ok {
		entry = normalized
	} else {
		return entries
	}
	for i := range entries {
		if knownPeerEntriesMatch(entries[i], entry) {
			if entry.NodeID != "" {
				entries[i].NodeID = entry.NodeID
			}
			if entry.NodeName != "" {
				entries[i].NodeName = entry.NodeName
			}
			addressChanged := entries[i].Address != entry.Address
			entries[i].Address = entry.Address
			if entry.PublicKey != "" {
				entries[i].RecordVersion = entry.RecordVersion
				entries[i].RecordSequence = entry.RecordSequence
				entries[i].PublicKey = entry.PublicKey
				entries[i].IdentityIssuedAt = entry.IdentityIssuedAt
				entries[i].IdentityExpiresAt = entry.IdentityExpiresAt
				entries[i].IdentitySignature = entry.IdentitySignature
			} else if addressChanged {
				entries[i].RecordVersion = 0
				entries[i].RecordSequence = 0
				entries[i].PublicKey = ""
				entries[i].IdentityIssuedAt = ""
				entries[i].IdentityExpiresAt = ""
				entries[i].IdentitySignature = ""
			}
			return entries
		}
	}
	return append(entries, entry)
}

func mergeKnownPeerRecord(entries []KnownPeerEntry, rec record.EndpointRecord) ([]KnownPeerEntry, bool) {
	for i := range entries {
		if knownPeerRecordMatches(entries[i], rec) {
			updated := entries[i]
			updated.NodeID = rec.NodeID
			updated.NodeName = rec.NodeName
			updated.Address = rec.Address
			updated.RecordVersion = rec.Version
			updated.RecordSequence = rec.Sequence
			updated.PublicKey = rec.PublicKey
			updated.IdentityIssuedAt = rec.IssuedAt
			updated.IdentityExpiresAt = rec.ExpiresAt
			updated.IdentitySignature = rec.Signature
			if updated == entries[i] {
				return entries, false
			}
			entries[i] = updated
			return entries, true
		}
	}
	return append(entries, KnownPeerEntry{
		NodeID: rec.NodeID, NodeName: rec.NodeName, Address: rec.Address,
		RecordVersion: rec.Version, RecordSequence: rec.Sequence,
		PublicKey: rec.PublicKey, IdentityIssuedAt: rec.IssuedAt,
		IdentityExpiresAt: rec.ExpiresAt, IdentitySignature: rec.Signature,
	}), true
}

func knownPeerEntriesMatch(a, b KnownPeerEntry) bool {
	if a.NodeID != "" && b.NodeID != "" && a.NodeID == b.NodeID {
		return true
	}
	if a.NodeName != "" && b.NodeName != "" && a.NodeName == b.NodeName {
		return true
	}
	return a.Address != "" && a.Address == b.Address
}

func knownPeerRecordMatches(entry KnownPeerEntry, rec record.EndpointRecord) bool {
	if entry.NodeID != "" && entry.NodeID == rec.NodeID {
		return true
	}
	if entry.NodeName != "" && entry.NodeName == rec.NodeName {
		return true
	}
	return entry.Address != "" && entry.Address == rec.Address
}

func NormalizeFileReceiveMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", FileReceiveOff:
		return FileReceiveOff
	case FileReceiveTrusted:
		return FileReceiveTrusted
	case FileReceiveOpen:
		return FileReceiveOpen
	default:
		return FileReceiveOff
	}
}

func NormalizeRelayMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", RelayModeOn:
		return RelayModeOn
	case RelayModeOff:
		return RelayModeOff
	default:
		return ""
	}
}

func NormalizeRelayResourcePercent(percent int) int {
	switch {
	case percent <= 0:
		return 33
	case percent < 5:
		return 5
	case percent > 90:
		return 90
	default:
		return percent
	}
}

func NormalizeMaxConcurrentConns(n int) int {
	switch {
	case n <= 0:
		return 1024
	case n < 64:
		return 64
	case n > 65535:
		return 65535
	default:
		return n
	}
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func defaultDataDirValue() string {
	path, err := DefaultDataDir()
	if err != nil {
		return filepath.Join(".", "vx6-data")
	}
	return path
}

func defaultDownloadDirValue() string {
	path, err := DefaultDownloadDir()
	if err != nil {
		return filepath.Join(".", "Downloads")
	}
	return path
}
