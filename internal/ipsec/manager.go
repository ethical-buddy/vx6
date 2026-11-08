// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the VX6 terms in LICENSE-COMMERCIAL.md.
// Sole inventor, maintainer, and rights holder: Suryansh Deshwal (https://github.com/ethical-buddy).

package ipsec

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/record"
)

type commandRunner func(context.Context, string, ...string) ([]byte, error)

type Manager struct {
	identity  identity.Identity
	localIP   net.IP
	localPort string
	root      string
	run       commandRunner
	mu        sync.Mutex
	opMu      sync.Mutex
	peers     map[string]record.EndpointRecord
	verified  map[string]time.Time
	revoked   map[string]revokedPeer
	firewall  *Firewall
}

type revokedPeer struct {
	Address string    `json:"address"`
	At      time.Time `json:"at"`
}

const saVerificationCache = 3 * time.Second

func NewManager(root, localAddress string, id identity.Identity) (*Manager, error) {
	return newManager(root, localAddress, id, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = make([]string, 0, len(os.Environ())+1)
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "SWANCTL_DIR=") {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		cmd.Env = append(cmd.Env, "SWANCTL_DIR="+root)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return out, nil
	})
}

func newManager(root, localAddress string, id identity.Identity, run commandRunner) (*Manager, error) {
	if err := id.Validate(); err != nil {
		return nil, fmt.Errorf("invalid local identity: %w", err)
	}
	if !safeNodeID.MatchString(id.NodeID) {
		return nil, fmt.Errorf("local node ID contains unsupported characters")
	}
	host, _, err := net.SplitHostPort(localAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid local IPv6 endpoint: %w", err)
	}
	localIP := net.ParseIP(host)
	if localIP == nil || localIP.To4() != nil {
		return nil, fmt.Errorf("local endpoint is not IPv6")
	}
	if root == "" {
		return nil, fmt.Errorf("strongSwan runtime directory is required")
	}
	_, localPort, _ := net.SplitHostPort(localAddress)
	if udpServicePort(localPort) == "" {
		return nil, fmt.Errorf("local VX6 port must be below 65534 to reserve the UDP service port")
	}
	m := &Manager{identity: id, localIP: localIP, localPort: localPort, root: root, run: run, peers: make(map[string]record.EndpointRecord), verified: make(map[string]time.Time), revoked: make(map[string]revokedPeer)}
	if data, err := os.ReadFile(filepath.Join(root, "revoked-peers.json")); err == nil {
		if err := json.Unmarshal(data, &m.revoked); err != nil {
			return nil, fmt.Errorf("read revoked peer state: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read revoked peer state: %w", err)
	}
	return m, nil
}

// PreparePeer installs credentials and an IKEv2 connection pinned to a verified
// signed endpoint record. It also installs trap policies so matching traffic
// cannot use an unprotected route while the SA is absent.
func (m *Manager) PreparePeer(ctx context.Context, peer record.EndpointRecord) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.preparePeer(ctx, peer)
}

func (m *Manager) preparePeer(ctx context.Context, peer record.EndpointRecord) error {
	verifiedPeer, err := record.VerifyEndpoint(peer, time.Now())
	if err != nil {
		return fmt.Errorf("reject unverified IPsec peer: %w", err)
	}
	peer = verifiedPeer.Endpoint()
	if !safeNodeID.MatchString(peer.NodeID) {
		return fmt.Errorf("peer node ID contains unsupported characters")
	}
	if udpServicePort(peerPort(peer.Address)) == "" {
		return fmt.Errorf("peer VX6 port must be below 65534 to reserve the UDP service port")
	}
	if peer.NodeID == m.identity.NodeID {
		return fmt.Errorf("cannot create an IPsec peer connection to self")
	}
	m.mu.Lock()
	_, revoked := m.revoked[peer.NodeID]
	m.mu.Unlock()
	if revoked {
		return fmt.Errorf("peer %s is locally revoked", peer.NodeID)
	}
	peerIP, _, err := net.SplitHostPort(peer.Address)
	if err != nil || net.ParseIP(peerIP) == nil || net.ParseIP(peerIP).To4() != nil {
		return fmt.Errorf("peer endpoint must be an IPv6 host and port")
	}
	if peerIP == m.localIP.String() {
		return fmt.Errorf("peer endpoint resolves to local IPv6 address")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.peers[peer.NodeID]; ok && existing.Signature == peer.Signature && existing.Address == peer.Address {
		return nil
	}
	if err := m.writeFiles(verifiedPeer); err != nil {
		return err
	}
	if _, err := m.run(ctx, "swanctl", "--load-creds", "--file", filepath.Join(m.root, "swanctl.conf")); err != nil {
		return fmt.Errorf("load strongSwan credentials: %w", err)
	}
	if _, err := m.run(ctx, "swanctl", "--load-conns", "--file", filepath.Join(m.root, "swanctl.conf")); err != nil {
		return fmt.Errorf("load strongSwan peer connection: %w", err)
	}
	m.peers[peer.NodeID] = peer
	delete(m.verified, peer.NodeID)
	return nil
}

// RevokePeer persistently blocks a peer, terminates its active SA and removes
// its trap policy. Revocation is local to this node and must be explicitly
// lifted by an administrator before this identity can be used again.
func (m *Manager) RevokePeer(ctx context.Context, peer record.EndpointRecord) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	verifiedPeer, err := record.VerifyEndpoint(peer, time.Now())
	if err != nil {
		return fmt.Errorf("cannot revoke unverified peer record: %w", err)
	}
	peer = verifiedPeer.Endpoint()
	nodeID := peer.NodeID
	if !safeNodeID.MatchString(nodeID) || nodeID == m.identity.NodeID {
		return errors.New("invalid peer node ID")
	}
	host, _, err := net.SplitHostPort(peer.Address)
	if err != nil || net.ParseIP(host) == nil || net.ParseIP(host).To4() != nil {
		return errors.New("peer revocation requires a verified IPv6 endpoint")
	}
	m.mu.Lock()
	state := revokedPeer{Address: peer.Address, At: time.Now().UTC()}
	m.revoked[nodeID] = state
	delete(m.verified, nodeID)
	data, err := json.MarshalIndent(m.revoked, "", "  ")
	if err == nil {
		err = writeAtomic(filepath.Join(m.root, "revoked-peers.json"), data, 0o600)
	}
	if err != nil {
		delete(m.revoked, nodeID)
		m.mu.Unlock()
		return fmt.Errorf("persist peer revocation: %w", err)
	}
	fw := m.firewall
	m.mu.Unlock()

	name := connectionName(nodeID)
	out, err := m.run(ctx, "swanctl", "--list-sas", "--ike", name)
	var revokeErr error
	if err != nil {
		revokeErr = fmt.Errorf("check IKE SA during peer revocation: %w", err)
	} else if strings.Contains(string(out), name) && (strings.Contains(string(out), "ESTABLISHED") || strings.Contains(string(out), "INSTALLED")) {
		if _, err := m.run(ctx, "swanctl", "--terminate", "--ike", name, "--timeout", "5"); err != nil {
			revokeErr = fmt.Errorf("terminate peer IKE SA: %w", err)
		}
	}
	if fw != nil {
		if err := fw.Revoke(ctx, nodeID, state.Address); err != nil {
			revokeErr = errors.Join(revokeErr, fmt.Errorf("enforce peer revocation in firewall: %w", err))
		}
	}
	for _, child := range []string{outboundChild(name), inboundChild(name)} {
		if _, err := m.run(ctx, "swanctl", "--uninstall", "--ike", name, "--child", child); err != nil {
			revokeErr = errors.Join(revokeErr, fmt.Errorf("remove revoked peer trap policy %s: %w", child, err))
		}
	}
	return revokeErr
}

// EnsurePeer prepares and initiates a tunnel, then verifies that strongSwan
// reports the peer's CHILD_SA installed before allowing the caller to dial.
func (m *Manager) EnsurePeer(ctx context.Context, peer record.EndpointRecord) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	if err := m.preparePeer(ctx, peer); err != nil {
		return err
	}
	m.mu.Lock()
	_, revoked := m.revoked[peer.NodeID]
	m.mu.Unlock()
	if revoked {
		return fmt.Errorf("peer %s is locally revoked", peer.NodeID)
	}
	if m.saRecentlyVerified(peer.NodeID) {
		return nil
	}
	if m.saInstalled(ctx, peer) {
		return nil
	}
	name := connectionName(peer.NodeID)
	if _, err := m.run(ctx, "swanctl", "--initiate", "--ike", name, "--child", outboundChild(name), "--timeout", "15"); err != nil {
		return fmt.Errorf("IKEv2 negotiation failed for %s: %w", peer.NodeID, err)
	}
	out, err := m.run(ctx, "swanctl", "--list-sas", "--ike", name)
	if err != nil {
		return fmt.Errorf("query IPsec SA for %s: %w", peer.NodeID, err)
	}
	if !childSAInstalled(string(out), outboundChild(name)) {
		return fmt.Errorf("IPsec CHILD_SA for %s is not installed; refusing cleartext dial", peer.NodeID)
	}
	m.mu.Lock()
	m.verified[peer.NodeID] = time.Now()
	m.mu.Unlock()
	return nil
}

func (m *Manager) saRecentlyVerified(nodeID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	verifiedAt, ok := m.verified[nodeID]
	return ok && time.Since(verifiedAt) < saVerificationCache
}

// AuthenticatePeer returns the verified peer record only when the remote IPv6
// endpoint maps to a configured peer with an installed inbound CHILD_SA.
func (m *Manager) AuthenticatePeer(ctx context.Context, remoteAddress string) (record.EndpointRecord, bool) {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return record.EndpointRecord{}, false
	}
	remoteIP := net.ParseIP(host)
	if remoteIP == nil || remoteIP.To4() != nil {
		return record.EndpointRecord{}, false
	}
	m.mu.Lock()
	peers := make([]record.EndpointRecord, 0, len(m.peers))
	for _, candidate := range m.peers {
		peerHost, _, splitErr := net.SplitHostPort(candidate.Address)
		if splitErr == nil && net.ParseIP(peerHost).Equal(remoteIP) && record.VerifyEndpointRecord(candidate, time.Now()) == nil {
			if _, revoked := m.revoked[candidate.NodeID]; revoked {
				continue
			}
			peers = append(peers, candidate)
		}
	}
	m.mu.Unlock()
	for _, peer := range peers {
		if m.childInstalled(ctx, peer, inboundChild(connectionName(peer.NodeID))) {
			return peer, true
		}
	}
	return record.EndpointRecord{}, false
}

// AcceptPeer preserves the boolean admission API for callers that only need
// to reject connections without consuming the authenticated identity.
func (m *Manager) AcceptPeer(ctx context.Context, remoteAddress string) bool {
	_, ok := m.AuthenticatePeer(ctx, remoteAddress)
	return ok
}

func (m *Manager) saInstalled(ctx context.Context, peer record.EndpointRecord) bool {
	return m.childInstalled(ctx, peer, outboundChild(connectionName(peer.NodeID)))
}

// childInstalled reports whether the named CHILD_SA of the peer's IKE_SA is
// installed. Dials need the outbound child; accepted connections need the
// inbound child, because each covers a different ephemeral-port direction.
func (m *Manager) childInstalled(ctx context.Context, peer record.EndpointRecord, child string) bool {
	name := connectionName(peer.NodeID)
	out, err := m.run(ctx, "swanctl", "--list-sas", "--ike", name)
	if err != nil || !childSAInstalled(string(out), child) {
		return false
	}
	m.mu.Lock()
	m.verified[peer.NodeID] = time.Now()
	m.mu.Unlock()
	return true
}

func (m *Manager) writeFiles(verifiedPeer record.VerifiedEndpointRecord) error {
	peer := verifiedPeer.Endpoint()
	for _, dir := range []string{"conf.d", "private", "pubkey"} {
		dirPath := filepath.Join(m.root, dir)
		if err := os.MkdirAll(dirPath, 0o700); err != nil {
			return fmt.Errorf("create strongSwan %s directory: %w", dir, err)
		}
		if err := os.Chmod(dirPath, 0o700); err != nil {
			return fmt.Errorf("restrict strongSwan %s directory: %w", dir, err)
		}
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(m.identity.PrivateKey))
	if err != nil {
		return fmt.Errorf("encode local Ed25519 private key: %w", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	localPublicDER, err := x509.MarshalPKIXPublicKey(m.identity.PublicKey)
	if err != nil {
		return fmt.Errorf("encode local Ed25519 public key: %w", err)
	}
	localPublicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: localPublicDER})
	peerRaw := verifiedPeer.PublicKey()
	peerDER, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(peerRaw))
	if err != nil {
		return fmt.Errorf("encode peer Ed25519 public key: %w", err)
	}
	peerPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: peerDER})
	name := connectionName(peer.NodeID)
	files := map[string][]byte{
		"swanctl.conf": []byte("include conf.d/*.conf\n"),
		filepath.Join("private", m.identity.NodeID+".pem"): privatePEM,
		filepath.Join("pubkey", m.identity.NodeID+".pem"):  localPublicPEM,
		filepath.Join("pubkey", peer.NodeID+".pem"):        peerPEM,
		filepath.Join("conf.d", name+".conf"):              []byte(connectionConfig(name, m.localIP.String(), m.localPort, peerRawAddress(peer.Address), peerPort(peer.Address), filepath.Join(m.root, "pubkey", m.identity.NodeID+".pem"), filepath.Join(m.root, "pubkey", peer.NodeID+".pem"))),
	}
	for path, data := range files {
		mode := os.FileMode(0o600)
		if path == "swanctl.conf" || strings.HasPrefix(path, "conf.d/") || strings.HasPrefix(path, "pubkey/") {
			mode = 0o644
		}
		if err := writeAtomic(filepath.Join(m.root, path), data, mode); err != nil {
			return err
		}
	}
	return nil
}

// connectionConfig generates one IKE connection with two CHILD_SAs.
//
// A VX6 service connection has the listener's port on one end and an
// ephemeral port on the other. A single child with the VX6 port on both
// selectors (local[tcp/P] === remote[tcp/P]) matches only traffic whose
// source and destination ports are both P, so ordinary dials from an
// ephemeral port would match no policy. Each child here pins only the
// listener side:
//
//   - <name>-out: local host, any port === peer host, TCP VX6 port and UDP port+2
//     (this node dials the peer)
//   - <name>-in:  local host, TCP VX6 port and UDP port+2 === peer host, any port
//     (the peer dials this node)
//
// Only TCP/UDP is covered, so the separate liveness probe port remains
// outside the SA as before, while all VX6 service traffic is protected.
func connectionConfig(name, localIP, localPort, remoteIP, remotePort, localKeyFile, peerKeyFile string) string {
	child := func(child, localTS, remoteTS string) string {
		return fmt.Sprintf(`      %s {
        mode = tunnel
        local_ts = %s
        remote_ts = %s
        esp_proposals = aes128gcm16
        start_action = trap
        close_action = trap
        dpd_action = restart
      }
`, child, localTS, remoteTS)
	}
	ts := func(ip, tcpPort, udpPort string) string {
		if tcpPort != "" {
			tcpPort = "/" + tcpPort
		}
		if udpPort != "" {
			udpPort = "/" + udpPort
		}
		return fmt.Sprintf("%s/128[tcp%s], %s/128[udp%s]", ip, tcpPort, ip, udpPort)
	}
	return fmt.Sprintf(`connections {
  %s {
    version = 2
    local_addrs = %s
    remote_addrs = %s
    proposals = aes128gcm16-prfsha256-curve25519
    mobike = no
    local {
      auth = pubkey
      pubkeys = %s
    }
    remote {
      auth = pubkey
      id = %%any
      pubkeys = %s
    }
    children {
%s%s    }
  }
}
`, name, localIP, remoteIP, localKeyFile, peerKeyFile,
		child(outboundChild(name), ts(localIP, "", ""), ts(remoteIP, remotePort, udpServicePort(remotePort))),
		child(inboundChild(name), ts(localIP, localPort, udpServicePort(localPort)), ts(remoteIP, "", "")))
}

func incrementPort(port string) string {
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value >= 65535 {
		return ""
	}
	return strconv.Itoa(value + 1)
}

func udpServicePort(port string) string {
	probePort := incrementPort(port)
	if probePort == "" {
		return ""
	}
	return incrementPort(probePort)
}

func outboundChild(name string) string { return name + "-out" }
func inboundChild(name string) string  { return name + "-in" }

func peerRawAddress(address string) string {
	host, _, _ := net.SplitHostPort(address)
	return host
}

func peerPort(address string) string {
	_, port, _ := net.SplitHostPort(address)
	return port
}

var safeNodeID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func connectionName(nodeID string) string {
	sum := sha256.Sum256([]byte(nodeID))
	return fmt.Sprintf("vx6-%x", sum[:8])
}

// childSAInstalled reports whether swanctl --list-sas output lists the exact
// CHILD_SA name as INSTALLED. Child lines look like
// "  <child>: #2, reqid 1, INSTALLED, TUNNEL, ...". The name must match the
// whole label so "vx6-x-in" never satisfies a check for "vx6-x-out" or the
// IKE_SA line "vx6-x: #1, ESTABLISHED".
func childSAInstalled(output, child string) bool {
	for _, line := range strings.Split(output, "\n") {
		label, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && label == child && strings.Contains(rest, "INSTALLED") {
			return true
		}
	}
	return false
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vx6-ipsec-*")
	if err != nil {
		return fmt.Errorf("create temporary strongSwan file for %s: %w", path, err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set strongSwan file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write strongSwan file %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync strongSwan file %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close strongSwan file %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("install strongSwan file %s: %w", path, err)
	}
	return nil
}
