package ipsec

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/record"
)

func TestPreparePeerWritesPinnedIPv6TunnelConfig(t *testing.T) {
	local, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	remote, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := record.NewEndpointRecord(remote, "peer", "[2001:db8::2]:4242", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "private"), 0o755); err != nil {
		t.Fatal(err)
	}
	var calls []string
	manager, err := newManager(root, "[2001:db8::1]:4242", local, func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.PreparePeer(context.Background(), peer); err != nil {
		t.Fatal(err)
	}

	config, err := os.ReadFile(filepath.Join(root, "conf.d", connectionName(remote.NodeID)+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"version = 2", "auth = pubkey", "pubkeys = " + filepath.Join(root, "pubkey", local.NodeID+".pem"), "id = %any", "pubkeys = " + filepath.Join(root, "pubkey", remote.NodeID+".pem"), "mode = tunnel", "-out {", "-in {", "local_ts = 2001:db8::1/128[tcp], 2001:db8::1/128[udp]", "remote_ts = 2001:db8::2/128[tcp/4242], 2001:db8::2/128[udp/4242]", "local_ts = 2001:db8::1/128[tcp/4242], 2001:db8::1/128[udp/4242]", "remote_ts = 2001:db8::2/128[tcp], 2001:db8::2/128[udp]", "start_action = trap", "esp_proposals = aes128gcm16"} {
		if !strings.Contains(string(config), want) {
			t.Errorf("generated connection config lacks %q", want)
		}
	}
	if strings.Contains(string(config), "id = @") {
		t.Fatal("generated IKE config must not use the VX6 node name as the raw-key IKE identity")
	}
	if strings.Contains(string(config), "service") || strings.Contains(string(config), "udp/4243") {
		t.Fatal("generated IPsec config unexpectedly includes a VX6 service label or cleartext liveness port")
	}
	info, err := os.Stat(filepath.Join(root, "private", local.NodeID+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("local private key mode is %o, want 600", info.Mode().Perm())
	}
	peerKeyFile, err := os.ReadFile(filepath.Join(root, "pubkey", remote.NodeID+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(peerKeyFile)
	if block == nil {
		t.Fatal("peer public-key pin is not valid PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse pinned peer public key: %v", err)
	}
	pinned, ok := parsed.(ed25519.PublicKey)
	if !ok || !pinned.Equal(remote.PublicKey) {
		t.Fatal("IKE peer pin does not match the expected node's Ed25519 key")
	}
	for _, dir := range []string{"private", "pubkey", "conf.d"} {
		info, err := os.Stat(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("directory %s mode = %o, want 700", dir, info.Mode().Perm())
		}
	}
	if len(calls) != 2 || !strings.Contains(calls[0], "--load-creds") || !strings.Contains(calls[1], "--load-conns") {
		t.Fatalf("unexpected strongSwan load sequence: %v", calls)
	}
}

func TestPreparePeerRejectsKeySubstitution(t *testing.T) {
	local, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	remote, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	other, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := record.NewEndpointRecord(remote, "peer", "[2001:db8::2]:4242", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	peer.PublicKey = base64.StdEncoding.EncodeToString(other.PublicKey)
	manager, err := newManager(t.TempDir(), "[2001:db8::1]:4242", local, func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("invoked IPsec manager for a substituted peer key")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.PreparePeer(context.Background(), peer); err == nil {
		t.Fatal("accepted a peer record whose key no longer matches its signature and node ID")
	}
}

func TestPreparePeerRejectsTamperedOrExpiredRecord(t *testing.T) {
	local, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	remote, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	peer, err := record.NewEndpointRecord(remote, "peer", "[2001:db8::2]:4242", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := newManager(t.TempDir(), "[2001:db8::1]:4242", local, func(context.Context, string, ...string) ([]byte, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	peer.Address = "[2001:db8::3]:4242"
	if err := manager.PreparePeer(context.Background(), peer); err == nil {
		t.Fatal("accepted tampered endpoint record")
	}
	peer, err = record.NewEndpointRecord(remote, "peer", "[2001:db8::2]:4242", time.Second, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.PreparePeer(context.Background(), peer); err == nil {
		t.Fatal("accepted expired endpoint record")
	}
}

func TestEnsurePeerFailsClosedWithoutInstalledChildSA(t *testing.T) {
	local, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	remote, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := record.NewEndpointRecord(remote, "peer", "[2001:db8::2]:4242", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := newManager(t.TempDir(), "[2001:db8::1]:4242", local, func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "swanctl" && len(args) > 0 && args[0] == "--list-sas" {
			return []byte(connectionName(remote.NodeID) + ": ESTABLISHED, IKEv2\n"), nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.EnsurePeer(context.Background(), peer); err == nil || !strings.Contains(err.Error(), "CHILD_SA") {
		t.Fatalf("EnsurePeer = %v, want fail-closed missing CHILD_SA", err)
	}
}

func TestEnsurePeerAcceptsOnlyInstalledChildSA(t *testing.T) {
	local, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	remote, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := record.NewEndpointRecord(remote, "peer", "[2001:db8::2]:4242", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	manager, err := newManager(t.TempDir(), "[2001:db8::1]:4242", local, func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		if len(args) > 0 && args[0] == "--list-sas" {
			return []byte(connectionName(remote.NodeID) + ": #1, ESTABLISHED, IKEv2\n  " + connectionName(remote.NodeID) + "-out: #1, INSTALLED, TUNNEL\n"), nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.EnsurePeer(context.Background(), peer); err != nil {
		t.Fatalf("EnsurePeer rejected installed SA: %v", err)
	}
	if len(calls) != 3 || strings.Contains(strings.Join(calls, " "), "--initiate") || !strings.Contains(calls[2], "--list-sas") {
		t.Fatalf("unexpected ensure sequence: %v", calls)
	}
	if err := manager.EnsurePeer(context.Background(), peer); err != nil {
		t.Fatalf("cached SA verification failed: %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("cached SA caused redundant strongSwan calls: %v", calls)
	}
}

func TestAcceptPeerRequiresCurrentlyInstalledSA(t *testing.T) {
	local, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	remote, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := record.NewEndpointRecord(remote, "peer", "[2001:db8::2]:4242", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	installed := false
	manager, err := newManager(t.TempDir(), "[2001:db8::1]:4242", local, func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--list-sas" && installed {
			name := connectionName(remote.NodeID)
			return []byte(name + "-in: #1, INSTALLED, TUNNEL\n"), nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.PreparePeer(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	if _, ok := manager.AuthenticatePeer(context.Background(), "[2001:db8::2]:50000"); ok {
		t.Fatal("accepted inbound peer with no installed CHILD_SA")
	}
	installed = true
	authenticated, ok := manager.AuthenticatePeer(context.Background(), "[2001:db8::2]:50000")
	if !ok {
		t.Fatal("rejected peer after CHILD_SA became installed")
	}
	if authenticated.NodeID != remote.NodeID || authenticated.PublicKey != peer.PublicKey {
		t.Fatalf("authenticated identity mismatch: got %s", authenticated.NodeID)
	}
	if _, ok := manager.AuthenticatePeer(context.Background(), "[2001:db8::3]:50000"); ok {
		t.Fatal("accepted inbound traffic from an unrecognized address")
	}
}

func TestRevokePeerPersistsBlocksAndTerminatesPeer(t *testing.T) {
	local, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	remote, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := record.NewEndpointRecord(remote, "peer", "[2001:db8::2]:4242", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	var events []string
	manager, err := newManager(t.TempDir(), "[2001:db8::1]:4242", local, func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) > 0 {
			events = append(events, args[0])
		}
		if len(args) > 0 && args[0] == "--list-sas" {
			connection := connectionName(remote.NodeID)
			return []byte(connection + ": #1, ESTABLISHED, IKEv2\n  " + connection + "-out: #1, INSTALLED, TUNNEL\n  " + connection + "-in: #2, INSTALLED, TUNNEL\n"), nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.firewall, err = newFirewall(filepath.Join(manager.root, "firewall"), func(context.Context, string) error {
		events = append(events, "firewall")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.PreparePeer(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	if err := manager.RevokePeer(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	if manager.AcceptPeer(context.Background(), "[2001:db8::2]:50000") {
		t.Fatal("accepted an installed peer after local revocation")
	}
	if len(calls) != 6 || !strings.Contains(calls[3], "--terminate") || !strings.Contains(calls[4], "--uninstall") || !strings.HasSuffix(calls[4], "-out") || !strings.HasSuffix(calls[5], "-in") {
		t.Fatalf("unexpected revoke sequence: %v", calls)
	}
	if len(events) != 7 || events[2] != "--list-sas" || events[3] != "--terminate" || events[4] != "firewall" || events[5] != "--uninstall" || events[6] != "--uninstall" {
		t.Fatalf("unexpected revocation enforcement order: %v", events)
	}
	if err := manager.PreparePeer(context.Background(), peer); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("PreparePeer after revoke = %v, want revoked error", err)
	}
	manager2, err := newManager(manager.root, "[2001:db8::1]:4242", local, func(context.Context, string, ...string) ([]byte, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := manager2.PreparePeer(context.Background(), peer); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("restart forgot local revocation: %v", err)
	}
}

func TestReplacementIdentityRequiresNewNodeIDAndExplicitEnrollment(t *testing.T) {
	local, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldIdentity, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	newIdentity, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if oldIdentity.NodeID == newIdentity.NodeID {
		t.Fatal("replacement key retained the old NodeID")
	}
	now := time.Now()
	oldPeer, err := record.NewEndpointRecord(oldIdentity, "peer", "[2001:db8::2]:4242", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	newPeer, err := record.NewEndpointRecord(newIdentity, "peer", "[2001:db8::3]:4242", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	manager, err := newManager(t.TempDir(), "[2001:db8::1]:4242", local, func(_ context.Context, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--list-sas" {
			connection := connectionName(newIdentity.NodeID)
			return []byte(connection + ": #1, ESTABLISHED, IKEv2\n  " + connection + "-out: #1, INSTALLED, TUNNEL\n  " + connection + "-in: #2, INSTALLED, TUNNEL\n"), nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.firewall, err = newFirewall(filepath.Join(manager.root, "firewall"), func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.PreparePeer(context.Background(), oldPeer); err != nil {
		t.Fatal(err)
	}
	if err := manager.RevokePeer(context.Background(), oldPeer); err != nil {
		t.Fatal(err)
	}
	if err := manager.EnsurePeer(context.Background(), newPeer); err != nil {
		t.Fatalf("explicitly enrolled replacement identity was rejected: %v", err)
	}
	if err := manager.EnsurePeer(context.Background(), oldPeer); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("old identity after replacement = %v, want locally revoked", err)
	}
}

func TestChildSAInstalledRequiresExpectedConnectionAndState(t *testing.T) {
	output := "vx6-a: #1, ESTABLISHED, IKEv2\n  vx6-a-out: #1, reqid 1, INSTALLED, TUNNEL"
	if !childSAInstalled(output, "vx6-a-out") {
		t.Fatal("failed to recognize installed CHILD_SA")
	}
	for _, tc := range []struct{ output, child string }{
		{"vx6-a: #1, ESTABLISHED, IKEv2", "vx6-a-out"},
		{"vx6-b-out: #1, INSTALLED, TUNNEL", "vx6-a-out"},
		{output, "vx6-a-in"},                                 // other direction only
		{"  vx6-a-outx: #1, INSTALLED, TUNNEL", "vx6-a-out"}, // prefix only
	} {
		if childSAInstalled(tc.output, tc.child) {
			t.Fatalf("accepted non-installed or wrong SA %q for %q", tc.output, tc.child)
		}
	}
}

// A VX6 service connection always has an ephemeral port on the dialing side.
// Every (dialer, listener) direction must be covered by exactly the child the
// manager checks for it; a selector pair with the VX6 port on both ends would
// leave ordinary dials unprotected (they match no IPsec policy).
func TestSelectorsCoverEphemeralSourcePorts(t *testing.T) {
	cfg := connectionConfig("vx6-x", "2001:db8::1", "4242", "2001:db8::2", "4343", "/l.pem", "/r.pem")
	children := parseChildren(t, cfg)
	type flow struct{ lport, rport int }
	covers := func(c childTS, f flow) bool {
		return c.local.match(f.lport) && c.remote.match(f.rport)
	}
	// This node dials the peer's listener (4343) from an ephemeral port.
	if c := children["vx6-x-out"]; !covers(c, flow{51234, 4343}) {
		t.Fatalf("outbound child does not cover local ephemeral -> peer listener: %+v", c)
	}
	// The peer dials this node's listener (4242) from an ephemeral port.
	if c := children["vx6-x-in"]; !covers(c, flow{4242, 60001}) {
		t.Fatalf("inbound child does not cover peer ephemeral -> local listener: %+v", c)
	}
	// Neither child may cover arbitrary non-VX6 port pairs.
	for name, c := range children {
		if covers(c, flow{51234, 60001}) {
			t.Fatalf("child %s covers non-VX6 traffic: %+v", name, c)
		}
	}
}

type portSel struct {
	any  bool
	port int
}

func (p portSel) match(port int) bool { return p.any || p.port == port }

type childTS struct{ local, remote portSel }

func parseChildren(t *testing.T, cfg string) map[string]childTS {
	t.Helper()
	out := map[string]childTS{}
	var current string
	sel := func(v string) portSel {
		first := strings.TrimSpace(strings.Split(v, ",")[0])
		open := strings.Index(first, "[")
		if open < 0 {
			return portSel{any: true}
		}
		inner := strings.TrimSuffix(first[open+1:], "]")
		_, port, ok := strings.Cut(inner, "/")
		if !ok {
			return portSel{any: true}
		}
		var n int
		if _, err := fmt.Sscanf(port, "%d", &n); err != nil {
			t.Fatalf("bad selector %q", first)
		}
		return portSel{port: n}
	}
	for _, line := range strings.Split(cfg, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "{") && strings.HasPrefix(line, "vx6-x-") {
			current = strings.TrimSpace(strings.TrimSuffix(line, "{"))
			continue
		}
		if current == "" {
			continue
		}
		c := out[current]
		if v, ok := strings.CutPrefix(line, "local_ts = "); ok {
			c.local = sel(v)
		}
		if v, ok := strings.CutPrefix(line, "remote_ts = "); ok {
			c.remote = sel(v)
		}
		out[current] = c
	}
	if len(out) != 2 {
		t.Fatalf("expected two children, got %v", out)
	}
	return out
}
