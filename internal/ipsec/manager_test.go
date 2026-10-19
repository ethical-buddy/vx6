package ipsec

import (
	"context"
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
	for _, want := range []string{"version = 2", "auth = pubkey", "id = @" + remote.NodeID, "pubkeys = " + remote.NodeID + ".pem", "mode = tunnel", "local_ts = 2001:db8::1/128", "remote_ts = 2001:db8::2/128", "start_action = trap", "esp_proposals = aes128gcm16"} {
		if !strings.Contains(string(config), want) {
			t.Errorf("generated connection config lacks %q", want)
		}
	}
	if strings.Contains(string(config), "service") || strings.Contains(string(config), "4242") {
		t.Fatal("generated IPsec config unexpectedly exposes VX6 application details")
	}
	info, err := os.Stat(filepath.Join(root, "private", local.NodeID+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("local private key mode is %o, want 600", info.Mode().Perm())
	}
	if len(calls) != 2 || !strings.Contains(calls[0], "--load-creds") || !strings.Contains(calls[1], "--load-conns") {
		t.Fatalf("unexpected strongSwan load sequence: %v", calls)
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
			return []byte(connectionName(remote.NodeID) + ": #1, ESTABLISHED, IKEv2\n  " + connectionName(remote.NodeID) + ": #1, INSTALLED, TUNNEL\n"), nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.EnsurePeer(context.Background(), peer); err != nil {
		t.Fatalf("EnsurePeer rejected installed SA: %v", err)
	}
	if len(calls) != 4 || !strings.Contains(calls[2], "--initiate") || !strings.Contains(calls[3], "--list-sas") {
		t.Fatalf("unexpected ensure sequence: %v", calls)
	}
	if err := manager.EnsurePeer(context.Background(), peer); err != nil {
		t.Fatalf("cached SA verification failed: %v", err)
	}
	if len(calls) != 4 {
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
			return []byte(name + ": #1, INSTALLED, TUNNEL\n"), nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.PreparePeer(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	if manager.AcceptPeer(context.Background(), "[2001:db8::2]:50000") {
		t.Fatal("accepted inbound peer with no installed CHILD_SA")
	}
	installed = true
	if !manager.AcceptPeer(context.Background(), "[2001:db8::2]:50000") {
		t.Fatal("rejected peer after CHILD_SA became installed")
	}
	if manager.AcceptPeer(context.Background(), "[2001:db8::3]:50000") {
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
	manager, err := newManager(t.TempDir(), "[2001:db8::1]:4242", local, func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) > 0 && args[0] == "--list-sas" {
			connection := connectionName(remote.NodeID)
			return []byte(connection + ": #1, ESTABLISHED, IKEv2\n  " + connection + ": #1, INSTALLED, TUNNEL\n"), nil
		}
		return nil, nil
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
	if len(calls) != 5 || !strings.Contains(calls[3], "--terminate") || !strings.Contains(calls[4], "--uninstall") {
		t.Fatalf("unexpected revoke sequence: %v", calls)
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

func TestChildSAInstalledRequiresExpectedConnectionAndState(t *testing.T) {
	if !childSAInstalled("vx6-a: #1, ESTABLISHED, IKEv2\n  vx6-a: #1, INSTALLED, TUNNEL", "vx6-a") {
		t.Fatal("failed to recognize installed CHILD_SA")
	}
	for _, output := range []string{"vx6-a: #1, ESTABLISHED, IKEv2", "vx6-b: #1, INSTALLED, TUNNEL"} {
		if childSAInstalled(output, "vx6-a") {
			t.Fatalf("accepted non-installed or wrong peer SA: %q", output)
		}
	}
}
