package ipsec

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFirewallPersistsPortGuardAndRevokedPeer(t *testing.T) {
	var scripts []string
	dir := t.TempDir()
	apply := func(_ context.Context, script string) error {
		scripts = append(scripts, script)
		return nil
	}
	fw, err := newFirewall(dir, apply)
	if err != nil {
		t.Fatal(err)
	}
	if err := fw.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fw.RegisterPort(context.Background(), "4242"); err != nil {
		t.Fatal(err)
	}
	if err := fw.Revoke(context.Background(), "node-a", "[2001:db8::2]:4242"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(scripts, "\n")
	for _, want := range []string{
		"meta ipsec exists accept", "rt ipsec exists accept", "tcp dport 4242 drop",
		"udp dport 4242 drop", "ip6 saddr 2001:db8::2 udp dport 500 drop",
		"ip6 daddr 2001:db8::2 meta l4proto esp drop",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("firewall script missing %q", want)
		}
	}
	info, err := os.Stat(filepath.Join(dir, "firewall.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("firewall state mode is %o, want 600", info.Mode().Perm())
	}
	var restored string
	fw2, err := newFirewall(dir, func(_ context.Context, script string) error { restored = script; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := fw2.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(restored, "2001:db8::2") || !strings.Contains(restored, "4242") {
		t.Fatalf("firewall state did not restore port/revocation: %s", restored)
	}
}

func TestFirewallRejectsInvalidPortAndNonIPv6Revocation(t *testing.T) {
	fw, err := newFirewall(t.TempDir(), func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := fw.RegisterPort(context.Background(), "65536"); err == nil {
		t.Fatal("accepted out-of-range port")
	}
	if err := fw.Revoke(context.Background(), "node-a", "192.0.2.1:4242"); err == nil {
		t.Fatal("accepted IPv4 peer revocation")
	}
}

func TestFirewallKernelEnforcement(t *testing.T) {
	if os.Getenv("VX6_RUN_IPSEC_NETNS_TEST") != "1" {
		t.Skip("run only inside an isolated network namespace with CAP_NET_ADMIN")
	}
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	state := firewallState{Ports: []uint16{uint16(port)}, Revoked: map[string][]string{"revoked": {"2001:db8::2"}}}
	if err := applyNFT(context.Background(), firewallRules(state)); err != nil {
		t.Fatalf("install firewall policy in isolated netns: %v", err)
	}
	defer func() {
		_ = applyNFT(context.Background(), "delete table inet vx6\n")
	}()

	dialCtx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp6", fmt.Sprintf("[::1]:%d", port))
	if err == nil {
		_ = conn.Close()
		t.Fatal("cleartext TCP reached a VX6 listener despite the nftables guard")
	}
	select {
	case conn := <-acceptConn(listener):
		_ = conn.Close()
		t.Fatal("listener accepted cleartext TCP despite the nftables guard")
	case <-time.After(100 * time.Millisecond):
	}
}

func acceptConn(listener net.Listener) <-chan net.Conn {
	ch := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			ch <- conn
		}
	}()
	return ch
}
