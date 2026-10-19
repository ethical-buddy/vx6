// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type firewallState struct {
	Ports   []uint16            `json:"ports"`
	Revoked map[string][]string `json:"revoked"`
}

type firewallApply func(context.Context, string) error

// Firewall owns only the dedicated inet/vx6 nftables table.
type Firewall struct {
	mu    sync.Mutex
	path  string
	state firewallState
	apply firewallApply
}

func NewFirewall(stateDir string) (*Firewall, error) {
	return newFirewall(stateDir, applyNFT)
}

func newFirewall(stateDir string, apply firewallApply) (*Firewall, error) {
	f := &Firewall{path: filepath.Join(stateDir, "firewall.json"), state: firewallState{Revoked: make(map[string][]string)}, apply: apply}
	if data, err := os.ReadFile(f.path); err == nil {
		if err := json.Unmarshal(data, &f.state); err != nil {
			return nil, fmt.Errorf("read VX6 firewall state: %w", err)
		}
		if f.state.Revoked == nil {
			f.state.Revoked = make(map[string][]string)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read VX6 firewall state: %w", err)
	}
	return f, nil
}

func (f *Firewall) Restore(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.apply(ctx, firewallRules(f.state))
}

func (f *Firewall) RegisterPort(ctx context.Context, port string) error {
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return errors.New("invalid VX6 listener port")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.state.Ports {
		if existing == uint16(value) {
			return nil
		}
	}
	f.state.Ports = append(f.state.Ports, uint16(value))
	if err := f.saveAndApply(ctx); err != nil {
		f.state.Ports = f.state.Ports[:len(f.state.Ports)-1]
		return err
	}
	return nil
}

func (f *Firewall) Revoke(ctx context.Context, nodeID, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("cannot firewall-revoke peer with invalid address")
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		return errors.New("cannot firewall-revoke non-IPv6 peer")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	old := append([]string(nil), f.state.Revoked[nodeID]...)
	for _, existing := range old {
		if existing == ip.String() {
			return nil
		}
	}
	f.state.Revoked[nodeID] = append(old, ip.String())
	if err := f.saveAndApply(ctx); err != nil {
		f.state.Revoked[nodeID] = old
		return err
	}
	return nil
}

func (f *Firewall) saveAndApply(ctx context.Context) error {
	data, err := json.MarshalIndent(f.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	if err := writeAtomic(f.path, data, 0o600); err != nil {
		return fmt.Errorf("persist VX6 firewall state: %w", err)
	}
	if err := f.apply(ctx, firewallRules(f.state)); err != nil {
		return fmt.Errorf("apply VX6 nftables policy: %w", err)
	}
	return nil
}

func firewallRules(state firewallState) string {
	ports := append([]uint16(nil), state.Ports...)
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	var b strings.Builder
	b.WriteString("add table inet vx6\n")
	b.WriteString("add chain inet vx6 input { type filter hook input priority -10; policy accept; }\n")
	b.WriteString("add chain inet vx6 output { type filter hook output priority -10; policy accept; }\n")
	b.WriteString("flush chain inet vx6 input\nflush chain inet vx6 output\n")
	for _, port := range ports {
		p := strconv.Itoa(int(port))
		b.WriteString("add rule inet vx6 input tcp dport " + p + " meta ipsec exists accept\n")
		b.WriteString("add rule inet vx6 input udp dport " + p + " meta ipsec exists accept\n")
		b.WriteString("add rule inet vx6 input tcp dport " + p + " drop\n")
		b.WriteString("add rule inet vx6 input udp dport " + p + " drop\n")
		b.WriteString("add rule inet vx6 output tcp dport " + p + " rt ipsec exists accept\n")
		b.WriteString("add rule inet vx6 output udp dport " + p + " rt ipsec exists accept\n")
		b.WriteString("add rule inet vx6 output tcp dport " + p + " drop\n")
		b.WriteString("add rule inet vx6 output udp dport " + p + " drop\n")
	}
	nodes := make([]string, 0, len(state.Revoked))
	for node := range state.Revoked {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	for _, node := range nodes {
		ips := append([]string(nil), state.Revoked[node]...)
		sort.Strings(ips)
		for _, address := range ips {
			ip := net.ParseIP(address)
			if ip == nil || ip.To4() != nil {
				continue
			}
			b.WriteString("add rule inet vx6 input ip6 saddr " + ip.String() + " udp dport 500 drop\n")
			b.WriteString("add rule inet vx6 output ip6 daddr " + ip.String() + " udp dport 500 drop\n")
			b.WriteString("add rule inet vx6 input ip6 saddr " + ip.String() + " meta l4proto esp drop\n")
			b.WriteString("add rule inet vx6 output ip6 daddr " + ip.String() + " meta l4proto esp drop\n")
		}
	}
	return b.String()
}

func applyNFT(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-exist", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
