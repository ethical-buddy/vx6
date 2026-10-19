// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/vx6/vx6/internal/ipsec"
	"golang.org/x/sys/unix"
)

type serviceConfig struct {
	Socket      string   `json:"socket"`
	StateDir    string   `json:"state_dir"`
	SocketGID   uint32   `json:"socket_gid"`
	AllowedUIDs []uint32 `json:"allowed_uids"`
}

func main() {
	configPath := flag.String("config", "/etc/vx6/ipsecd.json", "root-managed service configuration")
	flag.Parse()
	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "vx6-ipsecd:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	if os.Geteuid() != 0 {
		return errors.New("must be started by the system service manager")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect service configuration: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("service configuration must not be a symlink or writable by group/other")
	}
	stat, ok := info.Sys().(*unix.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("service configuration must be owned by root")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open service configuration: %w", err)
	}
	defer file.Close()
	var cfg serviceConfig
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return fmt.Errorf("decode service configuration: %w", err)
	}
	if cfg.Socket == "" || cfg.StateDir == "" || len(cfg.AllowedUIDs) == 0 || cfg.SocketGID == 0 {
		return errors.New("socket, state_dir, and allowed_uids are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return ipsec.Serve(ctx, cfg.Socket, cfg.StateDir, cfg.AllowedUIDs, cfg.SocketGID)
}
