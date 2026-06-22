// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package sdk

import (
	"github.com/vx6/vx6/internal/identity"
)

type LocalNodeInfo struct {
	NodeID        string `json:"node_id"`
	NodeName      string `json:"node_name"`
	ListenAddr    string `json:"listen_addr"`
	AdvertiseAddr string `json:"advertise_addr"`
	ConfigPath    string `json:"config_path"`
	DataDir       string `json:"data_dir"`
}

func (c *Client) LocalNodeInfo() (LocalNodeInfo, error) {
	cfg, err := c.store.Load()
	if err != nil {
		return LocalNodeInfo{}, err
	}
	idStore, err := identity.NewStoreForConfig(c.store.Path())
	if err != nil {
		return LocalNodeInfo{}, err
	}
	id, err := idStore.Load()
	if err != nil {
		return LocalNodeInfo{}, err
	}
	return LocalNodeInfo{
		NodeID:        id.NodeID,
		NodeName:      cfg.Node.Name,
		ListenAddr:    cfg.Node.ListenAddr,
		AdvertiseAddr: cfg.Node.AdvertiseAddr,
		ConfigPath:    c.store.Path(),
		DataDir:       cfg.Node.DataDir,
	}, nil
}
