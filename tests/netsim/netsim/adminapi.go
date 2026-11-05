// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import "time"

// These mirror the JSON the simnode admin socket returns. They are duplicated
// here (rather than imported) so the orchestrator stays decoupled from the
// node binary and could, in principle, drive nodes on other hosts.

type Snapshot struct {
	Time    time.Time  `json:"time"`
	Name    string     `json:"name"`
	NodeID  string     `json:"node_id"`
	Addr    string     `json:"addr"`
	Active  int        `json:"active"`
	Peers   []PeerView `json:"peers"`
	Records int        `json:"registry_records"`
	RSSKB   int        `json:"rss_kb"`
	Uptime  float64    `json:"uptime_sec"`
}

type PeerView struct {
	ID       string `json:"id"`
	Addr     string `json:"addr"`
	Success  uint32 `json:"success"`
	Fail     uint8  `json:"fail"`
	RTTMicro uint32 `json:"rtt_us"`
	Pinned   bool   `json:"pinned,omitempty"`
}

type LookupReport struct {
	Target    string  `json:"target"`
	Outcome   string  `json:"outcome"`
	Found     bool    `json:"found"`
	Rounds    int     `json:"rounds"`
	Queried   int     `json:"queried"`
	LatencyMS float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
}
