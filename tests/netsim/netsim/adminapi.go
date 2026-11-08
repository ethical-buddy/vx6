// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import "time"

// These mirror the JSON the simnode admin socket returns. They are duplicated
// here (rather than imported) so the orchestrator stays decoupled from the
// node binary and could, in principle, drive nodes on other hosts.

type Snapshot struct {
	Time     time.Time    `json:"time"`
	Name     string       `json:"name"`
	NodeID   string       `json:"node_id"`
	NameHash string       `json:"name_hash"`
	Addr     string       `json:"addr"`
	Active   int          `json:"active"`
	Peers    []PeerView   `json:"peers"`
	Records  int          `json:"registry_records"`
	RSSKB    int          `json:"rss_kb"`
	Uptime   float64      `json:"uptime_sec"`
	Lookup   LookupPolicy `json:"lookup_policy"`
}

type LookupPolicy struct {
	MaxRounds      int   `json:"max_rounds"`
	MaxConcurrent  int   `json:"max_concurrent"`
	MaxPeerQueries int   `json:"max_peer_queries"`
	MaxReferrals   int   `json:"max_referrals_per_reply"`
	PeerTimeoutMS  int64 `json:"peer_timeout_ms"`
	TotalTimeoutMS int64 `json:"total_timeout_ms"`
}

type PeerView struct {
	ID       string `json:"id"`
	NameHash string `json:"name_hash"`
	Addr     string `json:"addr"`
	ASN      uint32 `json:"asn,omitempty"`
	Prefix48 string `json:"prefix_48,omitempty"`
	Success  uint32 `json:"success"`
	Fail     uint8  `json:"fail"`
	RTTMicro uint32 `json:"rtt_us"`
	Pinned   bool   `json:"pinned,omitempty"`
}

type LookupReport struct {
	Source         string  `json:"source,omitempty"`
	TargetType     string  `json:"target_type"`
	Target         string  `json:"target"`
	ExpectedNodeID string  `json:"expected_node_id,omitempty"`
	Outcome        string  `json:"outcome"`
	Found          bool    `json:"found_expected"`
	MatchCount     int     `json:"match_count"`
	Rounds         int     `json:"rounds"`
	Queried        int     `json:"queried"`
	LatencyMS      float64 `json:"latency_ms"`
	Error          string  `json:"error,omitempty"`
}
