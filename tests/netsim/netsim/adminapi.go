// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"encoding/json"
	"time"
)

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
	Source            string  `json:"source,omitempty"`
	TargetType        string  `json:"target_type"`
	Target            string  `json:"target"`
	ExpectedNodeID    string  `json:"expected_node_id,omitempty"`
	SourceTargetState string  `json:"source_target_state,omitempty"`
	Outcome           string  `json:"outcome"`
	Found             bool    `json:"found_expected"`
	MatchCount        int     `json:"match_count"`
	Rounds            int     `json:"rounds"`
	Queried           int     `json:"queried"`
	LatencyMS         float64 `json:"latency_ms"`
	Error             string  `json:"error,omitempty"`
	// Trace is the per-round lookup path (exhaustive mode). It is written to
	// lookups/<round>.json and stripped from report.json to keep that small.
	Trace json.RawMessage `json:"trace,omitempty"`
}

// NodeDiagnostics is the subset of a simnode /diagnostics document the
// runner summarizes; the full document is saved verbatim (plus ASN/prefix).
type NodeDiagnostics struct {
	Name    string  `json:"name"`
	NodeID  string  `json:"node_id"`
	Uptime  float64 `json:"uptime_sec"`
	RSSKB   int     `json:"rss_kb"`
	Records int     `json:"registry_records"`
	DHT     struct {
		Table struct {
			SelfID       string              `json:"self_id"`
			SelfNameHash string              `json:"self_name_hash"`
			Active       int                 `json:"active"`
			Offline      int                 `json:"offline"`
			Pending      int                 `json:"pending"`
			IDIndex      DiagnosticIndexHead `json:"node_id_index"`
			NameIndex    DiagnosticIndexHead `json:"name_hash_index"`
			Capacity     CapacityPolicy      `json:"capacity_policy"`
			Offlines     []struct {
				InProbation bool `json:"in_probation"`
			} `json:"offline_peers"`
		} `json:"table"`
		Store *struct {
			PeerRows   int                 `json:"peer_rows"`
			Categories map[string][]string `json:"categories"`
			Values     []struct {
				Valid bool `json:"valid"`
			} `json:"values"`
		} `json:"store"`
		StoreError   string `json:"store_error"`
		CachedValues int    `json:"cached_values"`
	} `json:"dht"`
}

type DiagnosticIndexHead struct {
	Entries         int                    `json:"entries"`
	NonEmptyBuckets int                    `json:"non_empty_buckets"`
	Buckets         []DiagnosticBucketHead `json:"buckets"`
}

type DiagnosticBucketHead struct {
	Index int                  `json:"index"`
	Peers []DiagnosticPeerHead `json:"peers"`
}

type DiagnosticPeerHead struct {
	Name        string `json:"name"`
	NodeID      string `json:"node_id"`
	NameHash    string `json:"name_hash"`
	InProbation bool   `json:"in_probation"`
}

// CapacityPolicy mirrors dht.CapacityPolicy.
type CapacityPolicy struct {
	K                    int `json:"k"`
	MaxPendingCandidates int `json:"max_pending_candidates"`
	MaxActivePeers       int `json:"max_active_peers"`
	MaxOfflinePeers      int `json:"max_offline_peers"`
	WarmStartFloor       int `json:"warm_start_candidates"`
}
