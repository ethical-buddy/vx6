// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Lookup modes for measurement rounds.
const (
	LookupModeAuto       = "auto"       // exhaustive up to exhaustiveMaxNodes, else sample
	LookupModeExhaustive = "exhaustive" // every node -> every other node, by ID and by name
	LookupModeSample     = "sample"     // -probes random pairs per round
	exhaustiveMaxNodes   = 10
	exhaustiveParallel   = 4
)

// NodeRoundSummary is one node's state at one capture point.
type NodeRoundSummary struct {
	Name               string `json:"name"`
	Label              string `json:"label"`
	Active             int    `json:"active"`
	Offline            int    `json:"offline"`
	Pending            int    `json:"pending"`
	InProbation        int    `json:"in_probation"`
	IDBuckets          int    `json:"node_id_non_empty_buckets"`
	NameBuckets        int    `json:"name_hash_non_empty_buckets"`
	StoreRows          int    `json:"bbolt_peer_rows"`
	StoreActive        int    `json:"bbolt_active"`
	StoreInactive      int    `json:"bbolt_inactive"`
	StoreProbation     int    `json:"bbolt_probation"`
	StoreClosestID     int    `json:"bbolt_closest_id"`
	StoreClosestName   int    `json:"bbolt_closest_name"`
	StoreValues        int    `json:"bbolt_values"`
	StoreValidValues   int    `json:"bbolt_valid_values"`
	XORPlacementChecks int    `json:"xor_bucket_placement_checks"`
	XORPlacementErrors int    `json:"xor_bucket_placement_errors"`
	CachedValues       int    `json:"cached_values"`
	StoreError         string `json:"store_error,omitempty"`
	RSSKB              int    `json:"rss_kb"`
	LookupsAsSource    int    `json:"lookups_as_source,omitempty"`
	FoundAsSource      int    `json:"found_as_source,omitempty"`
	IncompleteAsSource int    `json:"incomplete_as_source,omitempty"`
	NotFoundAsSource   int    `json:"not_found_as_source,omitempty"`
	CaptureError       string `json:"capture_error,omitempty"`
	capacity           CapacityPolicy
	capacityCaptured   bool
}

// captureDiagnostics saves every joined node's full /diagnostics document under
// diagnostics/<label>/<node>.json (with topology ASN and /48 added to each peer
// entry) and returns per-node summaries.
func (s *SimRun) captureDiagnostics(ctx context.Context, label string, nodes []Node) ([]NodeRoundSummary, error) {
	if s.r.dry {
		return nil, nil
	}
	dir := filepath.Join(s.dir, "diagnostics", label)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	mapWriter, err := newRoutingMapWriter(s.dir, label)
	if err != nil {
		return nil, err
	}
	defer func() {
		if mapWriter != nil {
			_ = mapWriter.close()
		}
	}()
	addressASN := s.addressASN()
	summaries := make([]NodeRoundSummary, 0, len(nodes))
	for _, node := range nodes {
		summary := NodeRoundSummary{Name: node.Name, Label: label}
		var raw json.RawMessage
		if err := s.adminGet(ctx, node, "/diagnostics", &raw); err != nil {
			summary.CaptureError = err.Error()
			summaries = append(summaries, summary)
			continue
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			summary.CaptureError = err.Error()
			summaries = append(summaries, summary)
			continue
		}
		annotatePeers(doc, addressASN)
		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, node.Name+".json"), data, 0o600); err != nil {
			return nil, err
		}
		var diag NodeDiagnostics
		if err := json.Unmarshal(raw, &diag); err != nil {
			summary.CaptureError = err.Error()
			summaries = append(summaries, summary)
			continue
		}
		summary = summarizeDiagnostics(label, diag)
		checks, failures, err := mapWriter.add(label, diag)
		if err != nil {
			summary.CaptureError = "routing map: " + err.Error()
		} else {
			summary.XORPlacementChecks = checks
			summary.XORPlacementErrors = failures
		}
		summaries = append(summaries, summary)
	}
	if err := mapWriter.close(); err != nil {
		return summaries, fmt.Errorf("close XOR routing map: %w", err)
	}
	mapWriter = nil
	return summaries, nil
}

func summarizeDiagnostics(label string, diag NodeDiagnostics) NodeRoundSummary {
	table := diag.DHT.Table
	summary := NodeRoundSummary{Name: diag.Name, Label: label, Active: table.Active, Offline: table.Offline,
		Pending: table.Pending, IDBuckets: table.IDIndex.NonEmptyBuckets, NameBuckets: table.NameIndex.NonEmptyBuckets,
		CachedValues: diag.DHT.CachedValues, StoreError: diag.DHT.StoreError, RSSKB: diag.RSSKB,
		capacity: table.Capacity, capacityCaptured: true}
	for _, bucket := range table.IDIndex.Buckets {
		for _, peer := range bucket.Peers {
			if peer.InProbation {
				summary.InProbation++
			}
		}
	}
	for _, peer := range table.Offlines {
		if peer.InProbation {
			summary.InProbation++
		}
	}
	if store := diag.DHT.Store; store != nil {
		summary.StoreRows = store.PeerRows
		summary.StoreActive = len(store.Categories["active"])
		summary.StoreInactive = len(store.Categories["inactive"])
		summary.StoreProbation = len(store.Categories["probation"])
		summary.StoreClosestID = len(store.Categories["closest-id"])
		summary.StoreClosestName = len(store.Categories["closest-name"])
		summary.StoreValues = len(store.Values)
		for _, value := range store.Values {
			if value.Valid {
				summary.StoreValidValues++
			}
		}
	}
	return summary
}

func (s *SimRun) addressASN() map[string]uint32 {
	out := make(map[string]uint32, len(s.t.Nodes))
	for _, node := range s.t.Nodes {
		if addr, err := netip.ParseAddr(node.Addr); err == nil {
			out[addr.String()] = node.ASN
		}
	}
	return out
}

// annotatePeers adds "asn" (when the address belongs to the generated
// topology) and "prefix_48" to every JSON object that has "node_id" and
// "addr" keys.
func annotatePeers(v any, addressASN map[string]uint32) {
	switch typed := v.(type) {
	case map[string]any:
		if _, hasID := typed["node_id"]; hasID {
			if addrText, ok := typed["addr"].(string); ok {
				if host, _, err := net.SplitHostPort(addrText); err == nil {
					if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
						if asn, ok := addressASN[addr.String()]; ok {
							typed["asn"] = asn
						}
						typed["prefix_48"] = netip.PrefixFrom(addr, 48).Masked().String()
					}
				}
			}
		}
		for _, child := range typed {
			annotatePeers(child, addressASN)
		}
	case []any:
		for _, child := range typed {
			annotatePeers(child, addressASN)
		}
	}
}

// exhaustiveLookups asks every joined node to resolve every other joined node,
// once by NodeID and once by canonical name, with a per-round trace.
func (s *SimRun) exhaustiveLookups(ctx context.Context, joined []Node) []LookupReport {
	if len(joined) < 2 {
		return nil
	}
	type target struct{ id, name string }
	targets := make(map[int]target, len(joined))
	var reports []LookupReport
	for _, node := range joined {
		var status struct {
			NodeID string `json:"node_id"`
			Name   string `json:"name"`
		}
		statusCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := s.adminGet(statusCtx, node, "/status", &status)
		cancel()
		if err != nil || status.NodeID == "" || status.Name == "" {
			reports = append(reports, LookupReport{Source: "-", TargetType: "status", Outcome: "admin_error",
				ExpectedNodeID: node.Name, Error: fmt.Sprint(err)})
			continue
		}
		targets[node.Index] = target{id: status.NodeID, name: status.Name}
	}
	type job struct {
		src        Node
		kind, val  string
		expectedID string
	}
	var jobs []job
	for _, src := range joined {
		for _, dst := range joined {
			tgt, ok := targets[dst.Index]
			if src.Index == dst.Index || !ok {
				continue
			}
			jobs = append(jobs, job{src, "id", tgt.id, tgt.id}, job{src, "name", tgt.name, tgt.id})
		}
	}
	results := make([]LookupReport, len(jobs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, exhaustiveParallel)
	for i, j := range jobs {
		if ctx.Err() != nil {
			results[i] = LookupReport{Source: j.src.Name, TargetType: j.kind, Outcome: "admin_error", Error: ctx.Err().Error()}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, j job) {
			defer wg.Done()
			defer func() { <-sem }()
			var rep LookupReport
			path := "/lookup?type=" + j.kind + "&target=" + url.QueryEscape(j.val) + "&timeout_s=10&trace=1"
			if err := s.adminGet(ctx, j.src, path, &rep); err != nil {
				rep = LookupReport{TargetType: j.kind, Outcome: "admin_error", Error: err.Error()}
			}
			rep.Source = j.src.Name
			rep.ExpectedNodeID = j.expectedID
			results[i] = rep
		}(i, j)
	}
	wg.Wait()
	return append(reports, results...)
}

// writeLookupTraces saves full lookup reports (with traces) for one round and
// returns copies without traces for report.json.
func (s *SimRun) writeLookupTraces(label string, reports []LookupReport) ([]LookupReport, error) {
	if s.r.dry || len(reports) == 0 {
		return reports, nil
	}
	dir := filepath.Join(s.dir, "lookups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return reports, err
	}
	data, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		return reports, err
	}
	if err := os.WriteFile(filepath.Join(dir, label+".json"), data, 0o600); err != nil {
		return reports, err
	}
	stripped := make([]LookupReport, len(reports))
	for i, rep := range reports {
		rep.Trace = nil
		stripped[i] = rep
	}
	return stripped, nil
}

// attachSourceStats adds per-source lookup outcomes to node summaries.
func attachSourceStats(summaries []NodeRoundSummary, reports []LookupReport) {
	index := make(map[string]int, len(summaries))
	for i, summary := range summaries {
		index[summary.Name] = i
	}
	for _, rep := range reports {
		i, ok := index[rep.Source]
		if !ok {
			continue
		}
		summaries[i].LookupsAsSource++
		switch {
		case rep.Found:
			summaries[i].FoundAsSource++
		case rep.Outcome == "incomplete" || rep.Outcome == "admin_error" || rep.Error != "":
			summaries[i].IncompleteAsSource++
		default:
			summaries[i].NotFoundAsSource++
		}
	}
}

// IdleSample aggregates one idle capture across all nodes.
type IdleSample struct {
	Label          string             `json:"label"`
	ElapsedSec     float64            `json:"elapsed_sec"`
	TotalActive    int                `json:"total_active"`
	MinActive      int                `json:"min_active"`
	MaxActive      int                `json:"max_active"`
	TotalOffline   int                `json:"total_offline"`
	TotalPending   int                `json:"total_pending"`
	TotalProbation int                `json:"total_in_probation"`
	StoreRows      int                `json:"total_bbolt_rows"`
	StoreInactive  int                `json:"total_bbolt_inactive"`
	CaptureErrors  int                `json:"capture_errors"`
	Nodes          []NodeRoundSummary `json:"nodes"`
}

func idleSample(label string, elapsed time.Duration, nodes []NodeRoundSummary) IdleSample {
	sample := IdleSample{Label: label, ElapsedSec: elapsed.Seconds(), MinActive: -1, Nodes: nodes}
	for _, node := range nodes {
		if node.CaptureError != "" {
			sample.CaptureErrors++
			continue
		}
		sample.TotalActive += node.Active
		if sample.MinActive < 0 || node.Active < sample.MinActive {
			sample.MinActive = node.Active
		}
		if node.Active > sample.MaxActive {
			sample.MaxActive = node.Active
		}
		sample.TotalOffline += node.Offline
		sample.TotalPending += node.Pending
		sample.TotalProbation += node.InProbation
		sample.StoreRows += node.StoreRows
		sample.StoreInactive += node.StoreInactive
	}
	if sample.MinActive < 0 {
		sample.MinActive = 0
	}
	return sample
}

// runIdle keeps background maintenance running with no lookups and captures
// every node at idle start and then every interval until duration elapses.
func (s *SimRun) runIdle(ctx context.Context, joined []Node, duration, interval time.Duration) ([]IdleSample, error) {
	if duration <= 0 || s.r.dry {
		return nil, nil
	}
	start := time.Now()
	var samples []IdleSample
	for i := 0; ; i++ {
		label := fmt.Sprintf("idle-%02d", i)
		nodes, err := s.captureDiagnostics(ctx, label, joined)
		if err != nil {
			return samples, err
		}
		samples = append(samples, idleSample(label, time.Since(start), nodes))
		if time.Since(start)+interval > duration+time.Second {
			return samples, nil
		}
		select {
		case <-ctx.Done():
			return samples, ctx.Err()
		case <-time.After(interval):
		}
	}
}

func sortedSummaries(summaries []NodeRoundSummary) []NodeRoundSummary {
	out := append([]NodeRoundSummary(nil), summaries...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
