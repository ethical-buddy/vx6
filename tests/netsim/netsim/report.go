// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type coverageItem struct {
	name   string
	status string
	note   string
}

func coverage(report *Report) []coverageItem {
	restartStatus := "NOT EXERCISED"
	restartNote := "Set -restart-count above zero to stop and restart nodes against the same state directory."
	if report.RestartCount > 0 && len(report.Restarts) > 0 {
		restartStatus = "PARTIAL"
		restartNote = "Identity and bbolt candidates are checked; see per-node persistence_verified. A node with no candidates provides no persistence proof."
		allVerified := true
		for _, result := range report.Restarts {
			if !result.IdentityStable || !result.PersistenceVerified {
				allVerified = false
			}
		}
		if allVerified {
			restartStatus = "EXERCISED"
			restartNote = "Identity stayed stable and at least one bbolt candidate reappeared in the restarted routing snapshot for each sampled node."
		}
	}
	items := []coverageItem{
		{"IPv6 namespace topology and multi-process node launch", "EXERCISED", "One process and isolated namespace per simulated peer."},
		{"Bootstrap from signed contacts", "EXERCISED", "Join waves use endpoint records from already-running peers; this does not establish global membership consensus."},
		{"Identity-ID lookup", "EXERCISED", "Random existing targets are queried by full VX6 NodeID."},
		{"Canonical-name lookup", "EXERCISED", "The admin adapter canonicalizes the name and sends only its name-hash coordinate into DHT lookup."},
		{"Routing snapshots and lookup outcomes", "EXERCISED", "Per-node snapshots and per-probe details are retained in report.json and snapshots/."},
		{"DHT restart and bbolt recovery", restartStatus, restartNote},
		{"Peer liveness expiry and IP update propagation", "NOT EXERCISED", "No clock-accelerated expiry or address-change scenario is injected."},
		{"Malformed or malicious DHT referrals", "NOT EXERCISED", "Attacker-AS nodes are ordinary VX6 peers; this harness does not inject malicious DHT responses."},
		{"Network partition, churn, and eclipse", "NOT EXERCISED", "Topology primitives exist, but this run path does not apply fault schedules."},
		{"IKEv2/IPsec confidentiality and authentication", "NOT EXERCISED", "The scale tier uses an explicit pass-through tunnel. Use the separate two-peer IPsec suite."},
	}
	if report.DryRun {
		for i := range items {
			if items[i].status == "EXERCISED" || items[i].status == "PARTIAL" {
				items[i].status = "PREVIEW ONLY"
				items[i].note = "Dry-run prints the planned workflow but did not execute this test."
			}
		}
	}
	return items
}

func writeReportFiles(dir string, report *Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), append(data, '\n'), 0o600); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# VX6 DHT Simulation Report\n\n")
	fmt.Fprintf(&b, "- Run ID: `%s`\n- Build revision: `%s`\n- Host: `%s/%s`\n- Dry run: **%t**\n- Started: `%s`\n- Finished: `%s`\n- Cleanup: **%s**\n",
		report.RunID, report.BuildRevision, report.HostOS, report.HostArch,
		report.DryRun, report.StartedAt.UTC().Format("2006-01-02T15:04:05Z"), report.FinishedAt.UTC().Format("2006-01-02T15:04:05Z"), report.CleanupStatus)
	fmt.Fprintf(&b, "- Topology SHA-256: `%s`\n- simnode SHA-256: `%s`\n\n", report.TopologySHA256, report.SimnodeSHA256)
	fmt.Fprintf(&b, "## Configuration\n\n- Sim nodes: %d\n- IPsec nodes: %d (not launched by this scale runner)\n- ASes: %d tier-1, %d ISP, %d org, %d attacker\n- Seed: %d\n- Join schedule: `%s`\n- Signed bootstrap contacts per join: %d\n- Sampled graceful restarts: %d\n- Post-join settle rounds: %d at %s each\n- Probe pairs per round: %d (one ID and one name lookup per pair)\n- Lookup timeout: 10 seconds\n\n",
		report.Params.Nodes, report.Params.IPsecNodes, report.Params.Tier1, report.Params.ISPs, report.Params.Orgs,
		report.Params.Attackers, report.Params.Seed, report.Params.Schedule, report.Params.Seeds,
		report.RestartCount, report.SettleRounds, report.SettleGap, report.ProbesPerRound)
	fmt.Fprintf(&b, "## Results by Round\n\n| Round | Joined | Snapshots OK/errors | Lookups attempted/completed | Found | Reachable-view not found | Expected target not returned | Incomplete/conflict | Request errors | p50/p95 ms | Avg lookup rounds |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	var observed *LookupPolicy
	for _, round := range report.Rounds {
		l := round.Lookups
		if observed == nil && round.LookupPolicy != nil {
			observed = round.LookupPolicy
		}
		fmt.Fprintf(&b, "| %s | %d | %d/%d | %d/%d | %d | %d | %d | %d | %d | %.2f/%.2f | %.2f |\n",
			round.Label, round.NodesJoined, round.SnapshotsOK, round.SnapshotErrors, l.Attempts, l.N,
			l.Found, l.NotFound, l.Missed, l.Other, l.Errors, l.P50ms, l.P95ms, l.AvgRound)
	}
	fmt.Fprintf(&b, "\n")
	if observed != nil {
		fmt.Fprintf(&b, "Observed code limits: **%d rounds**, **%d parallel queries**, **%d total peer queries**, **%d referrals per reply**, **%d ms peer timeout**, **%d ms total timeout**. These are read from a running node, not copied from a test assumption.\n\n",
			observed.MaxRounds, observed.MaxConcurrent, observed.MaxPeerQueries, observed.MaxReferrals, observed.PeerTimeoutMS, observed.TotalTimeoutMS)
	}
	fmt.Fprintf(&b, "`not_found_reachable` means no match was found among contacts this node could reach; it does not prove global non-existence. Expected-target-not-returned includes incomplete lookups and is an observation to investigate, not proof of absence.\n\n")
	if len(report.Restarts) > 0 {
		fmt.Fprintf(&b, "## Restart Evidence\n\n| Node | Same identity | Active peers before/after | Persisted candidates | Restored candidates | Persistence verified | Error |\n|---|---|---:|---:|---:|---|---|\n")
		for _, result := range report.Restarts {
			fmt.Fprintf(&b, "| %s | %t | %d/%d | %d | %d | %t | %s |\n", result.NodeName, result.IdentityStable,
				result.ActivePeersBefore, result.ActivePeersAfter, len(result.PersistedCandidateIDs), len(result.RestoredCandidateIDs),
				result.PersistenceVerified, strings.ReplaceAll(result.Error, "|", "\\|"))
		}
		fmt.Fprintf(&b, "\n")
	}
	fmt.Fprintf(&b, "## Coverage\n\n| Area | Status | What this run actually exercises |\n|---|---|---|\n")
	for _, item := range coverage(report) {
		fmt.Fprintf(&b, "| %s | **%s** | %s |\n", item.name, item.status, item.note)
	}
	fmt.Fprintf(&b, "\n## Evidence Files\n\n- `report.json`: parameters, every round, and every lookup probe.\n- `topology.json`: run-specific namespace names and generated topology.\n- `commands.log`: network setup and teardown commands.\n- `snapshots/<round>/<node>.json`: observed active DHT peers, including both identity and name-hash coordinates.\n- `nodes/<name>/node.log` and `simnode.out`: per-node logs.\n- `logs/`: FRR logs.\n\nThis is a DHT-scale simulation, not a proof of global DHT completeness, Sybil resistance, or IPsec security. Re-run with the same parameters and seed for repeatability; the random run ID only isolates Linux resources.\n")
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(b.String()), 0o600); err != nil {
		return err
	}
	return nil
}
