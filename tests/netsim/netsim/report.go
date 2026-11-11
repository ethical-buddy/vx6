// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
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
		{"Per-node XOR indexes and bbolt state", "EXERCISED", "Every round saves each node's NodeID and name-hash XOR indexes, offline/pending entries and bbolt categories/values (diagnostics/<round>/), read through the node's own open store."},
		{"IKEv2/IPsec confidentiality and authentication", "NOT EXERCISED", "The scale tier uses an explicit pass-through tunnel. Use the separate two-peer IPsec suite."},
	}
	offTableQueries := 0
	for _, round := range report.Rounds {
		offTableQueries += round.OffTableQueriesSelected
	}
	if report.OffTableLookups && offTableQueries > 0 {
		items = append(items, coverageItem{"Lookup of targets absent from the corresponding local XOR index", "EXERCISED",
			fmt.Sprintf("%d ID/name queries were selected only after checking the source's relevant active index; per-query index state and lookup traces are in the report.", offTableQueries)})
	} else if report.OffTableLookups {
		items = append(items, coverageItem{"Lookup of targets absent from the corresponding local XOR index", "NOT EXERCISED",
			"The mode was enabled, but no eligible source-target queries were selected; a zero eligible denominator is not referral-lookup evidence."})
	} else {
		items = append(items, coverageItem{"Lookup of targets absent from the corresponding local XOR index", "NOT EXERCISED",
			"Use -lookups sample -off-table-probes to deliberately select targets missing from the requester's relevant active index."})
	}
	if !report.DryRun && report.Totals.Attempts > 0 && report.Totals.Found == 0 {
		for i := range items {
			if items[i].name == "Identity-ID lookup" || items[i].name == "Canonical-name lookup" {
				items[i].status = "FAILED"
				items[i].note = "Lookups ran but none found its known-existing target; see the verdict and per-probe details."
			}
		}
	}
	if report.LookupMode == LookupModeExhaustive {
		items = append(items, coverageItem{"Exhaustive lookups with path traces", "EXERCISED",
			"Every node resolves every other joined node by NodeID and by name each round; per-round responders, referrals, XOR progress and stop reasons are in lookups/<round>.json."})
	} else {
		items = append(items, coverageItem{"Exhaustive lookups with path traces", "NOT EXERCISED",
			"Sample mode: random pairs only; use -lookups exhaustive (default up to 10 nodes) for a full denominator."})
	}
	if report.IdleDuration > 0 && len(report.Idle) > 0 {
		items = append(items, coverageItem{"Idle maintenance observation", "PARTIAL",
			fmt.Sprintf("%d captures over %s of real time with no lookups. Expiry windows longer than the run (for example 30-day address hints, 2h probation) are not reached; that needs an injected clock.", len(report.Idle), report.IdleDuration)})
	} else {
		items = append(items, coverageItem{"Idle maintenance observation", "NOT EXERCISED", "Set -idle (for example 15m) to capture nodes at intervals with no lookups."})
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
	fmt.Fprintf(&b, "- Run ID: `%s`\n- Build revision: `%s`\n- Host: `%s/%s`, kernel `%s`, %d logical CPUs\n- CPU model: `%s`\n- Go: `%s`\n- Dry run: **%t**\n- Started: `%s`\n- Finished: `%s`\n- Cleanup: **%s**\n",
		report.RunID, report.BuildRevision, report.HostOS, report.HostArch, report.HostKernel, report.LogicalCPUs,
		report.HostCPUModel, report.GoVersion,
		report.DryRun, report.StartedAt.UTC().Format("2006-01-02T15:04:05Z"), report.FinishedAt.UTC().Format("2006-01-02T15:04:05Z"), report.CleanupStatus)
	fmt.Fprintf(&b, "- Topology SHA-256: `%s`\n- simnode SHA-256: `%s`\n", report.TopologySHA256, report.SimnodeSHA256)
	if report.BGPConvergedMS > 0 {
		fmt.Fprintf(&b, "- BGP converged before first join: **%.0f ms**\n", report.BGPConvergedMS)
	}
	fmt.Fprintf(&b, "- Verdict: **%s**\n", report.Verdict)
	for _, reason := range report.VerdictReasons {
		fmt.Fprintf(&b, "  - %s\n", reason)
	}
	fmt.Fprintf(&b, "\n")
	capacity := "not captured"
	if c := report.Capacity; c != nil {
		active, offline := "none (uncapped)", "none (uncapped)"
		if c.MaxActivePeers > 0 {
			active = fmt.Sprint(c.MaxActivePeers)
		}
		if c.MaxOfflinePeers > 0 {
			offline = fmt.Sprint(c.MaxOfflinePeers)
		}
		capacity = fmt.Sprintf("K=%d, pending candidates <=%d, active cap %s, offline cap %s, warm-start candidates %d",
			c.K, c.MaxPendingCandidates, active, offline, c.WarmStartFloor)
	}
	fmt.Fprintf(&b, "## Tested revision\n\n- VX6 build revision: `%s`\n- DHT capacity policy (reported by the running nodes): %s\n- Lookup mode: **%s**\n\n",
		report.BuildRevision, capacity, report.LookupMode)
	fmt.Fprintf(&b, "## Configuration\n\n- Sim nodes: %d\n- IPsec nodes: %d (not launched by this scale runner)\n- ASes: %d tier-1, %d ISP, %d org, %d attacker\n- Seed: %d\n- Join schedule: `%s`\n- Signed bootstrap contacts per join: %d\n- Sampled graceful restarts: %d\n- Post-join settle rounds: %d at %s each\n- Probe limit per round: %d (normal mode: source-target pairs, each by ID and name; off-table mode: individual lookup queries)\n- Off-table lookup mode: **%t** (settle rounds only; target must be absent from its corresponding active XOR index)\n- Lookup timeout: 10 seconds\n\n",
		report.Params.Nodes, report.Params.IPsecNodes, report.Params.Tier1, report.Params.ISPs, report.Params.Orgs,
		report.Params.Attackers, report.Params.Seed, report.Params.Schedule, report.Params.Seeds,
		report.RestartCount, report.SettleRounds, report.SettleGap, report.ProbesPerRound, report.OffTableLookups)
	duration := report.FinishedAt.Sub(report.StartedAt)
	totals := report.Totals
	fmt.Fprintf(&b, "## Overall Results\n\n- Wall-clock run duration: **%s**\n- DHT snapshots: **%d successful**, **%d failed**\n- Lookup attempts/completed: **%d/%d**; exact expected target found: **%d (%.1f%% of completed)**\n- Expected target not returned: **%d**; reachable-view not found: **%d**; incomplete/conflict: **%d**\n- Admin/request errors: **%d**; DHT lookup errors: **%d**\n- Lookup latency p50/p95/p99: **%.2f / %.2f / %.2f ms**\n- Peer queries average/p50/p95: **%.2f / %d / %d**; lookup rounds average/p50/p95: **%.2f / %.0f / %.0f**\n- Simnode combined process CPU time: **%d ms**; host-wide CPU busy estimate: **%.1f%%**\n- Host available memory start/end: **%d / %d MiB**\n\nHost CPU and free-memory values are machine-wide context, not attribution to VX6. Simnode CPU is the sum of measured process user+system time. Per-node RSS comes from each simnode snapshot.\n\n",
		duration.Round(time.Millisecond), report.SnapshotTotal, report.SnapshotErrors,
		totals.Attempts, totals.N, totals.Found, totals.FoundRatePct, totals.Missed, totals.NotFound,
		totals.Other, totals.Errors, totals.LookupErrors, totals.P50ms, totals.P95ms, totals.P99ms,
		totals.AvgQueries, totals.P50Queries, totals.P95Queries, totals.AvgRound, totals.P50Rounds, totals.P95Rounds,
		report.HostResources.SimnodeCPUTimeMS, report.HostResources.HostCPUUtilizationPct,
		report.HostResources.StartMemoryAvailableKB/1024, report.HostResources.EndMemoryAvailableKB/1024)
	fmt.Fprintf(&b, "## Results by Round\n\n| Round | Joined | Snapshots OK/errors | Avg peers | Unique ASNs avg/min/max | Max same ASN /48 | Avg/min/max RSS (MiB/node) | Total node RSS (MiB) | Join ms | Round ms | Lookups attempted/completed | Found | Not found | Missed | Other | Admin/lookup errors | Off-table selected/eligible | Preflight status/diagnostics errors | p50/p95/p99 ms | Avg queries/rounds |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	var observed *LookupPolicy
	for _, round := range report.Rounds {
		l := round.Lookups
		if observed == nil && round.LookupPolicy != nil {
			observed = round.LookupPolicy
		}
		fmt.Fprintf(&b, "| %s | %d | %d/%d | %.2f | %.2f/%d/%d | %d/%d | %.2f/%.2f/%.2f | %.2f | %.2f | %.2f | %d/%d | %d | %d | %d | %d | %d/%d | %d/%d | %d/%d | %.2f/%.2f/%.2f | %.2f/%.2f |\n",
			round.Label, round.NodesJoined, round.SnapshotsOK, round.SnapshotErrors, round.AvgActivePeers,
			round.Diversity.AvgUniqueASNsPerTable, round.Diversity.MinUniqueASNsPerTable,
			round.Diversity.MaxUniqueASNsPerTable, round.Diversity.MaxPeersFromOneASN,
			round.Diversity.MaxPeersFromOneIPv6Prefix48,
			float64(round.AvgRSSKB)/1024, float64(round.MinRSSKB)/1024, float64(round.MaxRSSKB)/1024,
			float64(round.TotalRSSKB)/1024, round.JoinDurationMS, round.RoundDurationMS,
			l.Attempts, l.N, l.Found, l.NotFound, l.Missed, l.Other, l.Errors, l.LookupErrors,
			round.OffTableQueriesSelected, round.OffTableQueriesAvailable,
			round.OffTableStatusErrors, round.OffTableDiagnosticErrors,
			l.P50ms, l.P95ms, l.P99ms, l.AvgQueries, l.AvgRound)
	}
	fmt.Fprintf(&b, "\n")
	if observed != nil {
		fmt.Fprintf(&b, "Observed code limits: **%d rounds**, **%d parallel queries**, **%d total peer queries**, **%d referrals per reply**, **%d ms peer timeout**, **%d ms total timeout**. These are read from a running node, not copied from a test assumption.\n\n",
			observed.MaxRounds, observed.MaxConcurrent, observed.MaxPeerQueries, observed.MaxReferrals, observed.PeerTimeoutMS, observed.TotalTimeoutMS)
	}
	fmt.Fprintf(&b, "`not_found_reachable` means no match was found among contacts this node could reach; it does not prove global non-existence. Expected-target-not-returned includes incomplete lookups and is an observation to investigate, not proof of absence. The found rate uses known-existing probe targets, so a miss is a lookup failure signal, not a claim that the node is absent.\n\n")
	if len(report.Restarts) > 0 {
		fmt.Fprintf(&b, "## Restart Evidence\n\n| Node | Same identity | Active peers before/after | Persisted candidates | Restored candidates | Persistence verified | Error |\n|---|---|---:|---:|---:|---|---|\n")
		for _, result := range report.Restarts {
			fmt.Fprintf(&b, "| %s | %t | %d/%d | %d | %d | %t | %s |\n", result.NodeName, result.IdentityStable,
				result.ActivePeersBefore, result.ActivePeersAfter, len(result.PersistedCandidateIDs), len(result.RestoredCandidateIDs),
				result.PersistenceVerified, strings.ReplaceAll(result.Error, "|", "\\|"))
		}
		fmt.Fprintf(&b, "\n")
	}
	if n := len(report.Rounds); n > 0 && len(report.Rounds[n-1].Nodes) > 0 {
		last := report.Rounds[n-1]
		fmt.Fprintf(&b, "## Per-node state (final round `%s`)\n\nIn-memory columns come from the routing table; `bbolt` columns come from the node's persisted store.\n\n", last.Label)
		fmt.Fprintf(&b, "| Node | Active | Offline | Pending | In probation | NodeID buckets | Name-hash buckets | bbolt rows | bbolt active/inactive/probation | bbolt closest ID/name | Values valid/total | As lookup source: found/incomplete/not found of total | RSS MiB |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
		for _, node := range last.Nodes {
			if node.CaptureError != "" {
				fmt.Fprintf(&b, "| %s | capture failed: %s | | | | | | | | | | | |\n", node.Name, strings.ReplaceAll(node.CaptureError, "|", "\\|"))
				continue
			}
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %d | %d | %d/%d/%d | %d/%d | %d/%d | %d/%d/%d of %d | %.1f |\n",
				node.Name, node.Active, node.Offline, node.Pending, node.InProbation, node.IDBuckets, node.NameBuckets,
				node.StoreRows, node.StoreActive, node.StoreInactive, node.StoreProbation, node.StoreClosestID, node.StoreClosestName,
				node.StoreValidValues, node.StoreValues, node.FoundAsSource, node.IncompleteAsSource, node.NotFoundAsSource,
				node.LookupsAsSource, float64(node.RSSKB)/1024)
		}
		fmt.Fprintf(&b, "\nEvery round's per-node summary is in report.json (`rounds[].nodes`); full documents are in `diagnostics/<round>/<node>.json`.\n\n")
	}
	if len(report.Idle) > 0 {
		fmt.Fprintf(&b, "## Idle observation (no lookups)\n\n| Capture | Elapsed | Active total (min/max per node) | Offline | Pending | In probation | bbolt rows | bbolt inactive | Capture errors |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
		for _, sample := range report.Idle {
			fmt.Fprintf(&b, "| %s | %s | %d (%d/%d) | %d | %d | %d | %d | %d | %d |\n", sample.Label,
				time.Duration(sample.ElapsedSec*float64(time.Second)).Round(time.Second), sample.TotalActive, sample.MinActive,
				sample.MaxActive, sample.TotalOffline, sample.TotalPending, sample.TotalProbation, sample.StoreRows,
				sample.StoreInactive, sample.CaptureErrors)
		}
		fmt.Fprintf(&b, "\nPer-node idle captures are in report.json (`idle[].nodes`) and `diagnostics/idle-NN/`.\n\n")
	}
	fmt.Fprintf(&b, "## Coverage\n\n| Area | Status | What this run actually exercises |\n|---|---|---|\n")
	for _, item := range coverage(report) {
		fmt.Fprintf(&b, "| %s | **%s** | %s |\n", item.name, item.status, item.note)
	}
	fmt.Fprintf(&b, "\n## Evidence Files\n\n- `report.json`: parameters, every round, and every lookup probe.\n- `topology.json`: run-specific namespace names and generated topology.\n- `commands.log`: network setup and teardown commands.\n- `snapshots/<round>/<node>.json`: observed active DHT peers, including both identity and name-hash coordinates.\n- `diagnostics/<capture>/<node>.json`: both XOR indexes with every bucket entry, offline/pending peers, bbolt categories and value health (no payloads), per round, restart and idle capture.\n- `lookups/<round>.json`: every lookup of the round with its per-round trace.\n- `nodes/<name>/node.log` and `simnode.out`: per-node logs.\n- `logs/`: FRR logs.\n\nThis is a DHT-scale simulation, not a proof of global DHT completeness, Sybil resistance, or IPsec security. Re-run with the same parameters and seed for repeatability; the random run ID only isolates Linux resources.\n")
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(b.String()), 0o600); err != nil {
		return err
	}
	return nil
}
