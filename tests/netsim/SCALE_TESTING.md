# VX6 DHT Scale Test: Handoff and Results

## Purpose

Measure DHT formation and lookup as the simulated network grows beyond the number of peers a single node can keep in its local routing table. The important scale result is not just whether a lookup succeeds: it is whether the target was absent from the requester's relevant local XOR index before the lookup, whether referrals move the search closer, and whether the exact expected identity is returned.

This is a DHT test. The scale tier runs separate VX6 node processes in isolated Linux network namespaces and uses the simulator's signed-record-gated pass-through transport. It does not test IKEv2, ESP, or IPsec. Those remain a separate two-node test.

## What the Simulator Captures

Each run writes a Markdown and JSON report, topology and command logs, per-round lookup traces, per-node diagnostics, XOR placement maps, logs, process records, and cleanup status. Diagnostics include both in-memory XOR indexes (NodeID and canonical-name hash), per-bucket occupancy and peers, offline and pending entries, bbolt peer categories and values, observed lookup limits, liveness observations, and per-node resource use. Never publish a raw run directory without checking it for private keys and machine-specific information.

The `-off-table-probes` mode runs only in settle rounds. Before selecting a probe, it reads the source node's diagnostics and independently checks that the target is absent from the appropriate active index: NodeID for an ID lookup, name-hash for a name lookup. Reports state the checked index and show candidate pairs available and selected. If no eligible candidates exist, the report shows zero and does not imply referral lookup was tested. Every sampled and off-table request asks for a referral trace; records in `lookups/<round>.json` include the responders, referrals, errors, duplicates, XOR progress and stop reason.

At every diagnostic capture, `routing-map/<capture>.csv.gz` contains each stored active peer in both indexes, its local XOR distance/rank, the bucket actually reported by the node, and the bucket independently recalculated by the runner. A mismatch fails the final run. This verifies that stored entries are filed into the correct local XOR range. It does not prove that the peer learned every globally closest node: no node has a global membership list, and Kademlia buckets are local views.

The scale harness exercises bootstrap joining, NodeID lookup and canonical-name lookup. It does not currently exercise a live signed UpdateIP/address-change propagation, service-record lookup, or opening a public/private service stream. UpdateIP signing/rejection has unit coverage elsewhere; that is not the same as proving propagation between live nodes. These missing workflows must be reported as NOT EXERCISED, not counted as passing DHT scale coverage.

## Current Local Evidence (One Seed, Not a Release Claim)

The following measurements were produced on one Arch Linux host (AMD Ryzen 7 250, 16 logical CPUs, about 14.3 GiB RAM), with seed 69 and a disposable Linux namespace/FRR topology. The identity-on-first-contact behavior was tested from PR #76 head `85e24d1` and is now merged as `106d622`. IPsec nodes: zero.

### Final exhaustive lookup sweep

Each directed source/target pair was queried both by NodeID and by name hash. Denominators are `N * (N - 1) * 2`.

| Nodes | Pre-#76 baseline found | #76 behavior found | Final interpretation |
|---:|---:|---:|---|
| 3 | 4/12 (33.3%) | 12/12 (100%) | Experiment fixed all measured small-mesh lookups in the final sweep. |
| 5 | 4/40 (10.0%) | 40/40 (100%) | Same. |
| 10 | 12/180 (6.7%) | 180/180 (100%) | Same. |

For the #76 run, each final target was already in the requester's local routing table. These sweeps test mesh population and known-local lookup behavior; they do **not** prove lookup by referrals for a target absent locally. The baseline failures included isolated nodes; 15 minutes of idle observation did not repair the baseline state.

### 100-node growth run

The #76 identity build joined 100 nodes through a five-wave schedule (`1,1,1,17,80`), with one bootstrap contact per join, two 60-second settle rounds, 50 random source-target pairs per round, one graceful restart, and one minute of idle observation.

- Both final settle rounds captured all nodes: 100/100 snapshots, zero snapshot errors.
- Final settle-1: 98/98 lookups found the expected target; zero incomplete, not-found, or request-error outcomes. The two skipped attempts were self-pairs.
- Overall, including growth/early-join measurements: 352/480 expected targets found (73.3%). This includes lookups made before the network had converged and must not be substituted for the final settle result.
- Final active peers: average 98.16 per node; minimum 38, maximum 99. Offline 0. Pending 1. bbolt peer rows averaged about 98 per node. All 100 peers were still in probation, which is expected before the configured probation duration elapsed.
- Final combined simnode RSS: 2,214.45 MiB; average 22.14 MiB/node; minimum 20.38, maximum 25.71 MiB. Simnode CPU time: 2,398,530 ms. Host busy estimate: 76.9%. Available host memory: 7,550 MiB at start and 5,616 MiB at end.
- One-minute idle observation retained about 9,816 active peer entries across 100 nodes (about 98.16/node).
- Every final 98/98 target was already in the source's local active routing table. Therefore this is strong evidence of population in this particular 100-node run, not proof of off-table referral routing.

### Exploratory absent-table probe

A temporary probe selector found one eligible source-target pair at 100 nodes. Both ID and name lookups were incomplete after 13 rounds and 41 peer queries. This was only one pair and is not a statistically meaningful scale result. The temporary selector used the NodeID index to choose the pair; the new `-off-table-probes` mode in this PR checks each XOR index independently and reports its eligible-pair denominator. The referral failure remains a follow-up to diagnose, not a pass.

### 200-node referral run: current warning, not a pass

Daiker ran off-table probes on a 10-vCPU/11-GiB Mac VM. The run was heavily CPU-bound and took about 2.2 hours. With the #78 test-harness dial guard applied to #76, settle lookups found **11/400** targets per round (2.75%). There were about 50,000 eligible off-table targets. This is enough to expose a problem, but the host saturation and record expiry make the result inconclusive as a measurement of production capacity.

The trace showed two main failure classes:

- About 23,949 liveness checks rejected signed peer records as expired. The current endpoint-record TTL is 20 minutes. Because this run was very slow, this may be load-amplified, a real refresh/republish gap, or both. A faster Linux rerun must distinguish those explanations.
- About 1,241 referrals were refused because the caller could not find a verified signed identity for the referred address. Refusing an unverified dial is correct security behavior. The lookup path needs to validate a signed referral safely before dialing it, without silently making it a permanent trusted route. Inspect the updated traces and production lookup code before changing protocol behavior.

The pre-#78 simulator did not exercise referrals: all simulated peer dials failed with `refusing unguarded peer dial`. #78 installed the same dial guard used by a running node in the simulator's admin lookup. Its CI rerun passed and it was merged. Earlier high small-mesh hit rates were local-table hits, not proof of referral success.

The updated #77 runner requests full traces for ordinary sampled and off-table lookups, independently audits local XOR bucket placement, and records each node's full active table and bbolt categories. Rerun it on a Linux host with resource headroom; retain all failures, including timeouts, expired-record errors, rejected referrals, and admin errors.

### Resource estimate for 10,000 nodes

The 100-node run measured 22.14 MiB average process RSS per node. A straight-line estimate is about 216 GiB for 10,000 simnode processes alone. This estimate excludes FRR, kernel/network-namespace memory, the runner, filesystem cache, and growth in per-node tables; it is a planning estimate, not a guarantee. We did not run 500, 1,000, or 10,000 nodes on the 14.3 GiB local host. Five hundred nodes would already imply roughly 10.8 GiB from simnode RSS alone at the measured average, so it was not safe to attempt here.

For a 10,000-node run, use a dedicated Linux host/VM with at least 320 GiB RAM, 32-64 CPU cores, at least 500 GiB free NVMe storage, file-descriptor limit >=100,000, and enough process/PID capacity. These are conservative starting recommendations derived from the 100-node observation and expected full snapshots, not hard simulator requirements. Run the 1,000-node pilot first; stop if memory or disk headroom is insufficient. Do not run on a production machine.

## Reproduction on Linux

Requirements: Linux with IPv6, Go matching the repository toolchain, `iproute2`, FRR (`bgpd` and `zebra`), root or equivalent network-namespace capabilities, and a dedicated disposable host. The simulator changes only its run-scoped namespaces and cleans them after normal completion. A hard kill can leave those namespaces; use the documented `teardown` command with that run's `topology.json`. Never use host networking in Docker. If using Docker, it needs the namespace/network administration capabilities required by the nested Linux topology; keep it isolated and disposable.

Build the runner and the simnode from this PR checkout:

```sh
go test ./tests/netsim/...
go build -ldflags="-X main.buildRevision=$(git rev-parse HEAD)" -o /tmp/vx6-netsim ./tests/netsim/netsim
go build -o /tmp/vx6-simnode-main ./tests/netsim/simnode
/tmp/vx6-netsim doctor
```

Use the same runner, seed, topology, schedule, settle duration, and lookup options for baseline and current binaries. Build the baseline simnode from pre-fix commit `64dcc57`; build the candidate from merged commit `106d622` plus merged harness guard PR #78. Do not combine binaries in one run. For future runs, record the exact source commit and binary SHA-256 rather than relying on branch names.

First run the 1,000-node resource pilot (250 ASes; same topology distribution):

```sh
sudo install -d -m 0700 -o root -g root /var/tmp/vx6-netsim-1k
sudo /tmp/vx6-netsim run \
  -tier1 8 -isps 64 -orgs 178 -attackers 0 \
  -nodes 1000 \
  -schedule 1,1,2,4,8,16,32,64,128,256,488 \
  -seed 69 -seeds-per-join 1 \
  -simnode /tmp/vx6-simnode-main \
  -lookups sample -off-table-probes -probes 500 \
  -settle-rounds 2 -settle-gap 60s -restart-count 0 \
  -idle 2m -idle-interval 30s \
  -out /var/tmp/vx6-netsim-1k
```

If the pilot finishes with adequate RAM and disk headroom, run the 10,000-node profile (250 ASes; 15 growth waves; one bootstrap contact per join):

```sh
sudo install -d -m 0700 -o root -g root /var/tmp/vx6-netsim-10k-main
sudo /tmp/vx6-netsim run \
  -tier1 8 -isps 64 -orgs 178 -attackers 0 \
  -nodes 10000 \
  -schedule 1,1,2,4,8,16,32,64,128,256,512,1024,2048,4096,1808 \
  -seed 69 -seeds-per-join 1 \
  -simnode /tmp/vx6-simnode-main \
  -lookups sample -off-table-probes -probes 1000 \
  -settle-rounds 2 -settle-gap 60s -restart-count 0 \
  -idle 2m -idle-interval 30s \
  -out /var/tmp/vx6-netsim-10k-main
```

For a baseline comparison, build a separate simnode from the recorded pre-#76 commit `64dcc57`; build the candidate from current `main`. Use this PR's runner for both runs. Run the same topology, seed, schedule, settle duration, and probe count against each simnode. Do not mix node binaries in one run. Use a fresh output directory for every run. The generated topology hash and binary hashes are recorded for comparison. Set `-probes 1000` for the 10k run; this means up to 1,000 individual off-table lookups per settle round, split across NodeID and name-hash probes based on eligible targets. Inspect `routing-map/idle-*.csv.gz` to see the full idle routing map and verify local bucket placement.

The scale run is **MEASURED**, not a blanket PASS. Report, at minimum:

1. For each join wave and settle round: node count, successful/failed snapshots, active/offline/pending counts, probation, both index bucket counts and occupancy, bbolt rows/categories/values, lookup outcomes, query/round counts, latency, per-node and total RSS, CPU time, host memory, and cleanup status.
2. Off-table probes: eligible and selected denominator; ID and name-hash results separately; exact target found, reachable-view miss, incomplete, conflict, and errors; lookup traces showing each referral and whether XOR distance improved.
3. Per-node snapshots and the sanitized full output directory/archive. Keep private keys and PID namespaces out of anything uploaded publicly.
4. Compare the pre-#76 baseline against merged #76 behavior only on the same topology and build tools. Explain any revision, configuration, or hardware difference.

## Interpretation Limits

- The simulated transport is not IPsec. A large DHT result cannot be cited as evidence of ESP, IKE authentication, or packet confidentiality.
- A found rate on random probes is not a proof of global DHT correctness. A lookup is a meaningful referral test only when the target was absent from the relevant source index before the request.
- A `not_found_reachable` result means the queried reachable view did not return the known target. It does not prove global absence.
- One seed/topology does not establish resilience to partitions, eclipse/Sybil behavior, malicious referrals, IP changes, or liveness expiry. Those need separate controlled scenarios.
- These results do not cover IP update propagation or service-record/service-stream access; separate live-node scenarios are required for those workflows.
