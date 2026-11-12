# VX6 DHT Scale Test: Handoff and Results

## Purpose

Measure DHT formation and lookup as the simulated network grows. A larger node count alone does not prove referrals work: the important condition is that a known target is absent from the requester's relevant local XOR index before lookup. Record whether referrals move the search closer and whether the exact expected identity is returned. Because K=20 is not a hard cap, small and medium networks may still retain most or all peers locally.

This is a DHT test. The scale tier runs separate VX6 node processes in isolated Linux network namespaces and uses the simulator's signed-record-gated pass-through transport. It does not test IKEv2, ESP, or IPsec. Those remain a separate two-node test.

## What the Simulator Captures

Each run writes a Markdown and JSON report, topology and command logs, per-round lookup traces, per-node diagnostics, XOR placement maps, logs, process records, and cleanup status. Diagnostics include both in-memory XOR indexes (NodeID and canonical-name hash), per-bucket occupancy and peers, offline and pending entries, bbolt peer categories and values, observed lookup limits, liveness observations, and per-node resource use. Never publish a raw run directory without checking it for private keys and machine-specific information.

The `-off-table-probes` mode runs only in settle rounds. Before selecting a probe, it reads the source node's diagnostics and independently checks that the target is absent from the appropriate active index: NodeID for an ID lookup, name-hash for a name lookup. Reports state the checked index and show candidate pairs available and selected. If no eligible candidates exist, the report shows zero and does not imply referral lookup was tested. Every sampled and off-table request asks for a referral trace; records in `lookups/<round>.json` include the responders, referrals, errors, duplicates, XOR progress and stop reason.

At every diagnostic capture, `routing-map/<capture>.csv.gz` contains each stored active peer in both indexes and any globally nearest-K contact absent from that table. It reports local XOR distance/rank, actual and recalculated bucket, global per-bucket rank, and whether the contact is present. A wrong local bucket fails the run; a missing globally-nearest contact is reported as a coverage gap, not as a malformed route. The global census is the set of nodes whose snapshots succeeded in that capture. This gives an independent plane map without pretending that nodes themselves know global membership.

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

### Test sizes and what they prove

There is no 1,000- or 10,000-process requirement. Daiker's available Linux VM has reached roughly 200 nodes before saturating CPU; use the largest size that completes reliably on the available host, with 200 as the initial target and 300 only if a pilot shows safe headroom. Do not interpret an incomplete or CPU-saturated run as a DHT result.

Use three complementary checks:

1. **Small exact checks (3, 5, 10 nodes):** exhaustively query every directed non-self pair by NodeID and canonical-name hash. These confirm identity/name lookup behavior and the test harness. They often become full-mesh/local-table hits, so do not count them as referral proof.
2. **Real-process growth and referral checks (up to about 200-300 nodes):** add nodes in waves, capture every node after each wave/settle/idle period, and select only targets known to the test census but absent from the source's matching active XOR index. For every selected lookup, preserve its full referral trace. This is the integration proof for actual processes, network namespace routing, admission, and lookup behavior within the tested size.
3. **Low-resource virtual-plane check (target 1,000 virtual identities):** add a deterministic in-process test that uses VX6's production XOR bucket and closest-contact selection code, but no OS processes, sockets, FRR, or namespaces. It should exercise incremental joins and idle refresh rounds, compare each node's local tables with a test-only global census, and test ID/name lookups where the target is deliberately absent locally. Report actual bucket placement, per-bucket population, global-nearest-K coverage, lookup path/stop reason, and convergence by round. This is an algorithmic scale check, not a substitute for the real-process run; it must be implemented and independently tested before anyone reports its results.

This split answers two different questions without asking Daiker's host to run thousands of binaries: the bounded process test asks whether real nodes can exchange referrals; the virtual test asks whether the routing math and maintenance logic scale over a larger deterministic population. No passing result from the virtual test alone proves production networking, signed-record verification, liveness, IP updates, or service access.

The current routing table uses dynamic buckets. `K=20` is the normal referral/replication target, not a hard per-bucket cap, and 256 empty bucket headers do not mean 256 populated buckets. Therefore `256 * 20 = 5,120` is not a network or implementation maximum. At small network sizes a node may know nearly every peer; that produces fast local hits but does not exercise referrals. The harness must report the source's pre-lookup local-index state and separately measure only lookups whose known target was absent there.

## Reproduction on Linux

Requirements: Linux with IPv6, Go matching the repository toolchain, `iproute2`, FRR (`bgpd` and `zebra`), root or equivalent network-namespace capabilities, and a dedicated disposable host. The simulator changes only its run-scoped namespaces and cleans them after normal completion. A hard kill can leave those namespaces; use the documented `teardown` command with that run's `topology.json`. Never use host networking in Docker. If using Docker, it needs the namespace/network administration capabilities required by the nested Linux topology; keep it isolated and disposable.

Build the runner and simnode from this PR checkout:

```sh
go test ./tests/netsim/...
go build -ldflags="-X main.buildRevision=$(git rev-parse HEAD)" -o /tmp/vx6-netsim ./tests/netsim/netsim
go build -o /tmp/vx6-simnode-main ./tests/netsim/simnode
/tmp/vx6-netsim doctor
```

Use the same runner, seed, topology, schedule, settle duration, and lookup options for baseline and current binaries. Build the baseline simnode from pre-fix commit `64dcc57`; build the candidate from merged commit `106d622` plus merged harness guard PR #78. Do not combine binaries in one run. For future runs, record the exact source commit and binary SHA-256 rather than relying on branch names.

Run the bounded process test first. Start at 100 nodes and increase to 200 only if the host has headroom. Use a fresh output directory per run:

```sh
sudo install -d -m 0700 -o root -g root /var/tmp/vx6-netsim-200
sudo /tmp/vx6-netsim run \
  -tier1 4 -isps 16 -orgs 40 -attackers 0 \
  -nodes 200 \
  -schedule 1,1,2,4,8,16,32,64,72 \
  -seed 69 -seeds-per-join 1 \
  -simnode /tmp/vx6-simnode-main \
  -lookups sample -off-table-probes -probes 400 \
  -settle-rounds 2 -settle-gap 60s -restart-count 0 \
  -idle 2m -idle-interval 30s \
  -out /var/tmp/vx6-netsim-200
```

The 200-node example uses 60 ASes to keep topology diversity while staying within the host limit Daiker observed. If a 200-node run saturates the machine or misses namespace deadlines, keep the smaller completed size and report the resource limit; do not force 300. `-probes 400` is an upper bound per settle round, not a promise that 400 eligible pairs exist. The report must show the eligible and selected denominators separately.

For a before/after comparison, build one candidate simnode from recorded pre-#76 commit `64dcc57` and one from current `main`, then run each separately with the exact same size, seed, schedule, and probe options. Do not mix binaries in one network. Inspect `routing-map/idle-*.csv.gz` for every completed idle capture.

The scale run is **MEASURED**, not a blanket PASS. Report, at minimum:

1. For each join wave and settle round: node count, successful/failed snapshots, active/offline/pending counts, probation, both index bucket counts and occupancy, bbolt rows/categories/values, lookup outcomes, query/round counts, latency, per-node and total RSS, CPU time, host memory, and cleanup status.
2. Off-table probes: eligible and selected denominator; ID and name-hash results separately; exact target found, reachable-view miss, incomplete, conflict, and errors; lookup traces showing each referral and whether XOR distance improved.
3. Per-node snapshots and the sanitized full output directory/archive. Keep private keys and PID namespaces out of anything uploaded publicly.
4. Compare pre-#76 baseline against current behavior only at a size the host can complete reliably. Explain any revision, configuration, or hardware difference.

## Interpretation Limits

- The simulated transport is not IPsec. A large DHT result cannot be cited as evidence of ESP, IKE authentication, or packet confidentiality.
- A found rate on random probes is not a proof of global DHT correctness. A lookup is a meaningful referral test only when the target was absent from the relevant source index before the request.
- A `not_found_reachable` result means the queried reachable view did not return the known target. It does not prove global absence.
- One seed/topology does not establish resilience to partitions, eclipse/Sybil behavior, malicious referrals, IP changes, or liveness expiry. Those need separate controlled scenarios.
- These results do not cover IP update propagation or service-record/service-stream access; separate live-node scenarios are required for those workflows.
