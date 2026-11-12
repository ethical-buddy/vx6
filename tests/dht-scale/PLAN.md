# VX6 DHT Growth and Lookup Test Plan

## Purpose

This test answers a bounded question: as a VX6 overlay grows by nodes joining through existing contacts, do the production DHT tables and iterative NodeID/name-hash lookup code learn and find signed peer identities? It records enough state to explain a miss instead of reporting only a success percentage.

It does not claim to prove that every online node is always discoverable, that the DHT is secure against Sybil/eclipse attacks, or that IKE/IPsec works. The runner uses the production `internal/dht.Server`, `RoutingTable`, DHT wire request validation/handler, signed endpoint-record code, and iterative lookup. Each simulated node is an in-process Go server on a distinct IPv6 loopback TCP port. IKE, ESP, public Internet routing, and cross-machine behavior are intentionally outside this test; see `tests/ipsec-e2e` for the separate two-peer IPsec proof.

## Why This Shape

- Running 500 or 1,000 complete OS/network namespaces costs a lot of memory and process overhead that is unrelated to XOR lookup correctness.
- An in-process node still uses a real TCP listener, VX6 DHT framing, the actual handler, and the actual lookup client. It removes namespace/FRR overhead, so a normal Linux developer machine can measure larger DHTs.
- The simulated overlay grows one node at a time. A new node starts from one randomly selected known contact, asks for bootstrap referrals, verifies signed contacts, and only adds referrals that answer a real DHT request. This avoids giving every node a prefilled global table.
- The lookup target is never disclosed as a name on the wire: name lookups send the full canonical name hash and the lookup-name request type. Identity lookups use the complete NodeID coordinate.
- An independent test oracle ranks the complete simulated population by the complete 256-bit XOR distance. It is used only to evaluate what the local table/lookup found; it is not given to simulated nodes.
- The bbolt peer store is exercised at final capture. It persists each node's peer observations and its category indexes; a separate restart/recovery test is still needed before claiming the full node startup path is proven.

## Join and Lookup Workflow

1. Generate a deterministic Ed25519 test identity for every node index and a signed endpoint record. Deterministic keys make NodeIDs stable for a seed; listener ports and issued-at times are ephemeral run data. These identities are test-only and must never be used by a real VX6 installation.
2. Start node zero as the initial contact.
3. For each new node, select one existing contact using the recorded seed. Add only the directly contacted pair to each other's active routing table to model a successful authenticated peer exchange.
4. Ask that one contact for bootstrap referrals using the joining node's complete NodeID. Verify each referral's signed endpoint record, issue a DHT query to it, and add it only after it responds.
5. The entrant then performs its own iterative lookup for its NodeID and canonical name hash. Each lookup has its production 20-round/4-parallel/80-query/10-second protocol ceilings. Successful responders with valid signed endpoint records are promoted in the simulated local table.
6. The entrant models announcements to the four closest responsive peers in each coordinate space. Their tables are updated as if the subsequent peer-authenticated contact exchange completed. This is a topology/admission model only: the runner does not perform IKE or Ed25519 private-key proof, and the report says so explicitly.
7. Save bootstrap contacts, referrals, self-lookup traces, responsive peers, and modeled announcements in `join/`.
8. After all joins, target every node once from a different sampled node in both lookup spaces: NodeID and canonical name hash. Also run `-pairs` seeded random source/target pairs in both spaces, plus two negative controls for identities that are not in the network.
9. For every lookup, attach the production lookup trace. Record seeds, each queried responder, errors/timeouts, returned referrals, XOR shared-prefix progress, duplicate/rejected contacts, stop reason, query count, rounds, found identity, and elapsed time.
10. At final capture, export every active/offline/pending entry in both routing indexes and persist peer observations to one bbolt file per simulated node. Reopen each database and load candidates to verify the storage round-trip. The tables are two XOR views over one local active peer set; they are not two globally complete databases.

## What the Report Contains

- `report.md` and `report.json`: version, revision, seed, actual lookup limits, population, complete-found versus found-but-incomplete counts, positive and negative lookup outcomes split by coordinate, exact-top-four comparisons, query and elapsed-time percentiles, local peer counts, bucket totals and placement audit, bbolt rows/bytes, heap use, goroutine count, and run duration.
- `snapshots/all-nodes.json`: every node's complete public signed identity record (NodeID, name, IPv6 loopback endpoint, public key, sequence/times, signature), join index, active/offline/pending counts, both indexes' non-empty buckets, bucket occupancy, peer metadata, liveness/probation/use observations, and bbolt category membership. Private keys are never emitted.
- `lookups/index.json`: compact index of all attempts. Each `lookups/NNNNNN-*.json` includes that attempt's full routing trace and independent global top-four oracle.
- `join/NNNNNN.json`: bootstrap contact, referrals, self-lookups, and reciprocal announcements modeled for each join. Separate files hold the full self-lookup traces.
- `stores/NNNNNN.db`: the bbolt peer store created from that node's final observation snapshot, reopened and read back as part of the run. It contains no private keys.
- `host.json`: Go/runtime/platform context. Use `/usr/bin/time -v` around the command for process peak RSS and CPU time; do not interpret Go heap as total process RSS.

The global top-four comparison is deliberately reported as a measurement, not a pass condition. A node cannot return a globally closest peer it has never learned about. Low recall indicates a routing/convergence gap in this topology or join process; it does not automatically mean the XOR arithmetic is wrong. The independent oracle is complete and global, while every production lookup sees only its current local/referral view. A target can be matched while the outcome is `incomplete`; that means the identity was discovered but the lookup did not exhaust its search (for example, the fixed query budget was reached). These are counted separately.

## Run Commands

Use Linux with IPv6 loopback enabled and a recent Go toolchain. The runner binds only `::1` ephemeral TCP ports and writes only to the chosen output directory. It does not use Docker, root, network namespaces, FRR, the host firewall, or IPsec.

From the repository root:

```sh
go test ./tests/dht-scale
go run ./tests/dht-scale -nodes 3 -pairs 4 -seed 75 -out /tmp/vx6-dht-3
go run ./tests/dht-scale -nodes 10 -pairs 20 -seed 75 -out /tmp/vx6-dht-10
go run ./tests/dht-scale -nodes 100 -pairs 100 -seed 75 -out /tmp/vx6-dht-100
```

Then increase one stage at a time:

```sh
go run ./tests/dht-scale -nodes 500 -pairs 250 -seed 75 -out /tmp/vx6-dht-500
go run ./tests/dht-scale -nodes 1000 -pairs 500 -seed 75 -out /tmp/vx6-dht-1000
```

For comparable resource readings, run:

```sh
/usr/bin/time -v go run ./tests/dht-scale -nodes 500 -pairs 250 -seed 75 -out /tmp/vx6-dht-500
```

Always use a fresh output path. Keep the complete output directory for each run. Record CPU model/core count, RAM, kernel, Go version, exact command, commit SHA, and whether the host was otherwise idle. Do not run multiple scale jobs in parallel on the same host when comparing resource numbers. A 500-node local baseline from this runner used about 428 MB Go heap-system space, 1,001 goroutines, and 231 MB of report/database files; use at least 8 GB RAM and 5 GB free disk for the first 1,000-node attempt, and watch actual RSS with `/usr/bin/time -v`. These are conservative test-host estimates, not VX6 production requirements or a guarantee that 1,000 will fit every host.

## Staged Execution and Stop Rules

1. `3` nodes: harness smoke test, signed-record verification, lookup trace completeness, report validity.
2. `10` nodes: sanity-check staged joining and both routing coordinates.
3. `100` nodes: first meaningful growth sample; inspect every snapshot and failed trace.
4. `500` nodes: compare lookup success, peer-degree distribution, global-top-four recall, database size, heap, process RSS, and CPU against 100.
5. `1,000` nodes: run only after 500 finishes cleanly and resource use is acceptable. Consider 2,000 next only if resource scaling remains predictable. The tool has a hard 5,000-node input guard; that is a harness safety ceiling, not a VX6 DHT node limit.

Stop and investigate before increasing size if any node has zero active contacts after joining, a lookup has a target present in its reachable topology but fails to find it, referrals fail signature verification, traces omit expected queries, the bbolt snapshot differs from memory without an explained retention rule, output size or runtime grows unexpectedly, or the host approaches memory/FD limits. Report incomplete lookups separately from not-found results. Never convert exhausted local search into proof of global absence.

## Required Analysis for the PR Result

For each population, compare:

- ID lookup and name-hash lookup found/incomplete/not-found percentages.
- Query count and duration p50/p95; identify repeated, failed, and non-progressing branches in traces.
- Per-node active degree: min/median/mean/p95/max, isolated nodes, and nodes with only one contact.
- Both 256-bucket occupancy distributions, including empty buckets, non-empty bucket count, and bucket index correctness.
- Local table's recall of the globally closest four peers independently for NodeID and name hash.
- Lookup result's returned closest-four agreement with the global oracle, while accounting for the node's reachable knowledge.
- Stored bbolt rows and categories versus the same node's in-memory entries.
- bbolt read-back candidate count versus persisted row count, accounting for the peer-store retention policy.
- Heap, process RSS, CPU time, file descriptors, output/database disk size, and runtime as node count grows.
- Whether the incremental join topology was connected at the TCP graph level. A found-rate alone cannot explain topology partitions.

Do not label a run “perfect,” “secure,” or “globally complete.” A useful conclusion names exactly what was exercised and what failed or remains untested.

## Known Gaps / Follow-up Tests

- The simulator models signed-record checks and successful DHT responses, then models peer admission/announcement. It does not perform IKE authentication or prove possession of the Ed25519 private key through the real node ingress path.
- Admission and reciprocal announcements after self-lookup are modeled in the harness; they do not exercise the production node lifecycle. Compare with `tests/netsim` and a future node-level test for that contract.
- This run does not advance a fake clock through the five-minute liveness cadence, three misses, two-hour probation, or 30-day offline retention. Those need clock-injected unit/integration scenarios.
- It does not simulate route loss, endpoint address change, ASN/prefix distribution, malicious referrals, Sybil/eclipsing peers, node restart, service publishing, or private-service authorization.
- Loopback latency and packet delivery are not Internet measurements. Use a separate namespace/FRR test for topology/routing behavior and the two-peer IPsec test for ESP.
