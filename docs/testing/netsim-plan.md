# VX6 DHT Network Simulation (#69)

## Purpose and current status

The Linux harness runs the real VX6 node/DHT in separate processes and
network namespaces. Its purpose is functional DHT validation at small and
medium local sizes, plus collecting evidence that can guide later scale work.
The current runner is a **limited baseline**, not the complete adversarial
matrix originally proposed in #69.

The runner currently executes:

1. Join waves using endpoint records from already-started nodes.
2. Per-node routing snapshots after each wave and during optional settle rounds.
3. Random existing-target lookups by full NodeID and by canonical name hash.
4. Optional graceful restart of selected nodes, with identity-stability and
   `dht-peers.db` persistence/recovery checks.
5. Report generation with exact parameters, binary hashes, lookup outcomes,
   observed code limits, snapshots, logs, and cleanup status.

The scale runner replaces the IPsec layer with a lab-only pass-through. It
does not test IKE authentication or ESP encryption. Use the separate two-peer
IPsec integration test for those properties.

## Explicit non-claims

- A lookup that returns no result only means the queried/reachable contacts did
  not return the target. It does not prove global non-existence.
- Attacker-AS nodes are currently ordinary honest simnodes. They do not inject
  false referrals or forged records.
- The current command path does not perform address changes, liveness expiry,
  network partition/heal, abrupt churn, eclipse scheduling, or BGP hijack.
- A 3/5/10-node local run does not establish behavior at thousands or millions
  of nodes, nor prove resistance to Sybil attacks.
- DHT-scale results are not evidence for IKE/ESP confidentiality or identity
  authentication.

## Test model

Each simulated node runs the production `node.Run` and DHT code with its own
identity, data directory, admin socket, and Linux network namespace. The
simulator presents signed endpoint records to joining nodes. The pass-through
tunnel accepts only a valid signed record already prepared for that endpoint;
it does not negotiate cryptographic keys or encrypt packets.

The topology generator lays out IPv6 networks across simulated ASes and emits
FRR configuration when FRR is installed. Nodes join in deterministic waves
from a recorded seed. The Linux runner assigns each run a random six-hex-digit
namespace prefix and verifies that namespaces and process records belong to
that run before cleanup.

Lookup probes exercise both coordinate spaces:

- `id`: query by the full VX6 NodeID derived from the public identity.
- `name`: canonicalize the requested name locally and query by the
  name-hash coordinate; the clear name is not used as the DHT key.

The report separates `found_verified`, reachable-view `not_found`, expected
target not returned, incomplete/conflict, and request errors. It also records
the running nodes' actual lookup policy, rather than assuming policy constants
from this document.

## Safe run procedure

Follow [`../../tests/netsim/README.md`](../../tests/netsim/README.md) for build,
doctor, plan, render, dry-run, live execution, and teardown commands. Live runs
are Linux-only and need root or equivalent network namespace capabilities,
IPv6, `iproute2`, and FRR for inter-AS BGP. Use a disposable Linux VM/host and
an empty root-owned mode-0700 output directory. Do not run the privileged
simulation on a production host.

Normal exit, error, SIGINT, and SIGTERM trigger managed cleanup. After a hard
kill or host shutdown, use `netsim teardown -params <run>/topology.json`; it
validates the random run ID and only removes namespace names derived from that
topology. Inspect cleanup status in `report.md`/`report.json` before rerunning.

## First local validation: 3 / 5 / 10 nodes

Use the same source revision and seed (`69`) for all sizes, and unique output
directories. Suggested schedules are `1,2`, `1,1,3`, and `1,1,2,6`. For each
size, capture:

- exact command line, source revision, simnode and netsim SHA-256;
- successful join/readiness for every node;
- routing snapshot success/errors per round;
- ID and name-hash lookup outcomes and latency/round counts;
- observed lookup limits, including query budget and total timeout;
- graceful-restart identity and bbolt candidate recovery evidence;
- cleanup status and host OS/RAM.

These sizes are smoke/functional progression, not statistically meaningful
network-scale benchmarks. Use multiple seeds and repetitions before drawing
comparative conclusions.

## Coverage matrix

| Scenario | Current runner status | Additional work needed |
|---|---|---|
| Cold bootstrap and join waves | Exercised | More repetitions and sizes |
| ID and name-hash lookup | Exercised | Include deliberate name conflicts and expected misses |
| Graceful restart and peer-store recovery | Exercised when enabled | Test empty-table and partial-persistence cases explicitly |
| Abrupt process failure / churn | Not exercised | Add controlled kill/rejoin schedules and recovery assertions |
| Liveness miss/expiry | Not exercised | Add deterministic clock/timer control or wait-based test |
| Endpoint/IP change propagation | Not exercised | Add signed update-IP scenario and assertions |
| Malicious/poisoned referrals | Not exercised | Add malicious peer behavior, invalid signatures, duplicate and self-serving referrals |
| Partition and heal | Not exercised | Add link fault injection, bounded duration, recovery checks |
| Eclipse and attacker concentration | Not exercised | Generate target-adjacent attacker IDs and measure outcomes by share |
| BGP hijack | Not exercised by run command | Add explicit FRR route injection and route/traffic assertions |
| IKE/ESP MITM and confidentiality | Not exercised here | Keep in a separate small real-IPsec test tier |

The report marks unrun scenarios as `NOT EXERCISED`; the presence of attacker
ASes in the topology is not itself an adversarial DHT test.

## Evidence interpretation

`report.json` is the machine-readable record. `report.md` is its concise
summary. `round-XX.json` and `snapshots/` hold per-round/per-node details.
`commands.log`, node logs, FRR logs, and process manifests support diagnosis.
Preserve all output directories and do not combine results from different
seeds or configurations into one success rate.

The live nodes expose the active DHT policy. The configured default is 20
rounds, four concurrent peer queries, at most 80 total peer queries, four
referrals per response, and a 10-second total lookup timeout. The report records
the values returned by a running node, and a DHT network test walks a signed
referral graph with more than 12 peers to verify the larger budget in practice.
