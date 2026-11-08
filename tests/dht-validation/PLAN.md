# VX6 Linux CLI DHT Validation Plan

## Purpose and scope

This suite will provide reproducible evidence that the Linux CLI can join a VX6 network, maintain its own local DHT state, find peers through iterative referrals, recover from ordinary peer failures, persist and revalidate peer history, and use the authenticated dataplane to reach services.

The suite is intentionally staged at 3, 5, and 10 real peers. It does not attempt to prove behavior at internet scale; large logical-network simulation belongs to issue #65, and the broader scenario/threat-model work belongs to issue #69. Hidden-service rendezvous and hidden-mode behavior are out of scope.

The goal is functional correctness and evidence, not latency tuning. Reports may record counts, state sizes, and resource snapshots for context, but will not define latency or throughput targets.

## Claims this suite can and cannot support

Passing results can show that, for the tested topology and injected failures:

- a joining node can bootstrap from a contact and discover additional peers;
- each lookup initiator performs the iterative work, while a responding peer returns only its local referrals;
- referrals are checked and deduplicated before they influence a lookup;
- node-name and NodeID lookup use their respective hashes and routing coordinates;
- the node makes its own active/candidate/inactive decisions and does not admit a peer merely because that peer asks to be admitted;
- a failed branch is not reported as a successful lookup or as proof of global absence;
- persisted peer metadata is treated as a candidate after restart and must be revalidated;
- the tested IKE/IPsec identity and service path works or fails closed under the listed conditions.

Passing results cannot prove global name uniqueness, Sybil resistance, immunity to a sufficiently large eclipse, or successful lookup of every online node in every internet topology. DHT replies are evidence from reachable peers, not global consensus. Those claims require separate analysis and scale/adversarial testing.

## Current lookup behavior to verify

For a name lookup, the initiator hashes the canonical name and selects up to four closest eligible contacts from its local NameHash index. For an identity lookup, it uses the target NodeID and local NodeID index. It sends the lookup type and hash to up to four peers concurrently. Each responder consults only its own local routing table and returns up to four signed peer records; it does not recursively query the network. The initiator verifies records, deduplicates by full NodeID, sorts by XOR distance to the requested coordinate, and queries the closest unqueried contacts in subsequent rounds.

The current configured safety ceilings are 20 rounds, four concurrent requests, up to 80 peer queries, two seconds per peer, and ten seconds total. Tests must check the actual configured values and must distinguish a fully explored reachable view from a timeout, failed branch, or exhausted limit. A timeout or query failure must produce an incomplete result, never a confident not-found result.

## Test environment

- Run Go-level deterministic tests on Linux without requiring Docker.
- Run real-peer tests in isolated Docker IPv6 networks. No public network, NAT, or external bootstrap service is required.
- Each real peer uses the current Linux CLI binary and the currently supported strongSwan/IPsec setup. Containers need the Linux networking capabilities required for XFRM and the test tunnel.
- Use a router/sniffer container only where packet-path evidence is required. Keep the test networks isolated from unrelated host interfaces.
- Fix random seeds and topology inputs for reproducibility. Keep private keys and secret configuration out of reports and logs.
- Record the source commit, binary SHA-256, Go version, kernel, Docker version/image digest, test configuration, topology, random seed, and exact command for every run.

The existing IPsec end-to-end script is a starting point for the container mechanics, but it currently exchanges endpoint records directly and therefore does not prove DHT bootstrap or multi-hop lookup. The new suite must exercise DHT in the topology rather than treating direct peer enrollment as a substitute.

### Implemented container coverage

`run-docker.sh` now builds and runs `mesh_test.go` inside an isolated Docker
network with IPv6 enabled. The test starts 3, 5, or 10 independent `dht.Server`
instances, each with a real IPv6 TCP listener and signed endpoint identity. It
checks iterative name-hash and NodeID referrals, exact wire lookup type/hash,
responder non-recursion, one failed branch with a reachable result, and
conflicting signed names. The same runner covers these DHT protocol scenarios
in one container/process; it does not prove separate CLI-process bootstrap or
IKE/IPsec protection for each DHT RPC. Those remain required integration work
below. Run it with `bash tests/dht-validation/run-docker.sh`; it appends evidence
to `DOCKER-TEST-REPORT.md`.

## Staged execution

Each stage is run and reviewed before moving to the next. A failure stops progression; fix or explain it, then rerun the same deterministic stage and preserve both the failed and passing reports.

### Stage 0: Test and evidence preflight

**Setup:** Verify the CLI builds, required Linux IPsec tools and kernel support exist, Docker is reachable, IPv6 networking works, and the test runner has permission to create isolated networks and XFRM state.

**Checks:** Run a known-good IPv6 packet capture control; verify the capture sees the control traffic. Verify the test image and VX6 binaries are built from the recorded source revision. Verify cleanup removes containers, networks, and temporary tunnel state after success and failure.

**Evidence:** Preflight report, environment manifest, build output, image digest, control-capture verdict, and cleanup verdict. A missing Docker daemon is an environment blocker, not a test pass.

### Stage 1: Deterministic DHT behavior without Docker

Use a controlled in-process peer graph and fake clock/network responses. This isolates DHT decisions from kernel networking and makes edge cases reproducible.

Required cases:

1. NameHash lookup and NodeID lookup select and sort using the correct independent coordinate.
2. The initiator starts from its closest four contacts, queries at most four concurrently, validates referrals, deduplicates them, and advances to the closest unqueried referrals.
3. A responder returns only its own local closest contacts. Assert it does not create downstream queries or recursively consume lookup work.
4. A target is found through multiple referral rounds; a lookup with two branches still explores referrals from both branches.
5. Duplicate, cyclic, malformed, wrong-signature, wrong-NodeID, bad-name-hash, and unusable-address referrals do not become trusted active peers or cause unbounded work.
6. A branch with no referrals does not cancel useful referrals returned by another branch.
7. A complete reachable search with no match is distinct from timeout, failed peer, cancellation, or configured-limit exhaustion. Those failures return incomplete.
8. Conflicting signed name claims are all retained in the result and are not silently replaced by a preferred local identity.
9. Inbound requests and referral floods cannot force the receiving node to add the sender to its active DHT.
10. Enforce concurrency, peer timeout, total timeout, query ceiling, response-size ceiling, cancellation, and socket/goroutine cleanup.

**Evidence and measurements:** Per-case pass/fail, query count, rounds, maximum concurrent requests, returned/refused referral counts, result category, and goroutine/connection cleanup assertions. No latency threshold.

### Stage 2: Three-peer Docker bootstrap and lookup

**Topology:** Peer A is an existing bootstrap contact; peer B is a target with a signed identity record; peer C is a fresh joining node. C starts with only A's configured IPv6 endpoint. A knows or can refer C toward B through its local DHT. All links use isolated IPv6 Docker networks.

**Flow:** Start A and B, establish their authenticated VX6 peer state, and publish their node records. Start C, bootstrap through A, validate referrals, perform C's own NodeID and NameHash lookups, and reach B through the returned referrals. Capture DHT and service traffic at the transit router where supported.

**Checks:** C does not need a central coordinator; A's response is only a referral; C validates peer records and verifies the expected IKE identity before accepting the protected peer path; DHT request types and hashes are correct; active routing state is created only after the implemented validation conditions succeed.

**Evidence:** Topology manifest, sanitized node logs, signed-record validation verdicts, per-node DHT snapshots before/after join, referral/query trace, IKE/CHILD_SA and XFRM snapshots, capture verdict, and cleanup result.

### Stage 3: Five-peer branching and fault handling

**Topology:** Add two referral branches and a second possible path to the target. Use distinct IPv6 subnets. Include a deterministic name-conflict fixture.

**Faults:** Make one referral stale or unreachable; delay or drop one peer's response; return duplicate referrals; return no referrals from one peer; provide two valid identities claiming the same canonical name.

**Checks:** The lookup explores useful results from other branches, stops on its configured limits, and does not report global absence when a branch failed. Name conflicts are surfaced. An unavailable peer does not become active based only on a referral. A lookup responder does not recursively fan out.

**Evidence:** Fault schedule, DHT snapshots at each checkpoint, query graph, per-node result outcome, failure counters, validated/rejected candidate counts, and tunnel state. No timing target.

### Stage 4: Ten-peer mesh, independent admission, and self-maintenance

**Topology:** Ten real Linux CLI peers across several isolated IPv6 subnets representing separate networks. Start with a small connected group, then add peers sequentially and in a small join burst. Do not make one peer the permanent controller; bootstrap endpoints are only initial contacts.

**Checks:** Each node maintains its own table; no node can force admission by connecting or sending referrals. Nodes can learn contacts through different entry peers. NameHash and NodeID routing remain distinct. Candidate, active, probation, and offline states are visible in snapshots and transitions follow the configured rules. Refresh and liveness work remains bounded and staggered.

**Evidence:** Per-node DHT snapshots for every checkpoint, peer-state transition log, contact provenance, join success/failure reason, query/referral counts per node, and persisted peer-store summaries. Compare table states across nodes without claiming that all tables must be identical.

### Stage 5: Persistence, liveness, and recovery

**Cases:** Restart a node and confirm saved peers return as candidates rather than automatically live routes. Return a peer at its valid endpoint and confirm revalidation can promote it. Use a wrong-key endpoint and confirm it is rejected. Exercise three explicit liveness misses using a test clock or test-only shortened intervals, then confirm inactive handling. Test the two-hour probation and 30-day retention with the fake clock, not wall-clock waiting. Confirm ordinary lookups exclude inactive peers while bootstrap lookup can use them as hints that still require fresh validation.

**Evidence:** Before/after bbolt peer-store summaries, checksummed database copies where safe, fake-clock inputs, state transition records, IKE identity result, and restart verdict. Never include private keys.

### Stage 6: Authenticated dataplane and service accessibility

This is a DHT release-readiness check, not a hidden-service test. Use peers discovered through the tested DHT flow. Establish the expected IKEv2/IPsec ESP association, then access two distinct local TCP services concurrently through VX6.

**Checks:** Correct service-to-local-port mapping; both services respond with unique test markers; the wrong peer key is rejected; service traffic does not succeed without the authenticated IPsec path; tunnel removal/restart does not silently fall back to clear application traffic. The transit capture must have a known-good capture control and show expected outer IPv6/IKE/ESP behavior.

**Evidence:** Service request/response verdicts, peer identity outcome, `swanctl --list-sas`, XFRM state/policy snapshots, and pcap plus a concise decoded packet summary. Do not infer security from an empty capture.

## Reports and benchmark-style measurements

Each run creates a unique report directory, for example `reports/<UTC-date>-<commit>-stage-03/`. Generated reports and captures should not be committed by default; preserve them as local artifacts or CI artifacts and publish only reviewed summaries.

Each stage report contains:

- purpose and exact claim being tested;
- source commit and binary/image hashes;
- environment and topology diagram/manifest;
- exact commands and configuration (with secrets removed);
- deterministic seed and fault schedule;
- expected result and actual result for every case;
- pass/fail verdict and any limitations;
- DHT snapshots at defined checkpoints;
- query/referral counts, unique peers reached, result categories, invalid referrals rejected, active/candidate/inactive counts, peer-store row counts/size, and IKE/ESP state counts;
- artifact index with SHA-256 checksums for logs, snapshots, and captures;
- cleanup result and any deviations from the plan.

These are functional and resource-accounting measurements, not latency benchmarks. Do not publish a single “DHT success percentage” without listing the topology, failure model, and denominator. Report found, reachable-view-not-found, conflict, and incomplete separately.

## Exit criteria for the Linux CLI validation phase

- All deterministic Stage 1 cases pass, including the false-not-found and no-recursive-responder checks.
- Stages 2, 3, and 4 pass with reproducible reports and saved DHT snapshots.
- Stage 5 proves persisted contacts require revalidation and liveness transitions match policy.
- Stage 6 proves services discovered through DHT work over the authenticated ESP path and fail closed when peer identity/tunnel requirements are not met.
- No stage reports timeout or partial reachability as global proof that a node/name does not exist.
- Test scripts clean up on both pass and failure; artifacts contain no private keys or other secrets.
- Any failure, unsupported topology, or mismatch between documentation, issue criteria, and code is recorded as unresolved rather than waved through.

Passing this plan demonstrates the tested Linux CLI behavior for these topologies. It does not close issue #65's logical scale simulation, issue #69's full scenario/threat-model work, or make global security guarantees.

## Execution order

1. Preflight and deterministic DHT tests.
2. Three-peer Docker bootstrap.
3. Five-peer branching/fault tests.
4. Ten-peer mesh and independent-admission tests.
5. Persistence and liveness recovery.
6. Authenticated dataplane and concurrent service checks.
7. Review reports and decide whether the Linux CLI behavior is ready for optimization work.
