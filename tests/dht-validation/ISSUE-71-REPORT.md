# Issue #71: DHT Routing Validation Report

## Result

**Local validation passed for the tested DHT behaviors.** The DHT routing and local peer-store tests, the DHT/node race suites, full Go test suite, build, and isolated 3/5/10-peer protocol mesh passed. This report is a local baseline, not a scale or global-security guarantee.

## Environment

- Date: 2026-11-08 UTC
- Source HEAD: `47ef0ab503c80d2ac05f07206d92eb3d29ad459a`
- Working tree: dirty; the DHT snapshot fix, candidate validation test, UDP/service work, and documentation changes were present. No commit was created for this run.
- OS/kernel: Linux x86_64, kernel `7.2.15-arch1-1`
- CPU: AMD Ryzen 7 250 with Radeon 780M, 16 logical CPUs
- Memory: 14 GiB total; 8.9 GiB available when sampled
- Go: `go1.27.3-X:nodwarf5 linux/amd64`
- Docker: `29.9.3`

## Covered Behaviors

- Two independent routing coordinates: NodeID and NameHash; both use XOR ordering.
- Sparse routing ranges and growth beyond the `k=20` target; there is no hard active peer cap.
- Candidate capacity: 512 globally, independently from active routes.
- Candidate flooding does not displace an established active peer.
- Restored bbolt peers start as candidates and are not active until revalidated; local peer history is capped at 512 rows and warms at least 50 when available.
- Signed identity validation, endpoint update sequence, expiry, name-hash matching, and rejection of malformed/invalid records.
- Candidate promotion order: signed endpoint and liveness check, expected peer identity through the IPsec verifier, protected-path health exchange, and only then active-route insertion. The new orchestration test uses a mock `PeerTunnel`; it verifies ordering/fail-closed control flow, not real ESP encryption.
- Liveness misses are spaced by at least five minutes; three misses mark a peer inactive; success resets misses. Offline retention and expiry are covered with controlled times.
- Refresh targets are bounded and do not populate empty ranges. Refresh chooses at most two targets per round.
- Diversity is supplemental: known ASN data can add a contact within a shared /48; when ASN is unknown the selection falls back to prefix information; neither condition blocks active admission or changes XOR ordering.
- Existing DHT protocol tests cover malformed/poisoned values, branch failures, query bounds, lookup outcomes, conflicts, replication, and peer-store persistence.

## Commands and Outcomes

| Command | Outcome |
|---|---|
| `GOCACHE=/tmp/vx6-go-build GOMODCACHE=/tmp/vx6-go-mod go test -race ./internal/dht ./internal/node -count=1` | PASS |
| `GOCACHE=/tmp/vx6-go-build GOMODCACHE=/tmp/vx6-go-mod go test ./... -count=1` | PASS |
| `GOCACHE=/tmp/vx6-go-build GOMODCACHE=/tmp/vx6-go-mod go build ./...` | PASS |
| `bash tests/dht-validation/run-docker.sh` | PASS, 3/5/10-peer IPv6 protocol mesh, branch failure, and signed-name conflict cases |
| `GOCACHE=/tmp/vx6-go-build GOMODCACHE=/tmp/vx6-go-mod go test ./internal/dht -run '^$' -bench 'Benchmark(CandidateInsertBatch|ClosestNodeSelection|RefreshTargetSelection|RoutingChurnRecovery)$' -benchmem -benchtime=300ms -count=3` | PASS, baseline values below |
| `git diff --check` | PASS |

The fresh Docker run, full output, test-binary checksum, and image ID are appended under `DHT Docker Mesh Run 20261108T022617Z-352578` in [DOCKER-TEST-REPORT.md](DOCKER-TEST-REPORT.md). That harness runs independent `dht.Server` instances in one test process and uses a permissive test dial guard. It does not prove separate CLI-process bootstrap or real IKE/IPsec between every DHT peer.

## Memory Baseline

`TestRoutingTableRetainedHeapReport` forces GC before and after constructing one active routing table. These are approximate retained heap deltas for the routing table and peer entries only; they exclude bbolt, goroutines, kernel state, and process/runtime overhead.

| Active peers | Retained heap | Approx. per peer |
|---:|---:|---:|
| 50 | 31,976 B | 639.5 B |
| 512 | 376,472 B | 735.3 B |
| 10,001 | 6,673,880 B | 667.3 B |

## Operation Benchmarks

Values below are medians of three 300 ms runs on the environment above. Batch insertion includes initializing the routing table; peer strings are prepared outside the timed loop. `B/op` and allocations are Go benchmark measurements, not wire bytes.

| Operation | Table/batch size | Median time | B/op | allocs/op |
|---|---:|---:|---:|---:|
| Candidate insertion batch | 50 | 48.8 us | 72,679 | 372 |
| Candidate insertion batch | 512 | 463.3 us | 457,535 | 3,618 |
| Closest NodeID selection, return K=20 | 50 active | 83.9 us | 169,096 | 2,891 |
| Closest NodeID selection, return K=20 | 512 active | 1.129 ms | 2,014,481 | 40,238 |
| Closest NodeID selection, return K=20 | 10,001 active | 39.65 ms | 72,565,028 | 1,349,580 |
| Refresh target selection, max 2 | 50 active | 1.013 us | 1,120 | 23 |
| Refresh target selection, max 2 | 512 active | 1.021 us | 1,120 | 23 |
| Refresh target selection, max 2 | 10,001 active | 0.932 us | 1,120 | 23 |
| Offline-to-active in-memory churn cycle | 50 active | 4.329 us | 1,344 | 27 |
| Offline-to-active in-memory churn cycle | 512 active | 14.284 us | 4,320 | 27 |

The 10,001-peer closest-selection result is a clear optimization target: it scans/sorts the local active set and allocates heavily. No performance threshold was agreed, so this report records the baseline without changing the routing policy. A later optimization should preserve the same exact XOR results and be compared with this command and environment.

## Limitations

- A passing local reachable-view lookup is not proof of global name uniqueness or universal reachability.
- This does not test Sybil/eclipse resistance at internet scale; #65 remains separate logical simulation work.
- The Docker mesh is protocol-level, not a separate-process CLI or IKE/ESP mesh. #69 can use a DHT-only scale tier as agreed; real IPsec security remains a separate small two-node test.
- A previous race-enabled hidden-service integration run exposed an unrelated onion-cell race in `internal/onion/cell.go`. DHT and node race suites pass; that hidden-service race is outside #71 and remains separate work.
- The measured Go heap does not include bbolt file size, full process RSS, network namespaces, or strongSwan/XFRM memory.
