# Benchmark tooling

| File | Purpose |
|---|---|
| `ipsec-netns-lab.sh` | Two-namespace strongSwan lab using VX6's proposals, pinned Ed25519 keys and selectors (`up`/`down`/`sw`/`pid`). `FAMILY=6\|4`, `DATAPLANE=xfrm\|libipsec`, `SELECTORS=split\|pinned`. |
| `ipsec-baseline.sh` | Runs the #51 measurements against the lab and writes raw data + `summary.md/json`. |
| `rrbench/` | Dependency-free TCP request/response load generator (latency percentiles, concurrency, connection churn). |
| `summarize.py` | Aggregates a results directory. |

See [docs/performance/ipsec-baseline.md](../../docs/performance/ipsec-baseline.md).
All scripts need root (network namespaces), and they never modify the host's
default namespace routing.
