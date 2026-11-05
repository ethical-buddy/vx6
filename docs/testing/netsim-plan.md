# Network simulation plan (#69)

Status: **plan for maintainer approval.** Per #69, whoever picks this up
presents a threat model and requirements, gets it approved in discussion, and
holds for the next release. This document is that proposal. Tooling that
implements it lives in [`tests/netsim/`](../../tests/netsim/).

## 1. Goal and non-goals

Replicate an Internet-like environment on one machine — many ASes with real
IPv6 prefixes, BGP routing, and thousands of VX6 nodes — to observe **DHT
behaviour at scale**: how routing tables converge, how many refresh rounds the
network needs to reach a steady (idle) state, how bootstrap flows as nodes
join one-by-one then in bursts, and how lookups behave under churn, partitions,
ASN/prefix concentration and eclipse attempts. This directly serves #65 (scale,
churn, eclipse) and complements #71 (bounded routing maintenance).

**Non-goals, stated plainly** (the user and maintainer agree on these):

- **Physical latency is not modelled.** All nodes are on one host, so RTTs are
  tens of microseconds, not tens of milliseconds. The DHT converges in *logical
  rounds*, independent of wire latency, so this is fine for DHT behaviour. Real
  inter-region latency and NIC effects are a **later** step, done between two
  real nodes only.
- **This is not a security proof of ESP/IKE.** The scale tier replaces the
  IPsec tunnel with a pass-through that still checks signed endpoint records
  (same as `internal/integration`). A separate, smaller `ipsec` tier runs the
  real `vx6` + `vx6-ipsecd` + strongSwan for MITM and auth scenarios.
- **Not a claim of a headline success rate.** Per #65, results are reported per
  network size and per condition, never combined into one percentage.

## 2. Threat model

The simulation exists to test VX6's own trust assumptions, so the adversary is
modelled explicitly.

| Capability | Modelled how | What it must NOT be able to do |
|---|---|---|
| Malicious peers returning poisoned referrals | Attacker-controlled nodes in the `attacker` AS that answer `FIND_NODE`/`FIND_VALUE` with bogus or self-serving contacts | Cause a verified signed record to be replaced by an unsigned/forged one; be counted as multi-source confirmation (VX6 requires ≥2 trusted sources across ≥2 ASNs) |
| Eclipse: surround a victim's keyspace neighbourhood | Spawn many attacker IDs close (XOR) to a target; vary attacker share 1–40% and placement (near target vs near source) | Fully isolate a victim while the diversity policy (≤2 per /48, ≤4 per ASN) has honest alternatives; report where success *does* collapse |
| Sybil via address/ASN concentration | Many attacker nodes behind one /48 or ASN | Exceed the per-/48 and per-ASN routing caps |
| BGP prefix hijack / on-path MITM | Attacker AS announces a more-specific /41 of a victim /40; traffic diverts by longest-prefix match | On the `ipsec` tier: forge IKE auth, downgrade, or get an unsigned binary/ record accepted. MITM may only delay/deny, never impersonate |
| Churn and partition as a cover for attacks | Kill/restart waves, cut inter-AS links | Have a timeout reported as a confirmed "node does not exist" (#65 hard rule) |
| Bootstrap-node abuse | Dead, slow, or hostile bootstrap peers | Make a newcomer depend on a single bootstrap, or accept an unsigned bootstrap record |

Trust anchors that must hold throughout: node identity is the Ed25519 key;
records are accepted only if signed and the NodeID derives from the key;
address/ASN are hints, never authority; a not-found is distinguished from
unreachable and from untrusted.

## 3. What is measured (per #65)

Collected from every node's admin API each round, written to `results/`:

- routing table: active peers, min/max/avg, per-/48 and per-ASN distribution
- convergence: how many refresh rounds until active-peer counts stop changing
  (the "DHT idle" condition the user asked about)
- lookups (random source→target): outcome split (found-verified /
  not-found-reachable / incomplete / conflict), p50/p95/p99 latency in *rounds*
  and ms, queries per lookup
- bootstrap: time/round for wave-N newcomers to reach a usable table
- churn recovery: rounds to re-converge after a kill wave
- cost: per-node RSS, host CPU, total memory, table bytes
- failure accounting: false-not-found rate, inconclusive rate (must be
  distinguished, never merged)

Seeds, params and commands are recorded so every run is reproducible.

## 4. Scenario list

1. **Cold bootstrap**: 1 node, then node B joins via A, then C via {A,B}; verify
   the single-bootstrap path and that records are signed.
2. **Wave growth**: 1,1,1,3,6,12,… doubling to N; snapshot convergence each wave.
3. **Idle convergence**: after the last join, snapshot every 30 s until active
   counts stabilise; report the round count.
4. **Flash join**: a large wave at once; measure table churn and lookup dip.
5. **Graceful churn**: random 10–30% leave then rejoin with same identity.
6. **Abrupt failure**: SIGKILL 10–30%; measure false-not-found and recovery.
7. **Partition/heal**: cut inter-AS links, run lookups, restore, re-measure.
8. **ASN/prefix concentration**: oversized org / residential ISP; check caps.
9. **Malicious referrals**: attacker share 1/5/10/20/40%, near-target and
   near-source; find where lookup success collapses.
10. **Eclipse**: cluster attacker IDs around one victim key.
11. **Conflicting signed name records**: two valid records, same name; verify
    conflict is reported, not silently resolved.
12. **BGP hijack + MITM** (`ipsec` tier): attacker announces victim /41, sits
    on-path; confirm IKE auth fails closed and no cleartext/forgery.
13. **Bootstrap abuse**: dead/slow/hostile bootstrap peers.

## 5. Architecture

One host, Linux network namespaces (see `tests/netsim/README.md`):

- one namespace per AS as a router, FRR (`bgpd`+`zebra`) speaking eBGP, each
  originating a real IPv6 /40 from `2001:db8::/32`;
- veth "cables" for AS peering (tier-1 mesh, ISP transit, org multihoming);
- bridged /64 LANs, named office/residential, nodes attached by veth;
- one `simnode` per node (scale tier) or real `vx6`+`vx6-ipsecd`+charon (ipsec
  tier); nodes join in waves, each seeded with a few signed bootstrap records
  from already-joined peers.

Everything is namespaced; the host's own routing is never touched. The whole
fabric tears down by deleting namespaces (or rebooting).

## 6. Host sizing

Memory is the limit. A `simnode` is a full Go node process. Measured RSS in the
sandbox lab was ~16–20 MB per node; budget **~25 MB** with routing tables
populated. CPU is near-idle once converged; refresh/lookup bursts are the load.

| Nodes | Node RAM (~25 MB) | +FRR/bridges/OS | Practical RAM | vCPU |
|---|---|---|---|---|
| 1,000 | ~25 GB | ~5 GB | **32 GB** | 8 |
| 5,000 | ~125 GB | ~15 GB | **160 GB** | 16–32 |
| 10,000 | ~250 GB | ~30 GB | **256–384 GB** | 32–64 |
| 50,000 | ~1.25 TB | — | needs the #65 event-simulator, not live processes |

Beyond ~10k live processes, one host hits the kernel/scheduler and RAM wall.
Per #65, the **10-million-ID** target is met by an event-driven Kademlia
simulator (logical IDs, no OS processes), with these live-process runs
validating its assumptions at 1k–10k. That simulator is separate work under #65.

### Mac mini (home, 24/7) — the primary host

A Mac mini runs Linux containers in a VM (Docker/Colima/OrbStack), so the
namespace fabric runs **inside one Linux VM**. It is limited by (a) the RAM you
give that VM and (b) that it is a VM, not bare metal.

| Mac mini RAM | VM RAM you can spare | Realistic live nodes |
|---|---|---|
| 16 GB | ~10 GB | ~300 |
| 24 GB | ~16 GB | ~550 |
| 32 GB | ~24 GB | ~900 |
| 64 GB | ~48 GB | ~1,800 |

The GPU does not help here (this is RAM- and scheduler-bound, not compute). A
Mac mini is ideal for **1k-class** scale, churn, eclipse and bootstrap runs,
which is what the DHT work needs now. For 5k–10k, use a cloud box for the run
and keep the Mac for development.

## 7. Cost estimate

**Mac mini: ~$0 marginal.** Already owned, already 24/7. This covers every
1k-node scenario. Recommended path for now.

**Cloud, only if you need 5k–10k live nodes.** Memory-optimized instances, one
big box per run, destroyed after. Indicative AWS on-demand, us-east-1 (verify
before relying — prices move):

| Need | Instance | ~RAM | On-demand ~$/hr | 6 h run | Spot ~$/hr |
|---|---|---|---|---|---|
| 5k nodes | r7g.8xlarge | 256 GB | ~$1.9 | ~$12 | ~$0.6 |
| 10k nodes | r7g.16xlarge | 512 GB | ~$3.9 | ~$23 | ~$1.2 |
| CPU-bound burst | c7g.16xlarge | 128 GB | ~$2.32 | ~$14 | ~$0.65 |

A full scenario matrix is a handful of 2–6 h runs: **well under ~$100/month**
on on-demand if used occasionally, or a few dollars per run on spot (fine, since
runs are reproducible and restartable). There is no steady-state hosting cost —
VX6 needs no servers; these instances exist only during a test run. Storage
(snapshots/logs) is a few GB per run on S3/EBS, cents.

Recommendation: **do all current DHT work on the Mac mini; reach for a spot
cloud box only for the occasional 10k run.**

## 8. Prerequisites and approval

- Host: Linux (or a Linux VM on the Mac) with IPv6 enabled, root/CAP_NET_ADMIN,
  FRR (`frr`/`bgpd`) for BGP scenarios, Go to build the binaries.
- `netsim doctor` checks all of this.
- Per #69, this plan is posted for maintainer approval before the matrix runs,
  and results are reported per size/condition with seeds and commands.

Open questions for the maintainer:
1. Target sizes for the first approved matrix (suggest 100 / 500 / 1,000 live).
2. Attacker-share points to report collapse at (suggest 1/5/10/20/40%).
3. Whether the 10M event-simulator is in scope here or stays in #65.
