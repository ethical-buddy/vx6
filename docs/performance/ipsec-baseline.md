# IKEv2/IPsec baseline benchmark (#51)

This issue only **measures**. It changes no algorithms and chooses no new
transport. It feeds the own-controller decision in
[`docs/research/ipsec-native-controller.md`](../research/ipsec-native-controller.md) (#57)
and the packet-I/O evaluation in [`packet-io-evaluation.md`](packet-io-evaluation.md) (#54).

## How to reproduce

```sh
# Target configuration: IPv6-only, kernel XFRM, no NAT-T (needs root,
# iproute2, strongSwan charon/swanctl/pki, iperf3, tcpdump, python3, go)
sudo REPEAT=5 DURATION=10 scripts/bench/ipsec-baseline.sh

# Fallback used in this report: kernel without IPv6 or XFRM ESP/GCM
sudo FAMILY=4 DATAPLANE=libipsec REPEAT=5 scripts/bench/ipsec-baseline.sh

# Negative control reproducing the selectors from commit 4e26ace
sudo SELECTORS=pinned scripts/bench/ipsec-baseline.sh

# Go micro-benchmarks
go test ./internal/ipsec     -run '^$' -bench IKE -benchmem -count 5
go test ./internal/transport -run '^$' -bench .   -benchmem -count 5 -benchtime 2s
```

What the harness does (`scripts/bench/ipsec-netns-lab.sh`, `ipsec-baseline.sh`,
`rrbench/`, `summarize.py`):

* Two network namespaces joined by a veth pair, MTU 1500, one `charon` per
  namespace with its own config, VICI socket and run directory. The host's
  routing is never touched.
* The same IKE/ESP proposal VX6 generates (`aes128gcm16-prfsha256-curve25519`,
  ESP `aes128gcm16`), Ed25519 raw public keys pinned on both sides
  (`auth = pubkey`, `id = %any`), `start_action = close_action = trap`,
  `mobike = no`, and per-peer host selectors on the VX6 port.
* Baseline traffic uses ports 5201/5202. They are outside the selectors, so
  they travel the identical veth path without ESP. Tunnel traffic uses
  port 4242, which the CHILD_SAs cover.
* Every metric is repeated (`REPEAT`, default 5; setup ×20, `list-sas` ×200).
  Raw outputs are kept: iperf3 JSON, rrbench JSON, timings, pcap summary,
  environment.

## Results: 2026-11-03, sandbox run (**not** the target configuration)

> **Read this first.** The only machine available for this run was a
> Firecracker VM whose kernel has **no IPv6** and **no XFRM ESP/AES-GCM**
> (`/proc/sys/net/ipv6` is absent; `ip xfrm state add ... rfc4106(gcm(aes))`
> → "Requested AEAD algorithm not found"). The run therefore used
> `FAMILY=4 DATAPLANE=libipsec`: strongSwan's **userspace** ESP over a TUN
> device, which forces UDP encapsulation (port 4500). Consequences:
>
> * **Control-plane numbers** (IKE setup, rekey, `swanctl` cost, daemon RSS)
>   are representative. They exercise the same charon, proposals and Ed25519
>   auth VX6 uses. The only differences are IPv4 instead of IPv6, and SAs
>   installed into libipsec instead of the kernel.
> * **Dataplane numbers** (throughput, request latency, CPU) measure
>   libipsec, **not** kernel XFRM. Do not quote them as VX6 ESP performance.
>   They do show what *userspace* ESP costs, which is relevant to #54.
> * The IPv6 + XFRM run on real hardware is still **pending**. It is one command (above).

Environment: Intel Xeon @ 2.10 GHz, 4 vCPU, 16 GB, Linux 6.18.44,
strongSwan 5.9.13 (Ubuntu 24.04 packages), iperf 3.16, Go 1.24.7.
Raw data: [`results/2026-11-03-sandbox-libipsec/`](results/2026-11-03-sandbox-libipsec/).

### Control plane (representative)

| Metric | median | p95 | min | max | n |
|---|---|---|---|---|---|
| IKE_SA + both CHILD_SAs established (`swanctl --initiate` ×2, LAN) | **54 ms** | 61 | 48 | 66 | 20 |
| CHILD_SA rekey (new SA installed, make-before-break) | **47 ms** | 54 | 44 | 54 | 5 |
| IKE_SA rekey (new IKE_SA established) | **50 ms** | 60 | 46 | 60 | 5 |
| Tunnel teardown → re-establish → first request answered | **67 ms** | 71 | 59 | 71 | 5 |
| `swanctl --list-sas --ike <conn>` (what `vx6-ipsecd` runs per `EnsurePeer`/`AcceptPeer`) | **23.7 ms** | 29.2 | 19.3 | 50.7 | 200 |
| charon RSS idle, no SA | 17.8 MB | | | | |
| charon RSS with 1 IKE_SA + 2 CHILD_SAs | 18.6 MB | | | | |
| charon RSS after load tests | 20.4 MB | | | | |

The rekey and setup times include the polling granularity of `swanctl`
itself (~20 ms per poll), so they are upper bounds.

The `list-sas` row matters most for VX6 today. `AcceptPeer` (node.go) runs it
for **every accepted connection**, through IPC and then fork+exec of `swanctl`.
At ~24 ms per call, one node can accept at most ≈40 connections/s per serial
accept loop before IPsec checking becomes the bottleneck. `EnsurePeer` has a 3 s
cache; `AcceptPeer` does not. Fix candidates (#57 Phase 1): a persistent VICI
session (govici) plus event-driven SA state, which brings this to
microseconds without changing the fail-closed semantics.

### Dataplane (libipsec userspace ESP; **not** XFRM)

| Metric | no ESP (same veth) | ESP via libipsec | factor |
|---|---|---|---|
| TCP throughput, 1 stream, iperf3 (Mbit/s, median of 5) | 14 477 | 673 | 21× slower |
| charon CPU during the ESP iperf (% of one core) | — | sender 136 %, receiver 149 % | |
| 64 B request/response, 1 conn: p50 / p95 / p99 (µs) | 24 / 95 / 139 | 297 / 395 / 586 | |
| 64 B req/resp, 64 concurrent conns: p50 / p99 (µs), req/s | 248 / 2 687, 177 k/s | 1 891 / 5 457, 31 k/s | |
| new TCP connection per request, 16 workers: p50 / p99 (µs), req/s | 928 / 8 045, 12.6 k/s | 3 537 / 9 431, 4.1 k/s | |
| 64 KiB request/response, 1 conn: p50 / p99 (µs) | 80 / 417 | 2 139 / 4 428 | |
| errors across all rr runs | 0 | 0 | |

Per-packet overhead from the capture (100-byte UDP payload): clear frame
142 B; libipsec ESP-in-UDP frame 206 B (**+64 B** over IPv4 with UDP encap).
For the target (IPv6, tunnel mode, no NAT-T) the overhead is
40 (outer IPv6) + 8 (ESP) + 8 (GCM IV) + 2–5 (pad/trailer) + 16 (ICV) =
**74–77 B per packet**. TCP MSS on the VX6 port should account for it.

### Go cost of the IKE crypto (for #57)

`go test ./internal/ipsec -bench IKE`, median of 5, same host:

| Operation | time |
|---|---|
| X25519 keygen + shared secret | 97 µs |
| Ed25519 sign (AUTH payload, 600 B) | 25.7 µs |
| Ed25519 verify | 54.4 µs |
| SKEYSEED + SK_* + one CHILD keymat (prf+ HMAC-SHA-256) | 6.2 µs |
| AES-GCM-128 seal of one 400 B IKE message | 0.30 µs |
| **Everything one side computes for IKE_SA_INIT + IKE_AUTH + first CHILD_SA** | **0.19 ms** |

So of the ~54 ms strongSwan setup on a sub-millisecond-RTT link, well under
1 ms is cryptography. The rest is daemon scheduling, the `swanctl`/VICI
round trips and XFRM/libipsec installation. A native controller could cut setup
time, but that is a *hypothesis* to measure (#57 §7), not a result.

### Inner transport: TCP vs optional QUIC (for #45/#46)

`go test ./internal/transport -bench .` on loopback, **no ESP**, median of 5.
This isolates the inner-transport cost VX6 adds on top of ESP:

| Benchmark | TCP | QUIC (quic-go 0.59, current `transport/quic.go`) | QUIC vs TCP |
|---|---|---|---|
| 64 B request/response on an open stream | 6.0 µs | 68.9 µs | 11× slower |
| 16 KiB request/response | 7.5 µs | 254 µs | 34× slower |
| bulk send, 64 KiB writes | 1 880 MB/s | 447 MB/s | 4× slower |
| connect + first byte round trip | 147 µs, 1.7 KB alloc | 3.5 ms, 290 KB alloc | 24× slower |

QUIC re-does a TLS 1.3 handshake (self-signed, `InsecureSkipVerify`) on every
connection and runs its own congestion control and encryption in userspace.
Inside mandatory ESP, that encryption is redundant. Nothing measured here shows
a reason to make QUIC a default. Keep it opt-in (#45). Re-evaluate only if a
workload needs many independent streams per peer with head-of-line isolation,
with a per-peer connection pool and the comparison made over ESP.

## Finding: the current CHILD_SA selectors do not match ordinary dials

Commit `4e26ace` (2026-11-02, "Add staged peer liveness checks") changed the
selectors from host `/128` to

```
local_ts  = <self>/128[tcp/4242], <self>/128[udp/4242]
remote_ts = <peer>/128[tcp/4242], <peer>/128[udp/4242]
```

A port in an IPsec traffic selector constrains that end's port, so this pair
only covers packets with **source and destination port both 4242**. A dial
comes from an ephemeral port and matches nothing.

Negative control (`SELECTORS=pinned`, raw data in
`results/.../pinned-selectors-negative/`):

| Client | Result | ESP counters |
|---|---|---|
| ephemeral source port → peer:4242 (normal `net.Dialer`) | **20 / 20 requests failed** (timeouts) | unchanged |
| source port bound to 4242 → peer:4242 | 20 / 20 succeeded, p50 251 µs | in 23 / out 25 packets |

Under kernel XFRM, the unmatched SYN leaves without IPsec and the `inet vx6`
nftables output rule (`tcp dport 4242 drop` unless `rt ipsec exists`) drops
it. VX6 still fails *closed* (no cleartext leak), but peers cannot connect.
The Oct 29 e2e capture run predates this commit. **Re-run
`tests/ipsec-e2e/run.sh` on an IPv6 Docker host to confirm on XFRM.**

Fix in this branch (`internal/ipsec/manager.go`): two CHILD_SAs per peer,
each pinning only the listener side's port:

```
<conn>-out: local <self>/128[tcp],[udp]          === remote <peer>/128[tcp/Ppeer],[udp/Ppeer]
<conn>-in:  local <self>/128[tcp/Plocal],[udp/Plocal] === remote <peer>/128[tcp],[udp]
```

`EnsurePeer` initiates and requires `-out`. `AcceptPeer` requires `-in`, and
`childSAInstalled` now matches the exact child label. The liveness probe port
stays outside the SA. With these selectors the lab carried the full iperf3 and
rrbench load inside ESP. The capture held ≈160 k ESP packets and zero clear
port-4242 packets.

## Other observations to follow up (#59)

* The selectors cover only TCP and UDP. When a datagram that arrived through
  ESP hits a closed UDP port, the ICMP "port unreachable" reply went back
  **in clear** in the lab, quoting the start of the decrypted datagram. Verify
  on XFRM, and consider adding ICMPv6 for the peer pair to the SA, or
  rate-limiting/dropping ICMP errors for VX6 ports in `inet vx6`.
* `AcceptPeer` has no SA-state cache, and `EnsurePeer` caches for 3 s. Either
  way, a revoked or deleted SA is seen within one check. Keep that property when
  replacing the polling with events.

## Pending for the real-host run

- [ ] IPv6 + kernel XFRM run (`sudo scripts/bench/ipsec-baseline.sh`) on two
      hosts or namespaces of a normal distro kernel; record NIC, AES-NI/VAES
- [ ] `tests/ipsec-e2e/run.sh` with the selector fix
- [ ] Parallel streams (`iperf3 -P 4/8`) to see the per-SA single-core limit
- [ ] Packet loss/recovery with `tc qdisc add dev va root netem loss 1%`
