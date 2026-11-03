# Research plan: a VX6-owned Linux IKEv2 controller (#57)

Status: **research plan, nothing approved for production.** Linux CLI only.
Inputs: the #51 baseline in [`docs/performance/ipsec-baseline.md`](../performance/ipsec-baseline.md).

## 1. Why we are considering this

Today a VX6 Linux node needs, besides the `vx6` binary:

| Item | Measured on Ubuntu 24.04, strongSwan 5.9.13 |
|---|---|
| Distro packages | `strongswan-charon` (or `charon-systemd`), `strongswan-swanctl`, `strongswan-libcharon`, `libstrongswan`, `libstrongswan-standard-plugins` ≈ **3.6 MB installed**, plus `libgcrypt`, `libgmp`, `libcap`, `libsystemd` and their own dependencies |
| Plugin directory | `/usr/lib/ipsec` = **4.2 MB** |
| A second long-running daemon | `charon`: **~17.7 MB RSS idle, ~18.5 MB with one peer** (see #51 numbers) |
| Provisioning work | VICI socket permissions, `strongswan.conf`, AppArmor profile, systemd ordering between `charon` and `vx6-ipsecd`, version skew across distros (Ed25519 needs ≥ 5.5.2; Curve25519 plugin may be split out) |
| Per-check cost | every `EnsurePeer`/`AcceptPeer` forks `swanctl --list-sas`: **~24 ms median per call** |

For comparison, `vx6` is 12.4 MB (8.4 MB stripped) and `vx6-ipsecd` is 6.6 MB,
both static Go binaries with no shared-library dependencies.

The goal is one signed package with no third-party IKE daemon. The goal is
**not** speed: the ESP dataplane stays in the kernel either way, so bulk
throughput will not change. Section 7 lists what can actually get better.

## 2. Hard constraints (from #57; restated so reviewers can check them)

1. Linux only, prototype only.
2. Kernel XFRM stays the ESP dataplane. No userspace ESP, no custom cipher.
3. Only standard IKEv2 (RFC 7296) and IETF algorithms from established
   libraries: Go `crypto/ecdh` (X25519), `crypto/ed25519`, `crypto/aes` +
   `crypto/cipher` (GCM), `crypto/hmac` + `crypto/sha256`. No new KDFs,
   signatures, packet formats or key exchange.
4. IPv6-only peer selectors, fail closed: no service socket opens unless the
   expected authenticated CHILD_SA is installed.
5. Mutual authentication against the verified VX6 Ed25519 endpoint record.
   An address or name alone is never trusted.
6. Privileged XFRM/nftables work stays in `vx6-ipsecd` behind the existing
   fixed-request Unix-socket IPC. The user `vx6` process gains no new power.
7. No silent clear fallback. Revocation, restart, rekey, partial failure and
   cleanup must be specified before code.
8. strongSwan stays as the reference implementation and interop target until
   the native controller passes interop and security tests and an independent
   review.

## 3. Options

| | Option | Removes strongSwan from install? | New security-critical code we own | Licence | Verdict |
|---|---|---|---|---|---|
| A | Keep charon, replace the `swanctl` exec with a VICI client ([govici](https://github.com/strongswan/govici), pure Go, MIT) | No (drops only `swanctl`) | none | OK | **Do now.** Removes fork/exec per check and a package. Needed anyway as a fallback. |
| B | Bundle a static monolithic charon (`--enable-monolithic --enable-static --disable-shared`) | Removes distro dependency, still a separate C daemon | build/packaging only | strongSwan is **GPLv2**. Shipping it as a separate program next to Apache-2.0/commercial VX6 is aggregation; linking it into our binary (cgo/libcharon) would not be. Needs legal review. | Fallback if C fails. |
| C | Native Go controller in `vx6-ipsecd` using an existing Go IKEv2 message codec (e.g. [free5gc/ike](https://github.com/free5gc/ike), Apache-2.0, written for 5G N3IWF/TNGF) + kernel XFRM over netlink | **Yes** | state machine, policy, XFRM glue | Apache-2.0 compatible | **Spike first.** Low popularity and 5G-oriented. Audit before we depend on it. |
| D | Native Go controller with our own minimal IKEv2 codec (wire format from RFC 7296 only, crypto from Go stdlib) | **Yes** | codec + state machine + XFRM glue | ours | **Main candidate if C's codec fails audit.** VX6 needs a tiny profile (§4), much smaller than a general IKE daemon. |
| E | Another daemon (libreswan, OpenIKED) | No | none | GPL / ISC | Same packaging problem. Rejected. |
| F | Replace IPsec with something else (WireGuard, QUIC/TLS) | — | — | — | Out of scope. The architecture decision is mandatory IKEv2/ESP. |

"Own controller" here means C or D: our own **control plane** (IKE messages,
state machine, XFRM programming) built from standard crypto. It never means
our own cryptography.

## 4. The IKEv2 profile VX6 actually needs

VX6 talks host-to-host between two known Ed25519 keys. No NAT-T, no EAP, no
certificates, no virtual IPs. That makes the profile close to
[RFC 7815 (Minimal IKEv2 Initiator)](https://www.rfc-editor.org/rfc/rfc7815),
but we also need a responder, rekeying and liveness.

| Area | Needed | RFC | Notes |
|---|---|---|---|
| IKE_SA_INIT | yes | 7296 §1.2 | One proposal only: `ENCR_AES_GCM_16(128)` / `PRF_HMAC_SHA2_256` / group 31 (Curve25519). Reject anything else, no negotiation. That removes downgrade by construction. |
| Curve25519 KE | yes | 8031 | `crypto/ecdh.X25519()`. Reject an all-zero shared secret. |
| Encrypted payload with AES-GCM | yes | 5282 | `cipher.NewGCM`, 8-byte explicit IV, 4-byte salt from keymat. |
| IKE_AUTH, Digital Signature auth with Ed25519 | yes | 7427, 8420 | AUTH method 14 with the Ed25519 AlgorithmIdentifier. Sign/verify with `crypto/ed25519`. |
| Identity | yes | 7296 §3.5 | Interop mode: ID_KEY_ID = SHA-1 of the SubjectPublicKeyInfo. That is what strongSwan sends for `pubkeys=` / `id=%any` (seen in the lab log). Native mode: same ID; the peer is still matched by **pinned key**, never by ID alone. |
| Raw public keys | maybe | 7670 | Not needed when both sides pin keys out of band, as we do. |
| CREATE_CHILD_SA: CHILD_SA create + rekey | yes | 7296 §1.3 | Two children per peer (see §5.1). PFS on rekey: yes, KE payload with X25519. |
| CREATE_CHILD_SA: IKE_SA rekey | yes | 7296 §2.18 | Including the simultaneous-rekey tie-break (§2.8.1). |
| INFORMATIONAL: DELETE, liveness (DPD) | yes | 7296 §1.4, §2.4 | Empty INFORMATIONAL as liveness, `dpd_action=restart` equivalent. |
| Retransmission, message-ID window = 1 | yes | 7296 §2.1–2.3 | Exponential backoff, bounded retries, then IKE_SA deleted and policy stays trapped (fail closed). |
| Cookies (DoS) | yes | 7296 §2.6 | Turn on above a half-open threshold. |
| Notifications | subset | 7296 §3.10 | INVALID_KE_PAYLOAD, NO_PROPOSAL_CHOSEN, AUTHENTICATION_FAILED, TS_UNACCEPTABLE, INVALID_SYNTAX, COOKIE, REKEY_SA, TEMPORARY_FAILURE. Ignore unknown status notifies; reject unknown error notifies. |
| Fragmentation | no | 7383 | IKE_AUTH carries no certificates and stays well under 1280 bytes. |
| NAT-T, MOBIKE, EAP, config payload, PPK, IKE redirect | no | | Explicitly unsupported. Reject. |

Rough size estimate (Go, excluding tests): codec ~1.5–2.5k LOC, state machine
and timers ~2–3k, XFRM/netlink glue ~0.8–1.2k (plus
[vishvananda/netlink](https://github.com/vishvananda/netlink), Apache-2.0, or
raw `x/sys/unix` netlink), policy and IPC integration ~0.5k. Tests and fuzzers
will be larger than the code itself.

## 5. Kernel XFRM operations the controller must own

| Operation | Netlink message | Used for |
|---|---|---|
| Install trap policies at peer prepare | `XFRM_MSG_NEWPOLICY` with a template and no SA | The kernel holds matching packets and sends ACQUIRE. While no SA exists, traffic is **dropped, never sent in clear**. This keeps today's `start_action=trap` fail-closed behavior even when the daemon is down. |
| React to traffic | subscribe to `XFRMNLGRP_ACQUIRE` | Start IKE on demand. |
| Allocate inbound SPI | `XFRM_MSG_ALLOCSPI` | Responder/initiator inbound SA. |
| Install / remove SAs | `XFRM_MSG_NEWSA`, `XFRM_MSG_DELSA` | `rfc4106(gcm(aes))`, 128-bit key + 4-byte salt, ICV 16, replay window ≥ 32 (or ESN), tunnel mode, soft/hard byte and time lifetimes. |
| Rekey trigger | `XFRMNLGRP_EXPIRE` (soft) | CHILD_SA rekey before the hard limit. |
| Counters | `XFRM_MSG_GETSA` | Replaces `swanctl --list-sas` and feeds `vx6 status`. |
| IKE socket bypass | `IPV6_XFRM_POLICY` setsockopt with ALLOW on the UDP/500 socket | IKE itself must never be caught by our policies. |
| Ownership marker | XFRM `mark` (or a reserved reqid range) on every VX6 object | Startup cleanup removes **only** VX6 objects and leaves other IPsec users on the host alone. |

### 5.1 Selector correction found during #51 (applies to both controllers)

Commit `4e26ace` (2026-11-02) changed the CHILD_SA to
`local[tcp/P,udp/P] === remote[tcp/P,udp/P]`. An IPsec selector port
constrains **both** ends, so this only matches packets whose source and
destination ports are both `P`. A normal dial comes from an ephemeral port, so
it matched no policy. With XFRM the packet then leaves without IPsec, and the
`inet vx6` nftables output rule drops it, so the connection fails closed. In
the lab, the SYN reached the libipsec TUN device and was discarded (0 ESP
packets). With the source port forced to `P`, the same tunnel carried the
traffic.

This branch therefore generates two children per peer:

* `<conn>-out`: `local[tcp,udp] === peer[tcp/Ppeer, udp/Ppeer]` — this node dials the peer
* `<conn>-in`: `local[tcp/Plocal, udp/Plocal] === peer[tcp,udp]` — the peer dials this node

`EnsurePeer` requires `-out` INSTALLED before a dial, and `AcceptPeer` requires
`-in`. The liveness probe port stays outside the SA, as `4e26ace` intended.
The native controller must keep the same model, and the e2e capture suite
(`tests/ipsec-e2e/run.sh`) must be re-run on a real IPv6/XFRM host to confirm it.

## 6. Security design points to settle before code

* **Fail-closed invariants** (each one gets a test): no SA ⇒ trap policy
  drops; IKE failure ⇒ no SA, dial error; daemon crash ⇒ policies persist
  and drop; daemon restart ⇒ flush VX6-marked states, reinstall trap policies,
  then renegotiate on ACQUIRE; revocation ⇒ DELETE sent, SAs removed,
  policies replaced by block policies, nftables IKE/ESP drop as today.
* **Downgrade:** exactly one proposal. There is nothing to negotiate.
* **Replay/reflection:** message-ID window 1; responder caches the last
  response for retransmits; nonces of 32 bytes from `crypto/rand`; constant-time
  comparison of AUTH and ICV values (`crypto/subtle`).
* **DoS:** half-open SA limit per source and in total, cookies above the
  threshold, bounded message size (e.g. 4 KiB). A peer is not authenticated
  until IKE_AUTH completes, so only the work needed for one response is done
  before that.
* **Key handling:** keys live only in `vx6-ipsecd`. The Go GC cannot guarantee
  zeroization, so document this. Never log key material, and keep heap dumps off.
* **Privilege:** run the controller in `vx6-ipsecd` with `CAP_NET_ADMIN` and
  `CAP_NET_BIND_SERVICE` only (systemd `AmbientCapabilities=`, `User=` a
  dedicated account), instead of full root.
* **Parsing:** every payload parser gets a native Go fuzz target, plus
  differential fuzzing against strongSwan's parser through interop captures.
* **Independent review** before any production claim (#57 item 6).

## 7. What a native controller can and cannot improve

Measured strongSwan costs (from #51) and what a native controller might change:

| Metric | strongSwan baseline | Native expectation | Why |
|---|---|---|---|
| ESP throughput / per-packet latency | kernel-bound | **same** | Same XFRM dataplane. Do not claim gains. |
| IKE_SA + CHILD_SA setup (LAN) | 54 ms median (lab host, two children) | lower bound ≈ 2 RTT + crypto. Go crypto for one side costs **≈ 0.2 ms** (bench below) | Most of today's time is daemon/IPC/exec overhead, not crypto. Must be measured, not assumed. |
| SA state check per dial/accept | ~24 ms (`swanctl` fork+exec+VICI) | µs (in-process map lookup + optional `GETSA`) | Biggest practical win. Option A already gets most of it. |
| Extra daemon RSS | 17.8–20.4 MB | a few MB inside `vx6-ipsecd` | One process fewer. |
| Install footprint | ≈ 3.6 MB of packages plus shared libs | +~1–2 MB in `vx6-ipsecd` | No third-party runtime dependency. |
| Operational complexity | two daemons, VICI permissions | one daemon | Fewer moving parts. |
| Security maturity | 20 years of review | **new code, unreviewed** | The main cost. It is why the gates in §9 exist. |

Go crypto cost per IKE primitive on the lab host: X25519 97 µs, Ed25519 sign 26 µs / verify 54 µs, key schedule 6 µs, AES-GCM per message 0.3 µs; one full side ≈ 0.19 ms
(`go test ./internal/ipsec -bench IKE -benchmem`; see the baseline doc for numbers).

## 8. Phased plan

| Phase | Deliverable | Exit criteria |
|---|---|---|
| 0 (now, this branch) | #51 harness + numbers; selector fix (§5.1); research plan | Maintainers accept the numbers and the plan. Real-host IPv6/XFRM run of `scripts/bench/ipsec-baseline.sh` and `tests/ipsec-e2e/run.sh` passes. |
| 1 (1–2 wk) | Option A: replace `swanctl` exec with govici in `vx6-ipsecd`; event-driven SA state (VICI `child-updown`, `ike-updown`) instead of polling | Same unit/e2e tests pass. `list-sas` cost disappears from the dial/accept path. |
| 2 (2 wk) | Spike: audit free5gc/ike's codec against §4; build a throw-away IKE_SA_INIT + IKE_AUTH initiator that strongSwan accepts | Decision C vs D written down with reasons. |
| 3 (4–6 wk) | `internal/ike` (codec + state machine) and `internal/xfrm` in `vx6-ipsecd` behind `ipsec.controller = strongswan \| native` (default strongswan) | Interop with strongSwan as initiator **and** responder. All of §9's tests pass. |
| 4 (2–3 wk) | Hardening: fuzzing, #59 adversarial suite against both controllers, crash/restart/rekey soak | 72 h soak with forced rekeys and restarts, zero clear packets on capture. |
| 5 | Independent IKE/IPsec security review | Review findings fixed. Only after this can `native` become the default and the strongSwan dependency become optional. |

## 9. Test matrix (both controllers)

* Interop: native↔strongSwan both roles, native↔native.
* Negative: wrong key, unknown key, replayed IKE_SA_INIT/IKE_AUTH, truncated
  and oversized payloads, wrong proposal (downgrade), invalid KE (all-zero
  X25519 point), bad AUTH signature, TS outside the expected `/128`, expired
  endpoint record, revoked node ID.
* Lifecycle: timeout, simultaneous initiation, simultaneous rekey (IKE and
  CHILD), peer restart, local daemon restart, `kill -9` while SAs are up,
  revocation during an active stream.
* Dataplane: XFRM state/policy dump, ESP counters, `tcpdump` shows only
  UDP/500 and ESP between peers, no clear TCP/UDP on the VX6 port, and a route-leak probe.
* Performance: re-run `scripts/bench/ipsec-baseline.sh` with
  `CONTROLLER=native` and compare every row of the baseline table.

## 10. Open questions for maintainers

1. Is GPLv2 aggregation (Option B) acceptable to the commercial licence
   holders as a fallback, or must the package be strongSwan-free?
2. May `vx6-ipsecd` drop from root to `CAP_NET_ADMIN`+`CAP_NET_BIND_SERVICE` as
   part of this work, or is that a separate issue?
3. Should native↔native mode later use ID_KEY_ID = VX6 node ID instead of the
   SHA-1 keyid (interop needs the latter)?
4. Who is the independent reviewer, and what budget/timeline applies?
