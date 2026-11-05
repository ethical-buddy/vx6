# Packet-I/O backend evaluation: kernel sockets + XFRM vs VPP vs AF_XDP (#54)

Scope: Linux CLI/daemon only. This is an architecture evaluation backed by the
#51 baseline ([`ipsec-baseline.md`](ipsec-baseline.md)), **not** a
recommendation to adopt anything.

## TL;DR

**Do not adopt VPP or AF_XDP for VX6 now.** No VX6 workload we have measured
is limited by packet I/O. The constraints from #57 (kernel XFRM is the ESP
dataplane, no custom ESP) and #54 itself (no VPP dependency for the portable
CLI) also rule out the only ways these backends could speed up encrypted
traffic. AF_XDP in particular **cannot coexist** with kernel XFRM on the same
flows. Kernel-side tuning (§5) comes first. VPP can be reconsidered later only
as an optional *dedicated gateway* product, with its own issue and its own
security review.

## 1. What each option actually is

| | Kernel sockets + XFRM (today) | VPP (FD.io) | AF_XDP |
|---|---|---|---|
| Who owns the NIC | Kernel | VPP (DPDK driver, or AF_XDP / af_packet "host-interface") | Kernel driver, but frames for the bound queue are redirected by an XDP program into a userspace UMEM ring |
| Who does ESP | Kernel XFRM (AES-NI/VAES via kernel crypto) | VPP's own IPsec (native or DPDK cryptodev), with its own IKEv2 plugin | **Nobody**. Frames reach userspace before the IP stack and XFRM. The application would have to implement ESP itself. |
| Who does TCP | Kernel | VPP host stack (separate TCP implementation; apps use VCL/LD_PRELOAD) | Nobody (raw frames) |
| Linux routing, nftables `inet vx6`, `meta ipsec` rules | Apply | Bypassed (VPP has its own FIB/ACLs) | Bypassed for redirected traffic |
| CPU model | Interrupt/NAPI, scales with load | Poll mode: worker cores pinned at **100 % even when idle** | Busy-poll or wakeup mode, dedicated queue/cores |
| Privileges | `CAP_NET_ADMIN` in `vx6-ipsecd` only | Root daemon, hugepages, IOMMU/VFIO, NIC unbound from the kernel (DPDK) | `CAP_NET_ADMIN` + `CAP_BPF`/`CAP_SYS_ADMIN`, an XDP program loaded on the NIC |
| Portability | Any Linux | x86_64/arm64 servers, supported NIC list | Needs driver support for native/zero-copy mode (e.g. ice, i40e, mlx5, ixgbe…). Generic (skb) mode works everywhere but is slower than plain sockets. |

## 2. Compatibility with VX6 requirements

| Requirement | Kernel + XFRM | VPP | AF_XDP |
|---|---|---|---|
| IKEv2 + ESP with the current trust model (pinned Ed25519, `/128` selectors, fail-closed trap) | yes (today) | Only by moving IKE/ESP into VPP: a third IKE implementation, VPP's `ikev2` plugin, with **no Ed25519 auth support known to us** (needs checking). It would replace strongSwan/native-controller work rather than complement it. | **No.** It conflicts with "kernel XFRM is the dataplane" (#57). It would require a userspace ESP, which #57 forbids. |
| nftables `inet vx6` enforcement and revocation | yes | No (must be re-implemented as VPP ACLs) | No for redirected queues |
| TCP inner stream (#46) | yes | Via the VPP host stack and VCL: a different TCP, and Go `net` does not use it natively | No TCP at all |
| QUIC optional inner transport (#45) | yes (UDP sockets) | Via VCL/UDP; quic-go would need a custom `net.PacketConn` | quic-go over a custom PacketConn is possible, but ESP is still missing |
| UDP/WebRTC (#49) | yes | via VCL | possible for clear UDP only, which conflicts with the fail-closed rule |
| Current CLI model (single static binary, user process + small root service) | yes | No: a separate root dataplane daemon, hugepages, core pinning | Partly (an XDP loader in `vx6-ipsecd`), but useless without ESP |
| Android / other OS later | yes (VpnService/TUN path) | no | no |

## 3. Measured baseline (what would need to be beaten)

From [`ipsec-baseline.md`](ipsec-baseline.md) (lab host: 4 vCPU Xeon @ 2.1 GHz VM,
Linux 6.18, veth between network namespaces):

* With the IPsec **control plane** in the path (setup, `list-sas` checks), costs
  are tens of milliseconds per operation: daemon and fork/exec overhead.
  A faster packet path does not touch these.
* With **userspace ESP** (strongSwan libipsec, which the sandbox fallback had
  to use because its kernel lacks ESP/GCM), throughput collapses compared with
  the no-ESP baseline (see the throughput row). That is the realistic
  cost of moving ESP out of the kernel without a heavily optimized engine like
  VPP's. In other words, it shows what AF_XDP+custom-ESP would be up against.
* Kernel-XFRM numbers must come from a real IPv6 host
  (`sudo scripts/bench/ipsec-baseline.sh`). That run is pending, and decisions
  about kernel tuning wait for it.

Typical public figures for kernel XFRM with AES-GCM-128 and AES-NI are several
Gbit/s per core, and multi-core scaling needs several SAs or `pcrypt`. That is
far above any current VX6 service workload (interactive services, file share,
chat). VPP reaches tens of Gbit/s, but only with dedicated cores and NIC
ownership.

## 4. When VPP could make sense

Only as a **separate deployment profile**, such as "VX6 gateway appliance"
fronting many peers at ≥ 10 Gbit/s, and only if all of these hold:

1. A stated workload that kernel XFRM measurably cannot serve on reasonable
   hardware after §5 tuning (with numbers, ≥ 2× material benefit).
2. The trust model (pinned Ed25519 identities, per-peer `/128` selectors,
   revocation, fail-closed) is re-implemented and re-reviewed on VPP.
3. Operators accept dedicated cores at 100 % poll, hugepages, VFIO, NIC
   ownership, and the energy cost of always-on polling.
4. It never becomes a dependency of the portable CLI or Android builds.

## 5. What to do instead (kernel-side, in priority order)

1. Get real XFRM numbers on IPv6 hardware with the #51 harness, including
   `-P 4/8` parallel streams to see single-SA single-core limits.
2. Fix control-plane overheads first. They dominate latency today: VICI
   instead of `swanctl` exec (#57 Phase 1) and event-driven SA state.
3. MTU/MSS: ESP tunnel mode over IPv6 adds ≈ 74–77 bytes per packet (outer IPv6
   40 + ESP 8 + IV 8 + pad/trailer 2–5 + ICV 16). Clamp TCP MSS on the VX6
   port or set the path MTU to avoid fragmentation.
4. ESP GSO/GRO (in mainline for years) and NIC **crypto/packet offload**
   (`ip xfrm state ... offload [packet] dev <nic> dir out`, e.g. mlx5) where
   hardware supports it. Packet offload keeps the kernel policy model intact.
5. Multi-core: one SA is processed on one core per direction. If needed,
   use several CHILD_SAs per peer pair or `pcrypt`. Consider per-CPU SAs
   (RFC 9611) once the kernel and IKE implementations both support it.
6. eBPF/XDP for **filtering and accounting** is a separate question (#53).
   An XDP drop program in front of the kernel stack is compatible with XFRM.
   AF_XDP redirection is not.

## 6. Maintenance cost summary

| | Kernel + XFRM | VPP | AF_XDP |
|---|---|---|---|
| New code VX6 owns | none (dataplane) | VPP config/agent, trust-model port, ACLs | ESP engine (forbidden), ARP/ND, routing, IP |
| Failure recovery | kernel policies persist; trap = fail closed | VPP restart = dataplane down for all peers | program/queue teardown; risk of clear leaks if mis-steered |
| Upgrade risk | distro kernel | VPP releases every ~4 months, API churn | driver/kernel feature matrix |
| Security review surface | small | large | large |

**Decision proposed for #54:** close as "evaluated, not adopted". Keep this
document. Open a follow-up only if a workload meets §4.
