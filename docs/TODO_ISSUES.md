# Tracked Work

GitHub issues are the source of truth for ownership, acceptance, and status.
This page is only a short index; do not add a parallel untracked task list.

## Current Priority Sequence

The initial Linux IPsec baseline suite is complete in [#50](https://github.com/ethical-buddy/vx6/issues/50). The full adversarial matrix is separated into [#59](https://github.com/ethical-buddy/vx6/issues/59) and must follow the features it tests.

1. [#51 Benchmark Linux IKEv2/IPsec](https://github.com/ethical-buddy/vx6/issues/51) and [#60 define peer-local identity/name trust](https://github.com/ethical-buddy/vx6/issues/60).
2. Coordinate [#63 signed metadata and lookup keys](https://github.com/ethical-buddy/vx6/issues/63) with [#62 local XOR-table maintenance](https://github.com/ethical-buddy/vx6/issues/62).
3. Implement [#64 bootstrap and liveness](https://github.com/ethical-buddy/vx6/issues/64), validated by [#65 churn/eclipse simulation](https://github.com/ethical-buddy/vx6/issues/65). [#66 ingress validation](https://github.com/ethical-buddy/vx6/issues/66) can proceed in parallel.
4. Implement [#43 service authorization](https://github.com/ethical-buddy/vx6/issues/43) and [#48 bounded service OPEN](https://github.com/ethical-buddy/vx6/issues/48); remove redundant custom session crypto only after coverage proves every path is protected ([#44](https://github.com/ethical-buddy/vx6/issues/44)).
5. Complete [#59 active-attack and tunnel lifecycle tests](https://github.com/ethical-buddy/vx6/issues/59). Assess [#57 VX6-owned Linux IKE controller research/prototype](https://github.com/ethical-buddy/vx6/issues/57) against benchmark and security gates; strongSwan/XFRM remains current meanwhile.
6. Implement [#67 signed rollback-resistant updates over untrusted mirrors](https://github.com/ethical-buddy/vx6/issues/67), then mature the [#58 public Go SDK](https://github.com/ethical-buddy/vx6/issues/58) and platform work such as [#52 Android](https://github.com/ethical-buddy/vx6/issues/52).

The target has no network committee or consensus authority. Each node validates and maintains its own bounded DHT view. This is a resilience model, not a claim that a node can prove global name uniqueness or eliminate Sybil/eclipse attacks by itself.

Performance, UDP/WebRTC, eBPF, VPP/AF_XDP, and broader roadmap work are listed
in [issue #56](https://github.com/ethical-buddy/vx6/issues/56) and linked issues.
