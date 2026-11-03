# Roadmap

GitHub [issue #56](https://github.com/ethical-buddy/vx6/issues/56) is the
canonical ordered roadmap. The current security and delivery sequence is:

The initial baseline IKE/ESP capture milestone is complete in [#50](https://github.com/ethical-buddy/vx6/issues/50). The remaining full adversarial matrix is tracked in [#59](https://github.com/ethical-buddy/vx6/issues/59). DHT work follows a peer-local model: each node maintains and validates its own bounded routing view; there is no committee or network-wide consensus authority. This improves independence but does not automatically provide global name uniqueness or Sybil resistance.

1. Benchmark the working Linux strongSwan/XFRM dataplane before changing its controller ([#51](https://github.com/ethical-buddy/vx6/issues/51)); keep a VX6-owned Linux IKE controller as research/prototype work, not a custom ESP or crypto project ([#57](https://github.com/ethical-buddy/vx6/issues/57)).
2. Finish the remaining routing-table acceptance work in [#62](https://github.com/ethical-buddy/vx6/issues/62): configurable diversity limits, adversarial/churn tests, and memory/churn measurements.
3. Bound iterative lookup resource use and return honest incomplete results ([#68](https://github.com/ethical-buddy/vx6/issues/68)); then use the resulting bounded behavior in the scale/churn/eclipsing simulator ([#65](https://github.com/ethical-buddy/vx6/issues/65)). Harden bounded ingress parsing in parallel ([#66](https://github.com/ethical-buddy/vx6/issues/66)).
4. Signed metadata and separate identity/name lookup keys ([#63](https://github.com/ethical-buddy/vx6/issues/63)), peer-local identity/name policy ([#60](https://github.com/ethical-buddy/vx6/issues/60)), and multi-source bootstrap/liveness ([#64](https://github.com/ethical-buddy/vx6/issues/64)) are closed implementation milestones. Their closure does not prove global name uniqueness or Sybil/eclipse resistance.
5. Implement deny-by-default service authorization tied to the authenticated peer identity ([#43](https://github.com/ethical-buddy/vx6/issues/43)) and bounded service OPEN framing ([#48](https://github.com/ethical-buddy/vx6/issues/48)). Remove redundant custom session crypto only after every relevant path has a proven protection boundary ([#44](https://github.com/ethical-buddy/vx6/issues/44)).
6. Keep TCP and optional QUIC service streams inside required ESP. Neither is a clear-path security fallback ([#45](https://github.com/ethical-buddy/vx6/issues/45), [#46](https://github.com/ethical-buddy/vx6/issues/46)). Complete active-attack and tunnel-lifecycle tests ([#59](https://github.com/ethical-buddy/vx6/issues/59)).
7. Package the current Linux implementation, then gate any controller replacement on benchmark results and independent security review ([#57](https://github.com/ethical-buddy/vx6/issues/57)). Build signed, rollback-resistant updates that can use untrusted DHT mirrors ([#67](https://github.com/ethical-buddy/vx6/issues/67)); mature the public Go SDK separately ([#58](https://github.com/ethical-buddy/vx6/issues/58)).
8. Android and other operating systems need separate platform adapters ([#52](https://github.com/ethical-buddy/vx6/issues/52)). Evaluate UDP/WebRTC, eBPF, and VPP only against measured workloads ([#49](https://github.com/ethical-buddy/vx6/issues/49), [#53](https://github.com/ethical-buddy/vx6/issues/53), [#54](https://github.com/ethical-buddy/vx6/issues/54)).

For operator setup, use the [documentation map](README.md). For verified
guarantees versus outstanding risks, use the [security status](security.md).
