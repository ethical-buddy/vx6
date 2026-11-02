# Roadmap

GitHub [issue #56](https://github.com/ethical-buddy/vx6/issues/56) is the
canonical ordered roadmap. The current security and delivery sequence is:

The initial baseline IKE/ESP capture milestone is complete in [#50](https://github.com/ethical-buddy/vx6/issues/50). The remaining full adversarial matrix is tracked in [#59](https://github.com/ethical-buddy/vx6/issues/59). DHT work follows a peer-local model: each node maintains and validates its own bounded routing view; there is no committee or network-wide consensus authority. This improves independence but does not automatically provide global name uniqueness or Sybil resistance.

1. Benchmark the working Linux strongSwan/XFRM dataplane before changing its controller ([#51](https://github.com/ethical-buddy/vx6/issues/51)); keep a VX6-owned Linux IKE controller as research/prototype work, not a custom ESP or crypto project ([#57](https://github.com/ethical-buddy/vx6/issues/57)).
2. Define peer-local identity, name-conflict, and revocation behavior ([#60](https://github.com/ethical-buddy/vx6/issues/60)); a missing lookup response means “not confirmed,” not “globally available.”
3. Coordinate signed metadata and separate identity/name lookup keys ([#63](https://github.com/ethical-buddy/vx6/issues/63)) with bounded local XOR-table maintenance ([#62](https://github.com/ethical-buddy/vx6/issues/62)); agree on record/table interfaces before parallel implementation.
4. Add multi-source bootstrap and liveness without treating one seed as authority ([#64](https://github.com/ethical-buddy/vx6/issues/64)); validate churn and eclipse behavior with the simulator ([#65](https://github.com/ethical-buddy/vx6/issues/65)). Harden bounded ingress parsing in parallel ([#66](https://github.com/ethical-buddy/vx6/issues/66)).
5. Implement deny-by-default service authorization tied to the authenticated peer identity ([#43](https://github.com/ethical-buddy/vx6/issues/43)) and bounded service OPEN framing ([#48](https://github.com/ethical-buddy/vx6/issues/48)). Remove redundant custom session crypto only after every relevant path has a proven protection boundary ([#44](https://github.com/ethical-buddy/vx6/issues/44)).
6. Keep TCP and optional QUIC service streams inside required ESP. Neither is a clear-path security fallback ([#45](https://github.com/ethical-buddy/vx6/issues/45), [#46](https://github.com/ethical-buddy/vx6/issues/46)). Complete active-attack and tunnel-lifecycle tests ([#59](https://github.com/ethical-buddy/vx6/issues/59)).
7. Package the current Linux implementation, then gate any controller replacement on benchmark results and independent security review ([#57](https://github.com/ethical-buddy/vx6/issues/57)). Build signed, rollback-resistant updates that can use untrusted DHT mirrors ([#67](https://github.com/ethical-buddy/vx6/issues/67)); mature the public Go SDK separately ([#58](https://github.com/ethical-buddy/vx6/issues/58)).
8. Android and other operating systems need separate platform adapters ([#52](https://github.com/ethical-buddy/vx6/issues/52)). Evaluate UDP/WebRTC, eBPF, and VPP only against measured workloads ([#49](https://github.com/ethical-buddy/vx6/issues/49), [#53](https://github.com/ethical-buddy/vx6/issues/53), [#54](https://github.com/ethical-buddy/vx6/issues/54)).

For operator setup, use the [documentation map](README.md). For verified
guarantees versus outstanding risks, use the [security status](security.md).
