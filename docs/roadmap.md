# Roadmap

GitHub [issue #56](https://github.com/ethical-buddy/vx6/issues/56) is the
canonical ordered roadmap. The current security and delivery sequence is:

The initial baseline IKE/ESP capture milestone is complete in [#50](https://github.com/ethical-buddy/vx6/issues/50). The remaining full adversarial matrix is tracked in [#59](https://github.com/ethical-buddy/vx6/issues/59).

1. Define and enforce peer trust/credential lifecycle ([#42](https://github.com/ethical-buddy/vx6/issues/42)); DHT security is not established by the current packet-capture test.
3. Implement service authorization and bounded encrypted service requests ([#43](https://github.com/ethical-buddy/vx6/issues/43), [#48](https://github.com/ethical-buddy/vx6/issues/48)).
4. Replace the custom application session with maintained authenticated transports ([#44](https://github.com/ethical-buddy/vx6/issues/44)), then implement QUIC primary and equivalent TCP/TLS fallback ([#45](https://github.com/ethical-buddy/vx6/issues/45), [#46](https://github.com/ethical-buddy/vx6/issues/46)).
5. Package Linux with strongSwan and a verified install lifecycle ([#57](https://github.com/ethical-buddy/vx6/issues/57)); make the Go SDK externally consumable ([#58](https://github.com/ethical-buddy/vx6/issues/58)).
6. Add Android OS IKEv2/VPN and service SDK integration ([#52](https://github.com/ethical-buddy/vx6/issues/52)); other OSes need their own adapters and release gates.
7. Complete feature-gated security tests in [#59](https://github.com/ethical-buddy/vx6/issues/59), then continue performance, UDP/WebRTC, eBPF, and VPP evaluations only with measured use cases ([#49](https://github.com/ethical-buddy/vx6/issues/49), [#51](https://github.com/ethical-buddy/vx6/issues/51), [#53](https://github.com/ethical-buddy/vx6/issues/53), [#54](https://github.com/ethical-buddy/vx6/issues/54)).

For operator setup, use the [documentation map](README.md). For verified
guarantees versus outstanding risks, use the [security status](security.md).
