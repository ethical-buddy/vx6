# Security and limitations

## Current Linux dataplane

The Linux CLI has an IKEv2/IPsec control path using strongSwan and the Linux
kernel XFRM implementation. VX6 pins the expected peer's Ed25519 key from a
signed endpoint record, requests IKEv2 public-key authentication, and installs
an IPv6 tunnel-mode ESP CHILD_SA with `/128` selectors. The negotiated test
profile uses AES-GCM-128 for IKE and ESP, PRF-HMAC-SHA-256, and Curve25519.
The root-owned `vx6-ipsecd` service manages strongSwan and fail-closed firewall
policy; `swanctl` is an implementation control utility, not VX6's packet
crypto.

A two-peer IPv6 container test now captures traffic on a routed bridge. In the
successful run, IKE established, ESP/XFRM counters increased with tunneled
traffic, the private-service response marker was absent from the capture, no
clear peer-to-peer VX6-port traffic was observed after tunnel establishment,
and an untrusted clear TCP probe was blocked. The baseline ping before IKE
was intentionally visible in clear ICMPv6. Capture on `-i any` can report the
same frame at more than one interface, so its packet count is not a count of
unique wire frames. See [IPsec validation](ipsec.md#validation).

This is evidence for passive confidentiality on the tested IPv6 path, not a
proof against every active MITM. The test does not inject modified or replayed
packets, exercise rekey, or simulate tunnel loss/restart and route cleanup.
An on-path attacker can still drop, delay, or flood traffic. These cases belong
in the follow-up adversarial issue #59. DHT-wide name/key uniqueness, admission consensus,
membership freshness, and distributed revocation are also still outside this
test and remain separate DHT/trust work.

The endpoint record is locally verified and pinned for IKE. A DHT lookup by
itself is not currently a quorum-backed membership proof. Do not interpret
this as production-ready decentralized trust until the membership and
credential lifecycle is specified and implemented.

## Application crypto

The Go `internal/secure` protocol has **not** been removed. It is still used
by service proxying, file transfer, SDK sharing, hidden rendezvous, and onion
extension paths. IPsec protects packets on the peer-to-peer network path; it
does not automatically replace each application's authenticated protocol or
all non-IPsec paths. Do not delete this code as a cleanup: migrate each caller
to a standard authenticated transport under issue #44, verify identity and
fallback behavior, then remove the legacy protocol with compatibility tests.

VX6 must not introduce a new cipher, key exchange, or packet-encryption
protocol. The current application session code composes standard Go crypto
primitives in a VX6-specific protocol; its existence is a migration concern,
not a reason to stack another custom cipher over ESP.

## Visibility and remaining boundaries

IPsec tunnel mode hides the inner IP header, TCP/UDP ports, and payload only
while packets traverse the established tunnel. The outer IPv6 endpoints,
ESP/IKE use, packet sizes, timing, and traffic volume remain visible. IKE
bootstrap traffic and traffic before an SA is active are not protected by that
SA. A local observer on either endpoint can inspect traffic after decapsulation.
IPsec does not provide anonymity or hide endpoint identity in normal mode.

Service authorization remains distinct from peer authentication. IKE proves
control of the pinned peer key; it does not mean that peer may access every
service. Per-service deny-by-default authorization and robust credential
lifecycles remain open work. See the [dataplane threat model](dataplane-threat-model.md).
