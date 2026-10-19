# CLI Dataplane Threat Model

## Scope

This contract applies first to direct CLI service forwarding between VX6 nodes. It covers peer authentication, service authorization, network transport, and the local connection to the configured backend. DHT poisoning and discovery privacy are a separate later workstream. Hidden-mode anonymity is also separate; normal mode accepts exposure of endpoint identity and address.

## System and trust boundaries

```text
Local application
    | local TCP connection
VX6 client: expected peer + configured service permission
    | local TCP service forwarding
    | IPv6 traffic routed through IKEv2-negotiated IPsec ESP tunnel
VX6 server: authenticated peer + deny-by-default service ACL
    | configured local backend only
Remote application service
```

The Linux implementation uses IPsec as the network packet-protection layer.
The existing application session remains for callers that still depend on it;
it is not a substitute for peer membership or service authorization. The
current IKE identity is pinned from a locally verified signed endpoint record.
A DHT record is not automatically a membership proof: network-wide membership
rules are future work.

## Threats and required outcomes

| Threat | Required outcome |
| --- | --- |
| Passive network observer | Cannot read service payloads or inner IP/transport headers on links covered by IPsec. Can still observe outer tunnel endpoints, packet sizes, timing, volume, and that a tunnel is in use. |
| Active on-path MITM | Cannot impersonate the expected node, alter authenticated traffic undetected, or cause a silent downgrade. Both IKE/IPsec and the service transport verify configured peer identities. |
| Captured-packet replay or injection | Cannot create a new authenticated session or inject accepted transport packets. IPsec anti-replay and standard QUIC/TLS/TCP behavior are enabled. Disable QUIC/TLS 0-RTT until replay-safe application semantics are explicitly reviewed. |
| Unauthenticated service scanner | Cannot obtain a service banner or enumerate service names through VX6 before authentication and authorization. Service identifiers and OPEN requests are carried inside the encrypted transport. |
| Authenticated but unauthorized peer | Cannot open a service unless an explicit peer-to-service rule allows it. Authorization occurs before any backend dial. |
| Malicious or compromised authorized peer | Is limited by its configured services, concurrent streams, rates, timeouts, and resource quotas. VX6 cannot protect a service from an authorized client that is permitted to use it. |
| Denial of service | Apply bounded parsing, handshake/stream quotas, timeouts, rate limits, and backpressure. Availability against a sufficiently large network flood is not guaranteed. |
| Compromised endpoint or stolen private key | Outside the protection boundary until credentials are revoked and active sessions terminated. Protect private keys and keep endpoint software updated. |

## Identity and authorization contract

- The intended trust anchor is a verifiable decentralized DHT membership proof binding a node name to its full public key; a peer-supplied key, address, or magic value alone is not a trust anchor.
- IKEv2 must authenticate the IPsec peer using an established implementation and validate the expected key against that DHT proof. VX6 does not implement a custom challenge-response protocol.
- The authenticated identity is checked against the identity expected for the connection. Merely presenting a certificate accepted by some CA is not sufficient if it is the wrong node.
- Authentication answers “which peer proved possession of its private key?” Authorization separately answers “which services may that peer open?”
- Service permissions default to deny. The server must authorize the requested opaque service identifier before connecting to a backend. Remote requests never supply arbitrary destination addresses or ports.
- Key rotation, expiration, revocation, and termination of active sessions are part of the credential lifecycle. Logs must not contain private keys, tokens, or service payloads.

## Protocol and downgrade rules

- IKEv2/IPsec uses a maintained implementation. VX6 does not create its own key exchange, cipher, packet encryption, or challenge-response protocol.
- No clear TCP/QUIC fallback is permitted for traffic configured as tunnel-required. Authentication, membership validation, or SA failures must fail closed.
- IPsec is mandatory for traffic configured as tunnel-required. If tunnel setup or health fails, protected traffic must not escape over an ordinary route.
- The service OPEN message is bounded, encrypted, versioned, and contains an opaque service identifier rather than a backend host/port. An opaque identifier is not itself an authorization credential.

## What observers can still learn

On an external link, an observer can see the outer IPsec endpoint addresses and packet timing, size, and volume. Depending on deployment and NAT traversal, IKE and ESP or UDP-encapsulated ESP are also identifiable as tunnel traffic. IPsec tunnel mode hides the inner IP header, TCP/UDP ports, and payload while the packet traverses the tunnel.

An observer on the external path sees the outer IPv6 tunnel endpoints and traffic patterns. A local observer after IPsec decapsulation may see inner VX6 headers because IPsec protection ends at the peer host. Neither IPsec nor encryption guarantees that packet sizes and timing cannot suggest activity. Padding and cover traffic are not part of the default design because they consume bandwidth and can add latency.

## Current implementation snapshot

Implemented and tested on Linux:

- `vx6-ipsecd` uses strongSwan and kernel XFRM to establish IKEv2/ESP with
  Ed25519 peer-key pinning and IPv6 `/128` tunnel selectors.
- The local dial gate and nftables rules fail closed for the configured VX6
  listener path; local peer revocation is persisted and terminates the local
  association.
- The routed two-peer container test observes ESP, increasing XFRM counters,
  no service sentinel in the transit capture, and a blocked clear TCP probe.

Remaining gaps and limitations:

- `internal/secure/session.go` implements a custom X25519/Ed25519/HKDF/AES-GCM session protocol.
- `internal/transport/quic.go` creates a throwaway self-signed certificate and skips ordinary QUIC TLS peer verification, relying on the custom session above it.
- QUIC currently exposes one stream per connection; it does not yet provide the planned reusable per-peer multiplexed connection.
- The transport abstraction currently selects TCP for `auto`; QUIC is not yet the default.
- `internal/serviceproxy/proxy.go` does not enforce peer-to-service ACLs before backend dialing and does not consistently compare the authenticated remote identity with the configured expected owner.
- Active tamper/replay, rekey failure, tunnel-loss/restart, and comprehensive
  route-leak tests are not yet covered by the container suite (#50).
- DHT membership consensus, membership freshness, and distributed revocation
  are not implemented; test peer records are supplied directly.
- The DHT has no network-wide node-membership quorum or authorization epoch. Existing hidden-descriptor epochs rotate lookup keys and cannot be used as membership freshness proofs.
- The current service proxy handles TCP streams. Real-time UDP/WebRTC forwarding needs a separate datagram design.

These gaps are addressed by the ordered implementation work in [the dataplane roadmap](https://github.com/ethical-buddy/vx6/issues/56).

## Security acceptance checks

Before production use, tests must show that:

- An unknown or wrong peer, invalid/revoked DHT membership proof, or mismatched expected identity is rejected.
- A trusted but unauthorized peer cannot cause a backend dial; denial is the default.
- Tampered, replayed, malformed, or downgraded IKE/ESP traffic is rejected.
- Failure of a required IPsec tunnel does not send protected traffic through a clear route.
- Outer-link packet captures do not reveal the inner IP/TCP/UDP headers or application payload.
- Resource limits bound unauthenticated handshakes, streams, request sizes, memory, and idle connections.
- Fallback occurs only for transport availability failures and retains the same authentication and authorization requirements.

Performance must be measured for QUIC/TLS, TCP/TLS, IPsec alone, and their intended combinations. The design aims for a low-overhead fast path but does not claim zero cost or that QUIC is faster for every workload.

## Property-to-work mapping

| Property | Implementation issue | Required verification |
| --- | --- | --- |
| Peer trust, expected-identity checks, rotation, and revocation | [#42](https://github.com/ethical-buddy/vx6/issues/42) | Valid peer succeeds; unknown, wrong, expired, and revoked credentials fail. |
| Deny-by-default service access before backend dialing | [#43](https://github.com/ethical-buddy/vx6/issues/43) | Unauthorized and wrong-owner requests cause zero backend dials. |
| Bounded encrypted service request without remote-selected host/port | [#48](https://github.com/ethical-buddy/vx6/issues/48) | Golden vectors, parser fuzzing, malformed/oversized input rejection, and no service-catalog oracle. |
| Use maintained transport cryptography; no custom handshake or silent downgrade | [#44](https://github.com/ethical-buddy/vx6/issues/44) | Wrong identity, tampering, replay, downgrade, and legacy-version tests fail closed; 0-RTT is disabled. |
| QUIC primary transport, connection reuse, and stream/resource isolation | [#45](https://github.com/ethical-buddy/vx6/issues/45) | Concurrent-stream, identity, cancellation, flood-limit, and reconnect integration tests. |
| TCP/TLS fallback with equivalent authentication and authorization | [#46](https://github.com/ethical-buddy/vx6/issues/46) | Reachability failure may fall back; identity and authorization failures never do. |
| Inner-header confidentiality and no clear-route leakage when a tunnel is required | [#47](https://github.com/ethical-buddy/vx6/issues/47) | External packet capture hides inner IP/transport headers; tunnel failure cannot leak to the ordinary route. |
| Combined MITM, replay, malformed-input, denial, and fail-closed coverage | [#50](https://github.com/ethical-buddy/vx6/issues/50) | CI runs portable adversarial tests and a documented privileged IPsec integration job. |
| Overhead and latency remain measured rather than assumed | [#51](https://github.com/ethical-buddy/vx6/issues/51) | Reproducible benchmarks report throughput, p95/p99 latency, CPU, memory, jitter, and loss. |
| UDP/WebRTC identity, datagram handling, and tunnel-path protection | [#49](https://github.com/ethical-buddy/vx6/issues/49) | Datagram loss/reorder tests, signaling fingerprint checks, and packet-capture validation. |

The ordered dependencies and the platform and acceleration follow-up work are tracked in [roadmap issue #56](https://github.com/ethical-buddy/vx6/issues/56).
