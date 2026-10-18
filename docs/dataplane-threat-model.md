# CLI Dataplane Threat Model

## Scope

This contract applies first to direct CLI service forwarding between VX6 nodes. It covers peer authentication, service authorization, network transport, and the local connection to the configured backend. DHT poisoning and discovery privacy are a separate later workstream. Hidden-mode anonymity is also separate; normal mode accepts exposure of endpoint identity and address.

## System and trust boundaries

```text
Local application
    | local TCP connection
VX6 client: expected peer + configured service permission
    | QUIC/TLS 1.3 (primary) or TCP/TLS 1.3 (fallback)
    | carried inside IKEv2-negotiated IPsec ESP tunnel
VX6 server: authenticated peer + deny-by-default service ACL
    | configured local backend only
Remote application service
```

QUIC uses TLS 1.3 to establish authenticated keys and protect QUIC packets. In the TCP fallback, TLS 1.3 protects the byte stream. IPsec tunnel mode wraps the IP packet carrying either transport. This deliberately creates a network protection layer and a service transport protection layer; it also adds CPU and packet overhead that must be measured.

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

- Each peer is provisioned through an authenticated operator-controlled trust process. A peer-supplied key, node name, IP address, or magic value is not a trust anchor.
- IKEv2 authenticates the IPsec peer using an established implementation and configured credentials. The service transport independently authenticates the expected VX6 peer using TLS 1.3.
- The authenticated identity is checked against the identity expected for the connection. Merely presenting a certificate accepted by some CA is not sufficient if it is the wrong node.
- Authentication answers “which peer proved possession of its private key?” Authorization separately answers “which services may that peer open?”
- Service permissions default to deny. The server must authorize the requested opaque service identifier before connecting to a backend. Remote requests never supply arbitrary destination addresses or ports.
- Key rotation, expiration, revocation, and termination of active sessions are part of the credential lifecycle. Logs must not contain private keys, tokens, or service payloads.

## Protocol and downgrade rules

- IKEv2/IPsec, TLS 1.3, and QUIC use maintained platform or library implementations. VX6 does not create its own key exchange, cipher, record encryption, or challenge-response protocol.
- QUIC with TLS 1.3 is the intended default CLI transport. TCP with TLS 1.3 is the fallback and enforces identical identity and service policy.
- A reachability or transport availability failure may permit TCP/TLS fallback. Authentication, certificate, protocol-version, and authorization failures must fail closed and must never trigger a weaker fallback.
- Disable QUIC 0-RTT and TLS early data. Do not transparently replay application bytes after reconnecting; network replay protection does not provide exactly-once application operations.
- IPsec is mandatory for traffic configured as tunnel-required. If tunnel setup or health fails, protected traffic must not escape over an ordinary route.
- The service OPEN message is bounded, encrypted, versioned, and contains an opaque service identifier rather than a backend host/port. An opaque identifier is not itself an authorization credential.

## What observers can still learn

On an external link, an observer can see the outer IPsec endpoint addresses and packet timing, size, and volume. Depending on deployment and NAT traversal, IKE and ESP or UDP-encapsulated ESP are also identifiable as tunnel traffic. IPsec tunnel mode hides the inner IP header, TCP/UDP ports, and payload while the packet traverses the tunnel.

After IPsec decapsulation, a network observer on the inner path may see inner peer addresses and the QUIC UDP or TCP ports, but QUIC/TLS still encrypts application data. QUIC protects selected header fields, not every packet field. Neither IPsec nor QUIC guarantees that traffic patterns cannot suggest the type or timing of activity. Padding and cover traffic are not part of the default design because they consume bandwidth and can add latency.

## Current implementation snapshot

The following are current gaps, not properties of the target design:

- `internal/secure/session.go` implements a custom X25519/Ed25519/HKDF/AES-GCM session protocol.
- `internal/transport/quic.go` creates a throwaway self-signed certificate and skips ordinary QUIC TLS peer verification, relying on the custom session above it.
- QUIC currently exposes one stream per connection; it does not yet provide the planned reusable per-peer multiplexed connection.
- The transport abstraction currently selects TCP for `auto`; QUIC is not yet the default.
- `internal/serviceproxy/proxy.go` does not enforce peer-to-service ACLs before backend dialing and does not consistently compare the authenticated remote identity with the configured expected owner.
- No IKEv2/IPsec tunnel integration or verified fail-closed route policy is present in the CLI dataplane.
- The current service proxy handles TCP streams. Real-time UDP/WebRTC forwarding needs a separate datagram design.

These gaps are addressed by the ordered implementation work in [the dataplane roadmap](https://github.com/ethical-buddy/vx6/issues/56).

## Security acceptance checks

Before production use, tests must show that:

- An unknown or wrong peer, invalid certificate, revoked peer, or mismatched expected identity is rejected.
- A trusted but unauthorized peer cannot cause a backend dial; denial is the default.
- Tampered, replayed, malformed, or downgraded traffic is rejected, and 0-RTT is disabled.
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
