# Security and limitations

VX6's existing dataplane is still migrating toward the target security design. It currently uses a custom signed X25519/AES-GCM session, has QUIC transport code, and does not yet provide IKEv2/IPsec tunnel integration or per-peer service authorization. Do not treat the target design below as already implemented.

The target CLI dataplane uses an established IKEv2/IPsec implementation for routed packet protection, QUIC with TLS 1.3 mutual authentication as its primary service transport, and TCP with TLS 1.3 as fallback. Both service transports must verify the expected peer and enforce the same deny-by-default service permissions. VX6 will not implement its own cryptographic handshake or cipher.

IPsec can hide inner IP and transport headers only for traffic actually routed through the tunnel. The tunnel's outer endpoint addresses, packet sizes, timing, and traffic volume remain visible. QUIC protects application data and selected header fields; it does not hide the outer IP/UDP headers. Normal mode accepts endpoint identity exposure. Hidden-mode identity and traffic-analysis protections are separate concerns.

See [the dataplane threat model and security contract](dataplane-threat-model.md) for scope, assumptions, packet flow, current gaps, and the required properties. See [the architecture overview](architecture.md) for VX6's broader components.
