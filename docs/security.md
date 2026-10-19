# Security and limitations

VX6's existing dataplane is still migrating toward the target security design. It currently uses a custom signed X25519/AES-GCM session and has QUIC transport code, but it does not provide IKEv2/IPsec tunnel integration or per-peer service authorization. The shared TCP/QUIC transport now rejects non-IPv6 endpoints; this does not encrypt those connections. Do not treat the target design below as implemented.

The target direct CLI dataplane uses an established IKEv2/IPsec implementation for IPv6 tunnel-mode packet protection. IKE peer authentication must validate the expected Ed25519 identity obtained from a verified DHT membership result. ESP protects the selected VX6 packets; VX6 must not add a custom packet cipher or key exchange. Service authorization remains a separate deny-by-default check before a configured local backend is dialed.

IPsec can hide inner IP and transport headers only for traffic actually routed through the tunnel. The tunnel's outer IPv6 endpoint addresses, packet sizes, timing, and traffic volume remain visible. IKE bootstrap exchanges and any traffic sent before the SA is established are not protected by that SA. IPv6-only operation does not imply that every packet is tunneled. Normal mode accepts endpoint identity exposure; hidden-mode identity and traffic-analysis protections are separate concerns.

The DHT currently signs records and has quorum-like checks for selected hidden-descriptor lookups. It does not implement network-wide node admission consensus, a quorum-certified name-to-key membership record, or a membership authorization epoch. Hidden descriptor epochs are lookup-key rotation periods, not proof that a node identity is current or authorized. A DHT membership proof and its Sybil/equivocation assumptions must be specified before it can serve as IKE's decentralized trust anchor.

See [the dataplane threat model and security contract](dataplane-threat-model.md) for scope, assumptions, packet flow, current gaps, and the required properties. See [the architecture overview](architecture.md) for VX6's broader components.
