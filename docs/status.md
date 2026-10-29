# Current Status

VX6 is usable for controlled testing. Do not treat the Linux IPsec support as a
finished commercial installer or the decentralized identity system as a
completed trust authority.

## Working Areas

- TCP service transport and localhost service forwarding
- signed discovery, signed service publication, and DHT-backed lookup
- private service catalogs and hidden-service descriptors/rendezvous
- file transfer with local permission policy
- runtime status/reload and the `vx6-gui` frontend
- Linux IKEv2/IPsec integration through strongSwan and kernel XFRM
- a routed IPv6 two-peer container capture for ESP/service confidentiality

## Platform Scope

Linux is the reference platform for the IPsec implementation. Windows/macOS
Go builds do not imply equivalent IPsec adapters, privilege boundaries,
firewall behavior, installers, or validation. Android needs a separate native
VPN/IKEv2 and SDK integration. See the [platform packaging plan](packaging-plan.md).

## Remaining Security and Product Work

- adversarial IPsec tests for wrong peers, replay/tamper, rekey, and tunnel loss
- comprehensive fail-closed route and restart/cleanup verification
- DHT-backed membership and credential lifecycle; DHT is not yet the IKE trust
  authority
- deny-by-default service authorization and standard authenticated transport
  migration
- production Linux package and first-install/upgrade/removal lifecycle
- public SDK types suitable for external Go consumers
- Android integration and platform test matrix
- QUIC, UDP/WebRTC, and acceleration work remain separate and incomplete

For per-feature guarantees and limitations, start at [security.md](security.md).
