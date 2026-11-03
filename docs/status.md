# Current Status

VX6 is usable for controlled testing. Do not treat Linux IPsec as a finished
commercial installer or the decentralized identity system as a global name
authority.

## Working Areas

- TCP service transport and localhost service forwarding
- signed discovery, signed service publication, and DHT-backed lookup
- separate NodeID and canonical-name routing coordinates in the DHT
- bounded local DHT active/replacement/candidate state with bbolt peer-cache persistence
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
- peer-local DHT identity/name conflict and credential lifecycle; there is no
  planned committee or global consensus service, and a local lookup is not
  proof that a name is globally unique
- signed metadata and record semantics (#63), bootstrap/liveness (#64), and
  adversarial churn/eclipse simulation (#65)
- DHT routing implementation #62 is closed; configurable diversity caps,
  adversarial/restart tests, and memory/churn benchmarks remain in #71. The
  current 20-active, 10-replacement, 512-candidate defaults are starting
  points, not validated large-network settings.
- deny-by-default service authorization and proof that every service path uses
  its required IPsec protection
- production Linux package and first-install/upgrade/removal lifecycle
- public SDK types suitable for external Go consumers
- Android integration and platform test matrix
- a VX6-owned Linux IKE controller is research/prototype work; strongSwan and
  XFRM are the current tested implementation (#51, #57)
- QUIC is optional inside ESP, not the default security layer or a clear-path
  fallback; UDP/WebRTC and acceleration remain separate and incomplete

## Recent Verification Note

The latest full `go test ./... -count=1` run did not pass completely. DHT and
node packages passed, but `TestHiddenServiceRendezvousPlainTCP` failed because
two hidden rendezvous circuits reused one relay. The failure also reproduced
when that integration test ran alone. It belongs to hidden-service relay
selection, not the routing-table implementation, and remains an unresolved
repository test failure. The DHT/node race tests and `go build ./...` passed.

For per-feature guarantees and limitations, start at [security.md](security.md).
