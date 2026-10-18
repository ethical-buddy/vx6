# Current Status

VX6 is usable now for controlled testing and temporary internal deployment.

## Working Today

- TCP transport across the current release
- signed discovery and signed service publication
- direct service access to known VX6 addresses
- public service lookup through the DHT
- node-name clashes are detected and surfaced instead of being silently merged
- init and rename now probe the network for name clashes before accepting a node name
- private service catalogs for user-scoped visibility
- hidden services with:
  - encrypted descriptors
  - blinded lookup keys
  - invite secrets
  - anonymous descriptor store and lookup paths
- ASN-aware DHT diversity when a local ASN map is provided
- conservative DHT store admission for trusted records
- file transfer with local permission policy
- runtime status and reload
- `vx6-gui` over the same CLI/runtime surface
- `products/browser/qt` as a separate Qt WebEngine frontend over the same VX6 binary

## Linux Position

`main` is the Linux-first release branch.

That means:

- Linux is the primary reference environment
- systemd documentation exists
- Linux runtime behavior is the baseline used to shape the protocol branch
- eBPF/XDP controls exist here, but they are still experimental

## Other Platforms

- Windows uses the same protocol and feature behavior through the shared core and Windows runtime adapters
- macOS packaging and runtime polish are still behind Linux

## Still In Progress

- seamless hidden mid-stream failover
- stronger DHT hardening under adversarial WAN and churn
- real QUIC transport
- real eBPF/XDP fast path for the current encrypted relay plane
- polished Windows and macOS packaging and service lifecycle work
- richer ASN map tooling and operator data sources
- a fuller browser product layered on top of the new Qt browser shell

## Honest Summary

VX6 is no longer just an architecture sketch.

It already has:

- functioning service discovery
- functioning encrypted sessions
- functioning DHT-backed lookup
- functioning hidden services

The biggest remaining work is hardening, failover, packaging, and large-scale adversarial polish.
