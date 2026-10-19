# VX6 Packaging Plan

## Recommendation

Ship one VX6 installer/package experience per operating system, not one
monolithic executable that reimplements operating-system networking. On Linux,
VX6 depends on the kernel's XFRM IPsec datapath and a maintained IKEv2
implementation (currently strongSwan). The package should install and
configure those components so an ordinary user does not need to know about
`swanctl`; it cannot eliminate the kernel support, privileged setup, or
maintenance dependency.

`swanctl` is a control client for strongSwan's `charon` daemon through VICI; it
is not the ESP packet engine. VX6 could replace the CLI invocations with a
direct VICI client while still shipping/running `charon`. strongSwan exposes
its IKE daemon core as `libcharon`, but linking or embedding that core remains
use of strongSwan and its plugin/dependency ecosystem, not a VX6-only IKE
implementation. Linux kernel XFRM handles packet transforms and policy; it
does not independently authenticate peers or negotiate IKE keys. Writing that
IKE implementation in VX6 would create a security-critical protocol stack and
is not recommended.

The best initial product boundary is therefore: VX6 CLI/SDK + privileged
`vx6-ipsecd` + packaged strongSwan daemon/plugins + kernel XFRM + distro-owned
service manager and firewall integration. Keep the IPsec adapter behind a
platform interface so later OS work can use the platform's supported IPsec
facilities rather than pretending Linux XFRM is portable.

## Contributor Work Packages

### Shared release engineering

Own the canonical version, artifact naming, supported OS/architecture matrix,
reproducible build inputs, license inventory, SBOM, checksums, signing keys,
release provenance, and upgrade compatibility policy. Build Go artifacts for
each target from pinned toolchains; do not label a cross-compiled binary as a
supported platform until its service manager, privilege boundary, networking
adapter, and integration tests work there.

Proposed artifact names: `vx6_<version>_linux_<arch>`, matching
`vx6-ipsecd_<version>_linux_<arch>`, and OS-native package files. Publish
checksums and signed release metadata. CI should rebuild a release candidate
from a clean checkout and compare artifacts or document unavoidable
non-reproducible inputs.

### Linux packaging (first deliverable)

Separate contributors can own Debian/Ubuntu (`.deb`), Fedora/RHEL (`.rpm`), and
Arch (`PKGBUILD`) packaging from one reviewed Linux installation contract.
Package both VX6 binaries and systemd units; declare strongSwan runtime
dependencies and required plugins; create a dedicated service user/group;
provision a root-owned config and narrowly scoped VICI/control sockets; grant
the regular VX6 process only the local IPC access it needs; and enable the
privileged helper using systemd hardening. The exact `CAP_NET_ADMIN`, XFRM,
nftables, and socket permissions must be tested rather than guessed.

Package lifecycle scripts must be idempotent and transactional: install,
first start, upgrade with existing keys/state, rollback/failure, stop, purge,
and uninstall. They must not overwrite user configuration or delete identity
keys on ordinary removal. Remove only VX6-owned firewall state, never flush
host-wide rules. Provide an explicit state-removal option. No NAT-T is part of
the current IPv6-only requirement.

The existing `deployments/arch/PKGBUILD` is a sketch, not a releasable package:
it uses a placeholder maintainer, version, URL, and skipped checksum. Debian
and RPM packages and signed repository metadata do not yet exist.

### Windows platform group (later)

Own a Windows-specific tunnel adapter around Windows-supported IKE/IPsec and
filtering APIs, service installation, secure key storage, firewall policy,
upgrade/removal, and Windows CI. Do not port Linux XFRM commands or package a
Linux daemon. First produce a platform design and prove VX6's Ed25519 identity
mapping can be represented without weakening peer pinning; document any
platform algorithm or credential-format constraints before implementation.

### Android platform group (later)

First investigate the OS-owned IKEv2/IPsec profile path on supported Android
versions and the app-owned `VpnService` alternative. Android has a platform
IKEv2 profile API on supported versions, with user-consent/provisioning and
feature availability constraints; it is not simply a Linux daemon packaged
inside an APK. Prototype identity/key compatibility, app-to-native runtime
control, lifecycle/reconnect, per-app routing, and user consent before choosing
the adapter. Android CI/device tests must cover API levels and vendors.

### macOS and other OS contributors

Treat each OS as its own adapter, privilege model, installer, key lifecycle,
firewall, and CI effort. Do not promise cross-platform IPsec solely because
the Go CLI compiles there. Each platform proposal must include a supported
mechanism, identity interoperability proof, install/upgrade/removal behavior,
and packet-capture integration test.

### Architecture/CI owners

Keep shared service and identity logic in Go; isolate privileged operations
behind a narrow, versioned local IPC contract. Add build tags only at the
platform adapter boundary. Require unprivileged unit tests on all supported
architectures and privileged network integration tests on Linux runners that
can create network namespaces and install XFRM/nftables state. Publish the
support matrix from CI results, not intentions.

## Linux release gates

1. Reproducible build for `amd64` and `arm64`; unit tests and static checks.
2. Clean install on each supported distro with no manually authored
   strongSwan configuration and no interactive `swanctl` use.
3. First-run key/state creation, restricted permissions, systemd startup, and
   two-peer IKEv2/ESP establishment using IPv6 only.
4. Packet capture proves inner service data/headers are absent on the transit
   link; wrong key, replay/tamper, clear probe, tunnel loss, and restart tests
   fail closed.
5. Upgrade preserves identity and policy; uninstall removes only VX6-owned
   state/rules and follows documented key-retention choice.
6. SBOM, dependency/license review, signed package/repository metadata,
   checksum verification, and rollback/recovery instructions.

## Order and ownership

Start with #50 adversarial dataplane tests and #55 deployment/operations docs;
then implement the Linux first-install package in [#57](https://github.com/ethical-buddy/vx6/issues/57). In parallel, contributors can
prepare independent package recipes against the shared install contract, but
merge only after Linux behavior and lifecycle tests are stable. Keep #42
decentralized identity/credential lifecycle open; package installation does
not solve DHT membership trust. Windows and Android work starts after the
shared platform interface and identity mapping are documented and tested; the
Android platform work is tracked in [#52](https://github.com/ethical-buddy/vx6/issues/52).

See [IPsec implementation and test instructions](ipsec.md) and the upstream
[strongSwan daemon architecture](https://docs.strongswan.org/docs/latest/daemons/charon.html),
[`swanctl` role](https://docs.strongswan.org/docs/latest/swanctl/swanctl.html),
[Linux XFRM framework](https://docs.kernel.org/networking/xfrm/index.html),
and [Android IKEv2 profile API](https://developer.android.com/reference/android/net/Ikev2VpnProfile).
