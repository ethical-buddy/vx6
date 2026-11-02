# VX6 Packaging Plan

## Recommendation

Ship one VX6 installer/package experience per operating system, not one
monolithic executable that reimplements operating-system networking. The
current Linux prototype depends on strongSwan for IKEv2 and kernel XFRM for
ESP. The desired direction is to remove the strongSwan runtime dependency by
building a VX6-owned Linux IKE control plane, while continuing to use kernel
XFRM and established cryptographic libraries. That controller is not
implemented yet and must not be represented as part of today's binary.

`swanctl` is a control client for strongSwan's `charon` daemon through VICI; it
is not the ESP packet engine. VX6 could replace the CLI invocations with a
direct VICI client while still shipping/running `charon`. strongSwan exposes
its IKE daemon core as `libcharon`, but linking or embedding that core remains
use of strongSwan and its plugin/dependency ecosystem, not a VX6-only IKE
implementation. Linux kernel XFRM handles packet transforms and policy; it
does not independently authenticate peers or negotiate IKE keys. Writing that
IKE implementation in VX6 creates a security-critical protocol stack. The
selected direction accepts that complexity, but not custom cryptographic
primitives or a userspace ESP dataplane. Issue #57 must specify requirements,
privilege boundaries, interoperability, benchmarks, failure behavior, tests,
and independent review before implementation is accepted.

The current prototype boundary is VX6 CLI + privileged `vx6-ipsecd` +
strongSwan + kernel XFRM + Linux service manager/firewall. The target Linux
product boundary is VX6 CLI/SDK + privileged VX6 IKE controller + kernel XFRM
+ distro service manager/firewall. Keep the adapter behind a platform
interface; do not imply that a Linux controller or XFRM design ports directly
to other operating systems.

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
Package both VX6 binaries and systemd units; for today's prototype declare
strongSwan runtime dependencies and required plugins. Update that dependency
contract only after a reviewed replacement is complete. Create a dedicated
service user/group;
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

First measure the current Linux baseline in [#51](https://github.com/ethical-buddy/vx6/issues/51),
then research and prototype the replacement controller under [#57](https://github.com/ethical-buddy/vx6/issues/57),
with adversarial tests in [#59](https://github.com/ethical-buddy/vx6/issues/59).
Do not remove strongSwan until a replacement passes interoperability,
lifecycle, fail-closed, and independent security gates. Contributors can
prepare package recipes against the current install contract, clearly labeling
strongSwan as a runtime dependency. Keep #60 and #62-#65 peer-local DHT work
separate: packaging does not solve name conflicts or DHT eclipse risk. Windows and Android work starts after the
shared platform interface and identity mapping are documented and tested; the
Android platform work is tracked in [#52](https://github.com/ethical-buddy/vx6/issues/52).

See [IPsec implementation and test instructions](ipsec.md) and the upstream
[strongSwan daemon architecture](https://docs.strongswan.org/docs/latest/daemons/charon.html),
[`swanctl` role](https://docs.strongswan.org/docs/latest/swanctl/swanctl.html),
[Linux XFRM framework](https://docs.kernel.org/networking/xfrm/index.html),
and [Android IKEv2 profile API](https://developer.android.com/reference/android/net/Ikev2VpnProfile).
