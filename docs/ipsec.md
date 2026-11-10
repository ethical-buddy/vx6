# VX6 IKEv2/IPsec

This page describes the current Linux prototype, which uses strongSwan and
kernel XFRM. It does not describe a VX6-owned IKE implementation. Replacing
the strongSwan control plane is future research/prototype work in [#57](https://github.com/ethical-buddy/vx6/issues/57),
gated on baseline measurements ([#51](https://github.com/ethical-buddy/vx6/issues/51))
and security review. VX6 must continue to use established cryptographic
libraries and kernel ESP; the work is not permission to invent a cipher, key
exchange, or ESP engine.

VX6's Linux peer tunnel manager uses strongSwan `swanctl` and the kernel XFRM
backend. For each peer it verifies the signed endpoint record, pins that
record's Ed25519 public key for IKEv2 public-key authentication, and configures
an IPv6 tunnel-mode CHILD_SA with `/128` selectors. IKE uses AES-GCM-128,
PRF-SHA-256, and Curve25519; ESP uses AES-GCM-128. `start_action = trap` and
`close_action = trap` ensure the kernel policy does not send matching peer
traffic in cleartext when an SA is unavailable. The VX6 dial gate additionally
requires strongSwan to report the matching CHILD_SA installed before opening a
TCP connection. UDP service datagrams use a separate listener at endpoint port
`P+2`; the existing VX6 liveness probe remains at UDP `P+1`. Both service paths
are selected by explicit TCP/UDP ESP selectors.

The local identity key is sent to the root-owned IPsec service through the
authorized local Unix socket and written as PKCS#8 PEM with mode `0600` under
`<service-state>/<uid>/<node-id>/swanctl/private`. The private-key directory is
restricted to mode `0700`; peer public keys and generated connections are
stored in separately restricted directories. On Unix-like systems, the user
identity store is a regular owner-only file and is atomically replaced on
write. The regular VX6 process neither stores an IPsec copy of the key nor
launches `swanctl`. VX6 does not generate a new cryptographic identity or CA.

The signed endpoint record binds node ID, name, IPv6 address, and full Ed25519
public key. Record verification checks the signature, validity interval, and
that the node ID is derived from that key. The IPsec manager pins that verified
key for IKE authentication; a peer-supplied name or address alone is not a
trust anchor. This proves possession of the key named in the record, not that
the DHT has globally established the record's uniqueness. Each node makes its
own trust decision; there is no membership committee or global consensus
service. Conflict handling, metadata, local table maintenance, and bootstrap
remain work tracked in #60 and #62-#65.

## Bootstrap

An address alone is not enough to authenticate the first IKE exchange. Obtain a
fresh endpoint record for the bootstrap peer over a trusted channel and add it
locally:

```sh
vx6 peer add --record bootstrap-endpoint.json
```

A node can create such a signed record with:

```sh
vx6 identity export-endpoint --addr '[2001:db8::10]:4242' --out endpoint.json
```

The record's name, node ID, public key, address, validity interval, and
signature must be verified. The current implementation does not establish
network-wide DHT identity uniqueness; see #60.
Address-only peers remain accepted in config for compatibility, but fail closed
when used as a tunnel peer.

## Current Implementation Status

The Linux control path now has a separate `vx6-ipsecd` service. The regular VX6
process sends only fixed `prepare`, `ensure`, `accept`, `revoke`, and `check` requests over
a local Unix socket. The service verifies the caller UID with `SO_PEERCRED`,
validates the local identity, and generates all strongSwan configuration itself.
It rejects arbitrary command/configuration requests. The service, rather than
the CLI, invokes `swanctl` and stores the private key under its protected state
directory.

The service owns a dedicated nftables table named `inet vx6`. For every
configured VX6 listener port `P` it accepts packets marked as IPsec-protected
and drops cleartext TCP/UDP packets on `P` and `P+2` in both input and output
hooks. UDP `P+1` is the separate liveness probe and is not an application
service port.
Revocation also drops IKE (UDP/500) and ESP (IPv6 next-header 50) to and from
the peer's signed IPv6 endpoint. The table is rebuilt atomically from
root-owned state and contains no unrelated host rules. These rules can affect
another local application that shares a VX6 listener port; use a dedicated
port. The service requires `CAP_NET_ADMIN` and nftables support.

Each VX6 CHILD_SA now sets XFRM policy priority `1`, so its endpoint-specific
TCP/UDP selectors take precedence over broader pass policies already present
on the host. The nftables output rule still fails closed if the kernel does
not select an IPsec route. `vx6 peer check --ike` verifies both the installed
CHILD_SA and a protected TCP health request; an established IKE SA alone does
not prove that traffic matched the ESP policy.

`vx6 peer revoke --node-id ID` performs a local revocation, not a network-wide
DHT revocation. It requires a current signed endpoint record in the local peer
directory. The control service persists the node ID and endpoint, rejects
future tunnel setup and inbound app admission for it, blocks its IKE/ESP
endpoint in nftables, terminates its current IKE SA, and removes the CHILD_SA
trap policy. Revocation remains in force after service restart. It must be
explicitly lifted by an administrator; there is intentionally no automatic
unrevoke on a refreshed DHT record.

Node IDs are derived from identity public keys. Key replacement therefore
creates a new node ID, not a transparent rotation. Until a signed
identity-transition proof is implemented and locally accepted, planned
replacement means enrolling a new node identity and updating peer trust, then
locally revoking the old ID. If the old
key is lost or compromised, network-wide recovery cannot be proven by that key
and depends on the future peer-local identity/revocation design in #60. An expired
endpoint record must be refreshed and verified before it can be used for new
peer setup.

This is not yet a complete commercial installation. The repository has systemd
units and an example service config, but no finished signed Linux package or
installer that provisions the VX6 group, authorized UID, strongSwan VICI access,
package upgrades/removal, and firewall policy lifecycle. See the
[packaging plan](packaging-plan.md). Application-level listener rejection is
not a substitute for firewall enforcement.

The TCP and UDP service listeners can reject traffic that is not associated
with an installed peer SA. This does not hide the listening ports or prevent
connection attempts. Only kernel IPsec policy plus a real packet capture on a
two-peer test demonstrates that service data was protected on the wire.

## Host Requirements

The strongSwan daemon must be installed and running with the VICI plugin,
Ed25519/PKCS#8 and Curve25519 support, and access to the kernel XFRM backend.
The root-managed VX6 service must access the VICI socket. The regular VX6 process
must be authorized to use only the VX6 service socket; it does not need root.
Never make either socket world-writable.
The network must allow IPv6 UDP/500 for IKE and IP protocol 50 (ESP); NAT-T is
not used.

If the service or VICI is unavailable, node startup or tunnel preparation fails
closed. The local listener also rejects connections without an installed peer
SA, subject to the application-layer limitation described above. VICI socket
permissions and the authorized UID must be provisioned by the Linux package.

`deployments/systemd/ipsecd.json.example` contains service settings. Its UID and
GID values are examples only; a package installer must resolve the actual VX6
user/group, write a root-owned non-writable configuration, and enable
`deployments/systemd/vx6-ipsecd.service`. The regular VX6 CLI uses
`/run/vx6/ipsecd.sock` and fails rather than falling back to direct `swanctl`.

## Validation

Unit tests verify endpoint-record pinning, generated tunnel selectors and
proposals, private-key file permissions, installed-SA checks, fail-closed
dial behavior, persisted local revocation, and nftables rule generation. The
swarm integration suite uses an explicit test tunnel provider; it validates
application behavior, not real ESP encryption.

`tests/ipsec-e2e/run.sh` performs a real two-peer IPv6 container test. It places
a router/sniffer between the nodes and captures from before IKE through ping,
VX6 connection, a Python HTTP request, and a UDP echo service exchange. The successful run showed
an established IKEv2 SA with Ed25519-authenticated peer identities,
AES-GCM-128/PRF-SHA-256/Curve25519, an ESP AES-GCM-128 tunnel CHILD_SA, and
increasing XFRM counters. The post-tunnel ping was not visible as clear ICMPv6;
the HTTP and UDP echo services returned unique test markers to the client, but
neither marker appeared in the transit capture. UDP use increased the ESP SA
packet counters. The capture contained ESP and IKE, and no clear peer-to-peer
VX6 TCP traffic on `P` or UDP service traffic on `P+2` after tunnel
establishment. A third-party clear TCP probe to that port received no response
and was blocked. The intentionally pre-tunnel baseline ping was visible in
clear ICMPv6, demonstrating the before/after distinction.

The capture uses `tcpdump -i any`; Linux can show a packet at both ingress and
egress, so reported totals are observations, not necessarily unique frames.
This is passive capture plus an unauthenticated clear-port probe. It does not
yet prove resistance to active packet modification/replay, rekey failure,
tunnel loss/restart, or every route-leak scenario. Those cases are tracked in
follow-up adversarial issue #59. DHT lookup and peer-local name/conflict policy
are deliberately omitted: the test supplies signed peer endpoint records
directly and verifies the pinned-key IKE path. DHT trust remains separate
work; this test does not assume consensus.

Run the complete routed capture test with:

```sh
bash tests/ipsec-e2e/run.sh
```

It requires Docker and Linux networking capabilities. It writes logs, capture,
and a summary under a temporary directory and prints its path.
`scripts/test-ipsec-e2e-containers.sh` is a compatibility wrapper.
`scripts/test-ipsec-containers.sh` remains the narrower nftables-only test and
does not establish IPsec.

For an already provisioned Linux peer pair, run
`sudo bash scripts/verify-ipsec-linux.sh <interface> <peer-ipv6> <vx6-port> -- <traffic-test-command>`.
It checks the installed SA and XFRM state, captures the outer interface while
the supplied VX6 workload runs, then fails if it sees no ESP or sees clear
TCP/UDP traffic on the VX6 service ports. This is a verification harness, not an install
script; it does not configure system networking. The two-peer workload and a
failed-key test still have to be run in a controlled test environment before
release.
