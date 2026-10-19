# VX6 IKEv2/IPsec

VX6's Linux peer tunnel manager uses strongSwan `swanctl` and the kernel XFRM
backend. For each peer it verifies the signed endpoint record, pins that
record's Ed25519 public key for IKEv2 public-key authentication, and configures
an IPv6 tunnel-mode CHILD_SA with `/128` selectors. IKE uses AES-GCM-128,
PRF-SHA-256, and Curve25519; ESP uses AES-GCM-128. `start_action = trap` and
`close_action = trap` ensure the kernel policy does not send matching peer
traffic in cleartext when an SA is unavailable. The VX6 dial gate additionally
requires strongSwan to report the matching CHILD_SA installed before opening a
TCP or QUIC socket. The listener rejects connections unless the source maps to
a verified peer with an installed CHILD_SA.

The local identity key is sent to the root-owned IPsec service through the
authorized local Unix socket and written as PKCS#8 PEM with mode `0600` under
`<service-state>/<uid>/<node-id>/swanctl/private`. Peer public keys and
generated connections are stored beside it. The regular VX6 process neither
stores an IPsec copy of the key nor launches `swanctl`. VX6 does not generate a
new cryptographic identity or CA.

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
signature must be checked against the network's DHT identity/uniqueness process.
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
configured VX6 listener port it accepts packets marked as IPsec-protected and
drops cleartext TCP/UDP packets on that port in both input and output hooks.
Revocation also drops IKE (UDP/500) and ESP (IPv6 next-header 50) to and from
the peer's signed IPv6 endpoint. The table is rebuilt atomically from
root-owned state and contains no unrelated host rules. These rules can affect
another local application that shares a VX6 listener port; use a dedicated
port. The service requires `CAP_NET_ADMIN` and nftables support.

`vx6 peer revoke --node-id ID` performs a local revocation, not a network-wide
DHT revocation. It requires a current signed endpoint record in the local peer
directory. The control service persists the node ID and endpoint, rejects
future tunnel setup and inbound app admission for it, blocks its IKE/ESP
endpoint in nftables, terminates its current IKE SA, and removes the CHILD_SA
trap policy. Revocation remains in force after service restart. It must be
explicitly lifted by an administrator; there is intentionally no automatic
unrevoke on a refreshed DHT record.

This is not yet a complete commercial installation or independently verified
tunnel deployment. The repository has a systemd unit and example service config,
but not a finished signed Linux package/installer that provisions the VX6 group,
authorized UID, strongSwan VICI access, package upgrades/removal, or firewall
policy lifecycle. Application-level listener rejection is not a substitute for
firewall enforcement.

The listener check occurs after TCP/QUIC has reached VX6. It can prevent an
unauthorized connection from reaching VX6 protocol handling, but it does not
hide the listening port, prevent connection attempts, or prove that packets
were protected on the wire. Only kernel IPsec policy plus a real packet capture
on a two-peer test can demonstrate that.

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
dial behavior, persisted revocation, and nftables rule generation. The swarm integration suite uses an explicit test tunnel
provider; it validates application behavior, not real ESP encryption. A
production gate still requires two IPv6 peers and should verify mutual IKE
authentication, CHILD_SA state, XFRM counters, rejected wrong-key attempts,
firewall behavior, tunnel-loss fail-closed behavior, and a packet capture
showing ESP rather than VX6 TCP/QUIC payloads. No such two-peer wire test has
been completed by the current repository tests.

For an already provisioned Linux peer pair, run
`sudo bash scripts/verify-ipsec-linux.sh <interface> <peer-ipv6> <vx6-port> -- <traffic-test-command>`.
It checks the installed SA and XFRM state, captures the outer interface while
the supplied VX6 workload runs, then fails if it sees no ESP or sees clear
TCP/UDP traffic on the VX6 port. This is a verification harness, not an install
script; it does not configure system networking. The two-peer workload and a
failed-key test still have to be run in a controlled test environment before
release.
