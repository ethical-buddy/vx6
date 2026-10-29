# Identity

Each VX6 node has one long-term Ed25519 identity.

That identity is used to:

- derive the node ID
- sign endpoint records
- sign service records
- sign private catalogs
- sign DHT envelopes

The identity is local to the machine and is stored on disk. On Unix-like
systems, the identity file must be a regular file accessible only to its owner
(mode `0600`). VX6 atomically replaces it with owner-only permissions when
writing; it refuses to load a file with group or other access. Windows relies
on the user's profile ACLs rather than POSIX mode bits.

If you reuse the same identity after restart, other nodes still recognize you as the same VX6 node.

## Rotation and recovery

The node ID is derived from the Ed25519 public key. Replacing the key therefore
creates a different node ID; it is not a transparent key refresh. Until DHT
membership proofs support an authenticated old-key-to-new-key transition, do
not claim continuity between those identities.

For planned replacement or suspected key compromise, provision a new VX6
identity as a new node, publish a fresh signed endpoint record, and have peers
admit the new identity through their current peer-record trust process. Locally
revoke the old node ID on peers that still trust it and terminate its active
IPsec SA. If the old private key is lost, it cannot sign its own retirement;
network-wide recovery and revocation require the separate decentralized DHT
membership work in issue #60. Keep backups of private identity files encrypted
and offline; a backup preserves the old identity and must be treated as a live
credential.

Signed endpoint records expire. A refreshed record must be verified before it
is used to prepare an IPsec peer. Local revocation is persistent on that node,
blocks future setup, removes the peer's CHILD_SA policy, and terminates an
active IKE SA. It is not a network-wide revocation signal.

## Verified endpoint boundary

`record.VerifyEndpoint` returns a `VerifiedEndpointRecord` only after checking
the record signature, expiry, and that the NodeID is derived from its public
key. The IPsec manager uses that verified value when writing the strongSwan
public-key pin. This proves that the record is internally valid and that its
named key signed it; it does not prove DHT membership, global uniqueness, or
that a distributed quorum approved the key. Those checks belong to the future
membership-proof API in #60.
