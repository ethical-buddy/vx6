# VX6 Architecture

VX6 is a small stack with a few clear layers.

## 1. Identity

Every node has:

- one Ed25519 identity keypair
- one stable VX6 node ID derived from that key

This identity signs:

- endpoint records
- service records
- DHT envelopes and catalogs

The display name can change.
The key stays fixed.

## 2. Node Runtime

`vx6 node` is the runtime process.

It listens for:

- discovery traffic
- DHT requests
- direct service sessions
- relay extension traffic
- hidden-service control and rendezvous traffic
- file transfers

The same runtime is used on Linux, Windows, and macOS.

## 3. Service Model

VX6 is built around localhost-to-localhost service access.

That means:

- the owner keeps the real app on `127.0.0.1`
- the client uses a local forwarder on its own machine
- VX6 carries the stream between the two nodes

The app itself does not need to become directly public.

The frontend layers only help you publish, connect, inspect, and browse those services.

## 4. Discovery

VX6 has two discovery layers:

- registry sync between known peers
- DHT lookups for public, private, and hidden records

The local registry is a working cache.
The DHT is the distributed lookup path.

The local registry helps startup and repeated sync.
The DHT is the long-range lookup system.

## 5. DHT

The DHT stores a bounded distributed set of signed records.

Main record families:

- `node/name/...`
- `node/id/...`
- `service/...`
- `private-catalog/...`
- `hidden-desc/v1/...`

Trusted keys use conservative store admission:

- signed envelopes are required for trusted records
- stale updates are rejected
- repeated writes are throttled per source
- ASN-aware diversity is used when a local ASN map exists

Important point:

- not every node stores every record
- each record is stored only on a small responsible set of nodes
- diversity checks can use an optional offline ASN map when operators provide one
- if no ASN map exists, the DHT falls back to the existing prefix-based diversity logic

## 6. Security layers

The CLI dataplane target is:

- IKEv2 authenticates the expected peer using a verified DHT name-to-public-key membership proof and establishes an IPsec ESP tunnel.
- ESP tunnel mode protects the IPv6 packets routed through it, including inner addresses, transport headers, and VX6 payload. Do not add a custom packet encryption layer by default.

Peer authentication and service authorization are distinct: IKE verifies the peer key; VX6 must still authorize each service before opening its configured backend. These target properties are not implemented yet; see [the current security status](security.md) and [the dataplane threat model](dataplane-threat-model.md).

Hidden services also use encrypted descriptors, blinded rotating lookup keys, and invite secrets. These mechanisms are separate from normal-mode endpoint identity and dataplane transport protection.

## 7. Hidden Services

Hidden services use:

- intro nodes
- guard nodes
- rendezvous nodes
- encrypted and blinded descriptor lookup
- onion-style relay circuits

Current result:

- much stronger privacy than plain alias lookup
- not a full Tor replacement

The browser frontend and GUI both sit on top of this same core.
They do not change the protocol.

## 8. CLI service dataplane

The target direct-service flow is:

1. The nodes resolve an IPv6 endpoint and a verifiable membership proof binding the remote name to its full public key.
2. IKEv2 mutually authenticates the expected keys and establishes an ESP tunnel using a maintained platform implementation.
3. VX6 routes the peer traffic through the tunnel. Tunnel failure blocks that traffic; it never silently falls back to a clear connection.
4. The receiving VX6 node authorizes the requested service before dialing only its configured local backend.

The repository currently has a custom secure session and QUIC transport code, but no IKEv2/IPsec integration or verified fail-closed route policy. The DHT also lacks the membership quorum needed to act as a decentralized IKE trust anchor. Existing DHT descriptor epochs are not membership epochs. The target architecture is a roadmap, not a claim about the current build. See [the dataplane threat model](dataplane-threat-model.md) for assumptions and acceptance checks.

The tunnel does not provide anonymity. The outer tunnel endpoint addresses, packet sizes, timing, and volume remain observable. Normal mode accepts endpoint identity exposure; hidden-mode identity protection is handled separately.

## 9. Runtime Control

VX6 exposes a local runtime control channel for:

- live status
- reload requests
- DHT publish health

This is the shared control model for Linux, Windows, and macOS going forward.
