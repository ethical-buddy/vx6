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

The CLI dataplane is moving to two standard protection layers:

- IKEv2-managed IPsec ESP tunnel mode protects routed inner IP packets, including their transport headers, while they cross the tunnel.
- QUIC with TLS 1.3 is the intended primary service transport; TCP with TLS 1.3 is the fallback. Both authenticate the expected peer and encrypt service data.

The layers have different jobs. IPsec protects packets on the network path; the service transport authenticates the VX6 peer and protects the service connection. Per-peer service authorization is a separate policy check and must happen before a backend connection is opened. These target properties are not all implemented yet; see [the current security status](security.md) and [the dataplane threat model](dataplane-threat-model.md).

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

1. The nodes establish an IKEv2-authenticated IPsec ESP tunnel using a maintained platform implementation.
2. VX6 establishes a QUIC connection with TLS 1.3 mutual authentication and verifies the expected node identity.
3. Each forwarded local TCP connection gets a bidirectional QUIC stream. A bounded encrypted request selects an opaque configured service identifier.
4. The receiving node checks the authenticated peer's service permission before dialing only the configured local backend.
5. TCP with TLS 1.3 provides a fallback when QUIC is unavailable. It uses the same peer identity and service authorization policy; security failures never trigger fallback.

The repository currently has a custom secure session and QUIC transport code, but QUIC is not yet the `auto` default, its current wrapper exposes one stream per connection, IKEv2/IPsec is not integrated, and service authorization needs work. The target architecture is a roadmap, not a claim about the current build. See [the dataplane threat model](dataplane-threat-model.md) for packet visibility, assumptions, and acceptance checks.

The tunnel does not provide anonymity. The outer tunnel endpoint addresses, packet sizes, timing, and volume remain observable. Normal mode accepts endpoint identity exposure; hidden-mode identity protection is handled separately.

## 9. Runtime Control

VX6 exposes a local runtime control channel for:

- live status
- reload requests
- DHT publish health

This is the shared control model for Linux, Windows, and macOS going forward.
