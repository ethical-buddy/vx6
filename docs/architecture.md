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

The Go runtime is portable, but platform integration and packaging are not yet
feature-equivalent. The currently verified IKEv2/IPsec deployment is Linux-only.

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
- optional ASN/prefix groups are indexed as supplemental local lookup contacts;
  they do not change XOR routing order or block peers

Important point:

- not every node stores every record
- each record is stored only on a small responsible set of nodes
- the optional offline ASN map enriches the local contact index
- without it, IPv6-prefix grouping still provides supplemental contacts

## 6. Security layers

The CLI dataplane target is:

- IKEv2 authenticates the expected peer using a locally verified and trusted key record, then establishes an IPsec ESP tunnel.
- ESP tunnel mode protects the IPv6 packets routed through it, including inner addresses, transport headers, and VX6 payload. Do not add a custom packet encryption layer by default.

Peer authentication and service authorization are distinct. A public service
does not require the caller to be found in the owner's DHT or local identity
registry. A private service requires the caller's locally verified public key
and NodeID in `allowed_node_ids`; an empty list denies everyone. Both still
arrive through the IPsec-gated listener. Important limitation: the current
strongSwan manager creates inbound IKE connections from known signed peer
records, so this change removes the per-caller DHT check at service opening but
does not yet admit an arbitrary peer with no preconfigured IKE relationship.
Do not describe that broader public-access behavior as implemented until the
IKE admission model supports it securely. Linux IKEv2/IPsec is implemented.
The target DHT trust model is
peer-local validation, not a network-wide membership proof or committee. See [the current
security status](security.md) and [the dataplane threat model](dataplane-threat-model.md).

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

1. The caller resolves an IPv6 endpoint and signed record, reports name conflicts, and applies local key-trust, expiry, and revocation checks to the NodeID/public key. A local key trust entry does not reserve the advertised name.
2. IKEv2 mutually authenticates the expected keys and establishes an ESP tunnel using a maintained platform implementation.
3. VX6 sends TCP streams to the peer's TCP endpoint and framed UDP datagrams to
   UDP endpoint port `P+2`; `P+1` remains the liveness probe. Both service paths
   are covered by the IPsec selectors. Tunnel failure blocks protected traffic
   rather than silently falling back to a clear route.
4. The receiving VX6 node checks private-service identity and allowlist policy
   before forwarding to only its configured local backend. UDP is explicitly
   selected per service and uses a bounded flow table. For public services, it
   skips the per-service DHT lookup and relies on the accepted IPsec peer path.

Use `vx6 service add --private --allow-node NODE_ID` to give a private service
an explicit local allowlist; repeat `--allow-node` for additional peers. A
service request carries a version, the `open` action, and one service name.
Unknown fields and malformed requests are rejected. A public service skips the
owner's DHT identity lookup and service allowlist, but still requires an
IPsec-protected connection. The current strongSwan setup only admits peers for
which a signed peer record has already configured an IKE relationship;
arbitrary unknown-peer IKE admission is not implemented. Public does not mean
that the service is exposed without IPsec. UDP services use a separate VX6
datagram envelope; they are not raw IP forwarding.

On Linux, the repository has a strongSwan-backed IKEv2/IPsec integration and a
container packet-capture test for the ESP path. VX6 delegates privileged
tunnel setup to `vx6-ipsecd`. The endpoint record proves that its signing key
made the record and binds the key to the advertised fields; local policy must
decide whether to trust that identity. DHT lookup can return competing,
withheld, stale, or malicious data and is not a global consensus service.
Existing hidden-descriptor epochs are unrelated to identity freshness. The Go
application session protocol remains in use and is removed only after issue
#44 proves coverage of all relevant paths. See [the dataplane threat model](dataplane-threat-model.md).

The tunnel does not provide anonymity. The outer tunnel endpoint addresses, packet sizes, timing, and volume remain observable. Normal mode accepts endpoint identity exposure; hidden-mode identity protection is handled separately.

## 9. Runtime Control

VX6 exposes a local runtime control channel for:

- live status
- reload requests
- DHT publish health

This is the shared control model for Linux, Windows, and macOS going forward.
