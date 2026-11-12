# VX6 Location-Hidden Services: Replacement Design

**Status:** Architecture proposal for review. Not implemented, audited, or approved for production.

**Scope:** A from-scratch replacement for the current hidden-service path. Prototype v1 is IPv6-only and TCP-only. It describes a location-hidden service carried over adjacent VX6/IPsec links. It has no IPv4 socket, route, or fallback in its data path. The ordinary peer DHT and ordinary public/private services remain separate components.

**Audience:** An implementation agent should treat the requirements and invariants below as the contract. Values marked *prototype default* are starting limits for tests, not claims of optimality. Do not silently weaken security properties to make a test pass.

## 1. Goal and Honest Security Claim

The goal is to let client Z reach service A without either endpoint learning the other's network address, while relays forward traffic without reading the application data. Only the first relay at each end may learn that end's IPv6 address; no relay may learn both endpoint addresses. No relay other than that endpoint's first relay should learn its stable VX6 NodeID/public key. All other peers know only the adjacent peer/session needed to forward. The inside application payload is end-to-end encrypted between client and service.

The design is inspired by Tor onion services: multi-hop circuits, separately established service-side and client-side paths, introduction points, a rendezvous point, signed descriptors, per-hop keys, stream multiplexing, and flow control. Tor's specifications describe circuits where a relay knows its predecessor and successor, not the whole route, and onion services where client and service establish separate circuits to a rendezvous point. [Tor circuit overview](https://spec.torproject.org/intro/index.html), [onion-service overview](https://community.torproject.org/onion-services/overview/).

**Permitted claim:** With uncompromised endpoints and an honest separating relay on each side of the rendezvous, client and service do not learn each other's IPv6 address or stable VX6 identity; relays do not learn application plaintext if end-to-end encryption is correctly implemented. The first relay at each end is an explicit exception: it sees that endpoint's network address and may know its stable identity if the chosen entry-authentication design permits it.

**Not promised:** Complete anonymity, protection from a global traffic observer, protection if an adversary controls/colludes with strategically placed relays, guaranteed service availability, or resistance to Sybil operators. IPsec does not hide the IP addresses of adjacent peers, traffic sizes, timing, or the use of ESP/IKE. No document can prove the implementation secure; independent review and testing remain necessary.

## 2. Threat Model

Assume an adversary may:

- Operate some VX6 nodes and advertise them as relays.
- Control or observe one relay, an introduction point, or a rendezvous point.
- Drop, delay, reorder, replay, or attempt to modify packets.
- Observe traffic at one or more network links and correlate timing/volume.
- Send malformed messages, flood circuit creation, or exhaust memory/CPU/bandwidth.
- Provide stale, conflicting, or forged unsigned discovery data.

Assume the adversary does **not** automatically control either endpoint's OS or private keys. If it does, endpoint anonymity is lost. A **global traffic-correlation observer** is an observer able to watch the client's network link and the service's network link (or enough links near both ends). It compares packet timing, direction, sizes, and bursts to guess which two encrypted flows belong together. It does not need to decrypt packets or learn either endpoint's key. Low-latency encryption and random paths cannot guarantee protection from this observer; Tor also documents traffic correlation as a remaining attack. [Tor's discussion of onion-routing attacks](https://support.torproject.org/about-tor/security/attacks-on-onion-routing/), [Tor design paper](https://svn-archive.torproject.org/svn/projects/design-paper/tor-design.html).

The design must report which threats are mitigated, not label every failed connection as an attack or every successful handshake as proof of anonymity.

## 3. Roles and Topology

Roles are temporary circuit roles, not trusted authorities:

- **Client:** Locally opens a service stream and builds a client-side circuit.
- **Service:** Runs a local TCP service and builds outbound circuits. It never publishes its routable endpoint in the hidden descriptor.
- **Guard:** First relay on an endpoint's path. It sees that endpoint's network address and VX6 identity, but not the remote endpoint or service name.
- **Middle:** Forwards a circuit between adjacent relays.
- **Introduction point (IP):** Receives a sealed setup request and forwards it over a service-originated setup circuit. It is not on the application-data path. It necessarily knows its own service registration and can see the requesting circuit's adjacent relay, but not the client/service endpoint IPs or payload.
- **Rendezvous point (RP):** Pairs two circuits using an opaque one-use token and forwards encrypted cells. It necessarily knows which two adjacent circuits it paired and their timing/volume; it must not learn which side is client versus service, either endpoint IP, either stable endpoint identity, or payload.

```text
Client Z --IPsec--> Guard --IPsec--> Middle --IPsec--> RP
                                                         |
                                      end-to-end encrypted cells
                                                         |
Service A --IPsec--> Guard --IPsec--> Middle ------------+

Service A --separate setup circuit--> Introduction Point
Client Z --separate setup circuit--> Introduction Point --sealed setup--> A
```

The service builds a **new independent data circuit to the RP**. The IP handles only service registration and introduction; it is absent from all application-data cells. The client also uses a setup circuit to reach the IP. Setup circuits and data circuits use the same indistinguishable cell grammar; no `client`, `service`, `guard`, `middle`, `hop_number`, or path-length field is sent. A relay necessarily knows its immediate neighbors and local circuit mappings; hiding that adjacency from the relay is impossible because it forwards to that neighbor. The RP necessarily knows it paired two circuits, but not their semantic roles.

Each adjacent link uses IPv6 and IPsec. The descriptor and relay-cell payloads must not contain A's or Z's network endpoint. A circuit-extension request names a target NodeID inside an encrypted control cell, not an arbitrary host/port. The selected next relay is resolved from a locally accepted signed record; any stable identity used for this resolution must remain encrypted from intermediate hops.

### Identity-hiding gate

Current VX6 IKE peer authentication uses a stable Ed25519 identity. An IKE responder learns the identity used by its direct peer even though IKE_AUTH identities are protected from passive observers after IKE_SA_INIT. [RFC 7296](https://datatracker.ietf.org/doc/rfc7296/). Therefore the current stable-identity IKE configuration does **not** meet the requirement that intermediate relays cannot learn endpoint NodeIDs.

Before coding, define a circuit-scoped link identity that does not disclose the endpoint's stable NodeID to non-entry relays. Candidate links must still resist active man-in-the-middle attacks and bind the intended next hop to the circuit. Do not solve this by accepting arbitrary unauthenticated IKE peers or by trusting a self-presented key. If this cannot be achieved using a reviewed protocol and compatible IKE controller policy, the identity-privacy requirement is not met and implementation must stop for protocol review. First guards may learn their adjacent endpoint by the stated exception; other relays must not receive that stable identity.

## 4. Chosen Starting Parameters

These are conservative, configurable prototype defaults. They need measurement and security review before release.

| Parameter | Prototype default | Purpose / qualification |
|---|---:|---|
| Client-side path | 3 relays, RP is hop 3 | Guard, middle, RP |
| Service-side path | 3 relays, same RP is hop 3 | Service guard, middle, RP; 6 link traversals per data direction |
| Active introduction points per service | 3 | Availability; established through service-originated circuits |
| Standby introduction points | 2 | Rebuild after failure; do not publish as active until ready |
| RPs per connection | 1 | Chosen by client from eligible relays; retry with a new RP if setup fails |
| Sampled endpoint guards | 1 primary + 2 backups per endpoint | Keep stable; do not choose a fresh guard for every request |
| Relay cell size | 1,200 bytes fixed | Initial MTU target; verify ESP/NAT-T path MTU; no IP fragmentation by design |
| Rendezvous token | 32 random bytes | Single-use; store only a hash at RP |
| Rendezvous token lifetime | 120 seconds | Local expiry; does not prove identity |
| Client/service circuit idle timeout | 60 seconds | Close idle circuits; active streams may keep them alive |
| Circuit maximum age | 10 minutes | Prototype default; active streams are not silently migrated |
| Descriptor epoch | 1 hour | Rotating lookup namespace, not an identity timestamp |
| Descriptor overlap | Current + previous epoch | Tolerate clock skew and refresh races; reject older epochs after local policy window |
| Service descriptor refresh | At half the epoch, with jitter | Avoid synchronized update bursts |
| Concurrent circuit builds | 2 per local node initially | Bound CPU and IKE churn |
| Relay worker CPU quota | 5% of one logical CPU by default; operator may raise to 20% | Enforced by a Linux cgroup for the isolated relay worker; reject new circuits when quota/headroom is exhausted |
| Relay worker memory ceiling | 128 MiB | Linux cgroup hard ceiling; process must shed/deny work before reaching it |
| Relay bandwidth | 1 Mbit/s each direction by default; operator-configured hard maximum | Local token bucket; no remote peer can raise it |
| Global relay circuit state | 256 circuits initially | Configurable hard cap; reject new circuits safely when full |
| Streams per circuit | 32 initially | Multiplexing limit, independently rate-limited |
| Global stream count | 1,024 initially | Hard cap across all relayed circuits |
| Relay queue budget | 64 KiB per circuit, plus 16 MiB global queue budget | Apply backpressure; never allocate from peer-declared lengths before validating limits |
| Circuit creation per adjacent peer | 2 per second, burst 4 | Local admission token bucket |
| Pending introductions per service | 20; 5 new introductions per second | Local service/IP limits; excess requests fail before backend work |
| Hidden lookup fanout | 4 parallel requests | Iterative lookup; use a separate hidden-record namespace; perform over an already-established relay circuit |
| Hidden lookup maximum | 20 rounds, 80 peer queries total, 10 seconds total; 2 seconds per peer | Hard request budget; return `incomplete` on exhaustion, never claim global absence |
| Hidden descriptor replica target | 20 closest eligible stores | Reuse only as a replication target; this is not consensus or proof of availability |

All caps must be configurable and observable. Before changing defaults, report memory per circuit, CPU per Mbps, packet rate, setup latency, p50/p95/p99 stream latency, loss, and the failure mode at each cap. Do not increase limits merely to improve a success percentage.

## 5. Link Security, Circuit Security, and Application Security

Use three distinct layers for distinct purposes:

1. **Adjacent-link protection:** IKEv2/IPsec ESP between neighboring VX6 peers. An SA is reused for multiple circuits/streams. Do not create an IKE association per application stream. Existing VX6 IKE identity verification authenticates the adjacent peer; it does not authenticate the final service to the client.
2. **Circuit forwarding protection:** Each hop has a separate circuit key and sees only its next-hop instruction. Use a reviewed circuit/onion protocol or a protocol reviewed specifically for VX6. Never invent a cipher, nonce scheme, or key schedule in application code.
3. **End-to-end service protection:** Client and service establish an authenticated encrypted session through the RP. Relays, including the RP and IPs, must not see service plaintext. A service identity key is pinned in the locator/invite and verifies the signed descriptor and the end-to-end handshake.

The exact end-to-end, per-hop, and circuit-scoped link-identity protocol/library is a **hard pre-development gate**. Select a maintained, reviewed implementation with explicit key erasure, transcript binding, replay protection, and appropriate security analysis. It must preserve the stable NodeID from non-entry relays while still authenticating the chosen next hop against active substitution. Do not invent a crypto construction or silently downgrade IKE peer authentication. Public hidden services must not require or expose a stable client NodeID to the service. Private hidden services use a service-scoped capability or pseudonymous credential, not the client's global VX6 identity by default.

The first CHILD_SA keys and later rekeys are governed by the IKE/IPsec implementation. Configure and test rekeying, overlapping SAs, failure handling, and fail-closed behavior; never assume a long-lived SA needs no maintenance. [strongSwan IKE/IPsec SA renewal](https://docs.strongswan.org/docs/latest/config/rekeying.html).

## 6. Discovery and Descriptor Design

Hidden service discovery is **not** an ordinary node-name or peer-identity lookup. It is a separate DHT value namespace. Ordinary node DHT records must not gain hidden service names, service endpoints, intro tokens, or a hidden-service-to-owner mapping.

### Service locator

- A public locator contains protocol version, service identity public key (or its full fingerprint), a random 256-bit locator secret, and an optional human label for display. The key/fingerprint, not the label, identifies the service. The locator secret makes the DHT lookup unguessable by name; anyone given a public locator can use it, so it is not an access-control secret.
- A private invite additionally contains a service-scoped access capability (minimum 256 random bits) used for private authorization and, if needed, private descriptor decryption. Store it as a secret; never log it or put it in a public DHT value.
- A human-readable name alone is not proof that the service is the one the user intended. Two services can choose the same label. UI must show a short key fingerprint on first use and allow the user to pin the expected identity.

### Rotating lookup keys

Use domain-separated, full-length SHA-256 keys. Derive `lookup_key = HMAC-SHA-256(locator_secret, "vx6-hidden-lookup-v1" || service_id || epoch)`, where `service_id` is a domain-separated hash of the service identity public key and all fields have canonical fixed-length encodings. Derive a separate descriptor-encryption key from the locator secret and epoch using a reviewed KDF; never reuse the lookup key as an encryption key. The private access capability remains distinct from the public locator secret. Do not concatenate ambiguous strings or truncate hashes for routing.

The hidden descriptor lookup is sent through a client relay circuit. A direct DHT lookup exposes the client's network address to the queried DHT peers; relaying it changes what those peers see, but does not hide the lookup key from the DHT peer that answers or from the final relay that forwards the lookup. Use a blinded/epoch-scoped lookup key so the query does not contain a stable service name or stable service public key. A public locator lets its holder derive the right key; a private invite additionally protects it from enumeration. This still does not hide the target from the answering DHT peer for that epoch, nor prevent timing correlation. The DHT must not be treated as a source of identity truth or global membership authority.

### Descriptor fields and checks

Descriptor fields are fixed and versioned:

- Protocol version and service identity public key/fingerprint (inside the encrypted descriptor, not visible to DHT storage peers).
- Epoch and signed monotonically increasing descriptor sequence.
- Bounded local expiry/lease value and allowed epoch window.
- Up to 3 active introduction-point identities and their opaque service-specific introduction tokens.
- Optional encrypted private-service access metadata; no host address, listener address, client address, backend port, or stable client identifier.
- Service signature over the canonical encoded descriptor.

DHT storage peers see only the opaque lookup key and descriptor ciphertext. The locator holder decrypts, then validates exact schema, canonical encoding, signature, service identity, epoch window, sequence policy, field lengths, token lengths, and duplicate fields before using it. Maintain highest-seen descriptor sequence locally to reduce replay after restart. Local clocks are only for lease/cleanup and epoch-window handling; they do not prove ownership or DHT membership. Clock skew, rollback, and a first-time client's lack of sequence history remain residual risks.

Replicate to up to 20 closest records in the hidden namespace, subject to existing DHT write admission and resource limits. Use locally available diversity representatives as supplemental replica candidates where practical, but do not claim that this defeats Sybil or eclipse attacks. A descriptor being absent from queried peers means “not found in this reachable view,” not globally unavailable.

## 7. Connection Protocol

All control messages use a strict versioned schema. Unknown fields, duplicate fields, invalid enum values, oversized messages, invalid state transitions, and unexpected messages are rejected and the connection/circuit is closed. Never accept a peer-supplied arbitrary IP address or backend target as a relay instruction.

Message families (wire IDs and canonical encoding still require a protocol review):

1. `hidden_lookup`: request the descriptor for a derived hidden key/epoch. Response contains only bounded candidate ciphertext descriptors or a typed `not_found` / `incomplete` result. It uses 4-way parallelism, at most 20 rounds/80 peer queries, a 2-second per-peer timeout, and a 10-second total deadline. Exhaustion is `incomplete`, not proof that the service does not exist.
2. `hidden_publish`: publish/refresh an encrypted, signed descriptor under the hidden namespace. Storage peers validate bounded framing and store the ciphertext; only a locator holder decrypts and verifies the service signature. Ordinary node/service lookup handlers must not return this record type.
3. `circuit_create` / `circuit_extend`: allocate a random local circuit ID and extend by NodeID. Each hop authenticates its next adjacent peer before forwarding success.
4. `intro_register`: service registers an opaque token over its prebuilt circuit to an introduction point. Registration is service-scoped and expires; it carries no service endpoint.
5. `introduce`: client sends the RP identity and 32-byte one-use token inside a message sealed to the service identity. The introduction point forwards the opaque message to the matching registered service circuit.
6. `rendezvous_join`: either side sends the same unlabelled join message with the one-use token. The first message creates a pending slot; the second pairs it. There is no client/service role bit. RP stores only token hash, two local circuit handles, creation time, and expiry; it knows the two circuits are paired and may observe which arrived first, but not their endpoint roles or identities.
7. `stream_open`, `stream_data`, `stream_close`: multiplex application streams inside the end-to-end encrypted circuit. For v1, permit only a service ID already present in the verified descriptor; never allow remote-selected host/port.
8. `circuit_destroy` and authenticated liveness/control messages: bounded teardown, timeout, and failure propagation.

### End-to-end sequence

1. Service verifies its local backend is listening on a loopback/local target. It creates or loads a service identity key distinct from the node identity key.
2. Service builds three-hop **setup-only** circuits to 3 active IPs, registers fresh service-scoped tokens, and publishes a signed descriptor under the rotating blinded lookup key. Keep 2 standby IPs unadvertised until their circuits and registrations are ready. These setup circuits carry no application stream data.
3. Client obtains locator/invite out of band or through an explicitly designed name directory. It derives the hidden lookup key and queries the hidden descriptor namespace through a relay circuit.
4. Client verifies descriptor signature and pinned service identity, chooses one active IP, chooses an RP independently, and builds its three-hop circuit to that RP.
5. Client creates a 32-byte rendezvous token and sends the sealed setup message through its separate setup circuit to the IP. The message contains an opaque RP locator and token sealed to the service; the IP cannot read the target RP, token, client identity, or service payload.
6. Service receives the sealed request over its setup circuit, verifies it, then builds a **new, separate three-hop data circuit** to the RP and sends the same `rendezvous_join` message using the token. The IP is not used for or told about this data circuit.
7. Client and service both send the same `rendezvous_join` message; whichever arrives first creates the pending slot and the other completes it. Client and service then establish the end-to-end authenticated encrypted session over the joined circuits. The client verifies the service key against its locator. The service receives no stable client identity by default. RP sees two opaque circuit handles and pairs them; the protocol must not expose client/service role labels, stream names, or service identity to RP. RP still sees pairing and timing, which can support traffic-correlation inference.
8. After authorization, the service proxy connects only to its configured loopback backend. A missing, invalid, unauthorized, or unavailable service returns a suitably generic error to avoid becoming an enumeration oracle.
9. Circuit close, idle timeout, IKE failure, descriptor refresh, and relay failure must tear down local circuit state and release all queue/memory budgets. A stream is not transparently moved to a new route unless the application protocol explicitly supports reconnect/replay semantics.

## 8. Path Selection and Relay Identity

Use DHT results as **candidate discovery only**. A candidate must have a valid signed peer record, pass local conflict/revocation policy, and pass protected-path health before becoming eligible as a relay. An unauthenticated PONG is only a reachability hint. The circuit/link authentication design must verify the intended relay without disclosing the endpoint's stable NodeID to non-entry relays; the identity-hiding gate above blocks implementation until this is resolved.

Do not select relays by XOR closeness. XOR is for DHT lookup, not anonymity. Do not choose a new first hop for each circuit: keep one sampled primary guard and two backups, switching only for defined failure or policy reasons. Select middle/RP/IP candidates from locally verified eligible peers using a cryptographically secure random source, without repeating a NodeID within a path. Avoid known same-operator/network clusters as a heuristic, but treat ASN/prefix claims as untrusted hints and do not let diversity rules make a path deterministic or unbuildable.

Every ordinary node may opt in as a relay and accept or reject new work based on its own resource budget. No committee chooses relay roles. The network has no committee or global consensus, so it cannot prove a relay is independently operated or prevent a Sybil operator from advertising many keys. The user has explicitly deferred Sybil mitigation; random selection is only meaningful if the candidate population is not attacker-dominated. This remains a known limitation, not a problem solved by local bucket reshuffling.

## 9. Service Access Semantics

- **Public hidden service:** Any client who has the correct service locator may attempt a connection. “Public” means no service-specific allowlist; it does not mean publicly routable or unauthenticated at the adjacent IPsec peer links.
- **Private hidden service:** The owner provisions service-scoped capabilities/credentials for allowed users. Authorization occurs after the end-to-end session is established but before opening the backend. Unknown and unauthorized users should receive indistinguishable external failures where practical.
- **Backend boundary:** The service process connects only to the locally configured backend. The network protocol must never accept a caller's arbitrary backend address or port.
- **v1 transport:** TCP only. UDP, WebRTC media, SCTP, multicast, and arbitrary IP are excluded until the circuit framing, congestion behavior, privacy, and MTU rules are independently designed and tested.

## 10. Resource and Performance Model

Every data byte traverses 3 client-side relay links and 3 service-side relay links in one direction. Approximate aggregate link traffic is therefore `6 x delivered one-way payload rate`; for symmetric bidirectional traffic, total aggregate link traffic is approximately `6 x (upstream + downstream rate)`. This excludes framing, ESP, retransmissions, cover traffic, and control exchanges. Each receiving peer decrypts ESP; each relay also performs circuit processing and forwards the cell. These estimates are topology arithmetic, not benchmark results.

Memory is bounded by circuit tables, stream tables, descriptor caches, and queued cells. The implementation must enforce per-circuit, per-stream, per-peer, and global limits before allocating. Use bounded queues and backpressure; never let a slow service consume unbounded memory. Relay activity is opt-in and off by default. Run relay forwarding in a separate worker process so Linux can enforce CPU and memory ceilings without allowing relay traffic to starve identity/DHT control. Each node independently enforces bandwidth, CPU, circuit, stream, and memory limits; remote peers cannot raise them or allocate resources on another node. Use local token buckets, fair per-neighbor scheduling, bounded queues, and cgroup limits. If a node is busy or lacks quota, it rejects new circuits; it does not silently exceed its cap. The numerical caps above are prototype defaults to validate on low-end and high-end hardware, not final product settings.

Benchmark at 2, 3, 5, 10, and 20 relay nodes before scale claims. Report direct-vs-hidden TCP setup time, p50/p95/p99 latency, goodput, retransmissions, CPU per Mbps, RSS per circuit/stream, packet sizes, loss, circuit failures, IKE SA count, rekey behavior, and the point at which each quota rejects work. Later evaluate UDP separately.

## 11. Failure, Abuse, and Operational Handling

| Scenario | Required behavior |
|---|---|
| IP/guard/middle/RP unreachable | Tear down affected circuit, choose a fresh eligible candidate, retry with a bounded count; never fall back to direct client-service networking. |
| IKE/ESP missing or identity mismatch | Fail closed; no clear relay traffic. Do not trust a self-presented key outside the defined bootstrap/record verification flow. |
| IP captured | It knows which service token it registered and can see the client-side adjacent relay for an introduction. It must not learn the client's original IP, service IP, or payload. It can drop/observe introductions and timing. Replace it in the next signed descriptor. |
| RP captured | It can correlate the two adjacent circuit legs and traffic pattern; it must not learn endpoint IPs or application plaintext. Client retries via a different RP. |
| DHT stale/poisoned record | Verify signatures and identity; reject invalid data; try other replicas. Report incomplete/unknown, not a false global absence. |
| Descriptor replay | Enforce signed sequence, epoch window, local highest-seen state, and short local lease; recognize first-contact and clock rollback limits. |
| Introduction flood | Per-IP/service limits, circuit-build quotas, bounded queues, backend connection caps, and optional service-scoped admission challenge. Do not add proof-of-work without measuring low-resource client impact. |
| Circuit/stream flood | Per-neighbor token buckets, global concurrency caps, authenticated circuit control, idle timeouts, and fair scheduling. |
| Slow backend or relay | Backpressure through authenticated flow-control messages; bounded memory; close stalled circuits after configured deadlines. |
| Logging/debugging | Never log private keys, invite secrets, rendezvous tokens, decrypted cells, or full path. Route/circuit diagnostics must be opt-in, short-lived, and privacy-safe. |
| Service process compromise | Outside overlay protection. A compromised host can reveal its own IP, keys, backend data, and client application contents. |
| Network partition / all IPs down | Service is unavailable. Redundancy improves odds but cannot guarantee reachability. |

Tor's own design includes explicit circuit/stream flow control and resource controls for circuit creation and introduction floods; VX6 needs equivalent controls rather than an unbounded forwarding loop. [Tor flow control](https://spec.torproject.org/tor-spec/flow-control.html), [Tor DoS controls](https://spec.torproject.org/dos-spec/overview.html).

## 12. Implementation Plan for a Separate Agent

Do not begin by modifying the current hidden package. Create a versioned replacement package behind a feature flag and keep normal service behavior unchanged.

1. **Protocol decision gate:** Resolve circuit-scoped IKE/link identity privacy without unauthenticated downgrade; select/audit maintained per-hop and end-to-end protocol libraries; define canonical encodings, key lifecycle, replay model, transcript binding, and key erasure. Get independent crypto review before networking code.
2. **Cell and state-machine layer:** Implement strict parsers, circuit/stream state, random IDs, local neighbor mapping, limits, timers, and unit/property/fuzz tests. No network transport yet.
3. **Two-hop lab:** Use two or three isolated IPv6-only VX6 peers and real IPsec. Prove circuit control is authenticated, ESP carries relay traffic, stable endpoint identity is absent from non-entry logs/protocols, malformed/replayed messages fail closed, and no cell reaches a clear route.
4. **Three-hop echo prototype:** Add one middle relay and an end-to-end encrypted TCP echo. Packet captures at each link must show only adjacent IPv6 outer peers; relay logs must not disclose endpoint NodeIDs, roles, service names, or payload. Capture memory/CPU/latency counters.
5. **Rendezvous:** Add role-symmetric RP attach with a one-use token; capture at RP and prove it cannot decrypt app data or label sides client/service. Test token replay, guessing, expiry, simultaneous sessions, and RP loss.
6. **Introduction and descriptors:** Add service-originated setup circuits, a separate new service-to-RP data circuit, 3 active + 2 standby points, hidden namespace lookup, signed descriptor refresh, outage replacement, and DHT poisoning/replay tests. Assert no application bytes traverse an IP circuit.
7. **Public/private authorization:** Verify public access does not disclose client NodeID to service, RP, or non-entry relays; private service capabilities authorize only the configured user and do not expose global identity by default.
8. **Abuse/performance:** Exercise floods, slow consumers, memory caps, resource quotas, low bandwidth, packet loss, rekeys, restarts, IP changes, and partitions. Then compare paths and tune defaults.
9. **Independent review and release gate:** External protocol/security review, reproducible two-endpoint plus relay captures, documented residual risks, and rollback plan. No “anonymous” production claim before this gate.

### Local test harness plan

Build the first harness with Linux network namespaces or isolated Docker containers; prefer network namespaces for precise IPv6/XFRM policy inspection. The harness must never add routes, firewall rules, or policies to the host namespace. It must use an isolated ULA IPv6-only test network, real strongSwan/kernel XFRM for the links under test, deterministic test identities, and a cleanup trap that removes only resources it created. Require explicit root/CAP_NET_ADMIN and fail before setup if unavailable. No public IPv4 route or IPv4 socket is permitted in the hidden data path.

Test tiers:

1. **Unit/property/fuzz:** strict messages, state transitions, key/token handling, circuit mappings, bounds, replay, and service isolation; no root required.
2. **Two-node IPv6/ESP sanity:** create a real IKE/ESP adjacent link, send a fixed-size relay cell, inspect XFRM counters and a host-link capture, and prove teardown blocks/fails closed.
3. **Idle functional prototype:** 8 logical nodes minimum (client, service, two guards, two middles, RP, one IP); grow to 12 to include 3 active + 2 standby IPs. Use distinct nodes for security-critical path roles and assert the IP is not on the service-to-RP data route. Start with one stream and no background traffic, then add concurrent streams.
4. **Role/identity privacy:** collect logs and captures from every namespace. Verify only the entry guard can map its attached endpoint to that endpoint's local IPv6 address/NodeID; each other relay sees only adjacent link addresses and opaque local circuit IDs; RP pairs two opaque circuits without a side label; IP sees an opaque service registration and adjacent requester relay but no endpoint IP, stable endpoint key, RP locator, or payload.
5. **IPv6-only enforcement:** disable IPv4 in the test namespaces, inspect listeners/routes, and fail if any hidden control/data socket binds IPv4 or any fallback occurs.
6. **Failure/resource suite:** stop each guard/middle/RP/IP in turn, restart with changed IPv6, replay setup tokens, flood circuit opens, stall the backend, and exceed circuit/stream/queue/bandwidth caps. Verify local limits protect unrelated node work and reports explain every rejection.
7. **Correlation demonstration:** with a deliberately recognizable low-rate burst, capture both endpoint-facing links and show that a broad observer may match the burst despite encryption. Then compare fixed-cell/padding/cover-traffic variants separately. This is a limitation measurement, not a test the baseline is expected to pass.

Initial functional tests assume idle nodes as requested. They do not establish capacity, anonymity against traffic analysis, Sybil resistance, or production readiness. Those require separate load and adversarial studies.

## 13. Required Acceptance Tests

Every phase must include positive, negative, and resource tests. At minimum:

- Correct locator reaches the intended service key; wrong service key fails even when name matches.
- No descriptor, intro message, circuit extension, or service frame contains either endpoint's physical IP or backend address.
- A relay sees only predecessor/successor identity and local circuit mapping; test with instrumented logs and packet captures.
- IPsec captures show ESP for every adjacent relay data link; a deliberate SA teardown causes no clear fallback.
- Intro and RP cannot decrypt a recognizable application sentinel; client and service can.
- Public service accepts a client without sending a stable client identity to the service; private service denies a missing/wrong capability before backend dial.
- Invalid signature, wrong epoch, duplicate/unknown fields, oversized payload, replayed sequence, invalid token, repeated token, and cross-service token all fail closed.
- Taking down each path role causes bounded retry and eventual clean failure; replacing an intro point restores access without changing the service identity.
- Two concurrent services and multiple streams are correctly demultiplexed; one stream cannot read another's bytes.
- Saturating one circuit does not starve all other circuits; all memory/stream/circuit limits are enforced and observable.
- Restart and IP change preserve service identity, rotate endpoints/descriptors safely, and do not leak a prior route in persisted state.
- Traffic-correlation tests document what a single-link observer, one relay, colluding guard+RP, and broad observer can infer. These tests characterize limitations; they cannot prove immunity to all correlation attacks.

## 14. Reviewer Audit: Gaps and Improvements

This proposal is coherent enough to prototype, but **not yet sufficient to claim a secure anonymous network**. The following design risks remain:

1. **No Sybil resistance or independent-operator proof.** The equal-node/no-consensus model cannot establish that three keys represent three independent operators. Sybil mitigation is explicitly deferred; report that anonymity odds depend on attacker share.
2. **Reachability assumption is unresolved.** Circuit extension requires each selected next peer to be reachable for IKE/ESP. Nodes behind restrictive firewalls, broken IPv6, or changing endpoints may not accept the link. Decide whether only publicly reachable relays are eligible or build a safe reverse-channel/NAT traversal design. Never silently use a direct endpoint fallback.
3. **Global observer correlation remains.** A broad observer compares packet timing/size/bursts at both ends and may infer that the flows match without learning IPs from a relay or decrypting data. Low-latency relaying preserves these patterns. Padding/cover traffic or mixing costs bandwidth and/or latency and still has limits. “Like Tor” does not mean Tor prevents all such correlation.
4. **DHT lookup privacy is not solved by a separate namespace alone.** Querying through a relay hides the requester IP from the DHT peer but leaks the lookup to the relay path and may permit service-target correlation. Private locator secrecy and lookup padding need a separate design.
5. **Descriptor freshness depends on clocks and local history.** Epochs help rotate keys but do not give a first-time client global freshness. Define clock-skew tolerance, rollback behavior, and whether a client accepts a valid old signed descriptor during partition.
6. **Stable identity hiding conflicts with current IKE peer authentication.** Existing IKE peers learn the identity used by their direct peer. A circuit-scoped anonymous link identity must be designed and reviewed without making the link vulnerable to active MITM. This is a hard blocker, not an implementation detail.
7. **Private-service identity semantics need product agreement.** A global client key is convenient but linkable. A service-scoped capability is more private but harder to revoke, recover, and distribute. Choose before coding private hidden access.
8. **Relay liability and abuse are operational risks.** Nodes may forward abusive traffic, be rate-limited by networks, or face operator complaints. Add opt-in relay mode, clear bandwidth/role controls, abuse handling, and safe defaults.
9. **Resource defaults are unbenchmarked.** The caps in this document are prototype guardrails only. They must be measured on low-end devices and under adversarial load before release.
10. **DHT and relay trust are different.** A valid signed record proves key possession/origin, not honesty, independent ownership, reachable service, or network-wide membership.
11. **Current code is not this design.** `internal/hidden` is a different existing implementation (currently TCP-only). Do not cite its tests as evidence for this replacement architecture.

### Before development, owners must decide

- Whether v1 supports only TCP (recommended) or requires UDP from day one.
- Which maintained protocol/library supplies circuit handshakes and end-to-end encryption; no custom cryptographic construction without external review.
- Whether hidden service locators are key-based links only or support a human-name directory, and how first-use key pinning works.
- Whether relay candidates must be publicly reachable, and what happens to IPv6-only/filtered peers.
- Whether relay participation is opt-in (recommended), and the UI/configuration for per-node resource caps.
- The private-service credential model: service-scoped capability versus service-visible client identity.
- The target adversary: local ISP, malicious relays, a fraction of Sybil nodes, or a global observer. The guarantees change materially with this choice.
- What the product may honestly call “anonymous” and which residual risks must be displayed to users.
- Whether the stable identity hiding requirement can be met with a reviewed circuit-scoped IKE/link identity design. If not, reduce the guarantee explicitly or stop; do not implement a silent identity leak.

## 15. Current State Versus This Proposal

This is a design document only. The current repository has an existing hidden-service implementation and related CLI, descriptor, and relay code. It must not be assumed to satisfy this specification. The new implementation should be developed behind a feature flag, with a migration/removal plan for the old path, and should not alter normal public/private service behavior until its own tests pass.

## References

- Tor Project, [A short introduction to Tor](https://spec.torproject.org/intro/index.html).
- Tor Project, [How Onion Services Work](https://community.torproject.org/onion-services/overview/).
- Tor Project, [Tor design paper](https://svn-archive.torproject.org/svn/projects/design-paper/tor-design.html).
- Tor Project, [Flow control specification](https://spec.torproject.org/tor-spec/flow-control.html).
- Tor Project, [Denial-of-service controls](https://spec.torproject.org/dos-spec/overview.html).
- Tor Project, [Path construction notes](https://spec.torproject.org/vanguards-spec/path-construction.html).
- IETF, [RFC 7296: IKEv2](https://datatracker.ietf.org/doc/rfc7296/).
- strongSwan, [IKE and IPsec SA renewal](https://docs.strongswan.org/docs/latest/config/rekeying.html).
- Scherer, Weis, Strufe, [Provable Security for the Sphinx Packet Format](https://petsymposium.org/popets/2024/popets-2024-0140.php).
