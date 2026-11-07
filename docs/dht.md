# DHT

The VX6 DHT is the distributed lookup layer behind public, private, and hidden discovery.

## What It Stores

- node records by a hash of the canonical name
- node records by the full public-key-derived NodeID
- public service records
- private per-user catalogs
- hidden service descriptors

## What It Does Today

- multi-source lookup confirmation
- full 256-bit NodeID derivation from the complete Ed25519 public key
- separately domain-separated full SHA-256 name lookup keys
- canonical node names: uppercase letters, digits, and middle hyphens; 3-16 characters
- typed DHT RPC envelopes, validated before type-specific payload processing
- iterative lookup fanout defaults to four closest peers
- local identity trust checks keyed by NodeID and separate friend-retention preferences
- conflict detection
- conflict candidate reporting for same-name lookups
- interactive user choice support in the CLI when multiple candidates are returned
- bounded replication
- adaptive replication target under churn/failure pressure
- refresh tracking
- conservative store admission with signed trusted writes, authoritative publisher checks, stale-write rejection, and per-source throttling
- optional ASN/prefix contact diversity kept separately from XOR routing
- hidden descriptor caching, jittered refresh polling, and background cover lookups
- tracked hidden-invite warmers to reduce purely on-demand lookup patterns
- scheduled privacy traffic buckets (time-sliced baseline hidden descriptor cover activity)
- anomaly-driven cover escalation (higher hidden cover load when lookup instability or consensus failures rise)
- multi-group hidden descriptor consensus before acceptance
- blinded rotating hidden keys
- encrypted hidden descriptor payloads

## Routing Table: Current Implementation

The core bounded routing table and persistence path from
[#62](https://github.com/ethical-buddy/vx6/issues/62) have landed. Follow-up
[#71](https://github.com/ethical-buddy/vx6/issues/71) tracks the remaining
validation and tuning work; closing #62 does not claim scale behavior is
proven.

### Two Routing Coordinates

Every known peer can be reached through two independent 256-bit coordinates:

- **NodeID:** SHA-256 of the complete Ed25519 public key. Identity lookups use
  the `lookup_key` request type and this coordinate.
- **NameHash:** SHA-256 of the versioned, canonical uppercase node name. Name
  lookups use `lookup_name` and this separate coordinate. The name is not
  substituted for NodeID.

The routing table keeps an index for each coordinate. A peer record can appear
in both indexes, but they answer different lookup questions. Returned peers
are sorted by XOR distance to the requested target; recency does not change a
peer's coordinate or override the distance calculation.

### Bucket and Candidate Limits

The initial code defaults are:

| Setting | Current value | Meaning |
|---|---:|---|
| XOR ranges per coordinate | 256 | Possible ranges for a 256-bit coordinate. Empty ranges stay empty. |
| Normal DHT `k` value | 20 | Replication/closest-set target; not a hard per-range cap. |
| Parallel lookup width | 4 | At most four peers queried at once. |
| Referrals returned per lookup RPC | 4 | Closest active peers for the requested coordinate. |
| Underfilled refresh threshold | 15 | A non-empty range below this value is eligible for refresh. |
| Pending candidates total | 512 | Global cap across not-yet-active referrals. |
| Startup candidates restored | 50 minimum, up to 512 | Eligible saved contacts are offered for revalidation; none start active. |
| Active routing contacts | No fixed count ceiling | Authenticated peers are retained in dynamically growing slices/maps. |
| Local peer-index rows | 512 unique identities | bbolt keeps one row per NodeID; the category indexes refer to those same rows. |
| New-peer probation | 2 hours | Authenticated peers can route during probation; their probation state is persisted locally. |
| Offline history retention | 30 days | Based on local `OfflineSince`; old unpinned history is pruned. |

The arrays of ranges have fixed slice headers; peer slices grow only when
contacts are learned. A fresh node does not allocate thousands of peer records
merely because the coordinate space has 256 possible ranges. A small network
can retain every authenticated peer it learns; `k=20` is a normal closest-peer
and replication target, not a maximum per range. There is no fixed global
active-peer or database-row count ceiling. At restart, the node loads at least
50 eligible saved contacts when that many are available, up to the 512-peer
warm-start limit, and revalidates them before promoting them to active routes.
The 512-row cap applies to the secondary local retention index, not the live
XOR routing tables.

New successful contacts move to the front of their local range. XOR distance,
not recency or network location, determines which contacts are closest to a
lookup target. All authenticated peers are retained locally, including peers
sharing one prefix or ASN. There is no per-prefix, per-ASN, per-range, or fixed
global active-peer count limit. The 512-entry pending limit applies only to
unverified referrals and startup candidates, not authenticated peers.

The peer database also keeps dynamic categories for friend identities, peers
whose services were used, the closest 50 peers in each XOR coordinate, active
contacts, probation, inactive history, and diversity representatives. These
are indexes over the same capped NodeID rows, not duplicate records; one peer
may belong to several categories. Friend/use preference affects local retention
and candidate revalidation only. It does not change XOR distance, normal
referral ordering, or replication. Diversity metadata is a reachability hint,
not identity proof.

### Health, Retry, and Refresh

A failed DHT lookup by itself does not remove a peer. A separate liveness worker
checks active contacts one at a time, with a stable initial offset to avoid
starting all checks together. It checks the signed endpoint, probes the
advertised IPv6 address, ensures the IKE/IPsec peer identity, and confirms the
protected VX6 path. Consecutive failed liveness checks must be at least five
minutes apart; the third miss moves the peer to local inactive history. A
successful check resets the miss count. The worker is serialized, so a slow
peer delays later checks; the five-minute interval is a minimum spacing per
peer, not a promise that an arbitrarily large table is swept within five
minutes.

Newly authenticated contacts have a two-hour probation marker. They can
participate in this node's routing after signed identity, IKE/IPsec, and
protected liveness checks succeed. The marker and observations are saved in
the local index; probation is not a network-wide admission vote or proof that
a peer is honest. An unverified referral remains only a candidate until it
passes those checks.

Inactive contacts are excluded from ordinary lookup referrals. An explicit
bootstrap lookup can include locally retained inactive contacts as address
hints; a returned hint is not promoted to active and must be validated again.
Inactive unpinned history is retained for up to 30 days from the local time it
was marked inactive. Local times control retry and cleanup only; they do not
prove identity, DHT membership, or which signed record wins.

The node runs a local routing refresh approximately every 5 minutes, with
20-percent jitter (about 4-6 minutes). One round selects at most two stale or
underfilled non-empty bucket targets and asks up to four closest contacts for
referrals. It also asks up to four close contacts about the node's own NodeID
coordinate. This is bounded local maintenance, not a network-wide ping sweep.
An authenticated referral is kept as a candidate until it responds through the
normal signed-identity, IKE, and protected VX6 path. Peer liveness checks are
separate from these bounded routing refresh lookups.
When a node has no active routing contacts, refresh uses the explicit bootstrap
lookup type for both its NodeID and NameHash coordinates. That request can
return recently inactive contacts as hints; an ordinary lookup never gets
those inactive contacts from a peer.

### Persistent Peer Cache

When the DHT is enabled, VX6 stores local peer observations in
`<data-dir>/dht-peers.db`, an embedded bbolt database. Each update is a database
transaction; peer values are JSON for inspectability, with a separate
NameHash index. The database contains public peer metadata and local
observations, not private identity keys. The file is created with mode `0600`.

The bbolt peer table is capped at 512 unique NodeIDs. On restart, saved rows
are returned as candidates in preference order: friends, recently used peers,
closest-coordinate peers, diversity representatives, then other active,
probationary, and inactive contacts. At least 50 are offered when that many
eligible rows exist. They must be revalidated before returning to active
routes. Reading a record from disk is never proof that its address is live.
Inactive non-friend history expires after 30 days.

The CLI supports `vx6 peer friend --record ENDPOINT.json` and
`vx6 peer unfriend --node-id ID`. Friend status is stored by NodeID and means
“retain and retry this peer locally”; it does not reserve the advertised name
or grant service access. Successful direct-service traffic updates a local use
count and last-used time through the authenticated loopback control channel.
A local key pin is separate: it checks the public key for that exact NodeID
and is not a global name claim. Name lookup still reports multiple signed
identities sharing a name rather than silently selecting a locally pinned one.
A signed name conflict is reported as
multiple identities; it does not automatically evict one contact, because a
single peer's conflict report is not a network-wide proof that one identity is
the rightful owner.

### What Is Still Needed For #71

- Validate that the diversity index helps lookup reachability without changing
  XOR ordering or excluding peers in sparse or organization-only networks.
- Test that malformed/unverified referrals and an inbound contact flood cannot
  displace authenticated routes; test promotion only after fresh peer
  validation and test pinned state across restart.
- Add repeatable sparse, dense, churn, and prefix-concentrated simulations.
- Benchmark memory use, lookup/refresh work, false eviction, and recovery under
  churn. The current values are reasoned starting defaults, not measured
  production tuning.

Until those items are done, the routing table should be treated as an
implemented prototype with bounded behavior, not as a proven large-network
resilience guarantee.

The latest full-suite run also exposed a separate failure in
`TestHiddenServiceRendezvousPlainTCP`: two rendezvous circuits reused a relay.
This is not a DHT table acceptance criterion, but it is an unresolved
repository test failure and should be investigated in the hidden-service
workstream.

## What It Does Not Do Yet

- disk-backed large-scale value storage
- a stable, independently tested routing-table refresh/eviction policy across large churn
- global proof that a human-readable name is unique
- Sybil resistance or guaranteed protection against a coordinated eclipse
- full Tor-grade traffic-analysis resistance
- operator-managed publish tokens for high-trust deployments
- perfect live migration of an already-running hidden TCP stream after relay loss

## Hidden Descriptor Notes

Hidden descriptors are stronger than plain alias lookup because:

- the lookup key is blinded
- the descriptor payload is encrypted
- the invite carries the secret lookup part
- descriptor store and lookup can be relayed anonymously

Still, the responsible DHT holders can observe timing and volume on a blinded descriptor key. That is one of the main remaining privacy limits.

VX6 reduces the obvious alias leak, but it does not hide all metadata from a powerful observer yet.

## WAN/Churn Adaptation

The replication target can increase under churn based on observed lookup
failures. Lookup fanout and the bounded query budget currently remain fixed by
the configured lookup limits; they do not automatically increase when failures
rise. Adaptive lookup tuning remains a separate implementation and benchmark
task.

## Adversarial Test Harness

The DHT package includes CI-safe adversarial tests for:

- hidden cover escalation behavior under anomaly pressure
- hidden descriptor consensus threshold behavior across independent groups

These tests are intended to catch security-regression drift early without requiring privileged socket setup.

## ASN Diversity

VX6 can use an optional offline ASN map to populate its local supplemental
contact index. If the map is missing, IPv6 prefixes still provide grouping.
These contacts are only lookup fallbacks after normal XOR candidates are
exhausted; they do not change routing order, admission, or replica placement.

A signed value still needs multiple supporting sources and independent lookup
branches. ASN, provider, and prefix counts do not gate acceptance, so peers in
one organization or network can still resolve signed records. Diversity data
is a reachability hint, not identity proof.

This diversity is a local selection heuristic, not an identity proof. ASN,
prefix, PTR, WHOIS, geography, or ISP-derived data can be missing, stale, or
misleading and must not override cryptographic signatures or local trust.
SLAAC neighbor discovery only sees the local IPv6 link; it cannot discover the
global VX6 network. The current optional ASN map is offline and is not an
automatic BGP/WHOIS lookup.

The ASN map is optional and local. It is not fetched over the network.

## Store Admission

Trusted keys are handled carefully.

That means:

- the record must verify correctly
- the envelope must be from the authoritative publisher for trusted keys
- stale verified values are rejected
- repeat writes from the same source are rate limited

This keeps the DHT from accepting arbitrary trusted writes just because they are signed.

## Name Conflicts

VX6 treats the node keypair and NodeID as the real identity.

If two different nodes try to use the same human-readable node name:

- each node's local registry can reject or flag a conflict it has actually
  observed; this is not a network-wide atomic name reservation
- DHT lookup can report every conflicting candidate instead of silently picking one
- the CLI can show the full set of candidates and let the user choose which identity is correct
- each running node periodically checks its own name key and logs a clash warning if another identity claims the same name

This is intentional. Human names are labels. NodeID is the identity.

At init time and during explicit rename, VX6 can probe known peers before
accepting a name. A conflict found is shown and should block silent takeover.
No response is inconclusive: it cannot prove that nobody else uses the name.
The CLI reports this state as `unconfirmed`, not `available`, and may continue
publishing the node's signed claim. A conflicting claim blocks the name check.

`vx6 peer pin --record ENDPOINT.json` stores a local public-key trust check
for that NodeID, and `vx6 peer unpin --node-id ID` removes it. This local choice
does not reserve a name, override conflict display, prove DHT-wide membership,
or authorize access to a service. Use `peer friend` separately for retention.

## Peer-Local Maintenance Model

Each node owns its own routing-table decisions. The current table separates
active XOR contacts, unverified candidates, offline history, and a persisted
secondary index capped at 512 unique identities. That local index has friend,
recent-use, closest-coordinate, diversity, active, probation, and inactive
categories. The live active XOR table itself has no fixed count ceiling. The
50-contact warm-start floor is a target when enough eligible records exist,
not a requirement to invent or admit peers. The separate unverified-candidate
queue is also capped at 512. Identity trust and friend retention are different
local choices.

Lookups should ask several independently selected peers, validate signatures
and record freshness locally, compare conflicting answers, and continue via
closer contacts. A response count is evidence about what those responders
claim, not a consensus certificate. Use a bounded query budget and return
“not confirmed” when the search budget or reachable paths are exhausted; do
not report “name is free” based solely on silence. Pinning a known identity and
an out-of-band signed contact/QR are stronger recovery options for a specific
peer, but do not make the overall DHT immune to Sybil or eclipse attacks.

Implementation work is tracked by [#60](https://github.com/ethical-buddy/vx6/issues/60),
[#62](https://github.com/ethical-buddy/vx6/issues/62),
[#63](https://github.com/ethical-buddy/vx6/issues/63),
[#64](https://github.com/ethical-buddy/vx6/issues/64), and
[#65](https://github.com/ethical-buddy/vx6/issues/65). These are target plans;
do not read them as already implemented guarantees.

## Identity And Lookup Protocol

VX6 has two different lookup keys:

- Identity key: `SHA-256(full Ed25519 public key)`, represented as `vx6_` plus
  all 64 lowercase hexadecimal characters. This identifies a keypair, not a
  human-readable name.
- Name key: `SHA-256("vx6/node-name/v1\\0" + canonical_name)`, represented as
  `node/name/` plus all 64 lowercase hexadecimal characters. The name itself is
  not the DHT routing target.

Names are normalized to uppercase at user-facing input boundaries. Canonical
wire records must already be uppercase and contain only `A-Z`, `0-9`, or `-`,
with length 3-16 and no leading or trailing hyphen. Two different public keys
may still claim one name; local lookup can report a conflict, but there is no
global atomic name reservation.

An iterative name/key lookup begins with the four closest known peers, asks
them in parallel, and follows the closest candidates returned by those peers.
“No closer peers” means only that a responding peer has no closer contact in
its local table. It does not prove that no closer peer exists elsewhere or
that a name is globally unused. A network partition or eclipse can hide valid
answers. The current implementation also has a finite query budget and
timeouts; unlimited traversal is intentionally not used because peers could
otherwise consume unbounded network, CPU, and memory. The exact termination,
negative-result, and resource-limit policy needs its own follow-up design.

The DHT wire schema defines operation types such as `bootstrap`, `update`,
`lookup_name`, and `lookup_key`; requests and responses carry wire version `1`.
Both sides reject missing or unsupported versions. DHT JSON decoding rejects
unknown fields, duplicate object keys, and trailing values; SHA-256 lookup
coordinates must be full-length lowercase hexadecimal strings. Invalid node
names do not produce a fallback lookup hash. This intentionally means older
unversioned peers cannot exchange DHT messages with this version.

The complete first-join lifecycle,
where a seed only gives starter contacts and the joining node then performs
its own lookup and publication, remains tracked separately in #64. Bootstrap
is not a network-wide trust decision. IKE authentication proves possession of
the configured Ed25519 identity key for the peer session; DHT replies alone do
not prove the remote node owns another node's key.

Lookup timestamps are not used as authority to establish identity or prove
that a node exists. Local timestamps may be used to rank or expire cached
contacts. Some signed records and other subsystems still have their own
validity/freshness fields; those must not be interpreted as global DHT
consensus.

Changing from the previous truncated NodeID format to the full 256-bit format
is a protocol compatibility break. All peers that need to exchange and verify
the new records must run compatible software; local identity files are
migrated, but old published records and cached IDs are not upgraded by that
local migration.
