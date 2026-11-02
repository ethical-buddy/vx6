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
- persistent local peer pins that bind a name to a full NodeID/public key
- conflict detection
- conflict candidate reporting for same-name lookups
- interactive user choice support in the CLI when multiple candidates are returned
- bounded replication
- adaptive replication target under churn/failure pressure
- refresh tracking
- conservative store admission with signed trusted writes, authoritative publisher checks, stale-write rejection, and per-source throttling
- ASN-aware diversity when a local ASN map is present
- hidden descriptor caching, jittered refresh polling, and background cover lookups
- tracked hidden-invite warmers to reduce purely on-demand lookup patterns
- scheduled privacy traffic buckets (time-sliced baseline hidden descriptor cover activity)
- anomaly-driven cover escalation (higher hidden cover load when lookup instability or consensus failures rise)
- multi-group hidden descriptor consensus before acceptance
- blinded rotating hidden keys
- encrypted hidden descriptor payloads

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

The DHT now adjusts lookup and replication behavior from live lookup failure signals:

- lookup fanout (`alpha`) increases when recent failures rise
- lookup query budget (`beta`-style budget) increases under churn
- replication target increases under churn to keep availability stable

This reduces timeout risk in unstable WAN conditions without permanently paying high bandwidth cost in healthy periods.

## Adversarial Test Harness

The DHT package includes CI-safe adversarial tests for:

- hidden cover escalation behavior under anomaly pressure
- hidden descriptor consensus threshold behavior across independent groups

These tests are intended to catch security-regression drift early without requiring privileged socket setup.

## ASN Diversity

VX6 can use an offline ASN map to improve DHT diversity checks.

When the map is present:

- lookup confirmation prefers independent ASNs first
- replica selection spreads records across ASNs before falling back to prefix diversity

When the map is missing or incomplete:

- VX6 falls back to the current prefix-based provider grouping
- the DHT still works normally

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

Users can explicitly pin a verified peer endpoint record with
`vx6 peer pin --record ENDPOINT.json`. The local pin stores the canonical name, complete
NodeID, and public key separately from the expiring address record. A pin
survives endpoint expiry and restart; when resolving that name, VX6 looks up
the pinned identity and rejects a different key rather than silently
switching. `vx6 peer unpin --node-id ID` removes the local pin. A pin means
“this is the key I trust for this local contact”; it is not proof of DHT-wide
membership, global name ownership, or safety of that peer's services.

## Target Peer-Local Maintenance Model

Each node owns its own routing-table decisions. The planned table separates
active closest-XOR contacts, replacement candidates, verified/recently useful
peers, diversity candidates, and locally remembered offline contacts. These
are selection classes and bounded quotas, not a second global DHT or a promise
that every node has the same view. A peer must not be admitted just because it
connects often or claims a desirable ASN.

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
`lookup_name`, and `lookup_key`; current requests validate the type against
their action and target before processing. The complete first-join lifecycle,
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
