# Discovery

VX6 discovery has two parts.

## Local Registry

The registry is the local working view of the network.

It stores:

- known node records
- known service records

Peers exchange signed snapshots and updates.

## DHT

The DHT is the distributed lookup layer.

It is used when:

- the record is not already in your local registry
- you want a public service by exact name
- you want a private service catalog for one user
- you want a hidden descriptor by invite

## Important Rule

VX6 is not meant to store every user and every service on every node.

Instead:

- routing tables stay small
- records are replicated to a bounded set
- lookups walk toward the key

That is what makes the design scale better than a full global registry.

Each node's routing table is a partial, changing view, not a synchronized copy
of the network. XOR distance tells a node which of its known contacts are
closer to a lookup key; it cannot reveal a closer peer it has never learned.
Iterative lookups, signed records, table refresh, replacement contacts, and
churn handling are therefore all required. Multiple responses can expose
conflicts and reduce reliance on one responder, but do not create a global
guarantee. If a bounded search finds no record, the correct result is “not
found in the reachable search,” not proof of nonexistence.

The planned routing lifecycle and test model are tracked in
[#62](https://github.com/ethical-buddy/vx6/issues/62),
[#64](https://github.com/ethical-buddy/vx6/issues/64), and
[#65](https://github.com/ethical-buddy/vx6/issues/65). Metadata and signed
record semantics are tracked separately in
[#63](https://github.com/ethical-buddy/vx6/issues/63).
