# VX6 network simulator (#69)

Builds an Internet-like topology on one Linux host and runs the **real** VX6
node in it, to study DHT scale, churn, eclipse resistance and bootstrap flow
before any physical multi-region deployment.

- **Routers / ASes**: one network namespace per AS (tier-1 transit, ISPs, orgs,
  attacker), joined by veth "cables", each announcing a real IPv6 `/40` over
  eBGP via FRR. Longest-prefix match makes BGP prefix hijacks real.
- **Hosts**: one namespace per VX6 node on a bridged `/64` LAN, with
  human-looking names (e.g. `AMBER-FOX`), realistic ASN concentration, and
  residential-vs-office placement.
- **Nodes**: `simnode` runs `node.Run` (real DHT, signed records, registry,
  liveness). Only the IPsec tunnel is replaced by a pass-through that still
  requires valid signed endpoint records — so thousands fit on one host. This
  tier measures the DHT, **not** ESP. A separate `-ipsec-nodes` tier runs the
  real `vx6` + `vx6-ipsecd` + strongSwan for security scenarios and MITM.

## Safety

`simnode` refuses to start unless `VX6_NETSIM_NO_IPSEC=I_UNDERSTAND` is set and
its address is in `2001:db8::/32` or `fc00::/7`. It can never run as a real,
tunnel-less node on a public address.

## Use

```sh
go build -o /usr/local/bin/simnode ./tests/netsim/simnode
go build -o /usr/local/bin/netsim  ./tests/netsim/netsim

netsim doctor                                   # check host (needs root, IPv6, FRR)
netsim plan   -nodes 500 -out plan.json         # generate + validate (no root)
netsim render -params plan.json | less          # every ip/FRR command, no changes
sudo netsim run -params plan.json -out results/ # build and drive the sim
sudo netsim run -nodes 50 -dry-run -out /tmp/r  # preview without touching the host
```

`run` joins nodes in waves (`-schedule`), snapshots every node's routing table
between waves and during a settle period, runs random lookup probes, and writes
`results/report.json` plus per-round and per-node snapshots. The report shows,
per round: nodes joined, average/min/max active routing peers, average RSS, and
lookup success / not-found / p50 / p95 / average rounds — i.e. how many refresh
rounds the DHT needs to go idle, and how bootstrap scales.

See [`docs/testing/netsim-plan.md`](../../docs/testing/netsim-plan.md) for the
threat model, scenario list, host sizing and cost estimate.
