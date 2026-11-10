# VX6 network simulator (#69)

This Linux-only harness runs the real VX6 node/DHT in separate processes and
network namespaces. Its scale tier replaces IKE/IPsec with a **lab-only
pass-through**. It tests DHT behavior and bbolt peer recovery, not ESP
confidentiality or IKE authentication.

## What this runner currently tests

- Creates a deterministic IPv6/FRR topology, with a random run-specific prefix
  on every Linux namespace name.
- Starts nodes in the generated join waves using signed endpoint records from
  existing nodes as bootstrap contacts.
- Captures routing snapshots, then performs both NodeID and canonical-name
  lookups. Name lookups send the name-hash coordinate, not the clear name, to
  the DHT.
- Gracefully restarts a selected number of nodes and checks identity stability
  plus whether bbolt-persisted peer candidates return to the active routing
  snapshot.
- Exercises the default iterative lookup ceiling of 20 rounds, 4 concurrent
  peers, and 80 total peer queries (10-second total timeout). The DHT unit test
  builds a signed multi-hop referral graph and verifies that one lookup really
  queries more than 12 peers, while lookup-only referrals stay transient.
- Writes exact lookup outcomes, observed lookup limits, latency/query-count
  percentiles, convergence snapshots, route ASN/prefix distribution, per-node
  RSS, aggregate simnode CPU time, host CPU/memory context, logs, and hashes.

The attacker-AS entries in this version are ordinary honest simnodes. The run
does **not** yet inject poisoned referrals, partitions, address changes, liveness
expiry, churn schedules, or eclipse attacks. Those are not proven by running
this harness. The real-IPsec two-peer suite remains the evidence for IKE/ESP.

## Build and inspect without changing the host

From the repository root:

```sh
go build -o /tmp/vx6-simnode ./tests/netsim/simnode
go build -ldflags="-X main.buildRevision=$(git rev-parse HEAD)" \
  -o /tmp/vx6-netsim ./tests/netsim/netsim

/tmp/vx6-netsim doctor
/tmp/vx6-netsim plan -nodes 10 -schedule 1,1,2,6 -seed 69 \
  -out /tmp/vx6-plan-10.json
/tmp/vx6-netsim render -params /tmp/vx6-plan-10.json
```

For PR testing, GitHub Actions builds Linux `amd64` and `arm64` binaries and
publishes them as 30-day workflow artifacts named
`vx6-netsim-linux-amd64` and `vx6-netsim-linux-arm64`. Download the artifact
from the PR's **Linux simulator binaries** checks. Each archive contains
`vx6-netsim`, `vx6-simnode`, `SHA256SUMS`, and a short safety note. These are
test binaries, not a VX6 release package. In the extracted artifact directory,
verify both binaries before running them:

```sh
sha256sum -c SHA256SUMS
chmod +x vx6-netsim vx6-simnode   # artifact downloads drop the executable bit
```

`plan`, `render`, and `run -dry-run` do not create namespaces. For a dry-run,
use a new output directory:

```sh
/tmp/vx6-netsim run -nodes 3 -schedule 1,2 -seed 69 -simnode /tmp/vx6-simnode \
  -settle-rounds 0 -probes 1 -restart-count 1 -dry-run \
  -out /tmp/vx6-netsim-dry-3
/tmp/vx6-netsim teardown -dry-run \
  -params /tmp/vx6-netsim-dry-3/topology.json
```

## Live 3/5/10-node run

Only run this on a disposable Linux host or Linux VM. It needs root (or
equivalent `CAP_NET_ADMIN`/`CAP_SYS_ADMIN`), IPv6, `iproute2`, and FRR for
inter-AS BGP. Do not run on a production host or a host whose network must stay
untouched. The commands modify only run-specific namespaces; they do not
configure the host's normal interfaces. Use an empty, root-owned private output
directory for each run. The output path must not be inside a user-owned home
directory when using `sudo`.

Debian and Ubuntu install `zebra` and `bgpd` in `/usr/lib/frr`, outside
`PATH`; run `netsim` with `PATH=/usr/lib/frr:$PATH` (`doctor` points this
out). FRR drops privileges to the `frr` user, so each run keeps the daemons' pid
files, vty sockets and `zserv.api` in its own `/run/vx6-netsim/<run-id>/<router>`
directory (one per AS router, so many zebra/bgpd pairs can run side by side).
Cleanup and `teardown` remove that directory. Nodes join only after every AS
router has a BGP route to every other AS prefix; the run aborts if BGP has not
converged within 90 seconds.

Example for ten nodes; repeat with 3 and 5 nodes, using fresh output paths and
topology-appropriate topologies (`-tier1 2 -isps 1 -orgs 1 -schedule 1,2` for
3; `-tier1 2 -isps 2 -orgs 2 -schedule 1,1,3` for 5; at least two tier-1 ASes
are required). These smaller AS counts keep a smoke run manageable while
retaining multiple organizations, ISPs, and an attacker-AS topology entry:

```sh
sudo install -d -m 0700 -o root -g root /var/tmp/vx6-netsim-10
sudo env PATH=/usr/lib/frr:$PATH /tmp/vx6-netsim run \
  -tier1 2 -isps 2 -orgs 3 -attackers 1 \
  -nodes 10 -schedule 1,1,2,6 -seed 69 \
  -simnode /tmp/vx6-simnode -settle-rounds 4 -settle-gap 60s \
  -probes 10 -restart-count 1 -out /var/tmp/vx6-netsim-10
```

Keep `-settle-gap` at 60 seconds or more. Joined nodes promote bootstrap
contacts to active DHT peers on the node's own timers; with short gaps (for
example 5s) every snapshot shows zero active peers and every lookup misses. The
graceful-restart sample runs right after the last join wave, so on short runs
it usually restarts a node that has no peers yet and proves only identity
stability.

`run` writes a verdict into the report. It exits non-zero with verdict
**FAIL** when lookups ran but none found its known-existing target, or when no
node had an active DHT peer in the final round; both lookup coverage rows are
then marked FAILED. **PASS** only means the DHT formed and some lookups
succeeded; read the found rate and per-round tables for anything more.

The runner attempts cleanup on normal exit, error, SIGINT, and SIGTERM. If it is
forcibly killed (for example, SIGKILL or host shutdown), inspect the report and
then use the exact topology file to clean up only that run:

```sh
sudo /tmp/vx6-netsim teardown \
  -params /var/tmp/vx6-netsim-10/topology.json
```

`teardown -dry-run` prints the namespaces and recorded process files it would
clean without changing the host. Cleanup validates the run ID and exact derived
namespace names; it refuses arbitrary namespace names. The runner records each
process ID only after the process has exec'd inside its named namespace, with
the program (argv[0]) and that namespace's inode; teardown signals a PID only
if both still match, so a reused PID is left alone.

## Evidence to return

Each output directory contains `report.md`, `report.json`, `topology.json`,
`commands.log`, per-round JSON, `snapshots/`, node state/logs, FRR logs, and
process manifests. Return the whole directory (or an archive) for each 3/5/10
run, plus the exact command and host RAM/OS details. The report records binary
hashes and the DHT lookup policy actually exposed by running nodes.

The report's percentiles are calculated from observed lookup attempts. Its
route-diversity figures map each active peer address to the generated test
topology's ASN and IPv6 `/48`; these are measurements, not enforcement claims.
Host-wide CPU and memory are context and include unrelated host activity. A
successful run proves only the listed scenarios under that run's parameters;
it cannot prove global lookup completeness, adversarial resilience, or a
perfect DHT.

These are local functional checks, not a guarantee of global lookup
completeness, Sybil resistance, production-scale capacity, or IPsec security.
See [`docs/testing/netsim-plan.md`](../../docs/testing/netsim-plan.md) for the
scope and remaining scenario work.
