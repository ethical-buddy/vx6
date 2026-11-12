# Local DHT Scale-Test Results

## Scope and reproducibility

These are fresh runs of the committed harness at revision `ca0dd6e2104000b4f9077b4ac42aa7d82b94d795`. The runner starts real production DHT servers on distinct IPv6 loopback TCP ports in one Go process. It exercises staged joins, signed test records, NodeID and name-hash iterative lookups, lookup traces, routing snapshots, bbolt write/reopen/read-back, and negative controls.

It does **not** run the full VX6 node lifecycle, IKE/ESP, Internet routing, IP/ASN diversity, or the real startup/restart lifecycle. Reciprocal admission/announcement after the modeled key-authenticated exchange is represented by the harness, not established by IKE. These results are evidence about the production DHT components under this simulated topology, not proof of global reachability or attack resistance.

## Run environment

- OS/architecture: Linux/amd64
- Go: 1.27.3
- Host: 16 logical CPUs
- Commit: `ca0dd6e2104000b4f9077b4ac42aa7d82b94d795`
- Seed: `75`
- Full lookup settings: at most 20 rounds, 4 parallel queries per round, 80 total queried peers, 10-second lookup deadline
- The host was used for sequential runs. Go heap-system figures below are not process peak RSS; use `/usr/bin/time -v` for that.

Commands, from the repository root:

```sh
go run ./tests/dht-scale -nodes 10 -pairs 20 -seed 75 -out /tmp/vx6-dht-scale-10
go run ./tests/dht-scale -nodes 100 -pairs 100 -seed 75 -out /tmp/vx6-dht-scale-100
go run ./tests/dht-scale -nodes 500 -pairs 250 -seed 75 -out /tmp/vx6-dht-scale-500
```

Each output directory contains the Markdown/JSON summary, all-node snapshots, per-lookup traces, join traces, per-node bbolt files, and host metadata. The committed branch includes the runner and plan; large generated output directories are intentionally not committed.

## Results

| Nodes | Positive target checks | Complete positive lookups | Found but incomplete | Negative controls | Exact oracle top-4 matches / all checks | Mean active peers (min-max) | Local table global top-4 recall: NodeID / name | Bucket placement errors | bbolt rows / file bytes | Go heap alloc / heap sys | Goroutines | Output artifacts | Runtime |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 60/60 | 60/60 | 0 | 2/2 not found; 0 false positives | 41/62 | 8.00 (6-9) | 75.00% / 75.00% | 0 | 80 / 655,360 B | 3,204,424 B / 11,665,408 B | 21 | 2.0 MB | 0.13 s |
| 100 | 240/240 | 240/240 | 0 | 2/2 not found; 0 false positives | 185/242 | 23.71 (7-49) | 35.75% / 74.00% | 0 | 2,371 / 14,221,312 B | 21,074,416 B / 61,270,624 B | 201 | 31 MB | 1.902 s |
| 500 | 1,040/1,040 | 1,014/1,040 | 26 | 2/2 not found; 0 false positives | 750/1,042 | 39.476 (9-91) | 18.75% / 73.15% | 0 | 19,738 / 111,411,200 B | 88,624,832 B / 478,019,584 B | 1,001 | 232 MB | 15.072 s |

At 500 nodes, NodeID lookups were complete in 520/520 cases; name-hash lookups found all 520 targets but completed only 494/520. The 26 incomplete name lookups reached the configured query budget. This distinction matters: “found the target” does not mean “finished convergence and proved there are no closer referrals.”

## Interpretation

- **Positive reachability in this harness:** Every sampled existing target was returned as a matching signed identity at all three sizes. The tested referrals and target records were accepted by the production lookup validation path.
- **Negative controls:** The two absent-target controls returned not-found with no false positive at each size. Two controls per run are a smoke check, not statistically meaningful proof of absence correctness.
- **XOR arithmetic and placement:** The independent full-width XOR oracle found zero bucket-placement errors. This checks the recorded local bucket index, not whether every node has learned the globally closest peers.
- **Convergence concern:** At 500, local-table recall of the globally closest four NodeID peers was only 18.75%, while name-hash recall was 73.15%. These are the strongest routing follow-ups. A table cannot retain a globally close node it has not learned; inspect the all-node snapshots, joins, and referrals to identify where NodeID coverage is lost.
- **Lookup work limit:** The 26 budget-limited name lookups show that an 80-peer budget can be insufficient for this generated topology/lookup mix. Do not simply raise the cap before examining the traces; first identify redundant queries, stalled progress, referral quality, and whether the result should be marked incomplete as it currently is.
- **Topology is synthetic:** Every simulated listener is reachable over loopback. This avoids packet loss, firewall, IPv6 provider, and IPsec variables, so it cannot establish real-world liveness or availability.
- **Resource growth:** The 500-node output is 232 MB, largely because complete per-node database snapshots and detailed traces are retained. Go heap-system use was about 456 MiB. Measure process RSS with `/usr/bin/time -v`; do not equate heap-system with RSS. The simulator is intentionally evidence-heavy and its report volume is not the production VX6 storage footprint.

## Daiker's requested follow-up

1. Re-run these exact commands and confirm the results against the included revision and seed before changing code.
2. For 500 nodes, inspect every incomplete name trace and summarize why it consumed the 80-query budget: duplicate referrals, repeated responders, no XOR progress, timeout/error, or useful new candidates.
3. Explain the NodeID global-top-four recall drop from 75% at 10 nodes to 18.75% at 500. Use join snapshots and per-node routing buckets to find disconnected learning paths, not just aggregate percentages.
4. Report active-degree outliers (especially the 9-peer minimum and 91-peer maximum at 500), whether the transport graph is connected, and which nodes have a low local nearest-peer recall.
5. Check bbolt category counts and in-memory versus reopened peer rows, and call out any retention-policy differences.
6. Do not change lookup ceilings or routing admission policy until the trace-based cause is documented. If proposing a change, include a before/after run with the same seed, commands, and report artifacts.
7. After 500-node analysis is clean, run 1,000 nodes only if the host has at least 8 GB RAM and 5 GB free disk. Capture `/usr/bin/time -v`, CPU model, RAM, kernel, Go version, commit, elapsed time, and output size. Stop if resource use becomes unsafe or if earlier stages expose correctness failures.

## Evidence limitations

These numbers do not prove that all active peers are discoverable, that every node retains its global closest peers, that an exhausted lookup proves global absence, that the overlay resists malicious peers, or that the full service/IPsec stack works. The next useful evidence is trace-level diagnosis and then a production-lifecycle test for the contracts this harness models.
