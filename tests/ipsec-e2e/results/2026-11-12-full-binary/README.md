# VX6 Two-Node Full-Binary Integration Run

Date: 2026-11-12

Source branch and revision: `main`, `ba73abf` (`test(dht): verify four closest referrals from 50 signed peers (#79)`). The integration harness changes in this commit were applied to that revision before the run.

## Result

The final two-node Docker run passed. Both normal peers ran the production `vx6 node` binary, with strongSwan IKEv2 and kernel XFRM/ESP. Each peer used an isolated IPv6 ULA subnet connected through a forwarding container. The wrong-key case ran in a separate fresh topology.

The harness reported 15/15 DHT wire scenarios passed:

- Bootstrap request.
- Name-hash and NodeID `find_node` requests.
- Name-hash and NodeID `find_value` requests.
- Public service and private catalog lookups.
- Signed endpoint updates targeting NodeID and name hash.
- Signed public service storage.
- Rejection of unknown JSON fields, duplicate fields, uppercase hash input, oversized frames, and tampered signed endpoint data.

The standard user path also passed: `BETA.e2e` TCP and `BETA.media` UDP services were discovered by name and reached over the ESP tunnel. Private service `BETA.admin` denied ALPHA before authorization; after BETA added ALPHA's full NodeID to the allowlist, the same service returned its test sentinel. Revoking the connected peer removed the active IKE/ESP state.

## Security And Transport Evidence

- Different Ed25519 identity at the expected peer address: IKE_AUTH failed with `AUTH_FAILED`; the peer gate did not open the application connection.
- Wrong-key endpoint packet capture observed zero packets. The negative-control evidence is the strongSwan IKE_AUTH log, not packet-capture evidence.
- Positive tunnel capture counters: 4,650 ESP packets, 12 IKE UDP packets, zero clear VX6 TCP/UDP port packets, and no service sentinel in the capture.
- UDP service data caused the ESP SA packet count to increase from 1,963 to 1,972.
- An untrusted cleartext TCP connection to the VX6 listener was blocked.
- ICMPv6 is only diagnostic here. The current CHILD_SA selectors cover TCP/UDP; this run does not claim ICMPv6 is protected by ESP.

Raw PCAP files are intentionally not committed. The run's packet counts, strongSwan SA output, XFRM state, and service results are retained here.

## DHT And bbolt Snapshot

The full-binary topology had two nodes. Each node's idle routing table contained one active remote peer, so this confirms pairwise routing state only. The snapshots include both the NodeID and name-hash XOR indexes, bucket locations, peer liveness/probation fields, and persisted bbolt categories and DHT values.

The post-run BETA bbolt snapshot had one peer row, one name-index row, one diversity row, and these value keys:

- `node/id/...` for ALPHA and BETA
- `node/name/...` for ALPHA and BETA
- `service/ALPHA.probe`
- `service/BETA.e2e`
- `service/BETA.media`
- `private-catalog/BETA`

The private catalog lookup returns the `admin` service record to an authenticated DHT peer. This leaks private-service metadata, but did not grant service access: the separate tunnel service allowlist denied access until ALPHA's NodeID was explicitly added. Treat metadata confidentiality as an open security concern.

## Scenario Artifacts

Each directory under `dht/` contains the command, exact request bytes, exact response (or connection-drop result), and machine-readable pass result. `request.bin` preserves the oversized frame case. The four top-level `dht-*-before/after.json` files are full node/table/bbolt snapshots.

`wrong-key/` contains the strongSwan authentication failure logs, peer-gate output, and the empty packet/XFRM counter results for the negative identity test.

## Reproduction

From the repository root, run:

```sh
bash tests/ipsec-e2e/run.sh
```

The harness requires Docker, host `tcpdump`, and the ability to create privileged containers and IPv6 networks. It creates uniquely named temporary Docker networks and containers and cleans them up on exit. Results default to `/tmp/vx6-ipsec-e2e-suite-<run-id>`; set `VX6_E2E_RESULTS_DIR` to retain them elsewhere.

## What This Does Not Prove

Two nodes can validate message formats, direct request/response behavior, tunnel protection, service policy, and persistence across this pair. They cannot demonstrate multi-hop referral quality, DHT convergence under churn, partition recovery, or correctness at thousands of nodes. The separate 50-signed-peer nearest-referral test validates XOR ranking logic, but it is not a 50-peer full-IPsec run. Do not present this report as proof of large-network operation.
