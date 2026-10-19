# Linux IPv6 IPsec End-to-End Test

Run from the repository root:

```sh
sudo bash tests/ipsec-e2e/run.sh
```

The test builds the current VX6 binaries, launches two isolated IPv6 peers, and places a forwarding/sniffing container between them on two separate Docker networks. It captures from before a baseline ping through IKEv2 negotiation, a VX6 service request to a Python HTTP server, and a second ping after the CHILD_SA is installed. DHT/bootstrap is intentionally outside this test; the peers exchange signed endpoint records directly.

The run preserves the PCAP and text evidence in `/tmp/vx6-ipsec-e2e-*` by default. Set `VX6_E2E_RESULTS_DIR=/path/to/results` to choose another output directory. Inspect `packets.txt`, `verdict.txt`, `sas-a.txt`, `sas-b.txt`, and `xfrm-*.txt` alongside `wire.pcap`.

The pre-tunnel ping is a baseline and may be visible as clear ICMPv6 because no SA exists yet. After the VX6 connection, the endpoint selectors are `/128` tunnel selectors, so the post-tunnel ping should be carried in ESP too. The test fails if the transit capture sees clear TCP/UDP to the VX6 listener or finds the unique Python response marker in the PCAP. It does not claim to test active packet injection, replay, DHT security, or production packaging.
