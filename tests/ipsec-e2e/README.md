# Linux IPv6 IPsec End-to-End Test

Run from the repository root:

```sh
sudo bash tests/ipsec-e2e/run.sh
```

Run only the wrong-key identity-boundary test:

```sh
sudo env VX6_E2E_WRONG_KEY_ONLY=1 bash tests/ipsec-e2e/run.sh
```

Run the positive-control service, tunnel-capture, and revocation checks in a separate fresh topology (without address takeover):

```sh
sudo env VX6_E2E_SKIP_WRONG_KEY=1 bash tests/ipsec-e2e/run.sh
```

This focused mode stops the legitimate responder, clears both peers' XFRM state, assigns its IPv6 address to a different-key impostor, and attempts a guarded VX6 TCP dial while a TCP listener is present there. It passes only when IKE_AUTH rejects the impostor key, the dial fails at the IPsec peer gate, and neither side retains an IKE/CHILD_SA or ESP state. The initiator/responder strongSwan logs are the evidence for IKE_AUTH; the endpoint PCAP is supplementary and can miss packets in container networking.

The test builds the current VX6 binaries, launches two isolated IPv6 peers, and places a forwarding/sniffing container between them on two separate Docker networks. It captures from before a baseline ping through IKEv2 negotiation, a VX6 service request to a Python HTTP server, and a second ping after the CHILD_SA is installed. It then locally revokes the connected peer and verifies that the revocation persists and the active IKE/ESP state is removed. DHT/bootstrap is intentionally outside this test; the peers exchange signed endpoint records directly.

The run preserves the PCAP and text evidence in `/tmp/vx6-ipsec-e2e-*` by default. Set `VX6_E2E_RESULTS_DIR=/path/to/results` to choose another output directory. Inspect `packets.txt`, `verdict.txt`, `sas-a.txt`, `sas-b.txt`, and `xfrm-*.txt` alongside `wire.pcap`.

The pre-tunnel ping is a baseline and may be visible as clear ICMPv6 because no SA exists yet. After the VX6 connection, the endpoint selectors are `/128` tunnel selectors, so the post-tunnel ping should be carried in ESP too. The test fails if the transit capture sees clear TCP/UDP to the VX6 listener or finds the unique Python response marker in the PCAP. It does not claim to test active packet injection, replay, DHT security, or production packaging.
