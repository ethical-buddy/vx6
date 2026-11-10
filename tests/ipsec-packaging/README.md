# Clean Linux Install and Three-Peer Test

Run from the repository root:

```sh
sudo bash tests/ipsec-packaging/run.sh
```

The suite needs Docker access and privilege to create isolated IPv6 bridges,
forward packets, install XFRM state, and capture packets. It uses disposable
Ubuntu 22.04 containers and removes its containers/networks on exit. Reports,
logs, IKE state listings, XFRM state, and the router PCAP are written under
`/tmp/vx6-package-e2e-*`.

The test builds the actual `make package-linux` bundle, then installs that
bundle in three fresh containers with the bundle's own installer. Each system
gets a separate non-root `vx6test` account; the test checks that setup writes
that account's actual UID and primary GID and that `vx6 doctor` can contact the
privileged helper as that user.

The topology has three routed IPv6-only subnets and a forwarding router:

```text
Alpha <----> Beta
   |
   +-------> Charlie
```

Alpha and Beta first exchange signed endpoint records and Alpha's public TCP
service is reached through the DHT. Charlie then joins through Alpha using
signed endpoint records; Charlie reaches Alpha's service and Alpha reaches
Charlie's service through DHT discovery. The test requires established IKEv2
SAs, installed ESP states, successful HTTP response markers in both directions,
and ESP traffic in the router capture. It fails if either service marker appears
as plaintext in that capture. This verifies real service payload forwarding,
not just successful handshake setup. It does not test WAN IPv6 routing, NAT,
systemd boot behavior, wrong-key rejection, or scale beyond three nodes.
