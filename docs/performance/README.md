# Performance

| Document | Issue |
|---|---|
| [ipsec-baseline.md](ipsec-baseline.md): strongSwan + XFRM baseline, harness, results, selector finding | #51 (+ #45/#46 transport numbers) |
| [packet-io-evaluation.md](packet-io-evaluation.md): kernel vs VPP vs AF_XDP | #54 |
| [../research/ipsec-native-controller.md](../research/ipsec-native-controller.md): VX6-owned IKEv2 controller research plan | #57 |

Benchmark tooling lives in [`scripts/bench/`](../../scripts/bench/). Raw results
are committed under `results/<date>-<host>/` so numbers can be checked.
