## IPsec baseline (6 dataplane=xfrm selectors=split mtu=1500 repeat=5 duration=10)

| metric | median | p95 | min | max | n |
|---|---|---|---|---|---|
| IKE_SA+CHILD_SA(s) setup, ms | 16.5 | 21.0 | 14.0 | 26.0 | 20 |
| CHILD_SA rekey, ms | 13.0 | 15.0 | 12.0 | 15.0 | 5 |
| IKE_SA rekey, ms | 12.0 | 14.0 | 11.0 | 14.0 | 5 |
| terminate→first response, ms | 22.0 | 26.0 | 19.0 | 26.0 | 5 |
| swanctl --list-sas, ms | 5.7 | 7.6 | 5.0 | 16.2 | 200 |
| TCP throughput no ESP, Mbit/s | 137068.6 | 145332.7 | 136240.6 | 145332.7 | 5 |
| TCP throughput ESP, Mbit/s | 3635.7 | 7954.7 | 3268.4 | 7954.7 | 5 |

- charon rss_idle_no_sa_kb: {'a': 16104, 'b': 16100}
- charon rss_with_sa_kb: {'a': 17176, 'b': 17096}
- charon rss_after_load_kb: {'a': 17212, 'b': 17156}
- charon CPU during ESP iperf (% of one core, median): sender 0.0, receiver 0.0

| profile | path | p50 µs | p95 µs | p99 µs | req/s | errors |
|---|---|---|---|---|---|---|
| churn | base | 210.9 | 558.6 | 1558.2 | 60161 | 0 |
| churn | esp | 258.6 | 720.9 | 1541.4 | 48673 | 0 |
| concurrent | base | 71.3 | 192.4 | 516.4 | 650371 | 0 |
| concurrent | esp | 100.0 | 271.3 | 965.5 | 459883 | 0 |
| large | base | 32.7 | 48.8 | 74.5 | 27982 | 0 |
| large | esp | 278.6 | 305.5 | 321.9 | 3562 | 0 |
| small | base | 21.0 | 30.3 | 34.2 | 45361 | 0 |
| small | esp | 24.1 | 32.9 | 36.8 | 40314 | 0 |

- frame 162 B: 09:06:55.394951 2a:8e:75:65:20:6f > 12:7d:a3:05:a3:b8, ethertype IPv6 (0x86dd), length 162: fd00:56::a.37146 > fd00:56::b.5203: UDP, length 100
- frame 210 B: 09:06:55.394962 12:7d:a3:05:a3:b8 > 2a:8e:75:65:20:6f, ethertype IPv6 (0x86dd), length 210: fd00:56::b > fd00:56::a: ICMP6, destination unreachable, unreachable
- frame 238 B: 09:06:55.717407 2a:8e:75:65:20:6f > 12:7d:a3:05:a3:b8, ethertype IPv6 (0x86dd), length 238: fd00:56::a > fd00:56::b: ESP(spi=0xc52e7ebd,seq=0x7), length 184
- frame 210 B: 09:06:55.717424 12:7d:a3:05:a3:b8 > 2a:8e:75:65:20:6f, ethertype IPv6 (0x86dd), length 210: fd00:56::b > fd00:56::a: ICMP6, destination unreachable, unreachable
