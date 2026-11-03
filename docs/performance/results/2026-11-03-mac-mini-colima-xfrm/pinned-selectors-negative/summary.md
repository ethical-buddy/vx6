## IPsec baseline (6 dataplane=xfrm selectors=pinned mtu=1500 repeat=1 duration=2)

| metric | median | p95 | min | max | n |
|---|---|---|---|---|---|
| IKE_SA+CHILD_SA(s) setup, ms | 11.5 | 17.0 | 11.0 | 17.0 | 4 |
| CHILD_SA rekey, ms | 15.0 | 15.0 | 15.0 | 15.0 | 1 |
| IKE_SA rekey, ms | 14.0 | 14.0 | 14.0 | 14.0 | 1 |
| terminate→first response, ms | 12.0 | 12.0 | 12.0 | 12.0 | 1 |
| swanctl --list-sas, ms | 5.3 | 7.7 | 5.0 | 16.2 | 200 |
| TCP throughput no ESP, Mbit/s | 155066.7 | 155066.7 | 155066.7 | 155066.7 | 1 |
| TCP throughput ESP, Mbit/s | 153976.0 | 153976.0 | 153976.0 | 153976.0 | 1 |

- charon rss_idle_no_sa_kb: {'a': 16072, 'b': 16096}
- charon rss_with_sa_kb: {'a': 16876, 'b': 16824}
- charon rss_after_load_kb: {'a': 16928, 'b': 17024}
- charon CPU during ESP iperf (% of one core, median): sender 0.0, receiver 0.0

| profile | path | p50 µs | p95 µs | p99 µs | req/s | errors |
|---|---|---|---|---|---|---|
| churn | base | 261.4 | 1220.6 | 1960.9 | 40266 | 0 |
| churn | esp | 224.6 | 1413.4 | 3142.6 | 40072 | 0 |
| concurrent | base | 98.0 | 259.8 | 439.3 | 518653 | 0 |
| concurrent | esp | 130.1 | 271.9 | 522.8 | 457475 | 0 |
| large | base | 35.2 | 51.5 | 102.1 | 26202 | 0 |
| large | esp | 34.3 | 53.1 | 100.6 | 26887 | 0 |
| small | base | 5.5 | 31.6 | 38.3 | 104246 | 0 |
| small | esp | 5.4 | 30.4 | 36.3 | 115714 | 0 |

- frame 162 B: 09:07:16.040299 1e:83:62:d2:87:45 > f2:82:ab:93:90:c2, ethertype IPv6 (0x86dd), length 162: fd00:56::a.57153 > fd00:56::b.5203: UDP, length 100
- frame 210 B: 09:07:16.040309 f2:82:ab:93:90:c2 > 1e:83:62:d2:87:45, ethertype IPv6 (0x86dd), length 210: fd00:56::b > fd00:56::a: ICMP6, destination unreachable, unreachable
- frame 162 B: 09:07:16.346688 1e:83:62:d2:87:45 > f2:82:ab:93:90:c2, ethertype IPv6 (0x86dd), length 162: fd00:56::a.48095 > fd00:56::b.4242: UDP, length 100
- frame 210 B: 09:07:16.346696 f2:82:ab:93:90:c2 > 1e:83:62:d2:87:45, ethertype IPv6 (0x86dd), length 210: fd00:56::b > fd00:56::a: ICMP6, destination unreachable, unreachable
- frame 70 B: 09:07:16.435269 1e:83:62:d2:87:45 > 33:33:00:00:00:02, ethertype IPv6 (0x86dd), length 70: fe80::1c83:62ff:fed2:8745 > ff02::2: ICMP6, router solicitation, leng
- frame 70 B: 09:07:17.459290 f2:82:ab:93:90:c2 > 33:33:00:00:00:02, ethertype IPv6 (0x86dd), length 70: fe80::f082:abff:fe93:90c2 > ff02::2: ICMP6, router solicitation, leng
