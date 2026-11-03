## IPsec baseline (4 dataplane=libipsec selectors=split mtu=1500 repeat=5 duration=5)

| metric | median | p95 | min | max | n |
|---|---|---|---|---|---|
| IKE_SA+CHILD_SA(s) setup, ms | 54.0 | 61.0 | 48.0 | 66.0 | 20 |
| CHILD_SA rekey, ms | 47.0 | 54.0 | 44.0 | 54.0 | 5 |
| IKE_SA rekey, ms | 50.0 | 60.0 | 46.0 | 60.0 | 5 |
| terminate→first response, ms | 67.0 | 71.0 | 59.0 | 71.0 | 5 |
| swanctl --list-sas, ms | 23.7 | 29.2 | 19.3 | 50.7 | 200 |
| TCP throughput no ESP, Mbit/s | 14477.4 | 15196.6 | 13405.6 | 15196.6 | 5 |
| TCP throughput ESP, Mbit/s | 672.6 | 692.7 | 649.3 | 692.7 | 5 |

- charon rss_idle_no_sa_kb: {'a': 17820, 'b': 17844}
- charon rss_with_sa_kb: {'a': 18708, 'b': 18608}
- charon rss_after_load_kb: {'a': 20388, 'b': 20484}
- charon CPU during ESP iperf (% of one core, median): sender 135.9, receiver 148.8

| profile | path | p50 µs | p95 µs | p99 µs | req/s | errors |
|---|---|---|---|---|---|---|
| churn | base | 928.3 | 3295.0 | 8044.6 | 12580 | 0 |
| churn | esp | 3536.7 | 6987.2 | 9430.6 | 4095 | 0 |
| concurrent | base | 248.1 | 824.8 | 2686.7 | 177145 | 0 |
| concurrent | esp | 1890.5 | 3842.5 | 5456.6 | 30881 | 0 |
| large | base | 79.6 | 204.2 | 417.2 | 9159 | 0 |
| large | esp | 2139.1 | 3317.7 | 4427.9 | 434 | 0 |
| small | base | 23.8 | 95.2 | 138.9 | 27467 | 0 |
| small | esp | 297.3 | 395.4 | 585.9 | 3166 | 0 |

- frame 142 B: 08:11:49.866073 0a:ab:0f:04:52:9d > 0a:7f:2e:36:0d:b8, ethertype IPv4 (0x0800), length 142: 10.56.0.10.60376 > 10.56.0.11.5203: UDP, length 100
- frame 170 B: 08:11:49.866397 0a:7f:2e:36:0d:b8 > 0a:ab:0f:04:52:9d, ethertype IPv4 (0x0800), length 170: 10.56.0.11 > 10.56.0.10: ICMP 10.56.0.11 udp port 5203 unreachable, 
- frame 206 B: 08:11:50.193854 0a:ab:0f:04:52:9d > 0a:7f:2e:36:0d:b8, ethertype IPv4 (0x0800), length 206: 10.56.0.10.4500 > 10.56.0.11.4500: UDP-encap: ESP(spi=0xf061a39c,seq
- frame 170 B: 08:11:50.194042 0a:7f:2e:36:0d:b8 > 0a:ab:0f:04:52:9d, ethertype IPv4 (0x0800), length 170: 10.56.0.11 > 10.56.0.10: ICMP 10.56.0.11 udp port 4242 unreachable, 
