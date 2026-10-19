#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
image=vx6-ipsec-e2e:local
run_id="$(date +%Y%m%d-%H%M%S)-$$"
network_a="vx6-e2e-a-$run_id"
network_b="vx6-e2e-b-$run_id"
peer_a="vx6-e2e-peer-a-$run_id"
peer_b="vx6-e2e-peer-b-$run_id"
sniffer="vx6-e2e-sniffer-$run_id"
results=${VX6_E2E_RESULTS_DIR:-"/tmp/vx6-ipsec-e2e-$run_id"}
work=$(mktemp -d)
mkdir -p "$results"
capture_pid=

cleanup() {
  local status=${1:-$?}
  if [[ -n ${capture_pid:-} ]] && docker inspect "$sniffer" >/dev/null 2>&1; then
    docker exec "$sniffer" sh -c 'kill -INT "$(cat /tmp/capture.pid 2>/dev/null)" 2>/dev/null || true; sleep 1' >/dev/null 2>&1 || true
    docker cp "$sniffer:/captures/wire.pcap" "$results/wire.pcap" >/dev/null 2>&1 || true
  fi
  if ((status != 0)); then
    for container in "$peer_a" "$peer_b" "$sniffer"; do
      if docker inspect "$container" >/dev/null 2>&1; then
        docker logs "$container" >"$results/$container.docker.log" 2>&1 || true
      fi
    done
    printf 'Test failed. Diagnostics and any packet capture are in %s\n' "$results" >&2
  fi
  docker rm -f "$peer_a" "$peer_b" "$sniffer" >/dev/null 2>&1 || true
  docker network rm "$network_a" "$network_b" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

if ! docker info >/dev/null 2>&1; then
  printf 'Docker daemon unavailable; run with permission to use Docker.\n' >&2
  exit 2
fi
for command in docker tcpdump strings; do
  command -v "$command" >/dev/null || { printf 'Missing host command: %s\n' "$command" >&2; exit 2; }
done

printf 'Results directory: %s\n' "$results"
printf 'Building the Linux strongSwan/VX6 test image and current VX6 binaries...\n'
docker build -f "$repo_root/tests/ipsec-e2e/Dockerfile" -t "$image" "$repo_root"
GOCACHE="${GOCACHE:-/tmp/vx6-go-build}" GOMODCACHE="${GOMODCACHE:-/tmp/vx6-go-mod}" go build -o "$work/vx6" ./cmd/vx6
GOCACHE="${GOCACHE:-/tmp/vx6-go-build}" GOMODCACHE="${GOMODCACHE:-/tmp/vx6-go-mod}" go build -o "$work/vx6-ipsecd" ./cmd/vx6-ipsecd
GOCACHE="${GOCACHE:-/tmp/vx6-go-build}" GOMODCACHE="${GOMODCACHE:-/tmp/vx6-go-mod}" go build -o "$work/vx6-e2e-peer" ./tests/ipsec-e2e/peer

docker network create --ipv6 --subnet fd42:6:1::/64 --opt com.docker.network.bridge.name="br-vx6-a-${run_id##*-}" "$network_a" >/dev/null
docker network create --ipv6 --subnet fd42:6:2::/64 --opt com.docker.network.bridge.name="br-vx6-b-${run_id##*-}" "$network_b" >/dev/null
docker run -d --name "$peer_a" --network "$network_a" --ip6 fd42:6:1::10 --privileged -v "$work:/vx6-test:ro" "$image" >/dev/null
docker run -d --name "$peer_b" --network "$network_b" --ip6 fd42:6:2::20 --privileged -v "$work:/vx6-test:ro" "$image" >/dev/null
docker run -d --name "$sniffer" --privileged -v "$results:/captures" "$image" >/dev/null
docker network connect --ip6 fd42:6:1::2 "$network_a" "$sniffer"
docker network connect --ip6 fd42:6:2::2 "$network_b" "$sniffer"
docker exec "$sniffer" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
docker exec "$peer_a" ip -6 route add fd42:6:2::/64 via fd42:6:1::2
docker exec "$peer_b" ip -6 route add fd42:6:1::/64 via fd42:6:2::2

peer_exec() { local container=$1; shift; docker exec "$container" "$@"; }
for peer in "$peer_a" "$peer_b"; do
  docker exec -d "$peer" /usr/lib/ipsec/charon --debug-ike 1
  for attempt in $(seq 1 30); do
    peer_exec "$peer" swanctl --list-sas >/dev/null 2>&1 && break
    sleep 1
  done
  peer_exec "$peer" swanctl --list-sas >/dev/null
done

init_peer() {
  local container=$1 name=$2 address=$3
  peer_exec "$container" env VX6_CONFIG_PATH=/root/.config/vx6/config.json \
    /vx6-test/vx6 init --name "$name" --listen "[$address]:4242" --advertise "[$address]:4242" \
    --transport tcp --relay off --data-dir "/root/.config/vx6/$name-data" --downloads-dir "/root/.config/vx6/$name-downloads"
  peer_exec "$container" mkdir -p /etc/vx6 /var/lib/vx6/ipsec /run/vx6
  peer_exec "$container" sh -c "printf '%s\\n' '{\"socket\":\"/run/vx6/ipsecd.sock\",\"state_dir\":\"/var/lib/vx6/ipsec\",\"socket_gid\":1000,\"allowed_uids\":[0]}' > /etc/vx6/ipsecd.json"
  docker exec -d "$container" sh -c '/vx6-test/vx6-ipsecd --config /etc/vx6/ipsecd.json >/tmp/ipsecd.log 2>&1'
  for attempt in $(seq 1 20); do
    peer_exec "$container" test -S /run/vx6/ipsecd.sock && return
    sleep 1
  done
  peer_exec "$container" cat /tmp/ipsecd.log >&2 || true
  return 1
}
init_peer "$peer_a" alpha fd42:6:1::10
init_peer "$peer_b" beta fd42:6:2::20

peer_exec "$peer_a" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 identity export-endpoint --addr '[fd42:6:1::10]:4242' --out /tmp/peer-a.json
peer_exec "$peer_b" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 identity export-endpoint --addr '[fd42:6:2::20]:4242' --out /tmp/peer-b.json
docker cp "$peer_a:/tmp/peer-a.json" "$work/peer-a.json"
docker cp "$peer_b:/tmp/peer-b.json" "$work/peer-b.json"
docker cp "$work/peer-b.json" "$peer_a:/tmp/peer-b.json"
docker cp "$work/peer-a.json" "$peer_b:/tmp/peer-a.json"
peer_exec "$peer_a" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 peer add --record /tmp/peer-b.json
peer_exec "$peer_b" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 peer add --record /tmp/peer-a.json

marker="VX6_PRIVATE_SENTINEL_$run_id"
docker exec -d "$peer_b" sh -c "mkdir -p /tmp/www; printf '%s\\n' '$marker' >/tmp/www/index.html; exec python3 -m http.server 9000 --bind :: --directory /tmp/www >/tmp/http.log 2>&1"
peer_exec "$peer_b" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 service add --name e2e --target '[::1]:9000'

docker exec "$sniffer" ip -br link | tee "$results/sniffer-interfaces.txt"
printf 'Transit sniffer is forwarding between the two isolated peer networks.\n' | tee "$results/topology.txt"
docker exec -d "$sniffer" sh -c 'tcpdump -nni any -s 0 -U -w /captures/wire-live.pcap ip6 >/captures/tcpdump.log 2>&1 & echo $! >/tmp/capture.pid; wait $(cat /tmp/capture.pid)'
capture_pid=1
sleep 1

printf '\n=== Ping before IPsec negotiation (baseline) ===\n' | tee -a "$results/topology.txt"
peer_exec "$peer_a" ping -6 -c 2 -W 2 fd42:6:2::20 2>&1 | tee "$results/ping-before.txt" || true

docker exec -d "$peer_b" sh -c 'exec env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6-e2e-peer >/tmp/vx6-node-b.log 2>&1'
for attempt in $(seq 1 30); do
  peer_exec "$peer_b" sh -c 'ss -ltn | grep -q ":4242"' && break
  sleep 1
done
docker exec -d "$peer_a" sh -c "exec env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 connect --service e2e --addr '[fd42:6:2::20]:4242' --listen 127.0.0.1:18080 >/tmp/vx6-connect.log 2>&1"

for attempt in $(seq 1 30); do
  peer_exec "$peer_a" sh -c 'ss -ltn | grep -q ":18080"' && break
  sleep 1
done
printf '\n=== VX6 service request through tunnel ===\n' | tee -a "$results/topology.txt"
peer_exec "$peer_a" curl --fail --silent --show-error --retry 15 --retry-connrefused --retry-delay 1 http://127.0.0.1:18080/ \
  | tee "$results/service-response.txt"
grep -Fx "$marker" "$results/service-response.txt" >/dev/null

printf '\n=== Untrusted cleartext probe of the VX6 listener ===\n' | tee -a "$results/topology.txt"
if docker exec "$sniffer" timeout 3 nc -6 -z fd42:6:2::20 4242; then
  printf 'FAIL: an untrusted non-IPsec TCP probe connected to the VX6 listener.\n' | tee "$results/clear-probe.txt"
  exit 1
else
  printf 'PASS: untrusted non-IPsec TCP probe was blocked.\n' | tee "$results/clear-probe.txt"
fi

printf '\n=== Ping after CHILD_SA establishment ===\n' | tee -a "$results/topology.txt"
peer_exec "$peer_a" swanctl --list-sas | tee "$results/sas-a-before-post-ping.txt" >/dev/null
peer_exec "$peer_a" ping -6 -c 2 -W 2 fd42:6:2::20 2>&1 | tee "$results/ping-after.txt"
peer_exec "$peer_a" swanctl --list-sas | tee "$results/sas-a.txt"
peer_exec "$peer_b" swanctl --list-sas | tee "$results/sas-b.txt"
peer_exec "$peer_a" ip -6 -s xfrm state | tee "$results/xfrm-a.txt"
peer_exec "$peer_b" ip -6 -s xfrm state | tee "$results/xfrm-b.txt"

docker exec "$sniffer" sh -c 'kill -INT "$(cat /tmp/capture.pid)"; sleep 1'
docker cp "$sniffer:/captures/wire-live.pcap" "$results/wire.pcap"
capture_pid=

tcpdump -nnr "$results/wire.pcap" >"$results/packets.txt" 2>"$results/tcpdump-summary.txt"
tcpdump -nnr "$results/wire.pcap" 'ip6 proto 50' 2>/dev/null | wc -l >"$results/esp-packets.count"
tcpdump -nnr "$results/wire.pcap" 'udp port 500 or udp port 4500' 2>/dev/null | wc -l >"$results/ike-packets.count"
tcpdump -nnr "$results/wire.pcap" 'ip6 and host fd42:6:1::10 and host fd42:6:2::20 and (tcp port 4242 or udp port 4242)' 2>/dev/null | wc -l >"$results/clear-vx6-port-packets.count"
tcpdump -nnr "$results/wire.pcap" 'icmp6 and host fd42:6:1::10 and host fd42:6:2::20' 2>/dev/null | wc -l >"$results/clear-peer-icmp6-packets.count"
awk '$1 == "in" {in_packets += $5} $1 == "out" {out_packets += $5} END {print in_packets+0, out_packets+0}' "$results/sas-a-before-post-ping.txt" >"$results/sa-counters-before-ping.txt"
awk '$1 == "in" {in_packets += $5} $1 == "out" {out_packets += $5} END {print in_packets+0, out_packets+0}' "$results/sas-a.txt" >"$results/sa-counters-after-ping.txt"
read -r in_before out_before <"$results/sa-counters-before-ping.txt"
read -r in_after out_after <"$results/sa-counters-after-ping.txt"
first_ike=$(awk '/isakmp: parent_sa ikev2_init/ {print $1; exit}' "$results/packets.txt")
awk -v ike="$first_ike" '$0 ~ /ICMP6, echo (request|reply)/ && $1 > ike {count++} END {print count+0}' \
  "$results/packets.txt" >"$results/clear-icmp-after-ike.count"
if strings "$results/wire.pcap" | grep -F "$marker" >"$results/sentinel-match.txt"; then
  printf 'FAIL: service sentinel found in transit capture.\n' | tee "$results/verdict.txt"
  exit 1
fi
{
  printf 'pcap=%s\n' "$results/wire.pcap"
  printf 'ESP packets: '; cat "$results/esp-packets.count"
  printf 'IKE UDP packets: '; cat "$results/ike-packets.count"
  printf 'Clear VX6-port packets: '; cat "$results/clear-vx6-port-packets.count"
  printf 'Clear peer-to-peer ICMPv6 packets: '; cat "$results/clear-peer-icmp6-packets.count"
  printf 'Clear echo packets after IKE began: '; cat "$results/clear-icmp-after-ike.count"
  printf 'Peer SA packet counters before/after post-tunnel ping (in,out): %s/%s -> %s/%s\n' "$in_before" "$out_before" "$in_after" "$out_after"
  printf 'Service sentinel in capture: no\n'
} | tee "$results/verdict.txt"

if [[ $(cat "$results/esp-packets.count") -eq 0 ]]; then
  printf 'FAIL: transit sniffer saw no ESP packets.\n' >&2
  exit 1
fi
if [[ $(cat "$results/clear-vx6-port-packets.count") -ne 0 ]]; then
  printf 'FAIL: transit sniffer saw clear VX6-port traffic.\n' >&2
  exit 1
fi
if [[ $(cat "$results/clear-icmp-after-ike.count") -ne 0 || $in_after -le $in_before || $out_after -le $out_before ]]; then
  printf 'FAIL: post-tunnel ping was not confirmed inside the IPsec SA.\n' >&2
  exit 1
fi
printf '\nPacket listing: %s\n' "$results/packets.txt"
printf 'Full capture and logs: %s\n' "$results"
