#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${VX6_E2E_CHILD_RUN:-0} != 1 && ${VX6_E2E_WRONG_KEY_ONLY:-0} != 1 && ${VX6_E2E_SKIP_WRONG_KEY:-0} != 1 ]]; then
  suite_id="$(date +%Y%m%d-%H%M%S)-$$"
  suite_results=${VX6_E2E_RESULTS_DIR:-"/tmp/vx6-ipsec-e2e-suite-$suite_id"}
  mkdir -p "$suite_results"
  printf 'Running wrong-key validation and positive-control validation in separate fresh topologies.\n'
  env VX6_E2E_CHILD_RUN=1 VX6_E2E_WRONG_KEY_ONLY=1 VX6_E2E_RESULTS_DIR="$suite_results/wrong-key" bash "$0"
  env VX6_E2E_CHILD_RUN=1 VX6_E2E_SKIP_WRONG_KEY=1 VX6_E2E_RESULTS_DIR="$suite_results/positive-control" bash "$0"
  printf 'Combined suite results: %s\n' "$suite_results"
  exit 0
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
image=vx6-ipsec-e2e:local
run_id="$(date +%Y%m%d-%H%M%S)-$$"
network_a="vx6-e2e-a-$run_id"
network_b="vx6-e2e-b-$run_id"
peer_a="vx6-e2e-peer-a-$run_id"
peer_b="vx6-e2e-peer-b-$run_id"
impostor="vx6-e2e-impostor-$run_id"
sniffer="vx6-e2e-sniffer-$run_id"
results=${VX6_E2E_RESULTS_DIR:-"/tmp/vx6-ipsec-e2e-$run_id"}
work=$(mktemp -d)
mkdir -p "$results"
capture_pid=
ula_slot=$(( $$ % 60000 + 1000 ))
printf -v ula_slot_hex '%x' "$ula_slot"
net_a_prefix="fd42:6:${ula_slot_hex}:1"
net_b_prefix="fd42:6:${ula_slot_hex}:2"
net_a_subnet="${net_a_prefix}::/64"
net_b_subnet="${net_b_prefix}::/64"
peer_a_ip="${net_a_prefix}::10"
peer_b_ip="${net_b_prefix}::20"
router_a_ip="${net_a_prefix}::2"
router_b_ip="${net_b_prefix}::2"
impostor_ip="${net_b_prefix}::30"

cleanup() {
  local status=${1:-$?}
  if docker inspect "$sniffer" >/dev/null 2>&1; then
    docker exec "$sniffer" sh -c 'for f in /tmp/capture.pid /tmp/wrong-key-capture.pid; do if [ -s "$f" ]; then kill -INT "$(cat "$f")" 2>/dev/null || true; fi; done; sleep 1' >/dev/null 2>&1 || true
    docker cp "$sniffer:/captures/wire.pcap" "$results/wire.pcap" >/dev/null 2>&1 || true
  fi
  if docker inspect "$peer_a" >/dev/null 2>&1; then
    docker exec "$peer_a" sh -c 'if [ -s /tmp/wrong-key-capture.pid ]; then kill -INT "$(cat /tmp/wrong-key-capture.pid)" 2>/dev/null || true; sleep 1; fi' >/dev/null 2>&1 || true
    docker cp "$peer_a:/tmp/wrong-key.pcap" "$results/wrong-key.pcap" >/dev/null 2>&1 || true
    docker cp "$peer_a:/tmp/wrong-key-tcpdump.log" "$results/wrong-key-tcpdump.log" >/dev/null 2>&1 || true
  fi
  if ((status != 0)); then
    for container in "$peer_a" "$peer_b" "$impostor" "$sniffer"; do
      if docker inspect "$container" >/dev/null 2>&1; then
        docker logs "$container" >"$results/$container.docker.log" 2>&1 || true
        docker exec "$container" sh -c 'for f in /tmp/charon.log /tmp/ipsecd.log /tmp/vx6-connect.log /tmp/vx6-udp-connect.log /tmp/vx6-node-b.log /tmp/http.log /tmp/udp-echo.log; do if [ -f "$f" ]; then echo "=== $f ==="; cat "$f"; fi; done; echo "=== UDP sockets ==="; ss -lunp' \
          >"$results/$container.runtime.log" 2>&1 || true
      fi
    done
    printf 'Test failed. Diagnostics and any packet capture are in %s\n' "$results" >&2
  fi
  docker rm -f "$peer_a" "$peer_b" "$impostor" "$sniffer" >/dev/null 2>&1 || true
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
GOCACHE="${GOCACHE:-/tmp/vx6-go-build}" GOMODCACHE="${GOMODCACHE:-/tmp/vx6-go-mod}" go build -o "$work/vx6-dhtprobe" ./tests/ipsec-e2e/dhtprobe

docker network create --ipv6 --subnet "$net_a_subnet" "$network_a" >/dev/null
docker network create --ipv6 --subnet "$net_b_subnet" "$network_b" >/dev/null
docker run -d --name "$peer_a" --network "$network_a" --ip6 "$peer_a_ip" --privileged -v "$work:/vx6-test:ro" -v "$results:/results" "$image" >/dev/null
docker run -d --name "$peer_b" --network "$network_b" --ip6 "$peer_b_ip" --privileged -v "$work:/vx6-test:ro" -v "$results:/results" "$image" >/dev/null
docker run -d --name "$sniffer" --privileged -v "$results:/captures" "$image" >/dev/null
docker network connect --ip6 "$router_a_ip" "$network_a" "$sniffer"
docker network connect --ip6 "$router_b_ip" "$network_b" "$sniffer"
docker exec "$sniffer" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
docker exec "$peer_a" ip -6 route add "$net_b_subnet" via "$router_a_ip"
docker exec "$peer_b" ip -6 route add "$net_a_subnet" via "$router_b_ip"

peer_exec() { local container=$1; shift; docker exec "$container" "$@"; }
for peer in "$peer_a" "$peer_b"; do
  docker exec -d "$peer" /usr/lib/ipsec/charon --debug-ike 1
  for attempt in $(seq 1 30); do
    peer_exec "$peer" swanctl --list-sas >/dev/null 2>&1 && break
    sleep 1
  done
  peer_exec "$peer" swanctl --list-sas >/dev/null
done

start_charon() {
  local container=$1
  docker exec -d "$container" /usr/lib/ipsec/charon --debug-ike 2
  for attempt in $(seq 1 30); do
    peer_exec "$container" swanctl --list-sas >/dev/null 2>&1 && break
    sleep 1
  done
  peer_exec "$container" swanctl --list-sas >/dev/null
}
start_ipsecd() {
  local container=$1
  docker exec -d "$container" sh -c '/vx6-test/vx6-ipsecd --config /etc/vx6/ipsecd.json >/tmp/ipsecd.log 2>&1'
  for attempt in $(seq 1 20); do
    peer_exec "$container" test -S /run/vx6/ipsecd.sock && return
    sleep 1
  done
  peer_exec "$container" cat /tmp/ipsecd.log >&2 || true
  return 1
}
stop_ipsec_daemons() {
  local container=$1
  peer_exec "$container" pkill -TERM -x vx6-ipsecd || true
  peer_exec "$container" pkill -TERM -x charon || true
  for attempt in $(seq 1 20); do
    if ! peer_exec "$container" pgrep -x vx6-ipsecd >/dev/null 2>&1 && \
       ! peer_exec "$container" pgrep -x charon >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  printf 'IPsec daemons did not stop in %s\n' "$container" >&2
  return 1
}
init_peer() {
  local container=$1 name=$2 address=$3
  peer_exec "$container" env VX6_CONFIG_PATH=/root/.config/vx6/config.json \
    /vx6-test/vx6 init --name "$name" --listen "[$address]:4242" --advertise "[$address]:4242" \
    --transport tcp --relay off --data-dir "/root/.config/vx6/$name-data" --downloads-dir "/root/.config/vx6/$name-downloads"
  peer_exec "$container" mkdir -p /etc/vx6 /var/lib/vx6/ipsec /run/vx6
  peer_exec "$container" sh -c "printf '%s\\n' '{\"socket\":\"/run/vx6/ipsecd.sock\",\"state_dir\":\"/var/lib/vx6/ipsec\",\"socket_gid\":1000,\"allowed_uids\":[0]}' > /etc/vx6/ipsecd.json"
  start_ipsecd "$container"
}
init_peer "$peer_a" alpha "$peer_a_ip"
init_peer "$peer_b" beta "$peer_b_ip"

peer_exec "$peer_a" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 identity export-endpoint --addr "[$peer_a_ip]:4242" --out /tmp/peer-a.json
peer_exec "$peer_b" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 identity export-endpoint --addr "[$peer_b_ip]:4242" --out /tmp/peer-b.json
docker cp "$peer_a:/tmp/peer-a.json" "$work/peer-a.json"
docker cp "$peer_b:/tmp/peer-b.json" "$work/peer-b.json"
docker cp "$work/peer-b.json" "$peer_a:/tmp/peer-b.json"
docker cp "$work/peer-a.json" "$peer_b:/tmp/peer-a.json"
peer_exec "$peer_a" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 peer add --record /tmp/peer-b.json
peer_exec "$peer_b" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 peer add --record /tmp/peer-a.json

if [[ ${VX6_E2E_SKIP_WRONG_KEY:-0} != 1 ]]; then
printf '\n=== Prepare a different-key IKE impostor at the expected address ===\n' | tee -a "$results/topology.txt"
docker run -d --name "$impostor" --network "$network_b" --ip6 "$impostor_ip" --privileged -v "$work:/vx6-test:ro" "$image" >/dev/null
start_charon "$impostor"
init_peer "$impostor" impostor "$peer_b_ip"
docker cp "$work/peer-a.json" "$impostor:/tmp/peer-a.json"

printf 'Preparing the wrong-key responder...\n' | tee -a "$results/topology.txt"
stop_ipsec_daemons "$peer_b"
peer_exec "$peer_b" ip -6 xfrm state flush
peer_exec "$peer_b" ip -6 xfrm policy flush
docker network disconnect "$network_b" "$peer_b"
peer_exec "$impostor" ip -6 addr add "$peer_b_ip/64" dev eth0
peer_exec "$impostor" ip -6 route add "$net_a_subnet" via "$router_b_ip"
peer_exec "$sniffer" ip -6 neigh flush to "$peer_b_ip" >/dev/null 2>&1 || true
sleep 2
stop_ipsec_daemons "$peer_a"
peer_exec "$peer_a" ip -6 xfrm state flush
peer_exec "$peer_a" ip -6 xfrm policy flush
start_charon "$peer_a"
start_ipsecd "$peer_a"
stop_ipsec_daemons "$impostor"
start_charon "$impostor"
start_ipsecd "$impostor"
peer_exec "$impostor" env VX6_CONFIG_PATH=/root/.config/vx6/config.json \
  /vx6-test/vx6-e2e-peer prepare-peer /tmp/peer-a.json
peer_exec "$impostor" swanctl --list-conns >"$results/impostor-connections-before.txt"
peer_exec "$impostor" ip -6 addr show dev eth0 >"$results/impostor-addresses.txt"
peer_exec "$impostor" ss -lunp >"$results/impostor-udp-listeners.txt"
docker exec -d "$impostor" sh -c 'exec python3 -m http.server 4242 --bind :: >/tmp/impostor-service.log 2>&1'
for attempt in $(seq 1 20); do
  peer_exec "$impostor" sh -c 'ss -ltn | grep -q ":4242"' && break
  sleep 1
done
peer_exec "$impostor" sh -c 'ss -ltn | grep -q ":4242"'
docker exec -d "$peer_a" sh -c 'tcpdump -nni any -s 0 -U -w /tmp/wrong-key.pcap ip6 >/tmp/wrong-key-tcpdump.log 2>&1 & echo $! >/tmp/wrong-key-capture.pid; wait $(cat /tmp/wrong-key-capture.pid)'
sleep 1
printf 'Testing wrong-key IKE_AUTH rejection...\n' | tee -a "$results/topology.txt"
if peer_exec "$peer_a" env VX6_CONFIG_PATH=/root/.config/vx6/config.json \
  /vx6-test/vx6-e2e-peer guarded-dial /tmp/peer-b.json >"$results/wrong-key-ensure.txt" 2>&1; then
  printf 'FAIL: the application dial was not rejected by the expected-peer key check.\n' | tee "$results/wrong-key-verdict.txt" >&2
  exit 1
fi
peer_exec "$peer_a" sh -c 'kill -INT "$(cat /tmp/wrong-key-capture.pid)"; sleep 1'
docker cp "$peer_a:/tmp/wrong-key.pcap" "$results/wrong-key.pcap"
docker cp "$peer_a:/tmp/wrong-key-tcpdump.log" "$results/wrong-key-tcpdump.log"
peer_exec "$impostor" cat /tmp/charon.log >"$results/impostor-charon.log" 2>&1 || true
if ! grep -Fq 'no trusted ED25519 public key found' "$results/wrong-key-ensure.txt" || \
   ! grep -Fq 'AUTH_FAILED' "$results/wrong-key-ensure.txt" || \
   ! grep -Fq 'IKE_AUTH request' "$results/impostor-charon.log" || \
   ! grep -Fq 'IPsec peer gate rejected' "$results/wrong-key-ensure.txt"; then
  printf 'FAIL: the endpoint logs do not prove that the expected key rejected the impostor during IKE_AUTH.\n' | tee "$results/wrong-key-verdict.txt" >&2
  exit 1
fi
tcpdump -nnr "$results/wrong-key.pcap" 'tcp port 4242' 2>/dev/null | wc -l >"$results/wrong-key-clear-tcp-packets.count"
tcpdump -nnr "$results/wrong-key.pcap" 'ip6 proto 50' 2>/dev/null | wc -l >"$results/wrong-key-esp-packets.count"
tcpdump -nnr "$results/wrong-key.pcap" 'udp port 500 or udp port 4500' 2>/dev/null | wc -l >"$results/wrong-key-ike-packets.count"
capture_packets=$(sed -n 's/^\([0-9][0-9]*\) packets captured$/\1/p' "$results/wrong-key-tcpdump.log" | tail -1)
capture_packets=${capture_packets:-0}
if ((capture_packets > 0)) && { [[ $(cat "$results/wrong-key-clear-tcp-packets.count") -ne 0 ]] || [[ $(cat "$results/wrong-key-esp-packets.count") -ne 0 ]]; }; then
  printf 'FAIL: capture saw clear application TCP or ESP for the rejected wrong-key attempt.\n' | tee "$results/wrong-key-verdict.txt" >&2
  exit 1
fi
peer_exec "$peer_a" swanctl --list-sas >"$results/wrong-key-sas-initiator.txt"
peer_exec "$impostor" swanctl --list-sas >"$results/wrong-key-sas-impostor.txt"
peer_exec "$peer_a" ip -6 xfrm state >"$results/wrong-key-xfrm-initiator.txt"
peer_exec "$impostor" ip -6 xfrm state >"$results/wrong-key-xfrm-impostor.txt"
if grep -E "ESTABLISHED|INSTALLED" "$results/wrong-key-sas-initiator.txt"; then
  printf 'FAIL: a usable IKE/CHILD_SA remained after wrong-key authentication.\n' | tee "$results/wrong-key-verdict.txt" >&2
  exit 1
fi
if grep -q "proto esp" "$results/wrong-key-xfrm-initiator.txt"; then
  printf 'FAIL: ESP state was installed for the wrong-key peer.\n' | tee "$results/wrong-key-verdict.txt" >&2
  exit 1
fi
if grep -E "ESTABLISHED|INSTALLED" "$results/wrong-key-sas-impostor.txt"; then
  printf 'FAIL: the impostor retained a usable IKE/CHILD_SA after AUTH_FAILED.\n' | tee "$results/wrong-key-verdict.txt" >&2
  exit 1
fi
if grep -q "proto esp" "$results/wrong-key-xfrm-impostor.txt"; then
  printf 'FAIL: the impostor retained ESP state after AUTH_FAILED.\n' | tee "$results/wrong-key-verdict.txt" >&2
  exit 1
fi
{
  printf 'PASS: expected-peer IKE setup rejected the different key.\n'
  printf 'Initiator log proves AUTH_FAILED for the responder key; guarded dial returned before opening the application socket.\n'
  printf 'Responder log proves it received IKE_AUTH. An active listener was present at the impostor endpoint; the guarded dial stopped before TCP connect.\n'
  printf 'EnsurePeer error: '; tr '\n' ' ' <"$results/wrong-key-ensure.txt"; printf '\n'
  printf 'Endpoint capture packets: %s\n' "$capture_packets"
  if ((capture_packets == 0)); then
    printf 'Endpoint PCAP inconclusive (container capture saw no packets); IKE evidence is from strongSwan logs.\n'
  fi
  printf 'IKE packets: '; cat "$results/wrong-key-ike-packets.count"
  printf 'Clear application TCP packets: '; cat "$results/wrong-key-clear-tcp-packets.count"
  printf 'ESP packets: '; cat "$results/wrong-key-esp-packets.count"
} | tee "$results/wrong-key-verdict.txt"

if [[ ${VX6_E2E_WRONG_KEY_ONLY:-0} == 1 ]]; then
  printf 'Wrong-key-only run complete; skipped the separate positive-control topology.\n'
  exit 0
fi

peer_exec "$impostor" ip -6 addr del "$peer_b_ip/64" dev eth0
docker network connect --ip6 "$peer_b_ip" "$network_b" "$peer_b"
peer_exec "$sniffer" ip -6 neigh flush dev eth1 >/dev/null 2>&1 || true
peer_exec "$sniffer" ip -6 neigh flush dev eth2 >/dev/null 2>&1 || true
peer_exec "$peer_a" ip -6 neigh flush dev eth0 >/dev/null 2>&1 || true
peer_exec "$peer_b" ip -6 neigh flush dev eth0 >/dev/null 2>&1 || true
sleep 2
# The failed authentication intentionally exercises retransmission and teardown;
# start the positive-control phase with a clean IKE daemon and XFRM state.
stop_ipsec_daemons "$peer_a"
peer_exec "$peer_a" ip -6 xfrm state flush
peer_exec "$peer_a" ip -6 xfrm policy flush
start_charon "$peer_a"
start_ipsecd "$peer_a"
peer_exec "$peer_b" pkill -TERM -x vx6-ipsecd || true
for attempt in $(seq 1 20); do
  if ! peer_exec "$peer_b" pgrep -x vx6-ipsecd >/dev/null 2>&1; then break; fi
  sleep 1
done
peer_exec "$peer_b" ip -6 xfrm state flush
peer_exec "$peer_b" ip -6 xfrm policy flush
start_charon "$peer_b"
start_ipsecd "$peer_b"
peer_exec "$peer_b" env VX6_CONFIG_PATH=/root/.config/vx6/config.json \
  /vx6-test/vx6 peer add --record /tmp/peer-a.json
fi

marker="VX6_PRIVATE_SENTINEL_$run_id"
docker exec -d "$peer_b" sh -c "mkdir -p /tmp/www; printf '%s\\n' '$marker' >/tmp/www/index.html; exec python3 -m http.server 9000 --bind :: --directory /tmp/www >/tmp/http.log 2>&1"
peer_exec "$peer_b" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 service add --name e2e --target '[::1]:9000'
peer_exec "$peer_b" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 service add --name admin --target '[::1]:9002' --private
udp_marker="VX6_UDP_SENTINEL_$run_id"
docker exec -d "$peer_b" sh -c "exec python3 -u -c 'import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.bind((\"::1\",9001)); exec(\"while True: data,addr=s.recvfrom(65507); s.sendto(data,addr)\")' >/tmp/udp-echo.log 2>&1"
peer_exec "$peer_b" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 service add --protocol udp --name media --target '[::1]:9001'
docker exec -d "$peer_b" sh -c "mkdir -p /tmp/admin; printf '%s\\n' 'VX6_PRIVATE_ADMIN_SENTINEL' >/tmp/admin/index.html; exec python3 -m http.server 9002 --bind :: --directory /tmp/admin >/tmp/admin-http.log 2>&1"

docker exec "$sniffer" ip -br link | tee "$results/sniffer-interfaces.txt"
printf 'Transit sniffer is forwarding between the two isolated peer networks.\n' | tee "$results/topology.txt"
docker exec -d "$sniffer" sh -c 'tcpdump -nni any -s 0 -U -w /captures/wire-live.pcap ip6 >/captures/tcpdump.log 2>&1 & echo $! >/tmp/capture.pid; wait $(cat /tmp/capture.pid)'
capture_pid=1
sleep 1

printf '\n=== Ping before IPsec negotiation (baseline) ===\n' | tee -a "$results/topology.txt"
peer_exec "$peer_a" ping -6 -c 2 -W 2 "$peer_b_ip" 2>&1 | tee "$results/ping-before.txt" || true

docker exec -d "$peer_b" sh -c 'exec env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 node >/tmp/vx6-node-b.log 2>&1'
for attempt in $(seq 1 30); do
  peer_exec "$peer_b" sh -c 'ss -ltn | grep -q ":4242"' && break
  sleep 1
done
peer_exec "$peer_b" sh -c 'ss -ltn | grep -q ":4242"'
docker exec -d "$peer_a" sh -c 'exec env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 node >/tmp/vx6-node-a.log 2>&1'
for attempt in $(seq 1 30); do
  peer_exec "$peer_a" sh -c 'ss -ltn | grep -q ":4242"' && break
  sleep 1
done
peer_exec "$peer_a" sh -c 'ss -ltn | grep -q ":4242"'

printf '\n=== Two full VX6 nodes: DHT wire requests over authenticated ESP ===\n' | tee -a "$results/topology.txt"
converged=0
for attempt in $(seq 1 30); do
  peer_exec "$peer_a" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 debug dht-snapshot >"$results/dht-alpha-before.json"
  peer_exec "$peer_b" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 debug dht-snapshot >"$results/dht-beta-before.json"
  if python3 - "$results/dht-alpha-before.json" "$results/dht-beta-before.json" <<'PY'
import json, sys
active = [json.load(open(path))["table"]["active"] for path in sys.argv[1:]]
raise SystemExit(0 if all(count > 0 for count in active) else 1)
PY
  then
    converged=1
    break
  fi
  sleep 1
done
if ((converged == 0)); then
  printf 'FAIL: both nodes did not independently populate their active XOR routing tables within 30 seconds.\n' >&2
  exit 1
fi
alpha_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["node_id"])' "$work/peer-a.json")
beta_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["node_id"])' "$work/peer-b.json")
beta_upper_id="vx6_$(printf '%s' "${beta_id#vx6_}" | tr '[:lower:]' '[:upper:]')"
alpha_name_hash=$(printf 'vx6/node-name/v1\0%s' ALPHA | sha256sum | cut -d' ' -f1)
beta_name_hash=$(printf 'vx6/node-name/v1\0%s' BETA | sha256sum | cut -d' ' -f1)
run_dht_case() {
  local scenario=$1; shift
  local scenario_dir="/results/dht/$scenario"
  mkdir -p "$results/dht/$scenario"
  printf '%q ' /vx6-test/vx6-dhtprobe "$@" --peer-record /tmp/peer-b.json --out "$scenario_dir" >"$results/dht/$scenario/command.txt"
  printf '\n' >>"$results/dht/$scenario/command.txt"
  docker exec "$peer_a" env VX6_CONFIG_PATH=/root/.config/vx6/config.json \
    /vx6-test/vx6-dhtprobe "$@" --peer-record /tmp/peer-b.json --out "$scenario_dir"
}
run_dht_case bootstrap --type bootstrap --action find_node --target "$alpha_id"
run_dht_case name-find-node --type lookup_name --action find_node --target "$beta_name_hash"
run_dht_case id-find-node --type lookup_key --action find_node --target "$beta_id"
run_dht_case name-find-value --type lookup_name --action find_value --target "$beta_name_hash"
run_dht_case id-find-value --type lookup_key --action find_value --target "$beta_id"
run_dht_case public-service-lookup --type lookup_service --action find_value --target service/BETA.e2e
run_dht_case private-catalog-lookup --type lookup_private --action find_value --target private-catalog/BETA
run_dht_case endpoint-update-id --type update_ip --action update_ip --target "node/id/$alpha_id" --data-kind endpoint --record-name ALPHA --record-address "[$peer_a_ip]:4242" --sequence 2
run_dht_case endpoint-update-name --type update_ip --action update_ip --target "node/name/$alpha_name_hash" --data-kind endpoint --record-name ALPHA --record-address "[$peer_a_ip]:4242" --sequence 3
run_dht_case public-service-store --type update --action store --target service/ALPHA.probe --data-kind service --record-name ALPHA --record-address "[$peer_a_ip]:4242" --service-name probe
run_dht_case reject-unknown-field --type lookup_key --action find_node --target "$beta_id" --corrupt unknown-field --expect-drop
run_dht_case reject-duplicate-field --type lookup_key --action find_node --target "$beta_id" --corrupt duplicate-field --expect-drop
run_dht_case reject-uppercase-hash --type lookup_key --action find_node --target "$beta_upper_id" --corrupt uppercase-hash --expect-drop
run_dht_case reject-oversized-frame --type lookup_key --action find_node --target "$beta_id" --corrupt oversized --expect-drop
run_dht_case reject-bad-endpoint-signature --type update_ip --action update_ip --target "node/id/$alpha_id" --data-kind endpoint --record-name ALPHA --record-address "[$peer_a_ip]:4242" --sequence 4 --tamper-signature --expect-drop
peer_exec "$peer_b" swanctl --list-sas >"$results/dht-sas-beta.txt"
peer_exec "$peer_b" ip -6 -s xfrm state >"$results/dht-xfrm-beta.txt"
printf 'Waiting for the one-minute bbolt peer-store flush.\n' | tee -a "$results/topology.txt"
sleep 61
peer_exec "$peer_a" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 debug dht-snapshot >"$results/dht-alpha-after.json"
peer_exec "$peer_b" env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 debug dht-snapshot >"$results/dht-beta-after.json"
python3 - "$results/dht" "$results/dht-beta-after.json" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
snapshot = json.loads(pathlib.Path(sys.argv[2]).read_text())
required = ["bootstrap", "name-find-node", "id-find-node", "name-find-value", "id-find-value",
            "public-service-lookup", "private-catalog-lookup", "endpoint-update-id",
            "endpoint-update-name", "public-service-store", "reject-unknown-field",
            "reject-duplicate-field", "reject-uppercase-hash", "reject-oversized-frame",
            "reject-bad-endpoint-signature"]
for name in required:
    result = json.loads((root / name / "result.json").read_text())
    if result.get("passed") is not True:
        raise SystemExit(f"DHT scenario failed: {name}: {result}")
for name in ("name-find-node", "id-find-node", "bootstrap"):
    response = json.loads((root / name / "response.json").read_text())
    if len(response.get("nodes", [])) > 4:
        raise SystemExit(f"{name}: referral cap exceeded")
    if not response.get("nodes"):
        raise SystemExit(f"{name}: expected a referral from the converged two-node table")
for name in ("public-service-lookup", "private-catalog-lookup"):
    response = json.loads((root / name / "response.json").read_text())
    if not response.get("value"):
        raise SystemExit(f"{name}: expected service/catalog value, got empty response")
store = snapshot.get("store", {})
if not store:
    raise SystemExit("post-test snapshot has no bbolt peer-store diagnostics")
catalog_response = json.loads((root / "private-catalog-lookup" / "response.json").read_text())
catalog_value = json.loads(catalog_response["value"])
catalog = json.loads(catalog_value["value"]) if "value" in catalog_value else catalog_value
private_service_names = [entry.get("service_name") for entry in catalog.get("services", [])]
findings = []
if "admin" in private_service_names:
    findings.append({"severity": "medium", "finding": "private service catalog metadata is visible to any authenticated DHT peer",
                     "evidence": "lookup_private response contains service name 'admin' and its signed service record; this reveals metadata but does not authorize service access"})
value_keys = {item.get("key") for item in store.get("values", [])}
expected_bbolt_keys = {"service/BETA.e2e", "private-catalog/BETA", "service/ALPHA.probe",
                       f"node/id/{json.loads((root / 'endpoint-update-id' / 'request.json').read_text())['target'].removeprefix('node/id/')}",
                       f"node/name/{json.loads((root / 'endpoint-update-name' / 'request.json').read_text())['target'].removeprefix('node/name/')}"}
missing = sorted(expected_bbolt_keys - value_keys)
if missing:
    raise SystemExit(f"expected records missing from post-test bbolt snapshot: {missing}")
(root / "security-findings.json").write_text(json.dumps(findings, indent=2) + "\n")
(root / "scenario-summary.json").write_text(json.dumps({"passed_scenarios": required, "count": len(required),
    "bbolt_store_categories": store.get("categories", {}), "bbolt_value_keys": sorted(value_keys),
    "private_catalog_service_names_visible": private_service_names, "security_findings": findings}, indent=2) + "\n")
PY
docker exec -d "$peer_a" sh -c 'exec env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 connect --service BETA.e2e --listen 127.0.0.1:18080 >/tmp/vx6-connect.log 2>&1'
printf '%s\n' 'vx6 connect --service BETA.e2e --listen 127.0.0.1:18080' >"$results/service-connect-command.txt"

for attempt in $(seq 1 30); do
  peer_exec "$peer_a" sh -c 'ss -ltn | grep -q ":18080"' && break
  sleep 1
done
printf '\n=== VX6 service request through tunnel ===\n' | tee -a "$results/topology.txt"
peer_exec "$peer_a" curl --fail --silent --show-error --retry 15 --retry-connrefused --retry-delay 1 http://127.0.0.1:18080/ \
  | tee "$results/service-response.txt"
grep -Fx "$marker" "$results/service-response.txt" >/dev/null
peer_exec "$peer_a" cat /tmp/vx6-connect.log >"$results/service-connect.log" 2>&1 || true

peer_exec "$peer_a" swanctl --list-sas >"$results/sas-before-udp.txt"
docker exec -d "$peer_a" sh -c 'exec env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 connect --service BETA.media --listen 127.0.0.1:18081 >/tmp/vx6-udp-connect.log 2>&1'
printf '%s\n' 'vx6 connect --service BETA.media --listen 127.0.0.1:18081' >"$results/udp-service-connect-command.txt"
for attempt in $(seq 1 30); do
  peer_exec "$peer_a" sh -c 'ss -lun | grep -q ":18081"' && break
  sleep 1
done
peer_exec "$peer_a" python3 -c 'import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(8); marker=sys.argv[1].encode(); s.sendto(marker,("127.0.0.1",18081)); data,_=s.recvfrom(65507); print(data.decode()); assert data==marker' "$udp_marker" \
  | tee "$results/udp-service-response.txt"
grep -Fx "$udp_marker" "$results/udp-service-response.txt" >/dev/null
peer_exec "$peer_a" swanctl --list-sas >"$results/sas-after-udp.txt"
peer_exec "$peer_a" cat /tmp/vx6-udp-connect.log >"$results/udp-service-connect.log" 2>&1 || true
awk '($1 == "in" || $1 == "out") && $6 ~ /^packets/ {sum += $5} END {print sum+0}' "$results/sas-before-udp.txt" >"$results/sa-packets-before-udp.count"
awk '($1 == "in" || $1 == "out") && $6 ~ /^packets/ {sum += $5} END {print sum+0}' "$results/sas-after-udp.txt" >"$results/sa-packets-after-udp.count"
read -r packets_before_udp <"$results/sa-packets-before-udp.count"
read -r packets_after_udp <"$results/sa-packets-after-udp.count"
if ((packets_after_udp <= packets_before_udp)); then
  printf 'FAIL: ESP SA packet counters did not increase for the UDP service exchange.\n' >&2
  exit 1
fi

printf '\n=== Private service lookup and allowlist enforcement ===\n' | tee -a "$results/topology.txt"
docker exec -d "$peer_a" sh -c 'exec env VX6_CONFIG_PATH=/root/.config/vx6/config.json /vx6-test/vx6 connect --service BETA.admin --listen 127.0.0.1:18082 >/tmp/vx6-private-connect.log 2>&1'
printf '%s\n' 'vx6 connect --service BETA.admin --listen 127.0.0.1:18082' >"$results/private-service-connect-command.txt"
for attempt in $(seq 1 30); do
  peer_exec "$peer_a" sh -c 'ss -ltn | grep -q ":18082"' && break
  sleep 1
done
peer_exec "$peer_a" sh -c 'ss -ltn | grep -q ":18082"'
if peer_exec "$peer_a" curl --max-time 8 --fail --silent --show-error http://127.0.0.1:18082/ \
  >"$results/private-service-denied-response.txt" 2>"$results/private-service-denied-error.txt"; then
  printf 'FAIL: a peer outside the private-service allowlist received a response.\n' >&2
  exit 1
fi
if grep -Fq 'VX6_PRIVATE_ADMIN_SENTINEL' "$results/private-service-denied-response.txt"; then
  printf 'FAIL: private service content reached a non-allowlisted peer.\n' >&2
  exit 1
fi
printf 'PASS: authenticated peer without allowlist entry was denied.\n' | tee -a "$results/topology.txt"
peer_exec "$peer_b" env VX6_CONFIG_PATH=/root/.config/vx6/config.json \
  /vx6-test/vx6 service allow --name admin --node-id "$alpha_id" >"$results/private-service-allow.txt"
sleep 1
peer_exec "$peer_a" curl --max-time 8 --fail --silent --show-error --retry 5 --retry-connrefused --retry-delay 1 \
  http://127.0.0.1:18082/ | tee "$results/private-service-allowed-response.txt"
grep -Fx 'VX6_PRIVATE_ADMIN_SENTINEL' "$results/private-service-allowed-response.txt" >/dev/null
peer_exec "$peer_a" cat /tmp/vx6-private-connect.log >"$results/private-service-connect.log" 2>&1 || true
printf 'PASS: after owner allowlisted ALPHA NodeID, the same private service returned its sentinel.\n' | tee -a "$results/topology.txt"

printf '\n=== Untrusted cleartext probe of the VX6 listener ===\n' | tee -a "$results/topology.txt"
if docker exec "$sniffer" timeout 3 nc -6 -z "$peer_b_ip" 4242; then
  printf 'FAIL: an untrusted non-IPsec TCP probe connected to the VX6 listener.\n' | tee "$results/clear-probe.txt"
  exit 1
else
  printf 'PASS: untrusted non-IPsec TCP probe was blocked.\n' | tee "$results/clear-probe.txt"
fi

printf '\n=== Ping after CHILD_SA establishment ===\n' | tee -a "$results/topology.txt"
peer_exec "$peer_a" swanctl --list-sas | tee "$results/sas-a-before-post-ping.txt" >/dev/null
peer_exec "$peer_a" ping -6 -c 2 -W 2 "$peer_b_ip" 2>&1 | tee "$results/ping-after.txt"
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
tcpdump -nnr "$results/wire.pcap" "ip6 and host $peer_a_ip and host $peer_b_ip and (tcp port 4242 or udp port 4244)" 2>/dev/null | wc -l >"$results/clear-vx6-port-packets.count"
tcpdump -nnr "$results/wire.pcap" "icmp6 and host $peer_a_ip and host $peer_b_ip" 2>/dev/null | wc -l >"$results/clear-peer-icmp6-packets.count"
awk '$1 == "in" {in_packets += $5} $1 == "out" {out_packets += $5} END {print in_packets+0, out_packets+0}' "$results/sas-a-before-post-ping.txt" >"$results/sa-counters-before-ping.txt"
awk '$1 == "in" {in_packets += $5} $1 == "out" {out_packets += $5} END {print in_packets+0, out_packets+0}' "$results/sas-a.txt" >"$results/sa-counters-after-ping.txt"
read -r in_before out_before <"$results/sa-counters-before-ping.txt"
read -r in_after out_after <"$results/sa-counters-after-ping.txt"
first_ike=$(awk '/isakmp: parent_sa ikev2_init/ {print $1; exit}' "$results/packets.txt")
awk -v ike="$first_ike" '$0 ~ /ICMP6, echo (request|reply)/ && $1 > ike {count++} END {print count+0}' \
  "$results/packets.txt" >"$results/clear-icmp-after-ike.count"
if strings "$results/wire.pcap" | grep -F -e "$marker" -e "$udp_marker" >"$results/sentinel-match.txt"; then
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
  printf 'ICMPv6 verdict: diagnostic only; current CHILD_SA selectors cover TCP/UDP, not ICMPv6\n'
  printf 'Service sentinel in capture: no\n'
  printf 'UDP service response: '; cat "$results/udp-service-response.txt"
  printf 'ESP SA packet count before/after UDP exchange: %s/%s\n' "$packets_before_udp" "$packets_after_udp"
} | tee "$results/verdict.txt"

if [[ $(cat "$results/esp-packets.count") -eq 0 ]]; then
  printf 'FAIL: transit sniffer saw no ESP packets.\n' >&2
  exit 1
fi
if [[ $(cat "$results/clear-vx6-port-packets.count") -ne 0 ]]; then
  printf 'FAIL: transit sniffer saw clear VX6-port traffic.\n' >&2
  exit 1
fi
printf '\n=== Revoke the connected peer and verify active SA removal ===\n' | tee -a "$results/topology.txt"
peer_node_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["node_id"])' "$work/peer-b.json")
peer_exec "$peer_a" env VX6_CONFIG_PATH=/root/.config/vx6/config.json \
  /vx6-test/vx6 peer revoke --node-id "$peer_node_id" | tee "$results/revoke.txt"
if peer_exec "$peer_a" swanctl --list-sas | grep -q 'ESTABLISHED'; then
  printf 'FAIL: an IKE SA remained established after peer revocation.\n' >&2
  exit 1
fi
if peer_exec "$peer_a" ip -6 xfrm state | grep -q 'proto esp'; then
  printf 'FAIL: an ESP state remained installed after peer revocation.\n' >&2
  exit 1
fi
if ! peer_exec "$peer_a" grep -R -F "$peer_node_id" /var/lib/vx6/ipsec >/dev/null 2>&1; then
  printf 'FAIL: the local revocation was not persisted.\n' >&2
  exit 1
fi
printf 'PASS: revocation persisted and the active IKE/ESP state was removed.\n' | tee -a "$results/revoke.txt"
printf '\nPacket listing: %s\n' "$results/packets.txt"
printf 'Full capture and logs: %s\n' "$results"
