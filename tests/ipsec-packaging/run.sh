#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
run_id="$(date +%Y%m%d-%H%M%S)-$$"
image=vx6-package-e2e:local
results=${VX6_PACKAGE_E2E_RESULTS_DIR:-"/tmp/vx6-package-e2e-$run_id"}
work=$(mktemp -d)
net_a="vx6-pkg-a-$run_id"
net_b="vx6-pkg-b-$run_id"
net_c="vx6-pkg-c-$run_id"
node_a="vx6-pkg-alpha-$run_id"
node_b="vx6-pkg-beta-$run_id"
node_c="vx6-pkg-charlie-$run_id"
router="vx6-pkg-router-$run_id"
mkdir -p "$results"

cleanup() {
  local status=${1:-$?}
  if docker inspect "$router" >/dev/null 2>&1; then
    docker exec "$router" sh -c 'kill -INT "$(cat /tmp/capture.pid 2>/dev/null)" 2>/dev/null || true; sleep 1' >/dev/null 2>&1 || true
    docker cp "$router:/tmp/vx6-mesh.pcap" "$results/vx6-mesh.pcap" >/dev/null 2>&1 || true
    docker cp "$router:/tmp/tcpdump.log" "$results/tcpdump.log" >/dev/null 2>&1 || true
  fi
  if (( status != 0 )); then
    for c in "$node_a" "$node_b" "$node_c" "$router"; do
      if docker inspect "$c" >/dev/null 2>&1; then
        docker logs "$c" >"$results/$c.docker.log" 2>&1 || true
        docker exec "$c" sh -c 'for f in /tmp/charon.log /tmp/ipsecd.log /tmp/vx6-node.log /tmp/connect.log /tmp/http.log; do [ ! -f "$f" ] || { echo "=== $f ==="; cat "$f"; }; done' \
          >"$results/$c.runtime.log" 2>&1 || true
        docker exec "$c" journalctl -b --no-pager >"$results/$c.journal.log" 2>&1 || true
      fi
    done
    printf 'Test failed; logs and captures are in %s\n' "$results" >&2
  fi
  docker rm -f "$node_a" "$node_b" "$node_c" "$router" >/dev/null 2>&1 || true
  docker network rm "$net_a" "$net_b" "$net_c" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

if ! docker info >/dev/null 2>&1; then
  printf 'Docker daemon unavailable or current user cannot access it.\n' >&2
  exit 2
fi
for command in docker tcpdump strings; do
  command -v "$command" >/dev/null || { printf 'Missing host command: %s\n' "$command" >&2; exit 2; }
done

printf 'Building Linux amd64 bundle and clean-node test image...\n'
make -C "$repo_root" package-linux
docker build -f "$repo_root/tests/ipsec-packaging/Dockerfile" -t "$image" "$repo_root"

docker network create --ipv6 --subnet fd42:6:1::/64 "$net_a" >/dev/null
docker network create --ipv6 --subnet fd42:6:2::/64 "$net_b" >/dev/null
docker network create --ipv6 --subnet fd42:6:3::/64 "$net_c" >/dev/null
docker run -d --name "$router" --privileged --network "$net_a" --ip6 fd42:6:1::2 "$image" sleep infinity >/dev/null
docker network connect --ip6 fd42:6:2::2 "$net_b" "$router"
docker network connect --ip6 fd42:6:3::2 "$net_c" "$router"
docker exec "$router" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

docker run -d --name "$node_a" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --network "$net_a" --ip6 fd42:6:1::10 -v "$repo_root/dist/linux:/vx6-bundle:ro" "$image" >/dev/null
docker run -d --name "$node_b" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --network "$net_b" --ip6 fd42:6:2::10 -v "$repo_root/dist/linux:/vx6-bundle:ro" "$image" >/dev/null
docker run -d --name "$node_c" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --network "$net_c" --ip6 fd42:6:3::10 -v "$repo_root/dist/linux:/vx6-bundle:ro" "$image" >/dev/null

peer_exec() { local c=$1; shift; docker exec "$c" "$@"; }
user_exec() {
  local c=$1; shift
  docker exec --user vx6test --env HOME=/home/vx6test --env VX6_CONFIG_PATH=/home/vx6test/.config/vx6/config.json "$c" "$@"
}

install_peer() {
  local c=$1
  peer_exec "$c" useradd --create-home --shell /bin/bash vx6test
  peer_exec "$c" /vx6-bundle/install.sh vx6test
  local uid gid
  uid=$(peer_exec "$c" id -u vx6test)
  gid=$(peer_exec "$c" id -g vx6test)
  peer_exec "$c" test -f /usr/bin/vx6
  peer_exec "$c" test -x /usr/bin/vx6-ipsecd
  peer_exec "$c" test -x /usr/bin/vx6-setup
  peer_exec "$c" bash -c "jq -e '.allowed_uids == [$uid] and .socket_gid == $gid' /etc/vx6/ipsecd.json >/dev/null" 2>/dev/null || \
    peer_exec "$c" python3 -c 'import json,os,sys; c=json.load(open("/etc/vx6/ipsecd.json")); assert c["allowed_uids"]==[int(sys.argv[1])] and c["socket_gid"]==int(sys.argv[2]); assert os.stat("/etc/vx6/ipsecd.json").st_uid==0; assert os.stat("/etc/vx6/ipsecd.json").st_mode & 0o022 == 0' "$uid" "$gid"
  peer_exec "$c" /usr/bin/vx6-setup vx6test
  for _ in $(seq 1 30); do
    if peer_exec "$c" systemctl is-active --quiet vx6-ipsecd.service; then break; fi
    sleep 1
  done
  peer_exec "$c" systemctl is-active --quiet vx6-ipsecd.service
  peer_exec "$c" swanctl --list-sas >/dev/null
  for _ in $(seq 1 15); do
    peer_exec "$c" test -S /run/vx6/ipsecd.sock && break
    sleep 1
  done
  peer_exec "$c" test -S /run/vx6/ipsecd.sock
}

install_pids=()
for c in "$node_a" "$node_b" "$node_c"; do
  install_peer "$c" >"$results/$c-install.log" 2>&1 &
  install_pids+=("$!")
done
for i in "${!install_pids[@]}"; do
  if ! wait "${install_pids[$i]}"; then
    cat "$results/$(printf '%s' "$node_a $node_b $node_c" | cut -d' ' -f$((i + 1)))-install.log" >&2 || true
    exit 1
  fi
done

# Route each isolated peer subnet through the three-interface router.
peer_exec "$node_a" ip -6 route add fd42:6:2::/64 via fd42:6:1::2
peer_exec "$node_a" ip -6 route add fd42:6:3::/64 via fd42:6:1::2
peer_exec "$node_b" ip -6 route add fd42:6:1::/64 via fd42:6:2::2
peer_exec "$node_b" ip -6 route add fd42:6:3::/64 via fd42:6:2::2
peer_exec "$node_c" ip -6 route add fd42:6:1::/64 via fd42:6:3::2
peer_exec "$node_c" ip -6 route add fd42:6:2::/64 via fd42:6:3::2
peer_exec "$node_a" ping -6 -c 1 -W 3 fd42:6:2::10 >"$results/route-a-b.txt"
peer_exec "$node_c" ping -6 -c 1 -W 3 fd42:6:1::10 >"$results/route-c-a.txt"

init_node() {
  local c=$1 name=$2 addr=$3
  user_exec "$c" /usr/bin/vx6 init --name "$name" --listen "[$addr]:4242" --advertise "[$addr]:4242" --relay off
}
init_node "$node_a" ALPHA fd42:6:1::10 | tee "$results/init-alpha.txt"
init_node "$node_b" BETA fd42:6:2::10 | tee "$results/init-beta.txt"
init_node "$node_c" CHARLIE fd42:6:3::10 | tee "$results/init-charlie.txt"
for c in "$node_a" "$node_b" "$node_c"; do
  user_exec "$c" /usr/bin/vx6 doctor >"$results/$c-doctor.txt" 2>&1 || true
  grep -q $'^OK\tipsec_helper$' "$results/$c-doctor.txt"
done

user_exec "$node_a" /usr/bin/vx6 identity export-endpoint --addr '[fd42:6:1::10]:4242' --out /tmp/alpha.json
user_exec "$node_b" /usr/bin/vx6 identity export-endpoint --addr '[fd42:6:2::10]:4242' --out /tmp/beta.json
user_exec "$node_c" /usr/bin/vx6 identity export-endpoint --addr '[fd42:6:3::10]:4242' --out /tmp/charlie.json
docker cp "$node_a:/tmp/alpha.json" "$work/alpha.json" >/dev/null
docker cp "$node_b:/tmp/beta.json" "$work/beta.json" >/dev/null
docker cp "$node_c:/tmp/charlie.json" "$work/charlie.json" >/dev/null

add_record() {
  local c=$1 file=$2
  docker cp "$file" "$c:/tmp/peer-record.json" >/dev/null
  user_exec "$c" /usr/bin/vx6 peer add --record /tmp/peer-record.json
}

printf '\n=== Stage 1: Alpha and Beta join and exchange signed peer records ===\n' | tee "$results/topology.txt"
add_record "$node_a" "$work/beta.json"
add_record "$node_b" "$work/alpha.json"
marker_ab="VX6_PACKAGE_AB_$run_id"
peer_exec "$node_a" sh -c "mkdir -p /tmp/www; printf '%s\\n' '$marker_ab' >/tmp/www/index.html; exec python3 -m http.server 9000 --bind :: --directory /tmp/www >/tmp/http.log 2>&1" >/dev/null 2>&1 &
user_exec "$node_a" /usr/bin/vx6 service add --name public --target '[::1]:9000'
for c in "$node_a" "$node_b"; do
  user_exec "$c" /usr/bin/vx6 node >"$results/$c-node.log" 2>&1 &
done
sleep 4
user_exec "$node_b" /usr/bin/vx6 connect --service ALPHA.public --listen 127.0.0.1:18080 >"$results/ab-connect.log" 2>&1 &
for _ in $(seq 1 30); do
  if peer_exec "$node_b" sh -c 'ss -ltn | grep -q ":18080"'; then break; fi
  sleep 1
done
peer_exec "$node_b" curl --fail --silent --show-error --retry 15 --retry-connrefused --retry-delay 1 http://127.0.0.1:18080/ >"$results/ab-response.txt"
grep -Fx "$marker_ab" "$results/ab-response.txt" >/dev/null
peer_exec "$node_a" swanctl --list-sas >"$results/ab-sas-alpha.txt"
peer_exec "$node_b" swanctl --list-sas >"$results/ab-sas-beta.txt"
grep -q ESTABLISHED "$results/ab-sas-alpha.txt"

printf '\n=== Stage 2: Charlie joins through Alpha and reaches Alpha service by DHT ===\n' | tee -a "$results/topology.txt"
add_record "$node_a" "$work/charlie.json"
add_record "$node_c" "$work/alpha.json"
marker_ca="VX6_PACKAGE_CA_$run_id"
peer_exec "$node_a" sh -c "printf '%s\\n' '$marker_ca' >/tmp/www/index.html"
peer_exec "$node_c" sh -c "mkdir -p /tmp/charlie-www; printf '%s\\n' 'VX6_PACKAGE_AC_$run_id' >/tmp/charlie-www/index.html; exec python3 -m http.server 9001 --bind :: --directory /tmp/charlie-www >/tmp/http.log 2>&1" >/dev/null 2>&1 &
user_exec "$node_c" /usr/bin/vx6 service add --name public --target '[::1]:9001'
user_exec "$node_c" /usr/bin/vx6 node >"$results/charlie-node.log" 2>&1 &
sleep 5
for _ in $(seq 1 20); do
  if user_exec "$node_c" /usr/bin/vx6 debug dht-get --service ALPHA.public >"$results/charlie-dht-service.txt" 2>&1 && \
     python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["node_name"]=="ALPHA" and r["service_name"]=="public"' "$results/charlie-dht-service.txt"; then
    break
  fi
  sleep 2
done
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["node_name"]=="ALPHA" and r["service_name"]=="public"' "$results/charlie-dht-service.txt"
user_exec "$node_c" /usr/bin/vx6 connect --service ALPHA.public --listen 127.0.0.1:18081 >"$results/ca-connect.log" 2>&1 &
for _ in $(seq 1 30); do
  if peer_exec "$node_c" sh -c 'ss -ltn | grep -q ":18081"'; then break; fi
  sleep 1
done
peer_exec "$node_c" curl --fail --silent --show-error --retry 15 --retry-connrefused --retry-delay 1 http://127.0.0.1:18081/ >"$results/ca-response.txt"
grep -Fx "$marker_ca" "$results/ca-response.txt" >/dev/null
peer_exec "$node_a" swanctl --list-sas >"$results/ca-sas-alpha.txt"
peer_exec "$node_c" swanctl --list-sas >"$results/ca-sas-charlie.txt"
grep -q ESTABLISHED "$results/ca-sas-alpha.txt"
grep -q ESTABLISHED "$results/ca-sas-charlie.txt"
peer_exec "$node_a" ip -6 -s xfrm state >"$results/ca-xfrm-alpha.txt"
peer_exec "$node_c" ip -6 -s xfrm state >"$results/ca-xfrm-charlie.txt"
grep -q 'proto esp' "$results/ca-xfrm-alpha.txt"
grep -q 'proto esp' "$results/ca-xfrm-charlie.txt"

user_exec "$node_a" /usr/bin/vx6 debug dht-get --service CHARLIE.public >"$results/alpha-dht-charlie-service.txt"
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["node_name"]=="CHARLIE" and r["service_name"]=="public"' "$results/alpha-dht-charlie-service.txt"
user_exec "$node_a" /usr/bin/vx6 connect --service CHARLIE.public --listen 127.0.0.1:18082 >"$results/ac-connect.log" 2>&1 &
for _ in $(seq 1 30); do
  if peer_exec "$node_a" sh -c 'ss -ltn | grep -q ":18082"'; then break; fi
  sleep 1
done
peer_exec "$node_a" curl --fail --silent --show-error --retry 15 --retry-connrefused --retry-delay 1 http://127.0.0.1:18082/ >"$results/ac-response.txt"
grep -Fx "VX6_PACKAGE_AC_$run_id" "$results/ac-response.txt" >/dev/null

docker exec -d "$router" sh -c 'tcpdump -nni any -s 0 -U -w /tmp/vx6-mesh.pcap ip6 >/tmp/tcpdump.log 2>&1 & echo $! >/tmp/capture.pid; wait $(cat /tmp/capture.pid)'
sleep 1
peer_exec "$node_c" curl --fail --silent http://127.0.0.1:18081/ >/dev/null
sleep 1
docker exec "$router" sh -c 'kill -INT "$(cat /tmp/capture.pid)"; sleep 1'
docker cp "$router:/tmp/vx6-mesh.pcap" "$results/vx6-mesh.pcap" >/dev/null
tcpdump -nnr "$results/vx6-mesh.pcap" 'ip6 proto 50' 2>/dev/null | wc -l >"$results/esp-packet-count.txt"
if strings "$results/vx6-mesh.pcap" | grep -F -e "$marker_ab" -e "$marker_ca" >"$results/clear-marker-matches.txt"; then
  printf 'Application marker leaked into the transit PCAP.\n' >&2
  exit 1
fi
[[ $(cat "$results/esp-packet-count.txt") -gt 0 ]]

{
  printf 'PASS: clean bundle installed in three fresh Ubuntu containers.\n'
  printf 'PASS: per-user helper configuration uses each test account UID/GID.\n'
  printf 'PASS: Alpha-Beta service exchange returned: '; cat "$results/ab-response.txt"
  printf 'PASS: Charlie reached Alpha and Alpha reached Charlie through DHT-discovered services.\n'
  printf 'PASS: IKE_SAs established on Alpha-Charlie; ESP states installed.\n'
  printf 'Transit ESP packet count: %s\n' "$(cat "$results/esp-packet-count.txt")"
  printf 'Application marker visible in transit PCAP: no\n'
  printf 'Evidence directory: %s\n' "$results"
} | tee "$results/REPORT.txt"

printf '\nFull evidence: %s\n' "$results"
