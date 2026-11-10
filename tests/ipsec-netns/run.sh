#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
if [[ ${VX6_NETNS_INNER:-0} != 1 ]]; then
  exec unshare --user \
    --map-users=0:1000:1 --map-users=1000:100000:1000 \
    --map-groups=0:1000:1 --map-groups=1000:100000:1000 --setgroups=allow \
    --mount --net env VX6_NETNS_INNER=1 bash "$0"
fi

mount --make-rprivate /
bin_dir=${VX6_BIN_DIR:-"$repo_root/dist/linux"}
for bin in vx6 vx6-ipsecd; do
  [[ -x $bin_dir/$bin ]] || { printf 'Missing %s; run make package-linux first.\n' "$bin_dir/$bin" >&2; exit 2; }
done
for cmd in ip nsenter sysctl tcpdump swanctl; do
  command -v "$cmd" >/dev/null || { printf 'Missing host command: %s\n' "$cmd" >&2; exit 2; }
done
[[ -x /usr/lib/strongswan/charon ]] || { printf 'strongSwan charon is unavailable.\n' >&2; exit 2; }

run_id="$(date +%Y%m%d-%H%M%S)-$$"
work=$(mktemp -d "/tmp/vx6-netns-$run_id.XXXXXX")
results=${VX6_NETNS_RESULTS_DIR:-"/tmp/vx6-netns-results-$run_id"}
mkdir -p "$results"
chmod 0755 "$work" "$results"
declare -A peer_pids
declare -a child_pids
capture_pid=

cleanup() {
  local status=${1:-$?}
  trap - EXIT INT TERM
  if [[ -n $capture_pid ]]; then kill -INT "$capture_pid" 2>/dev/null || true; fi
  for pid in "${child_pids[@]:-}"; do kill -TERM "$pid" 2>/dev/null || true; done
  for pid in "${peer_pids[@]:-}"; do kill -TERM "$pid" 2>/dev/null || true; done
  sleep 0.2
  for pid in "${child_pids[@]:-}"; do kill -KILL "$pid" 2>/dev/null || true; done
  for pid in "${peer_pids[@]:-}"; do kill -KILL "$pid" 2>/dev/null || true; done
  for pid in "${child_pids[@]:-}"; do wait "$pid" 2>/dev/null || true; done
  for name in alpha beta charlie; do
    pid=${peer_pids[$name]:-}
    [[ -z $pid ]] || wait "$pid" 2>/dev/null || true
  done
  if (( status != 0 )); then
    printf 'Namespace test failed; diagnostics are in %s\n' "$results" >&2
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT INT TERM

peer_dir() { printf '%s/%s' "$work" "$1"; }
peer_pid() { printf '%s' "${peer_pids[$1]}"; }
peer_exec() {
  local name=$1; shift
  local dir pid
  dir=$(peer_dir "$name")
  pid=$(peer_pid "$name")
  nsenter -t "$pid" -n -m -- env HOME="$dir/home" \
    VX6_CONFIG_PATH="$dir/home/.config/vx6/config.json" \
    setpriv --reuid=1000 --regid=1000 --clear-groups "$@"
}
peer_root() {
  local name=$1; shift
  local dir pid
  dir=$(peer_dir "$name")
  pid=$(peer_pid "$name")
  nsenter -t "$pid" -n -m -- env HOME="$dir/home" \
    VX6_CONFIG_PATH="$dir/home/.config/vx6/config.json" "$@"
}
spawn_peer() {
  local name=$1 log=$2; shift 2
  local pid
  pid=$(peer_pid "$name")
  nsenter -t "$pid" -n -m -- env HOME="$(peer_dir "$name")/home" \
    VX6_CONFIG_PATH="$(peer_dir "$name")/home/.config/vx6/config.json" \
    setpriv --reuid=1000 --regid=1000 --clear-groups "$@" >"$log" 2>&1 &
  child_pids+=("$!")
}
spawn_root_peer() {
  local name=$1 log=$2; shift 2
  local pid
  pid=$(peer_pid "$name")
  nsenter -t "$pid" -n -m -- "$@" >"$log" 2>&1 &
  child_pids+=("$!")
}
start_peer_ns() {
  local name=$1 dir pid
  dir=$(peer_dir "$name")
  mkdir -p "$dir/run/vx6" "$dir/home" "$dir/ipsec" "$dir/home/.config/vx6"
  chmod 0711 "$dir"
  chown -R 1000:1000 "$dir/home"
  cat >"$dir/strongswan.conf" <<EOF
charon {
	load_modular = yes
	plugins {
		include /etc/strongswan.d/charon/*.conf
		vici { socket = unix:///run/charon.vici }
	}
	filelog {
		charon {
			path = $dir/charon.log
			default = 1
			ike = 1
			cfg = 1
			knl = 1
			flush_line = yes
		}
	}
}
include /etc/strongswan.d/*.conf
EOF
  unshare --mount --net sh -c 'mount --make-rprivate /; mount --bind "$1/run" /run; mount --bind "$1/strongswan.conf" /etc/strongswan.conf; exec sleep infinity' sh "$dir" \
    >"$results/$name-namespace.log" 2>&1 &
  pid=$!
  peer_pids[$name]=$pid
  for _ in $(seq 1 50); do
    [[ -e /proc/$pid/ns/net && -e /proc/$pid/ns/mnt ]] && break
    sleep 0.1
  done
  [[ -e /proc/$pid/ns/net && -e /proc/$pid/ns/mnt ]]
  cat >"$dir/ipsecd.json" <<EOF
{
  "socket": "/run/vx6/ipsecd.sock",
  "state_dir": "$dir/ipsec",
  "socket_gid": 1000,
  "allowed_uids": [1000]
}
EOF
  chmod 0600 "$dir/ipsecd.json"
  ip link add "r-${name}" type veth peer name "p-${name}"
  ip link set "p-${name}" netns "$pid"
  ip link set "r-${name}" up
}

start_peer_ns alpha
start_peer_ns beta
start_peer_ns charlie
ip link set lo up
ip -6 addr add fd42:6:1::2/64 dev r-alpha nodad
ip -6 addr add fd42:6:2::2/64 dev r-beta nodad
ip -6 addr add fd42:6:3::2/64 dev r-charlie nodad
sysctl -q -w net.ipv6.conf.all.forwarding=1
sysctl -q -w net.ipv6.conf.default.forwarding=1
sysctl net.ipv6.conf.all.forwarding net.ipv6.conf.default.forwarding >"$results/router-forwarding.txt"
ip -6 addr show >"$results/router-addresses.txt"
ip -6 route show >"$results/router-routes.txt"

for name in alpha beta charlie; do
  dir=$(peer_dir "$name")
  case $name in
    alpha) addr=fd42:6:1::10; gateway=fd42:6:1::2; iface=p-alpha ;;
    beta) addr=fd42:6:2::10; gateway=fd42:6:2::2; iface=p-beta ;;
    charlie) addr=fd42:6:3::10; gateway=fd42:6:3::2; iface=p-charlie ;;
  esac
  pid=$(peer_pid "$name")
  nsenter -t "$pid" -n -- ip link set lo up
  nsenter -t "$pid" -n -- ip link set "$iface" up
  nsenter -t "$pid" -n -- ip -6 addr add "$addr/64" dev "$iface" nodad
  for prefix in fd42:6:1::/64 fd42:6:2::/64 fd42:6:3::/64; do
    [[ $prefix == "${addr%::*}::/64" ]] && continue
    nsenter -t "$pid" -n -- ip -6 route add "$prefix" via "$gateway" dev "$iface"
  done
  nsenter -t "$pid" -n -- ip -6 route show >"$results/$name-routes.txt"
  nsenter -t "$pid" -n -- ip -6 addr show >"$results/$name-addresses.txt"

  spawn_root_peer "$name" "$results/$name-charon.log" /usr/lib/strongswan/charon --debug-ike 1
  ready=0
  for _ in $(seq 1 50); do
    if peer_root "$name" swanctl --list-sas >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.2
  done
  (( ready == 1 )) || { printf 'charon/VICI did not start for %s\n' "$name" >&2; exit 1; }
  spawn_root_peer "$name" "$results/$name-ipsecd.log" "$bin_dir/vx6-ipsecd" --config "$dir/ipsecd.json"
  ready=0
  for _ in $(seq 1 50); do
    if peer_exec "$name" test -S /run/vx6/ipsecd.sock; then ready=1; break; fi
    sleep 0.2
  done
  (( ready == 1 )) || { printf 'vx6-ipsecd did not start for %s\n' "$name" >&2; exit 1; }
done

peer_root alpha ping -6 -I p-alpha -c 1 -W 2 fd42:6:1::2 >"$results/route-alpha-gateway.txt" || true
peer_root alpha ping -6 -I p-alpha -c 1 -W 2 fd42:6:2::10 >"$results/route-alpha-beta.txt" || true
peer_root charlie ping -6 -I p-charlie -c 1 -W 2 fd42:6:1::10 >"$results/route-charlie-alpha.txt" || true

init_peer() {
  local name=$1 node_name=$2 endpoint=$3
  peer_exec "$name" "$bin_dir/vx6" init --name "$node_name" \
    --listen "[$endpoint]:4242" --advertise "[$endpoint]:4242" --relay off
}
init_peer alpha ALPHA fd42:6:1::10 | tee "$results/init-alpha.txt"
init_peer beta BETA fd42:6:2::10 | tee "$results/init-beta.txt"
init_peer charlie CHARLIE fd42:6:3::10 | tee "$results/init-charlie.txt"

peer_exec alpha "$bin_dir/vx6" identity export-endpoint --addr '[fd42:6:1::10]:4242' --out "$(peer_dir alpha)/home/alpha.json"
peer_exec beta "$bin_dir/vx6" identity export-endpoint --addr '[fd42:6:2::10]:4242' --out "$(peer_dir beta)/home/beta.json"
peer_exec charlie "$bin_dir/vx6" identity export-endpoint --addr '[fd42:6:3::10]:4242' --out "$(peer_dir charlie)/home/charlie.json"
cp "$(peer_dir alpha)/home/alpha.json" "$(peer_dir beta)/home/alpha.json"
cp "$(peer_dir alpha)/home/alpha.json" "$(peer_dir charlie)/home/alpha.json"
cp "$(peer_dir beta)/home/beta.json" "$(peer_dir alpha)/home/beta.json"
cp "$(peer_dir charlie)/home/charlie.json" "$(peer_dir alpha)/home/charlie.json"
chown 1000:1000 "$(peer_dir beta)/home/alpha.json" "$(peer_dir charlie)/home/alpha.json"
chown 1000:1000 "$(peer_dir alpha)/home/beta.json" "$(peer_dir alpha)/home/charlie.json"
peer_exec alpha "$bin_dir/vx6" peer add --record "$(peer_dir alpha)/home/beta.json"
peer_exec beta "$bin_dir/vx6" peer add --record "$(peer_dir beta)/home/alpha.json"

mkdir -p "$work/alpha-www" "$work/charlie-www"
chown 1000:1000 "$work/alpha-www" "$work/charlie-www"
marker_ab="VX6_NETNS_AB_$run_id"
marker_ca="VX6_NETNS_CA_$run_id"
marker_ac="VX6_NETNS_AC_$run_id"
printf '%s\n' "$marker_ab" >"$work/alpha-www/index.html"
printf '%s\n' "$marker_ca" >"$work/alpha-www/ca.html"
printf '%s\n' "$marker_ac" >"$work/charlie-www/index.html"
spawn_peer alpha "$results/alpha-http.log" python3 -m http.server 9100 --bind :: --directory "$work/alpha-www"
spawn_peer charlie "$results/charlie-http.log" python3 -m http.server 9101 --bind :: --directory "$work/charlie-www"
peer_exec alpha "$bin_dir/vx6" service add --name public --target '[::1]:9100'
peer_exec charlie "$bin_dir/vx6" service add --name public --target '[::1]:9101'

for name in alpha beta; do spawn_peer "$name" "$results/$name-node.log" "$bin_dir/vx6" node; done
sleep 2

# Reproduce a broad, higher-priority pass policy that can shadow VX6's
# endpoint-specific CHILD_SA unless VX6 assigns its policies explicit priority.
peer_root alpha ip -6 xfrm policy add src fd42:6:1::/64 dst fd42:6:2::/64 dir out action allow priority 134463
peer_root beta ip -6 xfrm policy add src fd42:6:2::/64 dst fd42:6:1::/64 dir out action allow priority 134463
peer_root alpha ip -6 -s xfrm policy >"$results/alpha-policy-conflict.txt"
peer_root beta ip -6 -s xfrm policy >"$results/beta-policy-conflict.txt"
grep -q 'priority 134463' "$results/alpha-policy-conflict.txt"
grep -q 'priority 134463' "$results/beta-policy-conflict.txt"

tcpdump -nni any -s 0 -U -w "$results/transit.pcap" ip6 >"$results/tcpdump.log" 2>&1 &
capture_pid=$!
sleep 1

printf '=== A-B service test ===\n' | tee "$results/topology.txt"
spawn_peer beta "$results/beta-connect.log" "$bin_dir/vx6" connect --service ALPHA.public --listen 127.0.0.1:18080
for _ in $(seq 1 50); do
  if peer_exec beta sh -c 'ss -ltn | grep -q ":18080"'; then break; fi
  sleep 0.2
done
peer_exec beta curl --fail --silent --show-error --retry 20 --retry-connrefused --retry-delay 1 http://127.0.0.1:18080/ >"$results/ab-response.txt"
grep -Fx "$marker_ab" "$results/ab-response.txt" >/dev/null
peer_root alpha swanctl --list-sas >"$results/ab-sas-alpha.txt"
peer_root beta swanctl --list-sas >"$results/ab-sas-beta.txt"
grep -q ESTABLISHED "$results/ab-sas-alpha.txt"
grep -q ESTABLISHED "$results/ab-sas-beta.txt"

printf '=== C joins via A; bidirectional DHT service tests ===\n' | tee -a "$results/topology.txt"
peer_exec alpha "$bin_dir/vx6" peer add --record "$(peer_dir alpha)/home/charlie.json"
peer_exec charlie "$bin_dir/vx6" peer add --record "$(peer_dir charlie)/home/alpha.json"
spawn_peer charlie "$results/charlie-node.log" "$bin_dir/vx6" node
sleep 3
peer_root alpha ip -6 xfrm policy add src fd42:6:1::/64 dst fd42:6:3::/64 dir out action allow priority 134463
peer_root charlie ip -6 xfrm policy add src fd42:6:3::/64 dst fd42:6:1::/64 dir out action allow priority 134463
peer_root alpha ip -6 -s xfrm policy >"$results/alpha-charlie-policy-conflict.txt"
peer_root charlie ip -6 -s xfrm policy >"$results/charlie-alpha-policy-conflict.txt"
grep -q 'priority 134463' "$results/alpha-charlie-policy-conflict.txt"
grep -q 'priority 134463' "$results/charlie-alpha-policy-conflict.txt"
lookup_ok=0
for _ in $(seq 1 20); do
  if peer_exec charlie "$bin_dir/vx6" debug dht-get --service ALPHA.public >"$results/charlie-dht-alpha.json" 2>&1 && \
     python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["node_name"]=="ALPHA" and r["service_name"]=="public"' "$results/charlie-dht-alpha.json"; then
    lookup_ok=1; break
  fi
  sleep 1
done
(( lookup_ok == 1 )) || { printf 'Charlie could not resolve Alpha.public from the DHT.\n' >&2; exit 1; }
peer_exec alpha "$bin_dir/vx6" debug dht-get --service CHARLIE.public >"$results/alpha-dht-charlie.json"
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["node_name"]=="CHARLIE" and r["service_name"]=="public"' "$results/alpha-dht-charlie.json"

spawn_peer charlie "$results/charlie-connect.log" "$bin_dir/vx6" connect --service ALPHA.public --listen 127.0.0.1:18081
for _ in $(seq 1 50); do
  if peer_exec charlie sh -c 'ss -ltn | grep -q ":18081"'; then break; fi
  sleep 0.2
done
peer_exec charlie curl --fail --silent --show-error --retry 20 --retry-connrefused --retry-delay 1 http://127.0.0.1:18081/ca.html >"$results/ca-response.txt"
grep -Fx "$marker_ca" "$results/ca-response.txt" >/dev/null

spawn_peer alpha "$results/alpha-connect-charlie.log" "$bin_dir/vx6" connect --service CHARLIE.public --listen 127.0.0.1:18082
for _ in $(seq 1 50); do
  if peer_exec alpha sh -c 'ss -ltn | grep -q ":18082"'; then break; fi
  sleep 0.2
done
peer_exec alpha curl --fail --silent --show-error --retry 20 --retry-connrefused --retry-delay 1 http://127.0.0.1:18082/ >"$results/ac-response.txt"
grep -Fx "$marker_ac" "$results/ac-response.txt" >/dev/null

peer_root alpha swanctl --list-sas >"$results/ac-sas-alpha.txt"
peer_root charlie swanctl --list-sas >"$results/ac-sas-charlie.txt"
peer_root alpha ip -6 -s xfrm state >"$results/ac-xfrm-alpha.txt"
peer_root charlie ip -6 -s xfrm state >"$results/ac-xfrm-charlie.txt"
grep -q ESTABLISHED "$results/ac-sas-alpha.txt"
grep -q ESTABLISHED "$results/ac-sas-charlie.txt"
grep -q 'proto esp' "$results/ac-xfrm-alpha.txt"
grep -q 'proto esp' "$results/ac-xfrm-charlie.txt"

kill -INT "$capture_pid" 2>/dev/null || true
wait "$capture_pid" 2>/dev/null || true
capture_pid=
tcpdump -nnr "$results/transit.pcap" 'ip6 proto 50' 2>/dev/null | wc -l >"$results/esp-packet-count.txt"
if strings "$results/transit.pcap" | grep -F -e "$marker_ab" -e "$marker_ca" -e "$marker_ac" >"$results/clear-marker-matches.txt"; then
  printf 'Service marker appeared in the transit capture.\n' >&2
  exit 1
fi
esp_count=$(cat "$results/esp-packet-count.txt")
(( esp_count > 0 )) || { printf 'Transit capture contains no ESP packets.\n' >&2; exit 1; }

{
  printf 'PASS: all three VX6 nodes ran in isolated network namespaces; no host route/NAT was used.\n'
  printf 'PASS: Alpha-Beta DHT service forwarding returned: '; cat "$results/ab-response.txt"
  printf 'PASS: Charlie DHT lookups found both Alpha and Charlie service records.\n'
  printf 'PASS: Charlie reached Alpha and Alpha reached Charlie over authenticated IKEv2/ESP.\n'
  printf 'PASS: IKE_SAs established and ESP XFRM states installed on both endpoints.\n'
  printf 'PASS: service traffic succeeded with overlapping broad /64 pass policies installed at priority 134463.\n'
  printf 'Router capture ESP packets: %s\n' "$esp_count"
  printf 'Application markers visible in router capture: no\n'
  if rg -q 'lookup incomplete|insufficient confirmation' "$results/charlie-node.log"; then
    printf 'NOTE: the three-node topology did not satisfy the larger-network DHT self-lookup confirmation threshold.\n'
  fi
  printf 'Evidence directory: %s\n' "$results"
} | tee "$results/REPORT.txt"
printf '\nFull evidence: %s\n' "$results"
