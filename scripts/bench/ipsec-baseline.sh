#!/usr/bin/env bash
# Copyright (c) 2026 Suryansh Deshwal
# Licensed under the Apache License, Version 2.0
#
# Issue #51 baseline: strongSwan + kernel XFRM (or libipsec fallback) between
# two network namespaces, using VX6's proposals and Ed25519 pinned keys.
#
#   sudo REPEAT=5 scripts/bench/ipsec-baseline.sh               # IPv6 + XFRM (target)
#   sudo FAMILY=4 DATAPLANE=libipsec scripts/bench/ipsec-baseline.sh   # sandbox fallback
#
# Needs: iproute2, strongSwan (charon, swanctl, pki), iperf3, tcpdump,
# python3, go. Writes raw outputs and summary.json to $OUT.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export FAMILY="${FAMILY:-6}" DATAPLANE="${DATAPLANE:-xfrm}" SELECTORS="${SELECTORS:-split}"
REPEAT="${REPEAT:-5}"
DURATION="${DURATION:-5}"
OUT="${OUT:-$repo/bench-results/ipsec-$FAMILY-$DATAPLANE-$(date -u +%Y%m%dT%H%M%SZ)}"
L="$here/ipsec-netns-lab.sh"
mkdir -p "$OUT"
eval "$("$L" env | tr ' ' '\n' | sed 's/^/export /')"
hp() { if [[ "$FAMILY" == 6 ]]; then echo "[$1]:$2"; else echo "$1:$2"; fi; }
now_ms() { date +%s%3N; }
sw() { "$L" sw "$@"; }
children() { if [[ "$SELECTORS" == pinned ]]; then echo vx6-bench; else echo "vx6-bench-out vx6-bench-in"; fi; }
rss_kb() { awk '/VmRSS/{print $2}' "/proc/$1/status"; }
cpu_ticks() { awk '{print $14+$15}' "/proc/$1/stat"; }
log() { printf '[%s] %s\n' "$(date -u +%T)" "$*" | tee -a "$OUT/run.log"; }

cleanup() { pkill -f "$OUT/rrbench" 2>/dev/null || true; pkill -x iperf3 2>/dev/null || true; "$L" down >/dev/null 2>&1 || true; }
trap cleanup EXIT

(cd "$repo" && go build -o "$OUT/rrbench" ./scripts/bench/rrbench)
"$L" up 2>&1 | grep -v -i -e tpm -e 'opening directory' | tee -a "$OUT/run.log"

{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "kernel=$(uname -r)"
  echo "cpu=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
  echo "nproc=$(nproc)"
  echo "mem_total_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo)"
  echo "strongswan=$(swanctl --version 2>/dev/null | head -1 | tr -d '\n' || true)$(/usr/lib/ipsec/charon --version 2>/dev/null | head -1 || true)"
  echo "iperf3=$(iperf3 --version | head -1)"
  echo "go=$(go version)"
  echo "family=$FAMILY dataplane=$DATAPLANE selectors=$SELECTORS mtu=${MTU:-1500} repeat=$REPEAT duration=$DURATION"
  echo "ike_proposal=aes128gcm16-prfsha256-curve25519 esp_proposal=aes128gcm16 auth=ed25519-pubkey"
} >"$OUT/environment.txt"
cat "$OUT/environment.txt" | tee -a "$OUT/run.log"

PA=$("$L" pid "$NS_A"); PB=$("$L" pid "$NS_B")
sleep 2
echo "{\"a\": $(rss_kb "$PA"), \"b\": $(rss_kb "$PB")}" >"$OUT/rss_idle_no_sa.json"

initiate_all() { for c in $(children); do sw "$NS_A" --initiate --ike vx6-bench --child "$c" --timeout 15 >/dev/null; done; }
terminate_all() { sw "$NS_A" --terminate --ike vx6-bench --timeout 5 >/dev/null 2>&1 || true; sleep 0.2; }

log "IKE_SA + CHILD_SA establishment x$((REPEAT*4))"
: >"$OUT/setup_ms.txt"
for i in $(seq $((REPEAT*4))); do
  terminate_all
  t0=$(now_ms); initiate_all; t1=$(now_ms)
  echo $((t1-t0)) >>"$OUT/setup_ms.txt"
done
sleep 1
echo "{\"a\": $(rss_kb "$PA"), \"b\": $(rss_kb "$PB")}" >"$OUT/rss_with_sa.json"

log "swanctl --list-sas latency x200 (cost VX6 pays per EnsurePeer/AcceptPeer check)"
: >"$OUT/list_sas_ms.txt"
for i in $(seq 200); do t0=$(date +%s%N); sw "$NS_B" --list-sas --ike vx6-bench >/dev/null; t1=$(date +%s%N); echo "scale=3; ($t1-$t0)/1000000" | bc >>"$OUT/list_sas_ms.txt"; done

# Rekeying is make-before-break: the new SA is usable as soon as it is listed
# as INSTALLED/ESTABLISHED, while the old one lingers until deleted. Measure
# the time until an SA with an SPI not seen before the rekey is ready.
child_spis() { sw "$NS_A" --list-sas --ike vx6-bench | awk -v c="$1" '$1==c":"{f=($0 ~ /INSTALLED/)} f&&$1=="out"{print $2; f=0}' | tr -d , | sort; }
ike_spis() { sw "$NS_A" --list-sas --ike vx6-bench | awk '$1=="vx6-bench:" && /ESTABLISHED/{print $5}' | sort; }
wait_new() { # $1=function [args], old set on stdin-like var OLD
  local new
  for _ in $(seq 1000); do
    new=$(comm -13 <(echo "$OLD") <("$@"))
    [[ -n "$new" ]] && return 0
    sleep 0.005
  done
  return 1
}
log "CHILD_SA rekey x$REPEAT and IKE_SA rekey x$REPEAT"
first_child=$(children | awk '{print $1}')
: >"$OUT/child_rekey_ms.txt"; : >"$OUT/ike_rekey_ms.txt"
for i in $(seq "$REPEAT"); do
  OLD=$(child_spis "$first_child"); t0=$(now_ms)
  sw "$NS_A" --rekey --child "$first_child" >/dev/null
  wait_new child_spis "$first_child" && echo $(( $(now_ms) - t0 )) >>"$OUT/child_rekey_ms.txt"
  sleep 1
  OLD=$(ike_spis); t0=$(now_ms)
  sw "$NS_A" --rekey --ike vx6-bench >/dev/null
  wait_new ike_spis && echo $(( $(now_ms) - t0 )) >>"$OUT/ike_rekey_ms.txt"
  sleep 1
done

BASE_PORT=5201
ip netns exec "$NS_B" iperf3 -s -B "$ADDR_B" -p "$BASE_PORT" -D
ip netns exec "$NS_B" iperf3 -s -B "$ADDR_B" -p "$PORT" -D
sleep 0.5
# Ports 5201/5202 are outside the VX6 selectors, so they measure the same
# veth path without ESP. Port $PORT is covered by the CHILD_SA(s).
log "throughput x$REPEAT (baseline vs ESP), ${DURATION}s each"
for i in $(seq "$REPEAT"); do
  ip netns exec "$NS_A" iperf3 -J -c "$ADDR_B" -p "$BASE_PORT" -t "$DURATION" >"$OUT/iperf_base_$i.json"
  ca=$(cpu_ticks "$PA"); cb=$(cpu_ticks "$PB"); t0=$(now_ms)
  ip netns exec "$NS_A" iperf3 -J -c "$ADDR_B" -p "$PORT" -t "$DURATION" >"$OUT/iperf_esp_$i.json"
  t1=$(now_ms)
  echo "{\"a_ticks\": $(( $(cpu_ticks "$PA") - ca )), \"b_ticks\": $(( $(cpu_ticks "$PB") - cb )), \"wall_ms\": $((t1-t0)), \"hz\": $(getconf CLK_TCK)}" >"$OUT/charon_cpu_esp_$i.json"
done
echo "{\"a\": $(rss_kb "$PA"), \"b\": $(rss_kb "$PB")}" >"$OUT/rss_after_load.json"

pkill -x iperf3 2>/dev/null || true; sleep 0.5
ip netns exec "$NS_B" "$OUT/rrbench" -mode server -listen "$(hp "$ADDR_B" 5202)" &
ip netns exec "$NS_B" "$OUT/rrbench" -mode server -listen "$(hp "$ADDR_B" "$PORT")" &
sleep 0.5
log "request/response latency x$REPEAT per profile"
profiles=("small:-n 5000 -c 1 -size 64" "concurrent:-n 20000 -c 64 -size 64" "churn:-n 3000 -c 16 -size 64 -newconn" "large:-n 1000 -c 1 -size 65536")
for prof in "${profiles[@]}"; do
  name=${prof%%:*}; args=${prof#*:}
  for i in $(seq "$REPEAT"); do
    ip netns exec "$NS_A" "$OUT/rrbench" -mode client -timeout 2s -addr "$(hp "$ADDR_B" 5202)" $args >"$OUT/rr_base_${name}_$i.json" || true
    ip netns exec "$NS_A" "$OUT/rrbench" -mode client -timeout 2s -addr "$(hp "$ADDR_B" "$PORT")" $args >"$OUT/rr_esp_${name}_$i.json" || true
  done
done

log "reconnect: terminate IKE, re-establish, first VX6-port response x$REPEAT"
: >"$OUT/reconnect_ms.txt"
for i in $(seq "$REPEAT"); do
  terminate_all
  t0=$(now_ms); initiate_all
  ip netns exec "$NS_A" "$OUT/rrbench" -mode client -addr "$(hp "$ADDR_B" "$PORT")" -n 1 >/dev/null
  t1=$(now_ms); echo $((t1-t0)) >>"$OUT/reconnect_ms.txt"
done

log "per-packet overhead: 100-byte UDP payload, clear vs ESP"
dev=va
ip netns exec "$NS_A" timeout 4 tcpdump -ni "$dev" -w "$OUT/overhead.pcap" 2>/dev/null &
dump_pid=$!
sleep 0.5
for p in 5203 "$PORT"; do
  ip netns exec "$NS_A" python3 -c "
import socket,sys
f=socket.AF_INET6 if '$FAMILY'=='6' else socket.AF_INET
s=socket.socket(f,socket.SOCK_DGRAM); s.sendto(b'x'*100,('$ADDR_B',$p))"
  sleep 0.3
done
wait "$dump_pid" || true
tcpdump -nr "$OUT/overhead.pcap" -e 2>/dev/null >"$OUT/overhead.txt" || true

if [[ "$SELECTORS" == pinned ]]; then
  log "pinned selectors: ephemeral-port dial expected to fail"
fi
python3 "$here/summarize.py" "$OUT" | tee "$OUT/summary.md"
log "results in $OUT"
