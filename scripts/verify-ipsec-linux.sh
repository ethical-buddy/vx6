#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
printf 'Usage: %s <interface> <peer-ipv6> <vx6-port> -- <traffic-test-command> [args...]\n' "$0" >&2
  printf 'Example: sudo bash %s enp1s0 2001:db8::2 4242 -- vx6 send --peer peer-name --file test.bin\n' "$0" >&2
}

if [[ $# -lt 5 || "$4" != "--" ]]; then
  usage
  exit 2
fi
if [[ $(id -u) -ne 0 ]]; then
  printf 'Run this verifier as root so tcpdump and XFRM state are observable.\n' >&2
  exit 2
fi

iface=$1
peer=$2
port=$3
shift 4
command -v swanctl >/dev/null
command -v ip >/dev/null
command -v tcpdump >/dev/null
[[ $port =~ ^[0-9]+$ ]] && ((port > 0 && port <= 65535)) || { printf 'Invalid port.\n' >&2; exit 2; }
[[ $peer == *:* ]] || { printf 'Peer must be an IPv6 literal.\n' >&2; exit 2; }
ip link show dev "$iface" >/dev/null

capture=$(mktemp --suffix=.pcap)
tcpdump_pid=
cleanup() {
  if [[ -n ${tcpdump_pid:-} ]]; then
    kill "$tcpdump_pid" 2>/dev/null || true
    wait "$tcpdump_pid" 2>/dev/null || true
  fi
  rm -f "$capture"
}
trap cleanup EXIT INT TERM

tcpdump -nni "$iface" -s 0 -U -w "$capture" "ip6 and host $peer" >/dev/null 2>&1 &
tcpdump_pid=$!
sleep 1
if ! "$@"; then
  printf 'VX6 traffic test command failed.\n' >&2
  exit 1
fi
sleep 1
kill "$tcpdump_pid" 2>/dev/null || true
wait "$tcpdump_pid" 2>/dev/null || true
tcpdump_pid=

sa_output=$(swanctl --list-sas)
grep -Eq 'INSTALLED, TUNNEL' <<<"$sa_output" || { printf 'No installed tunnel CHILD_SA found after workload.\n' >&2; exit 1; }
ip -6 xfrm state | grep -q 'proto esp' || { printf 'No IPv6 ESP XFRM state found after workload.\n' >&2; exit 1; }
ip -6 xfrm policy | grep -q 'dir out' || { printf 'No outbound IPv6 XFRM policy found after workload.\n' >&2; exit 1; }

esp_count=$(tcpdump -nnr "$capture" "ip6 and host $peer and ip6 proto 50" 2>/dev/null | wc -l)
clear_count=$(tcpdump -nnr "$capture" "ip6 and host $peer and (tcp port $port or udp port $port)" 2>/dev/null | wc -l)
if ((esp_count == 0)); then
  printf 'FAIL: capture has no IPv6 ESP packets to/from %s.\n' "$peer" >&2
  exit 1
fi
if ((clear_count != 0)); then
  printf 'FAIL: capture contains %s clear VX6-port packet(s) to/from %s.\n' "$clear_count" "$peer" >&2
  exit 1
fi
printf 'PASS: CHILD_SA and XFRM state are installed; captured %s ESP packet(s), no clear packets on VX6 port %s.\n' "$esp_count" "$port"
