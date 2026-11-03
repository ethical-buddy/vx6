#!/usr/bin/env bash
# Copyright (c) 2026 Suryansh Deshwal
# Licensed under the Apache License, Version 2.0
#
# Two-peer IKEv2/ESP benchmark lab for issue #51.
#
# Builds two network namespaces joined by a veth pair, runs one strongSwan
# charon per namespace with the same IKE/ESP proposal and /128 (or /32)
# port selectors that internal/ipsec/manager.go generates, authenticates the
# peers with pinned Ed25519 public keys, and exposes helpers used by
# ipsec-baseline.sh. It never touches the host's default namespace routing.
#
# Usage:
#   sudo FAMILY=6 DATAPLANE=xfrm   scripts/bench/ipsec-netns-lab.sh up     # real target
#   sudo FAMILY=4 DATAPLANE=libipsec scripts/bench/ipsec-netns-lab.sh up   # kernels without IPv6/ESP
#   sudo scripts/bench/ipsec-netns-lab.sh down
#
# FAMILY=4 and DATAPLANE=libipsec exist only so the control plane can be
# measured on sandboxes whose kernel lacks IPv6 or ESP/GCM. VX6 itself is
# IPv6-only and uses kernel XFRM; results from the fallback lab must be
# labelled as such.
set -euo pipefail

FAMILY="${FAMILY:-6}"
DATAPLANE="${DATAPLANE:-xfrm}"
PORT="${VX6_PORT:-4242}"
MTU="${MTU:-1500}"
LAB="${LAB_DIR:-/var/lib/vx6-bench}"   # must not live under /run (bind-mounted per daemon)
NS_A=vx6a
NS_B=vx6b

if [[ "$FAMILY" == 6 ]]; then
  ADDR_A=fd00:56::a; ADDR_B=fd00:56::b; PLEN=64; HOSTLEN=128
else
  ADDR_A=10.56.0.10; ADDR_B=10.56.0.11; PLEN=24; HOSTLEN=32
fi

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "missing $1"; }

# SELECTORS=pinned reproduces manager.go as of 4e26ace: both ends pinned to
# the VX6 port, so a dial from an ephemeral source port matches no policy.
# SELECTORS=split is the proposed fix: one CHILD_SA per direction of service
# connection, each pinning only the listener side's port.
SELECTORS="${SELECTORS:-split}"
child() {
  local name="$1" lts="$2" rts="$3"
  cat <<C
      $name {
        mode = tunnel
        local_ts = $lts
        remote_ts = $rts
        esp_proposals = aes128gcm16
        start_action = trap
        close_action = trap
        dpd_action = restart
        rekey_time = ${CHILD_REKEY:-1h}
      }
C
}
children() {
  local self="$1" peer="$2" h="/$HOSTLEN"
  if [[ "$SELECTORS" == pinned ]]; then
    child vx6-bench "${self}${h}[tcp/$PORT], ${self}${h}[udp/$PORT]" "${peer}${h}[tcp/$PORT], ${peer}${h}[udp/$PORT]"
  else
    child vx6-bench-out "${self}${h}[tcp], ${self}${h}[udp]" "${peer}${h}[tcp/$PORT], ${peer}${h}[udp/$PORT]"
    child vx6-bench-in "${self}${h}[tcp/$PORT], ${self}${h}[udp/$PORT]" "${peer}${h}[tcp], ${peer}${h}[udp]"
  fi
}

write_node() {
  local n="$1" self="$2" peer="$3" dir="$LAB/$1" other="$4"
  mkdir -p "$dir"/swanctl/{conf.d,private,pubkey}
  chmod 700 "$dir"/swanctl/private
  local libipsec=no
  if [[ "$DATAPLANE" == libipsec ]]; then libipsec=yes; fi
  cat >"$dir/strongswan.conf" <<CONF
charon {
  # XFRM needs no routes for host-to-host /128 selectors. libipsec would
  # route the whole subnet (including IKE itself) into its TUN device, so
  # the lab installs port-scoped policy routes instead (see libipsec_routes).
  install_routes = no
  install_virtual_ip = no
  routing_table = 0
  retransmit_tries = 3
  filelog {
    log { path = $dir/charon.log
          time_format = %s
          default = 1
          ike = 2
          time_add_ms = yes
          flush_line = yes
          cfg = 2
          knl = 2 }
  }
  plugins {
    vici { socket = unix://$dir/charon.vici }
    kernel-libipsec { load = $libipsec
                      allow_peer_ts = yes }
    kernel-netlink { load = yes }
    socket-default { load = yes }
    resolve { load = no }
    bypass-lan { load = no }
    stroke { load = no }
  }
}
CONF
  cat >"$dir/swanctl/conf.d/peer.conf" <<CONF
connections {
  vx6-bench {
    version = 2
    local_addrs = $self
    remote_addrs = $peer
    proposals = aes128gcm16-prfsha256-curve25519
    mobike = no
    rekey_time = ${IKE_REKEY:-4h}
    local { auth = pubkey
            pubkeys = $dir/swanctl/pubkey/$n.pem }
    remote { auth = pubkey
             id = %any
             pubkeys = $dir/swanctl/pubkey/$other.pem }
    children {
$(children "$self" "$peer")
    }
  }
}
CONF
  echo "include conf.d/*.conf" >"$dir/swanctl/swanctl.conf"
}

nsx() { local n="$1"; shift; ip netns exec "$n" env STRONGSWAN_CONF="$LAB/$n/strongswan.conf" SWANCTL_DIR="$LAB/$n/swanctl" "$@"; }
sw() { local n="$1" op="$2"; shift 2; nsx "$n" swanctl "$op" --uri "unix://$LAB/$n/charon.vici" "$@"; }

up() {
  need ip; need swanctl; need pki
  [[ -x /usr/lib/ipsec/charon || -x /usr/libexec/ipsec/charon ]] || die "strongSwan charon not found"
  local charon=/usr/lib/ipsec/charon; [[ -x $charon ]] || charon=/usr/libexec/ipsec/charon
  down >/dev/null 2>&1 || true
  mkdir -p "$LAB"
  ip netns add $NS_A; ip netns add $NS_B
  ip link add va netns $NS_A mtu "$MTU" type veth peer name vb netns $NS_B mtu "$MTU"
  for pair in "$NS_A va $ADDR_A" "$NS_B vb $ADDR_B"; do
    set -- $pair
    ip -n "$1" link set lo up
    if [[ "$FAMILY" == 6 ]]; then ip -n "$1" -6 addr add "$3/$PLEN" dev "$2" nodad; else ip -n "$1" addr add "$3/$PLEN" dev "$2"; fi
    ip -n "$1" link set "$2" up
  done
  write_node $NS_A $ADDR_A $ADDR_B $NS_B
  write_node $NS_B $ADDR_B $ADDR_A $NS_A
  for n in $NS_A $NS_B; do
    pki --gen --type ed25519 --outform pem >"$LAB/$n/swanctl/private/$n.pem"
    chmod 600 "$LAB/$n/swanctl/private/$n.pem"
    pki --pub --in "$LAB/$n/swanctl/private/$n.pem" --outform pem >"$LAB/$n/swanctl/pubkey/$n.pem"
  done
  cp "$LAB/$NS_A/swanctl/pubkey/$NS_A.pem" "$LAB/$NS_B/swanctl/pubkey/"
  cp "$LAB/$NS_B/swanctl/pubkey/$NS_B.pem" "$LAB/$NS_A/swanctl/pubkey/"
  for n in $NS_A $NS_B; do
    # charon writes its pid under the compiled-in piddir; give each namespace
    # its own mount namespace view so the two daemons do not collide.
    mkdir -p "$LAB/$n/run"
    ip netns exec "$n" unshare -m sh -c "mount --bind '$LAB/$n/run' /run 2>/dev/null || mount --bind '$LAB/$n/run' /var/run; STRONGSWAN_CONF='$LAB/$n/strongswan.conf' exec $charon" >"$LAB/$n/stdout.log" 2>&1 &
    echo $! >"$LAB/$n/charon.pid"
  done
  for _ in $(seq 50); do
    [[ -S "$LAB/$NS_A/charon.vici" && -S "$LAB/$NS_B/charon.vici" ]] && break
    sleep 0.1
  done
  [[ -S "$LAB/$NS_A/charon.vici" && -S "$LAB/$NS_B/charon.vici" ]] || die "charon did not start; see $LAB/*/charon.log"
  for n in $NS_A $NS_B; do
    sw "$n" --load-creds --noprompt >/dev/null
    sw "$n" --load-conns >/dev/null
  done
  # Trap installation makes libipsec add routes, so fix routing afterwards.
  sleep 0.3
  if [[ "$DATAPLANE" == libipsec ]]; then
    for _ in $(seq 50); do ip -n $NS_A link show ipsec0 >/dev/null 2>&1 && ip -n $NS_B link show ipsec0 >/dev/null 2>&1 && break; sleep 0.1; done
    libipsec_routes $NS_A $ADDR_B va
    libipsec_routes $NS_B $ADDR_A vb
  fi
  echo "lab up: FAMILY=$FAMILY DATAPLANE=$DATAPLANE A=$ADDR_A B=$ADDR_B port=$PORT dir=$LAB"
}

libipsec_routes() {
  # Only VX6-port TCP/UDP enters the userspace ESP device; IKE stays on veth.
  local n="$1" peer="$2" dev="$3" fam="-$FAMILY" subnet
  subnet=$( [[ "$FAMILY" == 6 ]] && echo fd00:56::/64 || echo 10.56.0.0/24 )
  # Remove anything charon/libipsec put in its default table 220.
  ip -n "$n" $fam rule del lookup 220 2>/dev/null || true
  ip -n "$n" $fam route flush table 220 2>/dev/null || true
  ip -n "$n" $fam route flush dev ipsec0 table main 2>/dev/null || true
  # libipsec replaces the on-link subnet route with one via ipsec0; restore it.
  ip -n "$n" $fam route replace "$subnet" dev "$dev"
  ip -n "$n" $fam route add "$peer" dev ipsec0 table 156
  for proto in tcp udp; do
    ip -n "$n" $fam rule add ipproto $proto dport "$PORT" lookup 156 priority 100
    ip -n "$n" $fam rule add ipproto $proto sport "$PORT" lookup 156 priority 101
  done
}

down() {
  for n in $NS_A $NS_B; do
    if [[ -f "$LAB/$n/charon.pid" ]]; then kill "$(cat "$LAB/$n/charon.pid")" 2>/dev/null || true; fi
    pkill -f "STRONGSWAN_CONF='$LAB/$n/" 2>/dev/null || true
  done
  sleep 0.3
  for n in $NS_A $NS_B; do
    for p in $(ip netns pids "$n" 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
    ip netns del "$n" 2>/dev/null || true
  done
  rm -rf "$LAB"
}

charon_pid() {
  # PID of the charon process running inside namespace $1.
  local n="$1" p
  for p in $(ip netns pids "$n"); do
    if [[ "$(cat /proc/$p/comm 2>/dev/null)" == charon ]]; then echo "$p"; return; fi
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  env) echo "FAMILY=$FAMILY DATAPLANE=$DATAPLANE NS_A=$NS_A NS_B=$NS_B ADDR_A=$ADDR_A ADDR_B=$ADDR_B PORT=$PORT LAB=$LAB" ;;
  sw) shift; sw "$@" ;;
  pid) charon_pid "$2" ;;
  *) echo "usage: $0 up|down|env|sw <ns> <swanctl args>|pid <ns>" >&2; exit 2 ;;
esac
