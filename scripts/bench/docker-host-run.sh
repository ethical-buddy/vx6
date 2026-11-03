#!/usr/bin/env bash
# Copyright (c) 2026 Suryansh Deshwal
# Licensed under the Apache License, Version 2.0
#
# One-shot IPsec validation on any Docker host, including macOS (Docker
# Desktop / colima / OrbStack on Apple Silicon). Run as your normal user:
#
#   curl -fsSLO https://raw.githubusercontent.com/dailker/vx6/claude/compassionate-babbage-qjp4bm/scripts/bench/docker-host-run.sh
#   bash docker-host-run.sh
#
# It does, in a throw-away directory:
#   1. clones the branch under test
#   2. checks whether the Docker VM kernel has IPv6 and XFRM ESP/AES-GCM
#   3. runs scripts/bench/ipsec-baseline.sh (#51) in a privileged container
#      (IPv6 + kernel XFRM if available, otherwise the IPv4/libipsec fallback)
#   4. runs `go test` for internal/ipsec and internal/transport in Linux
#   5. runs the routed IPv6 capture suite tests/ipsec-e2e/run.sh
#   6. writes ~/Desktop/vx6-docker-results-<time>.tar.gz
#   7. removes every container, network, image and file it created
#      (images that existed before the run are kept)
#
# It never touches host networking; everything runs inside the Docker VM.
# Bash 3.2 compatible (macOS /bin/bash).
set -uo pipefail

REPO="${VX6_REPO:-https://github.com/dailker/vx6.git}"
BRANCH="${VX6_BRANCH:-claude/compassionate-babbage-qjp4bm}"
REPEAT="${REPEAT:-5}"
DURATION="${DURATION:-10}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vx6-docker-run.XXXXXX")
RESULTS="$WORK/results"
BENCH_IMAGE="vx6-bench:$STAMP"
E2E_IMAGE="vx6-ipsec-e2e:local"
LABEL="vx6-docker-host-run=$STAMP"
OUTDIR="${OUTDIR:-$HOME/Desktop}"
[ -d "$OUTDIR" ] || OUTDIR="$HOME"
ARCHIVE="$OUTDIR/vx6-docker-results-$STAMP.tar.gz"
mkdir -p "$RESULTS"

say() { printf '\n\033[1;35m▶ %s\033[0m\n' "$*" | tee -a "$RESULTS/run.log"; }
note() { printf '  %s\n' "$*" | tee -a "$RESULTS/run.log"; }

pre_images=$(docker images -q 2>/dev/null | sort -u)
cleanup() {
  status=$?
  say "Cleaning up"
  docker ps -aq --filter "label=$LABEL" | xargs docker rm -f >/dev/null 2>&1
  docker ps -aq --filter "name=vx6-e2e-" | xargs docker rm -f >/dev/null 2>&1
  docker network ls -q --filter "name=vx6-e2e-" | xargs docker network rm >/dev/null 2>&1
  for img in "$BENCH_IMAGE" "$E2E_IMAGE" golang:1.24-bookworm ubuntu:22.04; do
    id=$(docker images -q "$img" 2>/dev/null)
    if [ -n "$id" ] && ! printf '%s\n' "$pre_images" | grep -qx "$id"; then
      docker rmi -f "$img" >/dev/null 2>&1 && note "removed image $img"
    fi
  done
  docker image prune -f --filter "label=$LABEL" >/dev/null 2>&1
  if [ -d "$RESULTS" ]; then
    tar -czf "$ARCHIVE" -C "$WORK" results 2>/dev/null && note "results: $ARCHIVE"
  fi
  rm -rf "$WORK"
  note "temporary directory removed"
  exit $status
}
trap cleanup EXIT INT TERM

say "Preflight"
command -v docker >/dev/null || { echo "Install and start Docker Desktop (or colima) first."; exit 2; }
docker info >/dev/null 2>&1 || { echo "Docker is installed but not running. Start it and retry."; exit 2; }
command -v git >/dev/null || { echo "git is missing (xcode-select --install)."; exit 2; }
if ! command -v go >/dev/null; then
  if command -v brew >/dev/null; then note "installing Go with Homebrew"; brew install go >/dev/null; else echo "Install Go 1.24+ first."; exit 2; fi
fi
for c in tcpdump strings; do command -v "$c" >/dev/null || { echo "Missing $c (xcode-select --install)."; exit 2; }; done
{
  echo "host_os=$(uname -sm)"
  echo "docker_server=$(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null)"
  echo "docker_kernel=$(docker info --format '{{.KernelVersion}}' 2>/dev/null)"
  echo "docker_cpus=$(docker info --format '{{.NCPU}}' 2>/dev/null) docker_mem=$(docker info --format '{{.MemTotal}}' 2>/dev/null)"
  echo "go=$(go version)"
  echo "branch=$BRANCH"
} | tee "$RESULTS/host.txt"

say "Cloning $BRANCH"
git clone -q --depth 1 -b "$BRANCH" "$REPO" "$WORK/vx6" || exit 1
git -C "$WORK/vx6" log --oneline -1 | tee -a "$RESULTS/host.txt"

say "Building the Linux benchmark image"
mkdir -p "$WORK/ctx"
cat >"$WORK/ctx/Dockerfile" <<'EOF'
FROM golang:1.24-bookworm
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      iproute2 strongswan-charon strongswan-swanctl strongswan-pki \
      libstrongswan-standard-plugins libstrongswan-extra-plugins libcharon-extra-plugins \
      iperf3 tcpdump python3 bc procps psmisc util-linux kmod >/dev/null \
 && rm -rf /var/lib/apt/lists/*
EOF
docker build -q --label "$LABEL" -t "$BENCH_IMAGE" "$WORK/ctx" >/dev/null || exit 1

run_priv() { docker run --rm --privileged --label "$LABEL" -v "$WORK/vx6:/src" -v "$RESULTS:/results" -w /src "$BENCH_IMAGE" bash -c "$1"; }

say "Kernel capability check (inside the Docker VM)"
run_priv '
  ok6=no; okx=no
  [ -d /proc/sys/net/ipv6 ] && ok6=yes
  ip netns add vx6chk && ip -n vx6chk link add d0 type veth peer name d1 && ip -n vx6chk link set d0 up
  if [ $ok6 = yes ] && ip -n vx6chk -6 addr add fd00::1/64 dev d0 nodad 2>/dev/null; then
    K=0x$(od -An -tx1 -N20 /dev/urandom | tr -d " \n")
    ip -n vx6chk xfrm state add src fd00::1 dst fd00::2 proto esp spi 0x100 mode tunnel aead "rfc4106(gcm(aes))" $K 128 2>/results/xfrm-error.txt && okx=yes
  fi
  ip netns del vx6chk
  echo "ipv6=$ok6 xfrm_esp_gcm=$okx" | tee /results/kernel-capabilities.txt
'
caps=$(cat "$RESULTS/kernel-capabilities.txt" 2>/dev/null)
if echo "$caps" | grep -q "ipv6=yes xfrm_esp_gcm=yes"; then
  FAMILY=6; DATAPLANE=xfrm; note "using the target configuration: IPv6 + kernel XFRM"
else
  FAMILY=4; DATAPLANE=libipsec; note "kernel lacks IPv6 or XFRM ESP/GCM ($caps): using the IPv4/libipsec fallback"
fi

say "Unit tests: internal/ipsec, internal/transport (Linux, IPv6 loopback)"
run_priv 'sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.lo.disable_ipv6=0 2>/dev/null; go test ./internal/ipsec ./internal/transport -count=1 -v 2>&1 | tee /results/go-test.txt | grep -E "^(=== RUN|--- |ok|FAIL|PASS)" | grep -v "=== RUN"' || note "go test reported failures (see go-test.txt)"

say "Baseline benchmark (#51): FAMILY=$FAMILY DATAPLANE=$DATAPLANE REPEAT=$REPEAT DURATION=${DURATION}s"
run_priv "FAMILY=$FAMILY DATAPLANE=$DATAPLANE REPEAT=$REPEAT DURATION=$DURATION OUT=/results/bench-split bash scripts/bench/ipsec-baseline.sh" || note "baseline run failed (see results/bench-split/run.log)"
say "Negative control: pinned selectors from 4e26ace (expected to fail ephemeral-port dials)"
run_priv "FAMILY=$FAMILY DATAPLANE=$DATAPLANE SELECTORS=pinned REPEAT=1 DURATION=2 OUT=/results/bench-pinned timeout 900 bash scripts/bench/ipsec-baseline.sh" >/dev/null 2>&1
grep -h '"errors"' "$RESULTS"/bench-pinned/rr_esp_small_1.json 2>/dev/null | sed 's/^/  pinned rr_esp_small: /' | tee -a "$RESULTS/run.log"

say "Routed IPv6 capture suite (tests/ipsec-e2e/run.sh)"
if echo "$caps" | grep -q "ipv6=yes xfrm_esp_gcm=yes"; then
  ( cd "$WORK/vx6" && VX6_E2E_RESULTS_DIR="$RESULTS/e2e" bash tests/ipsec-e2e/run.sh ) 2>&1 | tee "$RESULTS/e2e.log" | tail -25
  e2e_status=${PIPESTATUS[0]}
  echo "e2e_exit=$e2e_status" | tee -a "$RESULTS/run.log"
else
  note "skipped: the e2e suite needs IPv6 + kernel XFRM in the Docker VM"
fi

say "Summary"
cat "$RESULTS/bench-split/summary.md" 2>/dev/null | tee -a "$RESULTS/run.log"
