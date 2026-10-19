#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=vx6-ipsec-netns-test:local

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is unavailable; start Docker and retry." >&2
  exit 2
fi

docker build -f "$repo_root/tests/ipsec-containers/Dockerfile" -t "$image" "$repo_root"

for peer in node-a node-b; do
  echo "Running real nftables cleartext-drop test in isolated container $peer"
  docker run --rm \
    --name "vx6-ipsec-test-$peer" \
    --network none \
    --cap-drop ALL \
    --cap-add NET_ADMIN \
    --security-opt no-new-privileges \
    -e VX6_RUN_IPSEC_NETNS_TEST=1 \
    "$image"
done

echo "Container firewall checks passed. This is not a two-peer IKE/ESP capture test."
