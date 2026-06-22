#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/apps/vx6comms-android/app/libs/vx6mobile.aar"

if ! command -v gomobile >/dev/null 2>&1; then
  echo "gomobile not found. Install with:"
  echo "  go install golang.org/x/mobile/cmd/gomobile@latest"
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
gomobile init
gomobile bind \
  -target=android/arm64,android/amd64 \
  -o "$OUT" \
  "$ROOT/mobile"

echo "wrote $OUT"
