#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "iOS framework builds require macOS with Xcode installed."
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/products/apps/vx6comms-ios/VX6Mobile.xcframework"

if ! command -v gomobile >/dev/null 2>&1; then
  echo "gomobile not found. Install with:"
  echo "  go install golang.org/x/mobile/cmd/gomobile@latest"
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
gomobile init
gomobile bind \
  -target=ios \
  -o "$OUT" \
  "$ROOT/products/mobile"

echo "wrote $OUT"
