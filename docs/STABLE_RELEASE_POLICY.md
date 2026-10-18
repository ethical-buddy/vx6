# VX6 Stable Release Policy

## Branch Model

- `main`: active development, feature integration, experimentation.
- `release/stable`: production-grade branch, only validated merges.
- `release/x.y` (optional): patch maintenance branch per minor series.

## Merge Rules for `release/stable`

No direct commits. Merge only via PR that passes:

1. `go test ./... -count=1`
2. Cross-build checks:
   - Linux: `GOOS=linux GOARCH=amd64`
   - Windows: `GOOS=windows GOARCH=amd64`
   - macOS: `GOOS=darwin GOARCH=amd64` and/or `arm64`
3. Protocol conformance tests:
   - `go test ./internal/conformance -count=1`
4. Fuzz smoke pass:
   - short fuzz job on DHT/session/signaling parsers
5. App smoke checks:
   - `products/apps/vx6comms` build
   - startup + invite flow basic validation

## Release Process

1. Cut release candidate on `main`.
2. Run full validation matrix.
3. Merge to `release/stable`.
4. Tag from `release/stable` only (`vX.Y.Z`).
5. Publish changelog + migration notes.

## Hotfix Policy

- Hotfix branch from `release/stable`.
- Minimal scope fix + regression tests.
- Merge back to `release/stable` and `main`.

