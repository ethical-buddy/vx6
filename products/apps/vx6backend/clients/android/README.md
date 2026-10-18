# Android UI Integration

Android UI should call the same logical backend contract as `vx6d`.

## Recommended model

- Keep protocol logic in shared Go core.
- For Android runtime:
  - either embed Go core using `gomobile bind`
  - or use a native wrapper that mirrors `vx6d` endpoint contract.

## Must-match actions

- Node init/start/stop/status
- Generic command exec surface for DHT/service/list operations
- Chat send endpoint contract

## Why

- Android UI team can move fast on UI without rewriting protocol logic.
- Behavior stays consistent with desktop clients.

