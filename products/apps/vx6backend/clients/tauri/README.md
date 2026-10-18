# Tauri UI Integration

Use `vx6d` as backend instead of spawning `vx6` directly.

## Flow

1. Start `vx6d`.
2. Tauri frontend calls local API (`http://127.0.0.1:4866`).
3. Render response/output/errors in UI.

## Suggested migration from current Tauri bridge

- Replace `invoke("vx6_exec", ...)` calls with HTTP POST `/v1/vx6/exec`.
- Replace `invoke("vx6_send_text", ...)` with HTTP POST `/v1/chat/send`.
- Replace init/start/stop/status commands with:
  - `/v1/node/init`
  - `/v1/node/start`
  - `/v1/node/stop`
  - `/v1/node/status`

## Benefit

- Same backend contract as Android/iOS/Web.
- No platform-specific CLI handling in UI code.

