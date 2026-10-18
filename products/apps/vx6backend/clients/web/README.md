# Web/Desktop-Web Integration

Web UI should not implement protocol logic directly.

Use local backend calls to `vx6d`:

- `GET /health`
- `POST /v1/node/init`
- `POST /v1/node/start`
- `POST /v1/node/stop`
- `GET /v1/node/status`
- `POST /v1/vx6/exec`
- `POST /v1/chat/send`

This keeps behavior aligned with Tauri/mobile clients.

