# VX6 Backend (`vx6d`)

Shared backend runtime for all UI clients (Linux, macOS, Windows, Android, iOS, Web/Desktop wrappers).

This app runs a local HTTP API on loopback and wraps the existing `vx6` CLI behavior so UI teams do not need to manage CLI flags directly.

## Goals

- Keep protocol/backend logic centralized in one place.
- Let each platform team build UI independently.
- Preserve feature parity with the current Tauri app behavior.

## Run

From repository root:

```bash
go build -o vx6d ./products/apps/vx6backend/cmd/vx6d
./vx6d --listen 127.0.0.1:4866
```

Health check:

```bash
curl -fsS http://127.0.0.1:4866/health
```

## API Surface (v1)

- `GET /health`
- `POST /v1/node/init`
- `POST /v1/node/start`
- `POST /v1/node/stop`
- `GET /v1/node/status`
- `POST /v1/vx6/exec`
- `POST /v1/chat/send`

Detailed request/response formats are in [API.md](./API.md).

## Platform client folders

- `clients/tauri/`
- `clients/android/`
- `clients/ios/`
- `clients/web/`

Each folder contains integration notes and starter guidance for UI developers.

