# VX6 Comms Tauri Desktop

This directory is reserved for the desktop UI frontend layer (Tauri + web UI) that sits on top of VX6 core (`main`, `internal`, `sdk`) without coupling protocol internals to frontend code.

## Run (Linux/macOS/Windows)

```bash
cd apps/vx6comms-tauri
npm install
npm run tauri:dev
```

Build desktop bundles:

```bash
npm run tauri:build
```

## Goals

- Cross-platform desktop app for Linux, Windows, macOS
- Modern UI/UX beyond Go-native desktop widgets
- Local-sidecar integration with VX6 runtime/service control

## Proposed Structure

- `src-tauri/` Rust host for window/runtime integration
- `ui/` Web frontend (React/Vite)
- `bridge/` Local IPC contracts (JSON RPC/WebSocket/HTTP localhost)

## Integration Contract

- VX6 core remains independent.
- Frontend calls SDK-backed local API.
- No protocol logic is duplicated in JS/Rust.

## Planned Tasks

1. Scaffold Tauri app.
2. Build local API bridge for:
   - node lifecycle
   - identity/invite/contact actions
   - chat/file/call actions
3. Add desktop packaging for:
   - `.AppImage/.deb` (Linux)
   - `.msi` (Windows)
   - `.dmg` (macOS)
