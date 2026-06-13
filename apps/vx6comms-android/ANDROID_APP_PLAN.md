# VX6 Comms Android App Plan

## Target Architecture

Android app:

- Kotlin + Jetpack Compose UI
- foreground service runs embedded VX6 node
- `vx6mobile.aar` generated from `./mobile`
- Room database for local contacts/messages
- no external API server required

VX6 core:

- `sdk.Client` handles node init/start/peer/DHT behavior
- `sdk/chat` handles desktop-compatible invite/envelope/ledger format
- `mobile.Engine` exposes JSON/string APIs for Kotlin

## First MVP Flow

1. Setup screen calls `Engine.Init(...)`.
2. Foreground service calls `Engine.StartNode()`.
3. Invite screen calls `Engine.GenerateChatInvite()`.
4. Add-contact screen calls `Engine.AcceptChatInvite(invite)` or `Engine.AddChatContactJSON(contact)`.
5. Chat screen calls `Engine.SendText(nodeID, text)`.
6. Chat screen refreshes with `Engine.MessagesJSON(nodeID)`.

## Android Build

From repo root:

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
scripts/build_android_mobile.sh
```

Output:

```text
apps/vx6comms-android/app/libs/vx6mobile.aar
```

Targets:

- `android/arm64`: real Android devices
- `android/amd64`: emulator

## Compatibility Rule

Desktop and Android must share:

- `vx6chat://invite/...` format
- `vx6chat/conv/<node-a>/<node-b>` DHT ledger key
- message envelope JSON fields
- AES-GCM shared-secret fallback encryption path

The current bridge supports the shared-secret desktop-compatible path. The next step is moving desktop X3DH/ratchet session code into `sdk/chat` so both desktop and mobile use the same advanced session state.

## Kotlin Implementation Guide

See [KOTLIN_QUICKSTART.md](./KOTLIN_QUICKSTART.md) for:

- Gradle setup
- Android permissions
- foreground service skeleton
- Compose ViewModel shape
- exact calls into `mobile.Engine`
