# VX6 Mobile Bridge

This package is the mobile-safe bridge for Android and iOS.

It intentionally exposes simple `string`/JSON APIs so `gomobile bind` can generate stable Kotlin/Java and Swift/Objective-C bindings without leaking Go-specific types such as maps, channels, contexts, or complex structs.

## Android

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
gomobile bind -target=android/arm64,android/amd64 -o apps/vx6comms-android/app/libs/vx6mobile.aar ./mobile
```

Targets:

- `android/arm64`: real modern Android devices
- `android/amd64`: emulator

## iOS

```bash
gomobile bind -target=ios -o apps/vx6comms-ios/VX6Mobile.xcframework ./mobile
```

## First App Flow

1. `NewEngine(configPath)`
2. `Init(name, listenAddr, advertiseAddr, dataDir, downloadsDir)`
3. `StartNode()`
4. `GenerateChatInvite()` or `AcceptChatInvite(invite)`
5. `SendText(contactNodeID, text)`
6. `MessagesJSON(contactNodeID)`

The bridge currently supports the desktop-compatible shared-secret chat envelope path. The next step is to move the full desktop X3DH/ratchet session implementation into `sdk/chat` so desktop and mobile both use the same advanced session state.
