# VX6 Comms Cross-Platform Plan

## Goal

Ship one protocol-compatible app experience across Linux, Windows, macOS, then Android.

## Current State

- Desktop GUI is implemented with Fyne.
- WebRTC negotiation path exists (`offer/answer/candidate`) over VX6 DHT signaling.
- Live media capture uses `ffmpeg` with OS-specific input backends.
- Messaging/session state is persisted locally.

## Windows Release Tasks

1. Device picker discovery:
   - Enumerate DirectShow device names and expose dropdowns.
2. Installer + signing:
   - MSI or signed portable build.
   - Defender reputation strategy (code-sign cert + release cadence).
3. Firewall UX:
   - Keep current firewall handling and add per-port confirmation in GUI.
4. Soak tests:
   - 2h call stability, reconnect tests, file transfer under packet loss.

## macOS Release Tasks

1. Device picker discovery:
   - Enumerate AVFoundation devices.
2. Permissions:
   - Mic/camera permission guidance and entitlement-safe bundle.
3. Packaging:
   - notarized `.app` bundle and dmg.
4. Stability:
   - sleep/wake reconnect behavior verification.

## Linux Release Tasks

1. Capture backend options:
   - PipeWire fallback in addition to pulse/v4l2 defaults.
2. Package targets:
   - AppImage + distro packages.
3. Device UX:
   - auto-detect camera/mic candidates and validate before call.

## Android Plan

1. Core protocol extraction:
   - Move chat/ratchet/call signaling into reusable SDK package with no desktop UI deps.
2. Mobile client:
   - Kotlin UI (Compose) wrapping Go core (gomobile or sidecar service).
3. Media plane:
   - Native Android camera/audio capture into WebRTC stack directly (not ffmpeg).
4. Background behavior:
   - foreground service, battery policy, reconnect policy.
5. Push-style wake:
   - optional lightweight notification relay for wakeup when fully offline.

## Quality Gates Before GA

1. NAT matrix test:
   - home NAT, corporate NAT, CGNAT, TURN fallback.
2. Long-session tests:
   - 4h call + concurrent file transfer + reconnect.
3. Security review:
   - ratchet state persistence, TURN credential handling, spam/rate-limit policy.
4. Upgrade safety:
   - state migration tests across app versions.
