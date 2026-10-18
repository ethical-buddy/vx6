# VX6 Comms Android Build Plan (Developer Task Document)

## 1) Objective

Build a production-grade Android client for VX6 Comms with:
- decentralized identity and discovery
- encrypted chat
- file sharing
- call signaling + WebRTC media
- offline-safe sync and retry

No mandatory third-party API keys are required for core P2P operation.

## 2) Recommended Stack

- Language/UI: Kotlin + Jetpack Compose
- App Architecture: MVVM + StateFlow + Repository pattern
- Local DB: Room
- Background Jobs: WorkManager
- Long-running node: Foreground Service
- Media calls: native WebRTC Android SDK
- VX6 protocol core: Go package bound to Android via `gomobile bind` (`.aar`)

Why not Flutter as primary:
- This app needs deeper control over background networking, realtime media, battery behavior, and device permissions. Native Android stack is lower-risk for this class of app.

## 3) High-Level Architecture

- `app` (Android UI + app logic)
- `vx6core-android` (generated `.aar` from Go bindings)
- `node-service` (ForegroundService controlling VX6 node lifecycle)
- `data` (Room entities/DAO/repositories)
- `calls` (WebRTC peer/session manager + call UI)
- `sync` (retry queue, dedupe, reconnect flow)

Core principle:
- Keep protocol logic in Go core.
- Keep Android module focused on UX, permissions, storage, lifecycle, notifications.

## 4) VX6 Core Extraction Tasks (Go Side)

Create a mobile-safe package from existing VX6 logic:
- remove desktop dependencies (`fyne`, `ffmpeg`)
- expose stable functions:
  - `InitNode(name, configPath)`
  - `StartNode()`, `StopNode()`
  - `GenerateInvite()`, `AcceptInvite(invite)`
  - `ListPeers()`
  - `SendMessage(peerID, text)`, `ListMessages(peerID)`
  - `SendFile(peerID, path)`
  - `PublishPresence()`, `FetchPresence(peerID)`
  - `PublishCallSignal(peerID, payload)`, `FetchCallSignal()`
  - `GetDiagnostics()`

Binding:
- use `gomobile bind -target=android ...`
- produce `vx6core.aar` + API docs for Android team.

## 5) Android Module Setup Tasks

1. Create Android app module with Compose.
2. Add generated `vx6core.aar`.
3. Define wrapper interface around AAR calls:
   - convert callback-based/bridge outputs to Kotlin `suspend` and `Flow`.
4. Implement repositories:
   - `IdentityRepository`
   - `PeerRepository`
   - `MessageRepository`
   - `TransferRepository`
   - `CallRepository`

## 6) Storage Design (Room + Filesystem)

### Room Tables
- `profile` (local user profile, device id)
- `contacts` (peer metadata, trust status)
- `messages` (message ID, peer ID, state, timestamp, type)
- `outbox` (retry queue, retry count, next retry)
- `sessions` (ratchet/session state metadata references)
- `calls` (session/call history + quality stats)
- `media_index` (file metadata, path, owner peer, hash, timestamps)

### File Storage
- Chat media/files in app-scoped directories first.
- Export/share via `MediaStore` and SAF flows.
- Keep local index synchronized with actual files.
- Periodic compaction:
  - gzip/archive old message payload chunks
  - retain summary metadata in Room.

### Security for Storage
- Encrypt sensitive state at rest (session blobs, private metadata).
- Wrap encryption keys via Android Keystore.

## 7) Network & Transport Tasks

### Connectivity Strategy
- IPv6 direct preferred where available.
- ICE flow:
  - STUN discovery
  - TURN fallback (UDP first, then TCP/TLS 443 fallback)
- maintain candidate/path health scores (latency/jitter/loss).

### Reconnect/Failover
- On network changes:
  - quickly re-bootstrap node
  - re-establish active sessions
  - replay pending outbox with dedupe.

### Retry/Dedupe
- Every outgoing item: deterministic ID + state machine.
- Retry policy with backoff + max attempts.
- Dedupe incoming by message/event ID.

## 8) Call Stack Tasks

### Signaling
- Use VX6 DHT signaling channel for:
  - offer
  - answer
  - candidates
  - hangup

### Media
- Use Android WebRTC capture (camera/mic), not ffmpeg.
- Device picker:
  - camera list (front/back + optional external)
  - mic input options where accessible
- Call quality loop:
  - poll WebRTC stats
  - adapt bitrate based on packet loss/jitter/RTT
  - controlled re-negotiation when needed

### TURN Hardening
- Support static credentials and REST-auth rotating credentials.
- Credential TTL + rotation policy.
- Prevent stale credential reuse.

## 9) Foreground Service & Background Model

ForegroundService responsibilities:
- keep VX6 node running when user enables it
- publish ongoing status notification
- expose quick actions (start/stop/status)

WorkManager tasks:
- periodic sync (presence/inbox)
- deferred retry sends
- low-priority cleanup/compaction

Battery rules:
- handle doze/app standby gracefully
- avoid aggressive wake loops

## 10) Permissions & UX Requirements

Permissions:
- INTERNET
- CAMERA
- RECORD_AUDIO
- POST_NOTIFICATIONS (modern Android)
- storage/media permissions only when needed

UX flows:
1. First-run identity + nickname.
2. Invite link/QR onboarding.
3. Contact list + chat + file send.
4. Call screen with controls and diagnostics.
5. Device test page:
   - camera preview
   - mic level meter
   - network readiness status.

## 11) Security Requirements

- Per-device identity keys.
- Session ratchet state persisted securely.
- Replay protection and nonce checks.
- Optional app lock (biometric/PIN).
- Tamper-evident local audit trail for sensitive actions.

## 12) Observability & Diagnostics

Add structured logs and metrics:
- connect/disconnect events
- DHT lookup durations
- retry counts
- call quality stats
- TURN fallback rate

Diagnostics export:
- user-triggered support bundle (redacted by default).

## 13) Testing Requirements

### Unit Tests
- repositories
- retry queue logic
- dedupe logic
- session state transitions

### Integration Tests
- two-device invite/chat/file/call flow
- network handoff (Wi-Fi to LTE) during call
- offline send then reconnect flush

### Long-Run/Soak Tests
- 2h and 4h call stability
- repeated reconnect cycles
- large file transfer under packet loss

### Security Tests
- replay attempts
- malformed signaling
- credential expiry and TURN rotation behavior

## 14) Release Engineering

- CI:
  - Go core tests
  - Android unit/instrumentation tests
  - lint/static checks
- Build artifacts:
  - debug APK
  - release AAB
- Signing + staged rollout:
  - internal -> closed test -> phased production

## 15) Milestone Execution Plan

### M1 (Core Messaging)
- identity, invite, chat, presence, outbox retry

### M2 (Files + Offline Robustness)
- file transfer, media indexing, sync hardening

### M3 (Calls)
- signaling + WebRTC media + adaptive bitrate + TURN fallback

### M4 (Hardening)
- security polish, diagnostics bundle, soak tests, release checklist

## 16) Definition of Done (Android GA Candidate)

All must pass:
- stable node lifecycle on modern Android versions
- reliable invite/chat/file flows across poor networks
- successful call setup with direct and TURN fallback
- deterministic retry/dedupe behavior
- no critical crash/security findings in test scope
- documented runbooks for support and incident handling
