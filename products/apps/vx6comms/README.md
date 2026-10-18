# VX6 Comms (Desktop)

Native desktop communications app over VX6 SDK (Linux-first baseline).

## Modes

- `open`: community/open-network style
- `org`: organization-first style with stricter defaults and policy framing

## Current Features (implemented now)

- Native desktop UI (Fyne), not browser-hosted
- First-time nickname init (auto VX6 config/identity)
- Start/Stop VX6 node from app
- IPv6 capability status message in UI
- Invite-link friend onboarding (`vx6chat://invite/...`)
- Friend request popup sync via decentralized key exchange
- Encrypted direct chat payloads (shared-secret per contact)
- DHT-backed conversation ledger (no central chat server)
- Message reliability primitives:
  - message IDs
  - ack envelopes
  - read receipts
  - dedupe tracking
  - retry queue for pending sends
  - unread counters persisted locally
- Per-message key evolution with sequence-based ratchet key derivation (foundation for full Double Ratchet)
- Presence + typing protocol over DHT keys
- Call signaling over DHT + WebRTC offer/answer/ICE negotiation path
- Live RTP media capture pipeline (camera+mic) via local `ffmpeg` feed into WebRTC tracks
- Local offline state persistence (`vx6comms-state.json`)
- Name conflict check before start/rename:
  - validates format
  - checks DHT name key
  - blocks rename if same name is owned by different NodeID
- File transfer with progress + media metadata message in chat
- Group room metadata publish (foundation for expanded group chat)
- Group event ledger with membership and role actions (`add/remove/promote/demote`) + group message events
- Media inbox browser from configured downloads directory
- Media index file stored locally (`vx6comms-media-index.json`) so files remain visible in filesystem and app
- Conversation storage compaction:
  - active ledger trimmed
  - older message chunks archived with gzip under local `archives/`
- Call diagnostics label (PeerConnection/ICE state)
- Device Test button:
  - probes camera input
  - probes microphone input
  - displays mic level summary from ffmpeg output
- Call settings UI for:
  - ffmpeg path
  - device input selection (dropdown enumeration + refresh)
  - resolution/fps
  - bitrate controls
  - TURN URL/credentials
  - TURN REST shared-secret rotation settings
- TURN hardening:
  - optional REST-auth ephemeral credentials (`exp:nodeid` + HMAC secret)
  - configurable credential TTL + rotation interval
- Adaptive bitrate loop:
  - monitors WebRTC stats
  - reduces bitrate on loss/disconnect pressure
  - increases bitrate slowly on stable conditions
- Periodic sync of requests/conversations + retry pump

## Build (Linux)

```bash
go build -o vx6comms ./apps/vx6comms
```

Run open mode:

```bash
./vx6comms open
```

Run org mode:

```bash
./vx6comms org
```

## Media Call Prerequisites

- Install `ffmpeg` on the host.
- Linux capture defaults currently use:
  - video: `/dev/video0` (v4l2)
  - audio: `pulse` device `default`
- Windows capture default uses `dshow` input `video=default:audio=default`
- macOS capture default uses `avfoundation` input `0:0`
- If these devices are unavailable, the app falls back to synthetic RTP keepalive frames so signaling/transport stays testable.

## Cross-build (next)

Windows/macOS binaries can be cross-built, but native packaging/signing and platform UI QA remain next-step tasks.

## Android Plan (next steps)

1. Move chat/ledger logic into SDK-mobile-safe package.
2. Build Android UI in Compose/Flutter with same protocol core.
3. Replace desktop local file paths with SAF/document pickers.
4. Add push-like local polling scheduler + battery-aware sync.
5. Add QR invite flow and background service permissions.

## Important Boundaries

- No central server is required for basic peer chat flow.
- True phone/email OTP verification cannot be trustless without a verification service; current profile fields are metadata only.
- Remaining for full Signal/Tor-grade chat parity:
  - camera/mic capture and encoded media pipeline (current implementation sends synthetic RTP keepalive frames)
  - richer video playback controls/stream pipeline
