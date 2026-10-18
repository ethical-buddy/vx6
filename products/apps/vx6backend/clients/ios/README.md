# iOS UI Integration

iOS should use the same backend contract and feature behavior as desktop.

## Runtime approach

- Prefer embedding shared Go core (via gomobile) for App Store-safe architecture.
- Keep UI/network orchestration in Swift, protocol logic in shared core.

## Required backend feature parity

- node init/start/stop/status
- DHT/service/peer/list execution surface
- chat send behavior + confirmation mapping

## Contract source

See [../../API.md](../../API.md).

