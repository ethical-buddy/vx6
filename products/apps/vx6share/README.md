# VX6Share

VX6Share is a separate browser-based decentralized file sharing app built on the VX6 SDK.

## Features

- First-run nickname initialization (auto-creates VX6 config/identity)
- Node start/stop from UI
- Peer invite link sharing (`vx6share://peer/...`)
- Large file sending with progress tracking
- Local file metadata catalog ("ledger") published to DHT
- Peer catalog fetch by NodeID
- Localhost-first browser UI

## Build

### Linux

```bash
go build -o vx6share ./apps/vx6share
```

### Windows

```bash
GOOS=windows GOARCH=amd64 go build -o vx6share.exe ./apps/vx6share
```

### macOS

```bash
GOOS=darwin GOARCH=arm64 go build -o vx6share ./apps/vx6share
```

## Run

```bash
./vx6share
```

UI opens at:

- `http://127.0.0.1:17990`

## Notes

- VX6Share uses SDK and VX6 runtime in the same process.
- File receiving depends on running node and configured download path.
- This is a protocol app layer, intended for a separate repo split.

