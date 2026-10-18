# VX6 Qt Browser

This directory is the browser-ready VX6 frontend built on Qt WebEngine.

It is separate from the Go protocol core:
- VX6 core still owns identity, DHT, sessions, hidden services, and relay logic.
- This app only provides the browser shell, tabs, navigation, and VX6-aware pages.

## Build

Example CMake build:

```bash
cmake -S products/browser/qt -B products/browser/qt/build
cmake --build products/browser/qt/build
```

The executable is `vx6-browser`.

## What this app does

- opens normal `http://` and `https://` pages
- opens VX6 internal pages through `vx6://`
- renders a colorful home dashboard with VX6 actions
- shows a left control drawer with:
  - copyable current IPv6
  - node rename
  - service / node / hidden lookup
  - service hosting and stop controls
- shows a right-side log drawer for node output and reload actions
- includes node start and stop controls in the side drawer
- keeps one system identity and one key, with no profile switching UI

## VX6 pages

- `vx6://home`
- `vx6://status`
- `vx6://dht`
- `vx6://registry`
- `vx6://services`
- `vx6://peers`
- `vx6://identity`
- `vx6://service/<name>`
- `vx6://node/<name>`
- `vx6://node-id/<id>`
- `vx6://key/<raw-key>`

## OS notes

- Windows, Linux, and macOS are the main Qt WebEngine targets.
- BSD is intentionally left for later if build/runtime gaps appear.
- The browser asks for first-run firewall/admin guidance on Windows and macOS.

## Planning Notes

See [PLAN.md](./PLAN.md) for the browser roadmap, contribution rules, build steps, and test matrix.
