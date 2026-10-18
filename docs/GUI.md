# GUI and Browser Frontend

VX6 now has two local frontends:

- `vx6-gui`
- `products/browser/qt`, which builds the Qt browser shell

## What They Are

Both frontends run locally and call the `vx6` binary underneath.
Neither one contains protocol logic of its own.

That means:

- the core protocol stays in one place
- the GUI and browser stay aligned with the CLI
- Windows, Linux, and macOS can share the same VX6 behavior

## `vx6-gui`

This is the command-style local control UI.
It exposes:

- node initialization
- node start
- reload
- status
- identity
- service publishing
- connect tunnels
- file send
- receive policy
- DHT lookups
- eBPF status
- custom CLI argument execution

## `products/browser/qt`

This is the browser-style VX6 shell built with Qt WebEngine.
It exposes:

- a colorful VX6 home dashboard
- tabbed navigation
- `vx6://` internal pages
- browser-style lookup for services, nodes, and raw keys
- a side drawer for runtime logs and reload actions
- first-run Windows/macOS permission guidance

## Why It Was Built This Way

This release is still stabilizing.
A thin frontend over the CLI is safer than duplicating VX6 logic in a separate desktop app.
