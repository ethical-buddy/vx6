<p align="right">
<b>SPONSORED BY</b><br>
<a href="https://github.com/dailker">@dailker (Ilker)</a>
</p>

<h1 align="center">VX6</h1>

<p align="center"> <strong>linux / windows / unix peer-to-peer service networking for real local apps.</strong><br> signed discovery, encrypted sessions, dht-backed lookup, relay paths, hidden services, file transfer, and a browser-ready frontend. </p> <p align="center"> this branch is the <strong>linux-first</strong> release branch.<br> build <code>vx6</code> and <code>vx6-gui</code> from the Go tree, and build the Qt browser frontend from <code>browser/qt</code>. </p>

## What VX6 Is

VX6 is a service network built for applications that already work locally.

The model is simple:

- your service stays on localhost
- VX6 publishes a signed record for that service
- another VX6 node resolves the record
- VX6 creates an encrypted stream between the two nodes
- the remote machine reaches the service through its own local forwarder

That means you do not have to redesign your application just to share it across a peer network.

VX6 is split into two layers:

- the Go core, which owns identity, discovery, DHT, relays, hidden services, and transfers
- the browser/frontend layer, which presents those features in a local app UI without changing the core protocol

Good fits include:

- SSH
- internal APIs
- dashboards
- development tools
- databases
- private admin services
- hidden internal services

## What This Branch Is For

This branch is meant for:

- Windows & UNIX/Linux builds
- Test deployments
- Production-style staging
- The reference protocol and security behavior for VX6

Typical binaries here are:

- `vx6`
- `vx6-gui`
- `vx6-browser` from `browser/qt`

## Connection Modes

VX6 currently supports three access styles:

1. `direct`
   Connect to a known VX6 node address directly.

2. `named`
   Resolve a public or private service through discovery and the DHT.

3. `hidden`
   Resolve a hidden service through blinded DHT keys and relay paths.

## What Works Right Now

- signed node identity with Ed25519
- encrypted node-to-node sessions
- public service publishing and lookup
- private per-user service catalogs
- hidden services with:
  - encrypted hidden descriptors
  - blinded rotating DHT keys
  - invite secrets
  - anonymous descriptor store and lookup over relay paths
- relay budgeting so transit work does not consume all local capacity
- file transfer with local receive policy
- runtime status and reload over a local control channel
- TCP-based transport across the whole system
- `vx6-gui` as a local web UI over the same CLI/runtime
- `browser/qt` as a separate Qt WebEngine browser frontend that talks to the same VX6 binary

## What Is Still In Progress

- real QUIC transport
- seamless mid-stream hidden TCP failover after relay loss
- stronger anti-Sybil and WAN-tuned DHT behavior
- a proven active eBPF/XDP fast path for the current encrypted relay plane
- production-grade Windows installer and service automation
- production-grade macOS packaging

## Platform Notes

### Linux

This is the branch you should use if your target environment is Linux.

Current Linux expectations:

- build `vx6`
- build `vx6-gui`
- build `vx6-browser`
- run the full current VX6 protocol feature set
- use TCP transport
- use the local runtime control channel
- optionally use Linux-only eBPF/XDP status and attach commands

Important:

- eBPF/XDP is still experimental
- it should be treated as optional work, not the reason to adopt VX6

### Windows

Windows follows the same protocol and service behavior through the shared Go core and Windows-specific runtime files.

That branch is intended for:

- `vx6.exe`
- `vx6-gui.exe`
- `vx6-browser` built from the Qt browser directory
- Windows 11
- Windows Server class deployments

## Security Model In Plain Language

VX6 is not claiming full Tor-equivalent anonymity.

What it does provide today:

- signed node and service identity
- encrypted peer-to-peer sessions
- encrypted hidden-service descriptors
- blinded rotating hidden lookup keys
- relay-based hidden-service paths

What it still does not fully solve:

- perfect traffic-analysis resistance
- seamless hidden-stream continuation after relay failure
- hardened large-scale adversarial DHT admission

## Transport

VX6 is currently TCP-only in production behavior.

The config surface may still mention `quic` for forward compatibility, but the current build does not activate a real QUIC transport.

## GUI

`vx6-gui` is the local command-driven control UI.
`browser/qt` is the browser-ready Qt WebEngine frontend.

They are both thin frontends over the same VX6 core, so the protocol logic stays in one place.

`vx6-gui`:

- starts on your own machine
- calls the `vx6` binary underneath
- exposes the same core features through forms instead of shell commands

`browser/qt`:

- opens a colorful browser-style home page
- supports `vx6://` internal pages
- keeps runtime logs in a side panel
- is designed so a future fuller browser can sit on top of the same backend

This keeps the GUI aligned with the CLI and avoids splitting the protocol logic into two different apps.

## Quick Start

### Build

```bash
make build
```

Or:

```bash
go build ./cmd/vx6
go build ./cmd/vx6-gui
cmake -S browser/qt -B browser/qt/build
cmake --build browser/qt/build
```

### Initialize a node

```bash
vx6 init --name alice --listen '[::]:4242'
```

### Run the node

```bash
vx6 node
```

### Add a public service

```bash
vx6 service add --name web --target 127.0.0.1:8080
```

### Inspect status

```bash
vx6 status
```

### Open the GUI

```bash
vx6-gui
```

### Open the browser app

```bash
browser/qt/build/vx6-browser
```

## Documentation

- [Setup](./docs/SETUP.md)
- [Linux Guide](./docs/LINUX.md)
- [Usage](./docs/USAGE.md)
- [Commands](./docs/COMMANDS.md)
- [Architecture](./docs/architecture.md)
- [Discovery](./docs/discovery.md)
- [DHT](./docs/dht.md)
- [Services](./docs/services.md)
- [Identity](./docs/identity.md)
- [GUI](./docs/GUI.md)
- [SDK](./docs/SDK.md)
- [Proxy Launcher](./docs/PROXY.md)
- [Browser Frontend](./browser/qt/README.md)
- [eBPF Status](./docs/ebpf.md)
- [Systemd](./docs/systemd.md)
- [Status](./docs/STATUS.md)
- [File Map](./docs/FILE_MAP.md)
- [Changes Directory](./docs/changes/)

## Release Position

VX6 is already a working system for controlled testing and temporary internal deployment.

It is best described as:

- a strong working prototype
- protocol-complete enough for real usage
- still in need of hardening, failover polish, and deeper adversarial testing

## Licensing

VX6 uses a dual-licensing model:

- Open/community usage is available under Apache-2.0: [LICENSE](./LICENSE)
- Commercial usage requires prior written permission from Suryansh Deshwal under separate terms: [LICENSE-COMMERCIAL.md](./LICENSE-COMMERCIAL.md)

Related legal files:

- [NOTICE](./NOTICE)
- [TRADEMARK.md](./TRADEMARK.md)

Commercial-use request flow:

1. Send a written request with intended commercial use details.
2. Contact through:
   - Email: `suryanshdeshwal@gmail.com`
   - GitHub: https://github.com/dailker
3. Wait for explicit written approval and a signed commercial agreement before commercial deployment or distribution.
