# VX6

VX6 is a peer-to-peer service network for applications that already run locally. A VX6 node publishes signed service records, discovers peers through the DHT, and opens encrypted connections so another node can reach a service without exposing it directly to the public internet.

The core project is a Go module. It provides the `vx6` command and the Go SDK. Optional desktop, browser, and mobile projects live under [`products/`](products/README.md) and build independently.

## What VX6 provides

- Node identities and signed service records
- Direct and DHT-backed service discovery
- Encrypted node sessions and local service forwarding
- Public, private, and invite-based hidden services
- Relay paths and file transfer
- Local status and runtime reload controls

The current transport is TCP. QUIC and eBPF/XDP acceleration are not production transport paths. Hidden-service routing is under active hardening and should not be treated as equivalent to a mature anonymity network. See [security and limitations](docs/security.md).

## Repository map

| Path | Purpose |
|---|---|
| `cmd/vx6/` | Main command entrypoint; builds the only core release binary, `vx6` |
| `internal/` | Protocol and runtime implementation; private to this Go module |
| `sdk/` | Public Go embedding API, including `sdk/chat` |
| `products/` | Optional apps, Qt browser, and mobile bridge; independent build targets |
| `deployments/` | systemd and Arch Linux packaging files |
| `docs/` | Short user and contributor guides, architecture references, and archive material |
| `scripts/` | Build helpers and maintenance utilities |

For the detailed directory and package map, see [Repository map](docs/repository-map.md). For app-specific status and build instructions, see [Products](products/README.md).

## Build the core

Requirements: Go version from [`go.mod`](go.mod); Linux builds that enable Fyne GUI dependencies may also need the system libraries noted in the product-specific documentation.

```sh
go build -o ./vx6 ./cmd/vx6
```

Or use the Makefile:

```sh
make build
```

`make build` builds `vx6` and the separate privileged `vx6-ipsecd` Linux
helper. The optional GUI, browser, and companion apps have separate build
instructions under `products/`. See the [documentation map](docs/README.md)
for the current platform and security boundaries.

## First node

Initialize a node identity and configuration:

```sh
./vx6 init --name alice --listen '[::]:4242'
```

Start it in the foreground:

```sh
./vx6 node
```

In another terminal, inspect status:

```sh
./vx6 status
```

Publish a local service and connect to it from another node:

```sh
./vx6 service add --name web --target 127.0.0.1:8080
./vx6 connect --service alice.web --listen 127.0.0.1:8081
```

The second command creates a local listener that forwards traffic to the discovered service. See [Usage](docs/usage.md) for complete workflows and [Commands](docs/commands.md) for CLI details.

## Use the Go SDK

Import `github.com/vx6/vx6/sdk` to embed node, forwarding, observation, and sharing APIs. Chat helpers are in `github.com/vx6/vx6/sdk/chat`. The SDK is the supported application boundary; `internal/` packages are implementation details.

Start with the [SDK guide](docs/sdk.md). Mobile binding experiments are documented separately under [`products/mobile`](products/mobile/README.md).

## Documentation

- [Setup and build](docs/setup.md)
- [Usage workflows](docs/usage.md)
- [Command reference](docs/commands.md)
- [Architecture](docs/architecture.md)
- [SDK guide](docs/sdk.md)
- [Current status and limitations](docs/status.md)
- [Security notes](docs/security.md)
- [Contributing](CONTRIBUTING.md)

Archived proposals, benchmark reports, and provenance material are kept outside the main reading path in `docs/archive/`.
