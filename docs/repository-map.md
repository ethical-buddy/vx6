# Repository map

## Core Go module

- `cmd/vx6/`: executable entrypoint; delegates to `internal/cli`.
- `internal/cli/`: command parsing and user-facing CLI behavior.
- `internal/node/`: node lifecycle, peer listeners, and background work.
- `internal/config/`, `internal/identity/`, `internal/record/`: configuration, local identity, and signed records.
- `internal/discovery/`, `internal/dht/`: peer discovery, DHT lookup, storage, and hidden descriptors.
- `internal/secure/`, `internal/transport/`, `internal/serviceproxy/`, `internal/transfer/`: encrypted sessions, network transport, forwarding, and file transfer.
- `internal/onion/`, `internal/hidden/`: relay circuits and hidden-service routing.
- `internal/runtimectl/`: local status and reload control channel.
- `sdk/`: supported public Go API. `sdk/chat/` contains chat client and crypto helpers.

## Optional products

`products/` contains the Qt browser, mobile bridge, and companion applications. Each product has its own README and build instructions. Root `make build` builds only the core `vx6` executable.

## Supporting directories

- `deployments/`: Linux service and package integration.
- `scripts/`: build and maintenance helpers.
- `docs/archive/`: proposals, exported reports, and historical/provenance files not required for ordinary development.
- `docs/internal/`: internal planning or threat-model material, excluded from the public quick-start reading path.
