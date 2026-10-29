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
- `sdk/`: intended public Go API. It builds in-repository, but some exported
  signatures still expose `internal/config` types; external consumer support
  is tracked by issue #58. `sdk/chat/` contains chat client and crypto helpers.
- `internal/ipsec/`: Linux strongSwan/XFRM peer tunnel manager, narrow Unix
  socket client/server, and owned nftables policy.
- `cmd/vx6-ipsecd/`: separate privileged service executable. It is not the
  regular VX6 CLI and must be installed/configured by the system package.

## Optional products

`products/` contains the Qt browser, mobile bridge, and companion applications.
Each product has its own README and build instructions. Root `make build`
produces `vx6` and `vx6-ipsecd`; `cmd/vx6-gui` and the Qt browser are separate
optional applications.

## Supporting directories

- `deployments/`: Linux service and package integration.
- `scripts/`: build and maintenance helpers.
- `docs/archive/`: proposals, exported reports, and historical/provenance files not required for ordinary development.
- `tests/ipsec-e2e/`: privileged IPv6 two-peer IKEv2/ESP packet-capture test.
- `docs/README.md`: documentation directory map and recommended reading paths.
