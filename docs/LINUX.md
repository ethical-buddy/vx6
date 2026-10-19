# Linux Guide

## What This Is

This guide is for running VX6 on Linux.

The `main` branch is the Linux-first protocol and release reference branch.

Typical binaries:

- `vx6`
- `vx6-gui`

## What Works On Linux

- node initialization
- node runtime
- signed discovery
- DHT lookup
- public services
- private service catalogs
- hidden services
- file transfer
- GUI
- runtime status and reload
- systemd-based long-running node workflows
- Linux IKEv2/IPsec peer tunnels using strongSwan and kernel XFRM, with the
  privileged `vx6-ipsecd` service (experimental deployment; packaging is not
  yet production-ready)

## Experimental Linux Feature

Linux is the only platform that exposes the current eBPF/XDP status and attach commands.

Important:

- this does not mean VX6 already has a proven production fast path
- the current eBPF/XDP work is still experimental

## Build

```bash
make build
```

Or:

```bash
go build ./cmd/vx6
go build ./cmd/vx6-gui
```

## First Run

Initialize:

```bash
vx6 init --name alice --listen '[::]:4242'
```

Run:

```bash
vx6 node
```

Check status:

```bash
vx6 status
```

Open the GUI:

```bash
vx6-gui
```

## Systemd

If you want a user-level long-running service, see:

- [systemd](./systemd.md)

## Notes

- VX6 still expects IPv6-capable node endpoints
- service stream transport currently uses TCP; the active IPsec protection is
  Linux-only
- Windows and Android do not yet have equivalent VX6 tunnel integration
- IPsec setup and packet-capture test: [IPsec guide](ipsec.md)
- installation and multi-platform contribution direction: [packaging plan](packaging-plan.md)
