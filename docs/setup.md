# Setup

## Requirements

- Go 1.22 or newer if you are building from source
- Qt 6 WebEngine if you are building the optional browser frontend from `products/browser/qt`
- IPv6 enabled on the Linux machines that will run VX6
- firewall rules that allow the VX6 listen port

## Build

The simplest build path is:

```bash
make build
```

That builds only the core `vx6` executable.

You can also build directly with Go:

```bash
go build ./cmd/vx6
go build -o vx6-gui ./cmd/vx6-gui
```

Build the Qt browser frontend separately:

```bash
cmake -S products/browser/qt -B products/browser/qt/build
cmake --build products/browser/qt/build
```

## Install

```bash
make install
```

For staged packaging:

```bash
make install DESTDIR=/tmp/vx6-install-root
```

## First-Time Node Setup

Create a config and identity:

```bash
vx6 init --name alice --listen '[::]:4242'
```

Optional:

- add `--advertise` if you already know the public IPv6 address
- add `--peer` to seed discovery from a known node
- add `--hidden-node` if you do not want to publish an endpoint record
- add `--downloads-dir` if you want received files somewhere else

## Run the Node

```bash
vx6 node
```

## Check Status

```bash
vx6 status
```

## Open the GUI

```bash
vx6-gui
```

The GUI opens a local browser page and calls the `vx6` binary underneath.

## Open the browser frontend

```bash
products/browser/qt/build/vx6-browser
```

The browser frontend uses the same `vx6` backend and local control surface.

## Linux-Specific Follow-Up

- [Linux Guide](./LINUX.md)
- [systemd](./systemd.md)
