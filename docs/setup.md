# Setup

## Install

For Linux amd64, build the self-contained installer bundle with:

```sh
make package-linux
```

This produces `dist/vx6-linux-amd64.tar.gz`. Extract it on the target Linux
system and run `sudo ./install.sh "$USER"`; it installs strongSwan/nftables,
the binaries and systemd units, then configures and starts the helper for that
normal account. Arch users can alternatively build/install the package in
`deployments/arch/`, then run `sudo vx6-setup "$USER"`.

## Requirements

- Linux with working IPv6 connectivity and a reachable IPv6 endpoint.
- VX6 binaries `vx6` and `vx6-ipsecd`.
- Kernel XFRM support and systemd. The installer/package supplies strongSwan
  and nftables for supported Linux distributions.
- A regular login user configured for the root helper's Unix socket.

## Build From Source

```sh
make build
```

This builds `vx6` and the privileged helper separately. For a distributable
amd64 bundle, run `make package-linux`. After package/bundle installation,
configure the root helper for the normal account with `sudo vx6-setup "$USER"`.
See the [Linux guide](LINUX.md).

## Initialize and Run

On each machine, substitute its own reachable global IPv6 address:

```sh
vx6 init --name ALICE --advertise '[2001:db8::10]:4242'
vx6 doctor
vx6 node
```

Exchange signed endpoint files using
`vx6 identity export-endpoint --addr '[IPv6]:4242' --out peer.json`, then add
the received record with `vx6 peer add --record peer.json`. Do not run the
normal node process with `sudo`.

See the concise [command workflow](commands.md), [service guide](services.md),
and [IPsec guide](ipsec.md). A successful local `doctor` check is not proof of
remote connectivity; service transfer must be verified separately on two
reachable systems.
