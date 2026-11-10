# Commands

This page covers the Linux CLI peer and service workflow. VX6 uses IPv6
endpoints and IKEv2/IPsec through strongSwan; `vx6 doctor` checks local setup,
not reachability or successful service transfer to another machine.

## First Run

For a Linux amd64 bundle, extract it and install its dependencies and system
helper setup:

```sh
mkdir vx6-linux && tar -xzf vx6-linux-amd64.tar.gz -C vx6-linux
cd vx6-linux
sudo ./install.sh "$USER"
```

For Arch, install the `.pkg.tar.zst` package and run `sudo vx6-setup "$USER"`.
The setup configures the privileged IPsec service for the current account; do
not run the VX6 node as root.

Initialize once on each system, using that system's reachable global IPv6:

```sh
vx6 init --name ALICE --advertise '[2001:db8::10]:4242'
vx6 doctor
vx6 node
```

Exchange signed endpoint records between the users. On the sender:

```sh
vx6 identity export-endpoint --addr '[2001:db8::10]:4242' --out alice.json
```

On the recipient, add the received record; do not run VX6 as root:

```sh
vx6 peer add --record alice.json
```

The peer record binds the peer's name, IPv6 address, NodeID, and public key.
IKE/IPsec then authenticates possession of the matching private key. Both
systems need working IPv6 routing, strongSwan, the `vx6-ipsecd` system service,
and permission for the normal login user to access its configured control
socket.

## Share a Service

Start the application on the host, listening locally, then register its
backend with VX6:

```sh
vx6 service add --name web --target 127.0.0.1:8080
```

Services are public by default. Public means any peer accepted by the node's
IKE/IPsec policy; it does not mean an anonymous, unauthenticated Internet
client. For a private service, allow the other node's full NodeID:

```sh
vx6 service add --name admin --target 127.0.0.1:22 \
  --private --allow-node vx6_FULL_64_HEX_DIGIT_NODE_ID
```

The owner can later change access with `vx6 service allow` or
`vx6 service revoke`. The service owner still needs the backend application
running at the configured local target.

Adding a service or signed peer record while `vx6 node` is already running
requests an immediate node reload. The CLI reports whether it reached the
running node. If it did not, start `vx6 node` or run `vx6 reload` after starting
it.

## Connect to a Service

On the client, create a local listener and leave this command running:

```sh
vx6 connect --service ALICE.web --listen 127.0.0.1:18080
```

Use the application as if the service were local, for example:

```sh
curl http://127.0.0.1:18080/
```

Each local application connection opens a VX6 connection to the peer's shared
listener. VX6 identifies the requested service inside the ESP-protected
connection, so multiple named services can share the peer listener.

## Diagnose a Failed Connection

Check a locally registered service backend before testing the remote path:

```sh
vx6 service check --name web
```

For a remote service, this reports whether the service is in the local
registry, the DHT result and peer-query counts, whether the returned service
signature is valid, and whether its owner matches a signed endpoint record:

```sh
vx6 service check --name SURYANSH.web
```

Check a known peer's UDP liveness response:

```sh
vx6 peer check --name SURYANSH
```

A PONG is only a reachability hint; it does not authenticate the peer. Add
`--ike` to initiate or verify IKEv2, require an installed ESP CHILD_SA, and
send a nonce-based TCP health request through the protected VX6 path:

```sh
vx6 peer check --name SURYANSH --ike
```

`ike_esp` confirms negotiation; `protected_path` confirms the TCP request
reached the authenticated VX6 handler. For packet-level confirmation, compare
the ESP SA counters before and after the health request:

```sh
sudo swanctl --list-sas
sudo ip -s xfrm state
```

## Other Commands

- `vx6 status`: show node and DHT runtime status.
- `vx6 reload`: ask a running node to reload config and republish records.
- `vx6 list [--user NODE_NAME]`: list locally known nodes and public services.
- `vx6 peer add --record FILE`: add a signed endpoint record.
- `vx6 peer friend --record FILE`: retain and retry a known identity locally.
- `vx6 peer revoke --node-id ID`: block a peer locally and remove its tunnel.
- `vx6 service remove --name NAME`: stop publishing and serving a local service.
- `vx6 send` and `vx6 receive`: file-transfer workflow.
- `vx6 debug`: DHT and local diagnostic commands.

Run `vx6 --help` for the concise workflow and `vx6 <command> --help` where
available for command flags.
