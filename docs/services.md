# Services

VX6 exposes local TCP and UDP services through an authenticated peer connection.
The application connects to a local VX6 listener; VX6 forwards traffic only to
the configured backend. The backend host and port are not chosen by the remote
peer.

## TCP

TCP services are the default and support ordinary stream applications such as
SSH, HTTP, databases, and file-transfer protocols.

```sh
vx6 service add --name web --target '[::1]:8080'
vx6 connect --service alice.web --listen 127.0.0.1:18080
```

The application then connects to `127.0.0.1:18080`. One VX6 node can publish
multiple named services. Each connection names the service inside the protected
peer connection, so those services do not need separate public VX6 listener
ports.

## UDP

UDP services are explicitly selected when publishing and connecting. VX6 wraps
each UDP datagram with a versioned service name and flow identifier, sends it
to the peer's UDP service socket, and forwards the payload to the configured
UDP backend. Replies use the same flow identifier to reach the originating
local UDP socket.

```sh
vx6 service add --protocol udp --name dns --target '[::1]:5353'
vx6 connect --service alice.dns --listen 127.0.0.1:15353
```

For a direct address, specify the protocol because there is no signed service
record to tell the client:

```sh
vx6 connect --service dns --addr '[2001:db8::10]:4242' \
  --protocol udp --listen 127.0.0.1:15353
```

With the default VX6 endpoint port `P`, TCP peer traffic uses `P`, the existing
unauthenticated liveness probe uses UDP `P+1`, and UDP service datagrams use
UDP `P+2`. The UDP datagrams are protected by the peer's IPsec ESP policy; the
UDP service socket does not accept unprotected service frames. The service
name, flow ID, and application datagram are inside ESP on the routed link.

The implementation bounds active UDP flows, expires idle flows, validates the
frame format, and checks a private-service allow-list against the IKE-authenticated
peer identity. Public services do not require a per-service allow-list, but
network-level IPsec peer admission still applies. A UDP service is not a general
raw-UDP or raw-IP tunnel.

UDP service connections currently support direct peer mode only; UDP over the
multi-hop proxy and hidden-service paths is rejected rather than silently
falling back to TCP.

## Application Protocol Scope

TCP and UDP cover most conventional client/server applications, but not every
network protocol automatically:

- WebRTC can use a UDP service for media/data packets when the application can
  configure VX6's local UDP endpoint. Its signaling, ICE candidate exchange,
  STUN/TURN behavior, and endpoint-address assumptions still need application
  integration; VX6 does not currently implement a WebRTC ICE agent.
- TCP-based signaling can use an ordinary TCP service.
- SCTP, ICMP, multicast, arbitrary IP protocols, and applications requiring
  several dynamically negotiated ports are not provided by this service proxy.
  Those need a separately designed Layer-3/TUN service mode.
- UDP is datagram-oriented and best-effort. VX6 does not add retransmission,
  congestion control, fragmentation/reassembly, or a promise that a datagram
  larger than the path MTU will work efficiently. Applications must handle
  loss, reordering, and MTU limits as they normally would over UDP.

The proxy does not reinterpret application bytes. It adds VX6 framing for UDP;
TCP payload bytes are relayed as a stream. Both are carried inside the
authenticated IPsec peer path in the Linux implementation.

## Access Types

### Public services

Public services are discoverable through the DHT and local registry. They do
not have a service-specific peer allow-list. The peer still has to establish
the IPsec connection accepted by the node's peer policy.

### Private services

Private services are not published in the public service namespace. The owner
allows specific peer identities by NodeID. VX6 checks that identity before
forwarding TCP or UDP traffic; removing permission also closes tracked active
TCP sessions. UDP authorization is checked while processing each datagram.

### Hidden services

Hidden services use a separate invite, encrypted descriptor, and relay flow.
They currently support TCP only; UDP and WebRTC are not supported in hidden
mode.
