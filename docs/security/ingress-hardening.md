# Control Ingress Hardening

This page records the current Linux CLI control-ingress boundaries implemented
for issue #66. These controls reduce parser abuse and resource exhaustion; they
do not establish global DHT truth, prevent network-level denial of service, or
replace IKEv2/IPsec authentication.

## Processing Order

1. Linux firewall/IPsec policy limits the peer dataplane to established ESP
   associations. VX6 then asks the local IPsec service to map the remote
   endpoint to its verified signed peer record.
2. Before protocol parsing, the node admits at most 64 peer-identity checks
   concurrently. Each check has a 10-second context deadline. Saturated checks
   are dropped; the listener does not wait for one check at a time.
3. After peer authentication, a peer can open at most 600 VX6 connections in
   a fixed 10-second window. The per-peer limiter holds at most 4,096
   identities; when full, stale entries are removed, otherwise new identities
   fail closed.
4. The existing overall active-connection default remains 1,024 and can be
   configured. The protocol header has a 10-second deadline, and unknown
   message kinds are rejected before dispatch.
5. Each kind uses its own bounded frame, strict schema, semantic checks, and
   handler limits. DHT/discovery values are not trusted merely because they
   arrived inside ESP: signed records are still independently verified.

The UDP liveness hint remains an intentional pre-IKE exception. It has a fixed
512-byte packet ceiling and responder rate limiting, but it is not encrypted
and does not prove identity. A PONG never grants DHT admission or service
access; IKE must still authenticate the peer.

## Parser and Frame Ceilings

| Input | Limit | Additional checks |
| --- | ---: | --- |
| Strict JSON document | 1 MiB | One value only; duplicate keys and unknown struct fields rejected; max depth 64, 4,096 total object fields, 4,096 array items, 32,768 parser tokens |
| DHT RPC frame | 1 MiB | Version/type/action/target/data combination validated; referrals and response type checked |
| DHT store/update `data` field | 160 KiB | Leaves room for JSON quoting/escaping inside the 1 MiB RPC frame |
| Discovery request/response | 64 KiB | Action-specific fields; malformed requests cannot publish or change the registry |
| Hidden-control message | 64 KiB | Known actions only; per-action field combinations, string sizes, and list counts checked |
| IPsec local IPC request/response | 64 KiB | Unix peer UID check, strict JSON, one request per socket, bounded read to EOF |
| Service OPEN request | 4 KiB | Version 1, `open`, valid service name; parsed before backend dial |
| Tunnel liveness message | 128 bytes | Version/type and a 16-byte challenge echoed exactly |
| UDP liveness packet | 512 bytes | Fixed binary header, flags, declared identity length, padding, and nonce checked |
| File-transfer metadata/resume frame | 4 KiB | Strict JSON; canonical sender-name format; safe basename only; nonnegative sizes/offsets |
| UDP service datagram | 65,507 bytes | Fixed header, bounded service name, nonzero flow ID, global association cap |

The JSON parser ceiling is a last-resort generic bound. Smaller protocol frame
limits apply first. DHT data was previously allowed up to 1 MiB by its field
validator even though the complete JSON RPC frame was also capped at 1 MiB;
the 160 KiB field limit removes that mismatch. This retains far more space than
current node/service records require, but applications must not use DHT as a
bulk-file transport.

## Per-Peer Budgets

| Operation | Default budget |
| --- | ---: |
| Authenticated VX6 connections, all kinds | 600 per peer per 10 seconds |
| DHT requests | 24 per peer per 10 seconds |
| Concurrent DHT frame reads/handlers | 64 globally |
| Discovery requests | 120 per peer per 10 seconds |
| Hidden-control raw messages | 128 per peer per second, before JSON decode |
| Hidden-control accepted actions | 96 per peer per 30 seconds, plus replay rejection |
| Concurrent TCP service sessions | 128 per authenticated peer |
| TCP service OPEN attempts | 600 per peer per 10 seconds |
| Concurrent peer identity checks | 64 globally |
| UDP service associations | 4,096 globally |
| UDP peer-authentication cache | 4,096 source identities, 2-second entries |

Rate windows use local monotonic/runtime timing for resource control only; they
are not DHT record timestamps and do not prove identity or record freshness.
Per-peer keys come from the peer identity returned by the IPsec service, not a
caller-supplied name. The generic authenticated connection budget also caps
file-transfer and liveness connection churn. DHT and discovery have tighter
operation-specific budgets.

## State and Authorization Boundaries

- DHT requests are limited before JSON decoding in the production listener.
  Invalid action/type/target combinations fail before a DHT write. Signed
  endpoint, service, private-catalog, hidden-service, and envelope values are
  decoded strictly and verified before storage/use.
- Discovery messages accept only known actions and the fields belonging to
  that action. Snapshot, resolve, publish, and service-publish payloads are
  separated; a malformed request receives an error and cannot mutate the
  registry.
- Hidden control has a bounded frame, strict JSON, a fixed action set, field
  and list ceilings, peer-ID binding, replay checks, an epoch window, and
  action-rate limits. This is ingress hardening only; it does not redesign
  hidden rendezvous.
- A service OPEN request is parsed and validated before a local backend is
  dialed. Public service authorization still means “any peer admitted by the
  current IPsec dataplane”; private service access additionally verifies the
  authenticated signed peer identity against the service allowlist.
- Endpoint and service records are size-checked before base64 decoding and
  signature verification. A valid signature proves the record's key binding
  and integrity, not network-wide uniqueness or that the publisher is honest.
- The privileged IPsec IPC still checks the caller's Unix UID before parsing
  and dispatching operations. VX6 and `vx6-ipsecd` must be installed from a
  matching build because the client now half-closes each bounded request
  before reading its response.

## Evidence and Remaining Limits

Unit tests cover duplicate/unknown/trailing JSON, parser budgets, unknown
message kinds, typed DHT validation and rate limiting, discovery action schemas
and mutation rejection, hidden-control action/replay validation, service
requests rejected before dialing, bounded per-peer session admission, UDP
identity-cache capacity, safe transfer filenames, and IPC schema validation.
Fuzz targets are included for the strict JSON decoder and the principal DHT,
discovery, hidden-control, service-open, IPC, and length-prefixed frame parsers.

The passing Go tests demonstrate the tested behavior, not a formal proof of
resource safety under arbitrary Internet-scale traffic. Kernel backlog,
firewall, strongSwan, CPU, memory, disk quotas, and cross-version protocol
negotiation remain separate operational concerns. Old peers that send unknown
fields or exceed the new DHT data ceiling are rejected rather than silently
accepted.
