# Usage

## Public Service

Publish a local service:

```bash
vx6 service add --name web --target 127.0.0.1:8080
```

Resolve and use it from another node:

```bash
vx6 list
vx6 connect --service alice.web --listen 127.0.0.1:8080
```

## Private Service

Publish a service that should not appear in public service lookups:

```bash
vx6 service add --name admin --target 127.0.0.1:9000 --private
```

Private services are resolved through a per-user private catalog, not through the public `service/...` keyspace.
That keeps private services out of the normal shared listing while still letting the owning user expose them intentionally.

## Hidden Service

Publish a hidden service:

```bash
vx6 service add --name admin --target 127.0.0.1:9000 --hidden --alias ghost-admin
```

VX6 prints a hidden invite that includes the secret lookup part.

Clients use that invite when resolving the hidden service.
The invite secret is what keeps the blinded hidden lookup key from being guessable by plain alias alone.

## Browser Frontend

Open the Qt browser frontend:

```bash
products/browser/qt/build/vx6-browser
```

Use it when you want a browser-style home page with:

- VX6 internal pages
- logs and reload actions in a side drawer
- the same backend behavior as the CLI and GUI

## File Transfer

Send a file:

```bash
vx6 send --file report.txt --to bob
```

Receive policy is local and explicit:

```bash
vx6 receive status
vx6 receive allow --node bob
```

## Direct Address Mode

If you already know the other VX6 node address, you can skip discovery:

```bash
vx6 connect --service web --addr '[2001:db8::10]:4242' --listen 127.0.0.1:8080
```
