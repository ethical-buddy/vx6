# Commands

## Main Commands

- `vx6 init`
- `vx6 node`
- `vx6 reload`
- `vx6 status`
- `vx6 identity`
- `vx6 list`
- `vx6 peer`
- `vx6 service`
- `vx6 connect`
- `vx6 send`
- `vx6 receive`
- `vx6 debug`
- `vx6-gui`
- `products/browser/qt/build/vx6-browser`

## Important Notes

- transport is TCP in this release
- `transport=quic` is not active
- hidden services use invite-based lookup
- private services are not published as public `service/...` records
- `vx6 status` reports whether an offline ASN map is loaded for DHT diversity
- trusted DHT stores now require authoritative signed envelopes
- the Qt browser frontend is built separately from `products/browser/qt`

## Most Used Flows

Initialize:

```bash
vx6 init --name alice --listen '[::]:4242'
```

Run:

```bash
vx6 node
```

Publish service:

```bash
vx6 service add --name web --target 127.0.0.1:8080
```

Open tunnel:

```bash
vx6 connect --service alice.web --listen 127.0.0.1:8080
```

Open GUI:

```bash
vx6-gui
```

Open browser app:

```bash
products/browser/qt/build/vx6-browser
```
