# VX6D API (Local Backend Contract)

Base URL: `http://127.0.0.1:4866`

All endpoints return JSON:

```json
{
  "ok": true,
  "output": "string",
  "error": ""
}
```

## 1) Health

`GET /health`

Response:

```json
{
  "ok": true,
  "output": "vx6d alive"
}
```

## 2) Node Init

`POST /v1/node/init`

Request:

```json
{
  "name": "alice",
  "listen": "[::]:4242",
  "peer": "[2001:db8::10]:4242"
}
```

Behavior:
- tries `vx6 init --name ... --listen ... --peer ...`
- fallback for old CLI builds:
  - `vx6 init --name ... --listen ...`
  - `vx6 peer add --addr ...`

## 3) Node Start/Stop

- `POST /v1/node/start`
- `POST /v1/node/stop`

Starts/stops `vx6 node` as local child process managed by `vx6d`.

## 4) Node Status

`GET /v1/node/status`

Runs `vx6 status`.

## 5) Generic VX6 Exec

`POST /v1/vx6/exec`

Request:

```json
{
  "args": ["peer", "add", "--addr", "[2001:db8::20]:4242", "--name", "bob"]
}
```

Use this for DHT, service actions, list/lookups, receive status, etc.

## 6) Chat Send

`POST /v1/chat/send`

Request:

```json
{
  "to": "bob",
  "text": "hello"
}
```

Backend writes a temporary payload file and sends with:

`vx6 send --file <tmpfile> --to <node>`
