# Observability Debug Tutorial

This example is for debugging an Amber scenario as a user thinks about it:

- components: `client`, `server`
- authored bindings: `client_server_api`, `client_external_api`, `public`

The dashboard should not force you to think about Amber's internal mesh. Instead, it gives you three resources:

- `amber.<run>.client`: the client program's stdout/stderr
- `amber.<run>.server`: the server program's stdout/stderr
- `amber.<run>.bindings`: structured request/response telemetry for the scenario's authored edges

`<run>` is the Compose project name. If you do not set one, it defaults to `default`.

## Prereqs

- Docker + Docker Compose v2
- `amber` CLI on `PATH`
- `python3` on the host

## 1) Start the dashboard

```sh
docker rm -f amber-dashboard >/dev/null 2>&1 || true
amber dashboard --detach
```

Dashboard UI: `http://127.0.0.1:18888`

## 2) Compile + start the scenario

```sh
amber compile examples/observability-debug/scenario.json5   --docker-compose examples/observability-debug/amber-observability-debug.yaml

COMPOSE_PROJECT_NAME=amberdemo docker compose -f examples/observability-debug/amber-observability-debug.yaml up -d
```

If you are validating local framework changes, set `AMBER_DEV_IMAGE_TAGS` when you run `amber compile`. For this example, router-only changes need `router=<tag>`. If your changes affect provisioning or generated mesh config metadata, use `router=<tag>,provisioner=<tag>` so the provisioned sidecar config matches the runtime you are testing.

## 3) Start the local upstream (Terminal A)

```sh
python3 examples/observability-debug/upstream-sse.py --port 38081
```

## 4) Wire the external slot and export (Terminal B)

```sh
COMPOSE_PROJECT_NAME=amberdemo \
amber proxy examples/observability-debug/amber-observability-debug.yaml \
  --slot ext_api=127.0.0.1:38081 \
  --export public=127.0.0.1:38080
```

This enables two manifest-level edges:

- `/client -> ext_api`
- `public -> /server`

Brief `502` or `503` responses are expected until the slot is registered and the upstream is reachable.

## 5) Generate explicit host traffic (Terminal C)

```sh
curl -sS \
  -H 'x-amber-tutorial: host-export' \
  http://127.0.0.1:38080/rpc
```

Expected response:

```json
{"jsonrpc":"2.0","id":"server-static","method":"tools/list","result":{"source":"server","ok":true}}
```

The `client` also generates traffic in a loop, so after this call you have all three stories in the dashboard:

- `public -> /server`
- `/client -> /server` via `client_server_api`
- `/client -> ext_api` via `client_external_api`, including SSE

## 6) Read the telemetry

Open `http://127.0.0.1:18888`.

### Component resources

`amber.amberdemo.client` shows the client program's own logs, for example:

- `[client] internal rpc -> server`
- `[client] external rpc -> upstream`
- `[client] external sse -> upstream`

`amber.amberdemo.server` shows the server program's own logs, for example:

- `[server] listening on :9000`
- `[server] received GET /rpc x-amber-tutorial=host-export`
- `[server] responded 200 /rpc id=server-static`

### Binding resource

`amber.amberdemo.bindings` is the important one. It contains the request/response lifecycle for authored edges.

Look for these edge refs:

- `public`
- `/client.client_server_api`
- `/client.client_external_api`

A novice should be able to read the logs as a story.

Examples you should see:

- `request received from public by /server [headers]`
- `response sent from /server to public: tools/list result (id=server-static) [body]`
- `request sent from /client to /server via /client.client_server_api [headers]`
- `response received by /client from /server via /client.client_server_api: tools/list result (id=server-static) [body]`
- `request sent from /client to external slot ext_api via /client.client_external_api: tools/call (id=external-1) [body]`
- `response received by /client from external slot ext_api via /client.client_external_api: notifications/progress response (id=sse-2) [stream event]`

Important details:

- the same request/response chain shares a `traceId`
- request and response logs live under the authored binding, not under mesh/router names
- protocol-aware fields are extracted when Amber can understand them: JSON-RPC method/id, MCP tool/progress fields, SSE event ids, and so on

## API checks

List the resources the tutorial should create:

```sh
curl -sS http://127.0.0.1:18888/api/telemetry/resources | jq .
```

Show the `public` edge story:

```sh
curl -sS 'http://127.0.0.1:18888/api/telemetry/logs?resource=amber.amberdemo.bindings&limit=500' \
  | jq -r '
      .data.resourceLogs[]?.scopeLogs[]?.logRecords[]?
      | [
          ([.attributes[]? | select(.key == "event") | .value.stringValue][0] // ""),
          (.body.stringValue // ""),
          (.traceId // "")
        ]
      | @tsv' \
  | rg 'public|host-export'
```

Show the internal client/server binding story:

```sh
curl -sS 'http://127.0.0.1:18888/api/telemetry/traces?resource=amber.amberdemo.bindings&limit=200' \
  | jq -r '
      .data.resourceSpans[]?.scopeSpans[]?.spans[]?
      | select((.attributes[]? | select(.key == "amber_edge_ref") | .value.stringValue) == "/client.client_server_api")
      | [.traceId, .name, ([.events[]?.name] | join(" | "))]
      | @tsv'
```

## Cleanup

```sh
COMPOSE_PROJECT_NAME=amberdemo docker compose -f examples/observability-debug/amber-observability-debug.yaml down -v
docker rm -f amber-dashboard >/dev/null 2>&1 || true
pkill -f 'upstream-sse.py --port 38081' >/dev/null 2>&1 || true
pkill -f 'amber proxy examples/observability-debug/amber-observability-debug.yaml' >/dev/null 2>&1 || true
```
