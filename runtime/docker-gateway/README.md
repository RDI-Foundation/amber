# Amber Docker Gateway

Amber Docker Gateway is a small policy layer that sits between Amber components and the host
Docker Engine API. It accepts TCP connections (for example from `uds2tcp`), authenticates callers
based on the peer address, injects Compose and ownership labels on create, and scopes all
operations to the owning component inside the scenario.

The gateway is designed to run as an Amber component injected by the compiler. It behaves like a
normal component container, except that it receives a host `docker.sock` mount.

## What it does

- Authenticates each TCP connection using the peer IP (and optional port) resolved from caller
  host entries in config.
- Injects ownership labels and `com.docker.compose.project` on create so Compose can clean up
  with `--remove-orphans`.
- Enforces per-component scoping: only the owning component can inspect, modify, exec, or delete
  its containers, networks, and volumes.
- Blocks endpoints that cannot be scoped safely (default-deny).
- Forwards all allowed requests to the upstream Docker daemon over a Unix socket using
  `hyperlocal`.
- Supports HTTP upgrade/hijack (exec/attach).

## Configuration

The gateway reads configuration from one of these environment variables:

- `AMBER_DOCKER_GATEWAY_CONFIG_B64` (base64 JSON)
- `AMBER_DOCKER_GATEWAY_CONFIG_JSON` (raw JSON)

Example config:

```json
{
  "listen": "0.0.0.0:23750",
  "docker_sock": "/var/run/docker.sock",
  "compose_project": "amber-scenario-123",
  "callers": [
    {
      "host": "c2-client-net",
      "port": 41732,
      "component": "component-a",
      "compose_service": "c2-client-net"
    }
  ]
}
```

Notes:

- `compose_project` is required. It is the Docker Compose project name for the scenario.
- `callers` is required. Each entry maps a peer `host` (and optional `port`) to a component and
  its Compose service name. The gateway resolves caller hosts periodically and authenticates peers
  by the resolved source IP (plus optional source port).
- If your TCP proxy uses ephemeral source ports, omit `port` and match by resolved IP only.
- Ownership labels are fixed to `amber.component` and `amber.project`.

## Labels and scoping

On create, the gateway injects these labels:

- Ownership labels: `amber.component`, `amber.project`
- Compose project label: `com.docker.compose.project` (normalized to outer scenario project)

These labels are used for two purposes:

1. Compose grouping (`com.docker.compose.project`) so `docker compose --remove-orphans`
   works for resources created through the gateway.
2. Ownership enforcement so only the owning component and scenario project can act on the resource.

## Allowed API surface

The gateway is default-deny. It only allows endpoints that can be scoped safely:

- `/containers/create`, `/networks/create`, `/volumes/create` (labels injected)
- `/images/{name}/json` (read-only image inspect; required by `docker compose up --no-build`)
- Container-scoped endpoints (start/stop/logs/inspect/remove/exec/etc) after ownership check
- Exec endpoints (`/exec/{id}/start`, `/exec/{id}/json`, `/exec/{id}/resize`) after mapping
  exec ID to container ownership
- List/prune endpoints with label filters injected:
  - `/containers/json`, `/events`, `/containers/prune`
  - `/networks`, `/networks/prune`
  - `/volumes`, `/volumes/prune`

Explicitly blocked:

- `/networks/{id}/connect` and `/disconnect`
- Any other endpoint that cannot be scoped to a single component

If you need to allow a specific endpoint, update the policy in the handler to explicitly
authorize it.

## Running locally (example)

```sh
export AMBER_DOCKER_GATEWAY_CONFIG_JSON='{"listen":"0.0.0.0:23750","docker_sock":"/var/run/docker.sock","compose_project":"dev","callers":[{"host":"localhost","component":"dev","compose_service":"dev"}]}'
./target/debug/amber-docker-gateway
```

In production, the component should mount the host Docker socket at `/var/run/docker.sock` and
receive the config via environment variables.
