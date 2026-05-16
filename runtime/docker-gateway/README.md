# Amber Docker Gateway

Amber Docker Gateway is the Docker Engine policy layer used by Amber router sidecars for
`framework.docker` capabilities. It is a Rust library, not a standalone network service: the
router accepts a Noise-authenticated mesh stream, uses the authenticated mesh peer id as the caller
identity, and hands the raw TCP stream to the gateway handler.

There is deliberately no source-IP, source-port, or caller-supplied-header authentication path.
All Amber component communication to the gateway travels over the mesh. The host Docker socket is
mounted only into the injected gateway sidecar, and the socket peer address is not part of the
authorization model.

## What It Does

- Uses the mesh peer id supplied by the router as the owning component identity.
- Injects ownership labels and `com.docker.compose.project` on create so Compose can clean up
  resources with `--remove-orphans`.
- Enforces per-component scoping: only the owning component can inspect, modify, exec, or delete
  its containers, networks, and volumes.
- Blocks endpoints that cannot be scoped safely.
- Forwards allowed requests to the upstream Docker daemon over a Unix socket.
- Supports HTTP upgrade/hijack for Docker exec and attach flows.

## Configuration

The router creates `DockerGatewayRuntime` from:

```json
{
  "docker_sock": "/var/run/docker.sock",
  "compose_project": "amber-scenario-123"
}
```

`docker_sock` is the Docker daemon Unix socket inside the sidecar. `compose_project` is the
scenario's Docker Compose project name and is used for Docker resource scoping.

## Labels and Scoping

On create, the gateway injects these labels:

- `amber.component`
- `amber.project`
- `com.docker.compose.project`

The Amber labels enforce ownership. The Compose project label keeps resources created through the
gateway in the scenario's Compose project so normal Compose teardown removes them.

## Allowed API Surface

The gateway is default-deny. It only allows endpoints that can be scoped safely:

- `/containers/create`, `/networks/create`, `/volumes/create`
- `/images/{name}/json`
- Container-scoped endpoints after ownership checks
- Exec endpoints after mapping exec ID to container ownership
- List/prune endpoints with label filters injected:
  - `/containers/json`, `/events`, `/containers/prune`
  - `/networks`, `/networks/prune`
  - `/volumes`, `/volumes/prune`

Explicitly blocked:

- `/networks/{id}/connect` and `/disconnect`
- Any other endpoint that cannot be scoped to a single component
