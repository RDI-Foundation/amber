<!-- amber-docs
summary: Use experimental `framework.docker` bindings and mounts in Docker Compose.
-->

# framework.docker Example (Docker Compose)

This example shows how to use the experimental `framework.docker` capability in Docker Compose.

It demonstrates both forms:

- URL binding form (`${slots.docker.url}`), exposed as `DOCKER_HOST`
- Mount form (`program.mounts` from `framework.docker`), which creates a Docker socket at
  `/var/run/docker.sock` so Docker CLI works with no extra setup

## Files

- `scenario.json5`: root manifest enabling `experimental_features: ["docker"]` and binding
  `framework.docker` to `#worker.docker`, then exporting `#worker.status` as `status`
- `worker.json5`: component that mounts `framework.docker` to `/var/run/docker.sock` and runs
  Docker CLI commands

## Run

From the repository root:

```sh
OUT=/tmp/framework-docker-compose
rm -rf "$OUT"
amber compile examples/framework-docker/scenario.json5 --docker-compose "$OUT"
```

If Docker is not using `/var/run/docker.sock` on your host (common on macOS), set
`AMBER_DOCKER_SOCK` before running compose:

```sh
export AMBER_DOCKER_SOCK="$HOME/.docker/run/docker.sock"
```

Run the scenario:

```sh
docker compose -f "$OUT/compose.yaml" up -d
```

Wait for `c1-worker` to finish and inspect the created container:

```sh
docker compose -f "$OUT/compose.yaml" wait c1-worker
docker inspect amber-framework-docker-demo
```

Tear down and remove orphans (including containers created via `framework.docker`):

```sh
docker compose -f "$OUT/compose.yaml" down -v --remove-orphans
```
