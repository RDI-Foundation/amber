<!-- amber-docs
summary: Reproduce DNS resolution failure for components with external HTTP slots on Linux Docker.
-->

# Egress DNS repro

Minimal reproduction of a DNS resolution bug in the Docker Compose target.

A component declares an external HTTP slot (`kind: "http"`). On native Linux
Docker, the component's sidecar is only connected to `amber_mesh`, which has
no external DNS resolution. The component cannot resolve external hostnames
even though it has declared an external dependency via the slot.

On Docker Desktop (macOS/Windows), DNS works because the VM transparently
forwards DNS for all containers regardless of network attachment.

The Kubernetes target handles this correctly: components with external slot
bindings get egress rules to `0.0.0.0/0` including DNS (UDP/TCP 53).

## Reproduce (Docker Compose)

```sh
OUT=/tmp/amber-egress-dns
rm -rf "$OUT"
amber compile examples/egress-dns/scenario.json5 --docker-compose "$OUT"
docker compose -f "$OUT/compose.yaml" up -d
docker compose -f "$OUT/compose.yaml" logs -f
```

On Linux, expect `FAIL nslookup openrouter.ai` in the logs.
On macOS (Docker Desktop), expect `OK nslookup openrouter.ai`.

## Workaround

Add the sidecar to the default Docker network after compilation:

```sh
yq -i '.services.c0-component-net.networks.default = {}' "$OUT/compose.yaml"
```

## Expected fix

The compiler's Docker Compose target should add `default: {}` to the sidecar's
`networks:` block when the component has external slot bindings, mirroring the
Kubernetes target's egress rules.

## Cleanup

```sh
docker compose -f "$OUT/compose.yaml" down -v
```
