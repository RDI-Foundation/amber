<!-- amber-docs
summary: Bind an external HTTP slot and re-export a public HTTP capability via one proxy.
-->

# Externalized slots

This example shows both directions with one `amber proxy` process:
- external slot ingress (`api`) from scenario -> your local HTTP server
- exported capability egress (`public`) from host -> scenario

Externalized root slots are supplied from outside the scenario via
`amber proxy --slot ...`. Any binding path that depends on such a slot must be weak
overall, because the consumer must tolerate that provider being absent until the proxy
attaches it. In practice, the clearest approach is usually to make the first binding from
`self.<slot>` weak:

```json5
bindings: [
  { to: "#router.api", from: "self.api", weak: true },
  { to: "#client.api", from: "#router.api" },
]
```

Downstream hops do not all need to repeat `weak: true` if a weak binding already exists
upstream. For a fuller multi-hop forwarding example, see `examples/slot-forwarding`.

## Quick start (Docker Compose)

Use three terminals.

If `amber` is not on your `PATH`, replace it with `target/debug/amber`.

1. Terminal A: start a local upstream HTTP service (slot target).

```sh
mkdir -p /tmp/amber-external-upstream
printf 'hello from upstream\n' > /tmp/amber-external-upstream/index.html
cd /tmp/amber-external-upstream
python3 -m http.server 8081 --bind 127.0.0.1
```

Keep this terminal running. You will use its logs to confirm slot traffic.

2. Terminal B: compile and start the scenario.

```sh
OUT=/tmp/amber-external
rm -rf "$OUT"
amber compile examples/externalized-slots/scenario.json5 \
  --docker-compose "$OUT"
docker compose -f "$OUT/compose.yaml" up -d
```

3. Terminal C: run one proxy for both mappings.

```sh
OUT=/tmp/amber-external
amber proxy "$OUT" \
  --slot api=127.0.0.1:8081 \
  --export public=127.0.0.1:18080
```

4. Verify host -> scenario (export path).

```sh
curl -i http://127.0.0.1:18080
```

You should get an HTTP response. A startup `503` for the first request can happen; retry after a
second. `404` for `/` is also fine here and still confirms end-to-end routing.

5. Verify scenario -> host (slot path).

In Terminal A, you should see repeated lines like:

```text
"GET / HTTP/1.1" 200 -
```

That confirms the component is calling your local upstream through the externalized slot.

## Cleanup

```sh
OUT=/tmp/amber-external
docker compose -f "$OUT/compose.yaml" down -v
```

Stop Terminal A and Terminal C with `Ctrl-C`.

## Troubleshooting

- `address already in use`: change `8081` and/or `18080` consistently in commands above.
- If you run Compose with `-p <name>`, pass the same project name to `amber proxy`:

```sh
OUT=/tmp/amber-external
docker compose -p amber-external-a -f "$OUT/compose.yaml" up -d
amber proxy "$OUT" \
  --project-name amber-external-a \
  --slot api=127.0.0.1:8081 \
  --export public=127.0.0.1:18080
```

## Kubernetes (advanced)

Compile and apply:

```sh
amber compile examples/externalized-slots/scenario.json5 \
  --kubernetes /tmp/amber-external
NS=$(awk '/^namespace:/{print $2; exit}' /tmp/amber-external/kustomization.yaml)
kubectl apply -k /tmp/amber-external
kubectl -n "$NS" rollout status deploy/amber-router
kubectl -n "$NS" rollout status deploy/c0-component
```

Start the same local upstream server as in the Compose section:

```sh
python3 -m http.server 8081 --bind 127.0.0.1
```

Pick free local ports and save them:

```sh
pick_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

cat > /tmp/amber-external.k8s.env <<EOF
ROUTER_MESH_LOCAL_PORT=$(pick_free_port)
ROUTER_CONTROL_LOCAL_PORT=$(pick_free_port)
PROXY_MESH_LOCAL_PORT=$(pick_free_port)
PROXY_EXPORT_LOCAL_PORT=$(pick_free_port)
EOF
```

Terminal B (keep running): port-forward router mesh + control.

```sh
source /tmp/amber-external.k8s.env
kubectl -n "$NS" port-forward deploy/amber-router \
  "${ROUTER_MESH_LOCAL_PORT}:24000" \
  "${ROUTER_CONTROL_LOCAL_PORT}:24100"
```

Terminal C: run proxy.

```sh
source /tmp/amber-external.k8s.env
MESH_HOST=host.docker.internal
# Linux kind usually needs the node gateway instead:
# MESH_HOST=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' kind-control-plane)

amber proxy /tmp/amber-external \
  --slot api=127.0.0.1:8081 \
  --export public="127.0.0.1:${PROXY_EXPORT_LOCAL_PORT}" \
  --mesh-addr "${MESH_HOST}:${PROXY_MESH_LOCAL_PORT}" \
  --router-addr "127.0.0.1:${ROUTER_MESH_LOCAL_PORT}" \
  --router-control-addr "127.0.0.1:${ROUTER_CONTROL_LOCAL_PORT}"
```

Verify:

```sh
source /tmp/amber-external.k8s.env
curl -i "http://127.0.0.1:${PROXY_EXPORT_LOCAL_PORT}"
kubectl -n "$NS" logs -f deploy/c0-component -c main
```

As with Compose, brief startup `503` responses are expected until proxy wiring is ready.
