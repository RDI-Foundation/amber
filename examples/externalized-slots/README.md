# Externalized slots

This scenario has a required external HTTP slot (`api`) and one exported HTTP capability
(`public`). It is the canonical local-dev workflow for wiring both directions with one
`amber proxy` process.

## Docker Compose loop

1. Start a local upstream service (slot target):

```sh
python3 -m http.server 8081
```

2. Compile and run the scenario:

```sh
amber compile examples/externalized-slots/scenario.json5 \
  --docker-compose /tmp/amber-external.yaml
docker compose -f /tmp/amber-external.yaml up -d
```

Router control is resolved automatically by `amber proxy` from compile metadata.
For Compose output, this is a project-scoped named volume that carries the router control socket.
A single `amber proxy` process uses one mesh identity across all bindings.

3. In another terminal, bind the slot and expose the export:

```sh
amber proxy /tmp/amber-external.yaml \
  --slot api=127.0.0.1:8081 \
  --export public=127.0.0.1:18080
```

4. Verify slot traffic:

```sh
docker compose -f /tmp/amber-external.yaml logs -f c0-component
```

You should see repeated calls from the root component to your local server.

5. Verify export traffic:

```sh
curl -i http://127.0.0.1:18080
```

The sample server may return `404` for `/`; that still confirms routing works if you get an
HTTP response from the proxy.

### Multiple local copies

If you run the same compose file with an explicit project name, pass the same
`COMPOSE_PROJECT_NAME` to `amber proxy` so it resolves the matching control socket:

```sh
docker compose -p amber-external-a -f /tmp/amber-external.yaml up -d
COMPOSE_PROJECT_NAME=amber-external-a \
  amber proxy /tmp/amber-external.yaml \
    --slot api=127.0.0.1:8081 \
    --export public=127.0.0.1:18080
```

You can run multiple `amber proxy` processes against one scenario. Each proxy process gets its own
mesh identity.

## Kubernetes loop

Compile and apply:

```sh
amber compile examples/externalized-slots/scenario.json5 \
  --disable-networkpolicy-check \
  --kubernetes /tmp/amber-external
NS=$(awk '/name: scenario-/{print $2; exit}' /tmp/amber-external/00-namespace.yaml)
kubectl apply -k /tmp/amber-external
kubectl -n "$NS" rollout status deploy/amber-router
kubectl -n "$NS" rollout status deploy/c0-component
```

Start your local upstream server:

```sh
python3 -m http.server 8081
```

Create a shared env file with free local ports (so multiple scenarios can run side-by-side
without collisions):

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

The env file now contains:
- `ROUTER_MESH_LOCAL_PORT`: local port where `amber proxy` reaches router mesh traffic.
- `ROUTER_CONTROL_LOCAL_PORT`: local port where `amber proxy` reaches router control APIs.
- `PROXY_MESH_LOCAL_PORT`: local port where router mesh traffic reaches `amber proxy`.
- `PROXY_EXPORT_LOCAL_PORT`: local port where host clients reach the exported capability.

Port-forward router mesh and control in a dedicated terminal (keep it running):

```sh
source /tmp/amber-external.k8s.env
kubectl -n "$NS" port-forward deploy/amber-router \
  "${ROUTER_MESH_LOCAL_PORT}:24000" \
  "${ROUTER_CONTROL_LOCAL_PORT}:24100"
```

In another terminal, run one proxy command for both mappings:

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

Why all three addresses are needed:
- `--router-addr` and `--router-control-addr` tell `amber proxy` how to reach the
  router through local `kubectl port-forward`.
- `--mesh-addr` tells the router pod how to reach `amber proxy` for external slot traffic.
  This must be routable from inside the cluster.

Verify:

```sh
source /tmp/amber-external.k8s.env
kubectl -n "$NS" logs -f deploy/c0-component -c main
curl -i "http://127.0.0.1:${PROXY_EXPORT_LOCAL_PORT}"
```
