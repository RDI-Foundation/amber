# Slot forwarding

This scenario exports `api` at the root, but the export is actually served by
`/router/consumer.public` through router-level forwarding.

The workflow here is: run the scenario, then use `amber proxy --export <name=addr>` to expose
the scenario export on localhost.

## Prereq images (local dev)

The manifests reference `example/root:v1` and `example/consumer:v1`. For local runs, alias them to
`busybox:1.36`:

```sh
docker pull busybox:1.36
docker tag busybox:1.36 example/root:v1
docker tag busybox:1.36 example/consumer:v1
```

## Docker Compose loop

1. Compile and start:

```sh
amber compile examples/slot-forwarding/scenario.json5 \
  --docker-compose /tmp/amber-slot-forwarding.yaml
docker compose -f /tmp/amber-slot-forwarding.yaml up -d
```

`amber proxy` auto-discovers router control from compile metadata.
For Compose output this uses a project-scoped named volume that carries the router control socket.

2. Start an HTTP server inside `c2-consumer` so the exported path has a concrete responder:

```sh
docker compose -f /tmp/amber-slot-forwarding.yaml exec -d c2-consumer \
  sh -lc 'httpd -f -p 9000'
```

3. In another terminal, run the export proxy:

```sh
amber proxy /tmp/amber-slot-forwarding.yaml \
  --export api=127.0.0.1:18080
```

4. Verify:

```sh
curl -i http://127.0.0.1:18080
```

You should see an HTTP response from the `c2-consumer` HTTP server through Amber routing.
The default `busybox httpd` content may be `404` at `/`; any HTTP response here confirms routing.

### Multiple local copies

If you run the same compose file with `-p`, pass the same `COMPOSE_PROJECT_NAME` when running
`amber proxy`:

```sh
docker compose -p amber-slot-forwarding-a -f /tmp/amber-slot-forwarding.yaml up -d
COMPOSE_PROJECT_NAME=amber-slot-forwarding-a \
  amber proxy /tmp/amber-slot-forwarding.yaml --export api=127.0.0.1:18080
```

You can run multiple proxy processes at once; each gets its own mesh identity.

## Kubernetes loop (kind-compatible)

1. Load local images into kind (if using kind):

```sh
kind load docker-image example/root:v1 example/consumer:v1
```

2. Compile and apply:

```sh
amber compile examples/slot-forwarding/scenario.json5 \
  --disable-networkpolicy-check \
  --kubernetes /tmp/amber-slot-forwarding
NS=$(awk '/name: scenario-/{print $2; exit}' /tmp/amber-slot-forwarding/00-namespace.yaml)
kubectl apply -k /tmp/amber-slot-forwarding
kubectl -n "$NS" rollout status deploy/amber-router
kubectl -n "$NS" rollout status deploy/c2-consumer
```

3. Start an HTTP server in the consumer main container:

```sh
CONSUMER_POD=$(kubectl -n "$NS" get pod -l amber.io/component=c2-consumer -o jsonpath='{.items[0].metadata.name}')
kubectl -n "$NS" exec "$CONSUMER_POD" -c main -- \
  sh -lc 'nohup httpd -f -p 9000 >/tmp/httpd.log 2>&1 &'
```

4. Create a shared env file with free local ports (so multiple scenarios can run side-by-side
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

cat > /tmp/amber-slot-forwarding.k8s.env <<EOF
ROUTER_MESH_LOCAL_PORT=$(pick_free_port)
ROUTER_CONTROL_LOCAL_PORT=$(pick_free_port)
PROXY_EXPORT_LOCAL_PORT=$(pick_free_port)
EOF
```

5. Port-forward router mesh + control in a dedicated terminal (keep it running):

```sh
source /tmp/amber-slot-forwarding.k8s.env
kubectl -n "$NS" port-forward deploy/amber-router \
  "${ROUTER_MESH_LOCAL_PORT}:24000" \
  "${ROUTER_CONTROL_LOCAL_PORT}:24100"
```

6. In another terminal, run the export proxy:

```sh
source /tmp/amber-slot-forwarding.k8s.env
amber proxy /tmp/amber-slot-forwarding \
  --export api="127.0.0.1:${PROXY_EXPORT_LOCAL_PORT}" \
  --router-addr "127.0.0.1:${ROUTER_MESH_LOCAL_PORT}" \
  --router-control-addr "127.0.0.1:${ROUTER_CONTROL_LOCAL_PORT}"
```

Why both addresses are needed:
- `--router-addr` is the local port-forward endpoint for router mesh traffic.
- `--router-control-addr` is the local port-forward endpoint for router control APIs.

7. Verify:

```sh
source /tmp/amber-slot-forwarding.k8s.env
curl -i "http://127.0.0.1:${PROXY_EXPORT_LOCAL_PORT}"
```
