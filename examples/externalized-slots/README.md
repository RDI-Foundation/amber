# Externalized slots

This example shows the most common local-dev workflow: run a scenario and plug in a local HTTP
service for an external slot. The root program reads `${slots.api.url}` (the external `api` slot),
and it also exports an HTTP capability named `public`.

## Docker Compose

1. Start your local component (any HTTP server on your host):

```sh
python3 -m http.server 8081
```

2. Compile the scenario to Docker Compose:

```sh
amber compile examples/externalized-slots/scenario.json5 \
  --docker-compose /tmp/amber-external.yaml
```

3. Run the scenario:

```sh
docker compose -f /tmp/amber-external.yaml up
```

4. In another terminal, bridge your local server into the scenario:

```sh
amber proxy /tmp/amber-external.yaml --slot api --upstream 127.0.0.1:8081
```

`amber proxy` reads the `x-amber` metadata from the compose file, registers the slot with the
router over its control port, and starts the mesh proxy.
You can run it before or after `docker compose up`; it will register once the control port is
reachable.
The control port only accepts connections from the host; other containers in the scenario cannot
reach it.

5. Verify the root program is calling your local component:

```sh
docker compose -f /tmp/amber-external.yaml logs -f c0-component
```

## Exported capability (optional)

To expose the scenario's `public` export on your machine:

```sh
amber proxy /tmp/amber-external.yaml --export public --listen 127.0.0.1:18080
```

Then:

```sh
curl http://127.0.0.1:18080
```

## Kubernetes (same flow, different output)

`amber proxy` also accepts Kubernetes output directories and registers with the
router control port:

```sh
amber compile examples/externalized-slots/scenario.json5 --kubernetes /tmp/amber-external
kubectl apply -k /tmp/amber-external
```

Then port-forward the router control port and register the slot:

```sh
kubectl -n <namespace> port-forward deploy/amber-router 24100:24100
amber proxy /tmp/amber-external --slot api --upstream 127.0.0.1:8081
```

Make sure the router can reach your machine (for example via a VPN, port-forward, or NodePort)
if you proxy from outside the cluster. The control port is recorded in
`/tmp/amber-external/amber-proxy.json`.
The control port listens on localhost inside the router pod, so host access requires a
`kubectl port-forward`.
