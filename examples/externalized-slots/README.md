# Externalized slots

This example is a single manifest with a root program that imports an external HTTP slot and
exports its own HTTP capability. The root program reads `${slots.api.url}`, so the unbound `api`
slot is treated as an externalized root input.

The program also serves HTTP on port 9000 and exports it as `public`.

## Docker Compose

1) Start any HTTP server on your host (for example):

```sh
python3 -m http.server 8081
```

2) Compile to Docker Compose:

```sh
amber compile examples/externalized-slots/scenario.json5 \
  --docker-compose /tmp/amber-external.yaml
```

3) Run and provide the external slot URL (reachable from inside the containers):

```sh
# macOS/Windows
AMBER_EXTERNAL_SLOT_API_URL=http://host.docker.internal:8081 \
  docker compose -f /tmp/amber-external.yaml up

# Linux
HOST_IP="$(ip route get 1.1.1.1 | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
AMBER_EXTERNAL_SLOT_API_URL="http://$HOST_IP:8081" \
  docker compose -f /tmp/amber-external.yaml up
```

4) Verify the root program is calling the external slot:

```sh
docker compose -f /tmp/amber-external.yaml logs -f c0-component
```

## Kubernetes

1) Compile to Kubernetes:

```sh
amber compile examples/externalized-slots/scenario.json5 --kubernetes /tmp/amber-external
```

2) Set the external slot URL to anything reachable from the cluster (a service DNS
name or public URL both work):

```sh
echo "AMBER_EXTERNAL_SLOT_API_URL=http://your-service-or-host:8081" \
  > /tmp/amber-external/router-external.env
```

3) Apply the kustomization:

```sh
kubectl apply -k /tmp/amber-external
```
