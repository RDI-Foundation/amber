# Externalized slots

This example shows how a root slot becomes externalized when it is left unbound and every binding
that uses it is marked `weak: true`.

## Docker Compose

1) Start any HTTP server outside the scenario (for example):

```sh
python3 -m http.server 8081
```

2) Compile to Docker Compose:

```sh
amber compile examples/externalized-slots/scenario.json5 --docker-compose /tmp/amber-external.yaml
```

3) Run and provide the external slot URL (reachable from inside the containers):

```sh
AMBER_EXTERNAL_SLOT_API_URL=http://host.docker.internal:8081 \
  docker compose -f /tmp/amber-external.yaml up
```

## Kubernetes

1) Compile to Kubernetes:

```sh
amber compile examples/externalized-slots/scenario.json5 --kubernetes /tmp/amber-external
```

2) Edit the generated `router-external.env` and set the external slot URL:

```sh
echo "AMBER_EXTERNAL_SLOT_API_URL=http://your-host-or-service:8081" >> /tmp/amber-external/router-external.env
```

3) Apply the kustomization:

```sh
kubectl apply -k /tmp/amber-external
```
