<!-- amber-docs
summary: Allocate a storage resource, route it into a child, write through an exported binding, and verify that state survives redeploys.
-->

# Storage persistence

This example is meant to answer one practical question: if a child mounts storage, how do you
prove that the data survives a redeploy without reaching into the container?

The answer in Amber is: make the child expose a normal interface, then do the whole exercise
through that declared binding.

This scenario does three things:

- the root scenario allocates `resources.app_state`
- the child declares a storage slot, `slots.state`
- the child mounts that slot at `/var/lib/app`
- the child exports an HTTP interface that lets you read and replace the stored value
- the root scenario routes `resources.app_state` into the child

The important boundary is still the same: the child does not know whether the storage becomes a
Docker volume, a direct-mode state directory, or a Kubernetes PVC. The parent just routes a
storage capability into the slot.

## The Amber model

The child manifest asks for storage and mounts it:

```json5
slots: {
  state: { kind: "storage" },
},
program: {
  mounts: [
    { path: "/var/lib/app", from: "slots.state" },
  ],
}
```

The root scenario allocates durable storage and routes it into the child:

```json5
resources: {
  app_state: {
    kind: "storage",
    params: {
      size: "1Gi",
    },
  },
},
bindings: [
  { to: "#app.state", from: "resources.app_state" },
]
```

That is the storage story. The rest of the example is just there to make the persistence visible
through a real export.

## The child interface

The child app serves three HTTP paths over the exported `http` capability:

- `GET /version` returns the deployment version from component config
- `GET /state` returns the current contents of `/var/lib/app/state.txt`
- `PUT /state` replaces `/var/lib/app/state.txt`

`initial_state` is only used when the storage is empty. That lets you make a small code/config
change between deploys and verify that the new deployment is running without overwriting the old
data.

## What gets compiled

Amber keeps the manifest model the same across backends, but the allocated storage resource
materializes differently:

- Docker Compose: a named volume
- Kubernetes: a PVC mounted by the workload

This walkthrough focuses on Compose and Kubernetes because they are the clearest first-time paths
for this example.

Compile the scenario:

```sh
amber compile examples/storage-persistence/scenario.json5 --docker-compose /tmp/amber-storage-compose
amber compile examples/storage-persistence/scenario.json5 --kubernetes /tmp/amber-storage-k8s
```

Each compiled output includes a generated `README.md`. That file explains the backend-specific
runtime shape. The steps below are the concrete persistence loop for this example.

## Docker Compose walkthrough

1. Start the stack:

```sh
cd /tmp/amber-storage-compose
docker compose up -d
```

2. In another terminal, export the scenario's HTTP binding:

```sh
cd /tmp/amber-storage-compose
amber proxy . --export http=127.0.0.1:18080
```

3. Verify the first deployment and write state through the export:

```sh
curl -fsS http://127.0.0.1:18080/version; echo
curl -fsS http://127.0.0.1:18080/state; echo
curl -fsS -X PUT --data-binary 'remembered from compose v1' http://127.0.0.1:18080/state; echo
docker compose down
```

At this point the containers are gone, but the named volume still exists.

4. Simulate a new deployment by changing the child component config in
`examples/storage-persistence/scenario.json5`:

```json5
config: {
  version: "v2",
  initial_state: "seeded by v2",
},
```

`initial_state` is intentionally different so you can tell whether storage was reused or recreated.

5. Recompile and bring the stack back:

```sh
amber compile examples/storage-persistence/scenario.json5 --docker-compose /tmp/amber-storage-compose
cd /tmp/amber-storage-compose
docker compose up -d
amber proxy . --export http=127.0.0.1:18080
curl -fsS http://127.0.0.1:18080/version; echo
curl -fsS http://127.0.0.1:18080/state; echo
```

Because `docker compose down` removed the router, restart `amber proxy` after the stack comes back
before you check the export again.

You should now see `v2` from `/version`, but `/state` should still return
`remembered from compose v1`.

6. Destroy the runtime and the stored data:

```sh
docker compose down -v
```

If you bring the stack up again after that, `/state` starts over from `initial_state`.

## Kubernetes walkthrough

The Kubernetes output uses a `Deployment` plus an explicit PVC. The rough edge is namespace
handling.

Amber regenerates `kustomization.yaml` on every compile with a fresh disposable namespace. If you
want storage to persist across recompiles, set a stable namespace after every compile and before
every `kubectl apply -k`.

1. Choose a stable namespace and set it in the generated output:

```sh
cd /tmp/amber-storage-k8s
$EDITOR kustomization.yaml
```

Replace the generated `namespace:` value with something stable, for example
`amber-storage-demo`.

2. Create that namespace once and apply the manifests:

```sh
kubectl create namespace amber-storage-demo
kubectl apply -k /tmp/amber-storage-k8s
kubectl -n amber-storage-demo rollout status deploy/amber-router
kubectl -n amber-storage-demo rollout status deploy/c1-app
```

3. In one terminal, run the router port-forward:

```sh
kubectl -n amber-storage-demo port-forward deploy/amber-router 24000:24000 24100:24100
```

4. In another terminal, run `amber proxy`:

```sh
cd /tmp/amber-storage-k8s
amber proxy . \
  --export http=127.0.0.1:18080 \
  --router-addr 127.0.0.1:24000 \
  --router-control-addr 127.0.0.1:24100
```

5. Verify the first deployment and write state through the export:

```sh
curl -fsS http://127.0.0.1:18080/version; echo
curl -fsS http://127.0.0.1:18080/state; echo
curl -fsS -X PUT --data-binary 'remembered from k8s v1' http://127.0.0.1:18080/state; echo
kubectl -n amber-storage-demo delete deploy c1-app amber-router
```

That removes the workloads, but the PVC remains in `amber-storage-demo`.

6. Recompile after changing the component config to `v2`, then set the same namespace again before
you apply:

```sh
amber compile examples/storage-persistence/scenario.json5 --kubernetes /tmp/amber-storage-k8s
cd /tmp/amber-storage-k8s
$EDITOR kustomization.yaml
kubectl apply -k /tmp/amber-storage-k8s
kubectl -n amber-storage-demo rollout status deploy/amber-router
kubectl -n amber-storage-demo rollout status deploy/c1-app
kubectl -n amber-storage-demo port-forward deploy/amber-router 24000:24000 24100:24100
cd /tmp/amber-storage-k8s
amber proxy . \
  --export http=127.0.0.1:18080 \
  --router-addr 127.0.0.1:24000 \
  --router-control-addr 127.0.0.1:24100
curl -fsS http://127.0.0.1:18080/version; echo
curl -fsS http://127.0.0.1:18080/state; echo
```

Because deleting the deployments also deletes the router pod, restart both the port-forward and
`amber proxy` after the redeploy before you check the export again.

You should now see `v2` from `/version`, but `/state` should still return
`remembered from k8s v1`.

7. Destroy everything, including storage:

```sh
kubectl delete namespace amber-storage-demo
```

That is the cleanest path when the namespace is dedicated to this example.

## Direct output

Direct mode is still useful for local development, so this example should stay available there:

```sh
amber compile examples/storage-persistence/scenario.json5 --direct /tmp/amber-storage-direct
cd /tmp/amber-storage-direct
./run.sh --storage-root /tmp/amber-storage-state
```

The issue I hit on macOS was not storage persistence itself. It was path remapping.
This example mounts storage at `/var/lib/app`, and current macOS direct mode cannot bind a host
storage directory into that different in-sandbox path the way Linux direct mode can.
So the runtime rejects this example on macOS today.

## Files

- `scenario.json5`: root scenario that allocates the durable storage resource and sets the child
  version
- `app.json5`: child component that mounts storage and exposes `GET /version`, `GET /state`, and
  `PUT /state`
