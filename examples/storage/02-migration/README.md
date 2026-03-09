<!-- amber-docs
summary: Preserve storage while refactoring the scenario so the storage sink moves behind a new intermediate component.
-->

# Storage migration

This example covers the storage migration case that is harder than a simple redeploy:
the component graph changes, but the stored bytes should still follow the same logical
storage resource.

The important constraint in Amber today is that storage identity comes from the resource
owner path plus the resource name. This example is built to show the structural change
that Amber can preserve today:

- the root keeps owning `resources.app_state`
- the resource name stays `app_state`
- the component that mounts storage moves
- a new intermediate component is introduced

That means the runtime structure changes, but the storage identity does not.

## What changes between v1 and v2

`scenario.json5` is the v1 shape:

- root owns `resources.app_state`
- root routes it directly to `#app.state`
- root exports `#app.http`

`scenario-v2.json5` is the migrated shape:

- root still owns `resources.app_state`
- root now routes it to `#stack.state`
- `stack-v2.json5` forwards that slot to its child `#api.state`
- root exports `#stack.http`

So the storage sink moves from `/app` to `/stack/api`, but the resource itself stays rooted
at the same place.

## Why this is realistic

This is the common refactor where a single storage-owning component becomes a small subtree:

- a monolith becomes a wrapper plus a storage-backed API
- a direct child becomes a nested child
- exports are rethreaded through a new intermediate component

What this does **not** demonstrate is renaming the resource owner or renaming the resource.
Amber does not have an explicit manifest-level storage migration mechanism for those cases yet.

Amber currently makes storage resources implicit. There is no separate `from: "framework.storage"`
field in the manifest syntax yet. Declaring `resources.app_state: { kind: "storage", ... }` is the
allocation step.

For a simple single-component service, Amber can now mount `resources.<name>` directly in the
program. This example intentionally keeps the routed form because the parent owner path is the
identity that must survive the v1 to v2 refactor.

## Files

- `scenario.json5`: v1 root scenario
- `scenario-v2.json5`: v2 root scenario after the structural refactor
- `service.json5`: storage-backed HTTP service used in both versions
- `stack-v2.json5`: new intermediate component introduced in v2

## Docker Compose walkthrough

1. Compile and start v1:

```sh
amber compile examples/storage/02-migration/scenario.json5 --docker-compose /tmp/amber-storage-migration-compose
cd /tmp/amber-storage-migration-compose
docker compose up -d
amber proxy . --export http=127.0.0.1:18080
```

2. Verify v1 and write state through the export:

```sh
curl -fsS http://127.0.0.1:18080/version; echo
curl -fsS http://127.0.0.1:18080/state; echo
curl -fsS -X PUT --data-binary 'remembered through migration' http://127.0.0.1:18080/state; echo
docker compose down
```

3. Compile the migrated v2 scenario into the same output directory and bring it back:

```sh
amber compile examples/storage/02-migration/scenario-v2.json5 --docker-compose /tmp/amber-storage-migration-compose
cd /tmp/amber-storage-migration-compose
docker compose up -d
amber proxy . --export http=127.0.0.1:18080
curl -fsS http://127.0.0.1:18080/version; echo
curl -fsS http://127.0.0.1:18080/state; echo
```

You should now see:

- `v2` from `/version`
- `remembered through migration` from `/state`

That proves the storage resource survived the structural refactor.

4. Remove everything, including the stored data:

```sh
docker compose down -v
```

## Kubernetes walkthrough

Use a stable namespace so the PVC identity survives recompiles.

1. Compile and deploy v1:

```sh
amber compile examples/storage/02-migration/scenario.json5 --kubernetes /tmp/amber-storage-migration-k8s
cd /tmp/amber-storage-migration-k8s
$EDITOR kustomization.yaml
kubectl create namespace amber-storage-migration
kubectl apply -k /tmp/amber-storage-migration-k8s
kubectl -n amber-storage-migration rollout status deploy/amber-router
kubectl -n amber-storage-migration rollout status deploy/c1-app
kubectl -n amber-storage-migration port-forward deploy/amber-router 24000:24000 24100:24100
```

Set `namespace:` in `kustomization.yaml` to `amber-storage-migration` before the apply.

2. In another terminal, run:

```sh
cd /tmp/amber-storage-migration-k8s
amber proxy . \
  --export http=127.0.0.1:18080 \
  --router-addr 127.0.0.1:24000 \
  --router-control-addr 127.0.0.1:24100
```

3. Verify v1 and write state:

```sh
curl -fsS http://127.0.0.1:18080/version; echo
curl -fsS http://127.0.0.1:18080/state; echo
curl -fsS -X PUT --data-binary 'remembered through migration' http://127.0.0.1:18080/state; echo
```

Stop the `kubectl port-forward` and `amber proxy` processes before continuing.

This migration removes the old v1 workload from the graph. Plain `kubectl apply -k`
does not prune removed objects, so delete the retired v1 workload objects but keep
the namespace and PVC:

```sh
kubectl -n amber-storage-migration delete deploy,service,networkpolicy -l amber.io/component=c1-app
```

4. Compile the migrated v2 scenario into the same output directory, set the same namespace again,
and redeploy:

```sh
amber compile examples/storage/02-migration/scenario-v2.json5 --kubernetes /tmp/amber-storage-migration-k8s
cd /tmp/amber-storage-migration-k8s
$EDITOR kustomization.yaml
kubectl apply -k /tmp/amber-storage-migration-k8s
kubectl -n amber-storage-migration rollout status deploy/amber-router
kubectl -n amber-storage-migration rollout status deploy/c2-api
kubectl -n amber-storage-migration port-forward deploy/amber-router 24000:24000 24100:24100
amber proxy . \
  --export http=127.0.0.1:18080 \
  --router-addr 127.0.0.1:24000 \
  --router-control-addr 127.0.0.1:24100
curl -fsS http://127.0.0.1:18080/version; echo
curl -fsS http://127.0.0.1:18080/state; echo
```

You should now see:

- `v2` from `/version`
- `remembered through migration` from `/state`

That proves the same PVC-backed storage resource survived the structural refactor.

5. Destroy everything cleanly:

```sh
kubectl delete namespace amber-storage-migration
```
