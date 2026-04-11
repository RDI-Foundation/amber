<!--
amber-docs
summary: Inspect exact, bounded, and open child templates, create dynamic children through `framework.component`, and provision dynamic capabilities to the new children.
-->
# `framework.component` tutorial

This example keeps everything on the direct runtime and focuses on the supported public control
surface for dynamic children.

The root manifest gives the `admin` component a `framework.component` binding. `admin` can then:

- list authored child templates
- inspect an authored template
- resolve a concrete contract for exact, bounded, or open templates
- create and destroy children under the root realm
- provision its own `http` capability to each new child after the child becomes live
- snapshot the live graph

`framework.component` is available over two transports:

- HTTP under `<CTL_URL>/v1/...`
- MCP at `<CTL_URL>/mcp`

The MCP surface is:

- `amber.v1.framework_component.inspect` handles the read operations
- `amber.v1.framework_component.mutate` handles create and destroy
- `amber://framework-component` and `amber://framework-component/op/{name}` provide on-demand help

The scenario defines three template modes on purpose:

- `exact_worker`: fixed manifest, runtime config still open
- `bounded_worker`: choose one manifest from a frozen allowed set
- `open_worker`: supply any absolute manifest URL at create or resolve time

The worker manifests all require one config field, `label`, export one `http` capability, and
expose a tiny dynamic-capability helper API. That lets the example show two control-plane layers
clearly:

- `GET /v1/templates/{name}` returns the authored partial application
- `POST /v1/templates/{name}/resolve` returns the concrete contract once a manifest is known
- `GET /held` and `POST /materialize` on a created worker let that worker rediscover and use the
  delegated `admin.http` capability it received after creation

## Requirements

- Amber
- Python 3 on the host
- `jq` is optional but useful for reading the JSON in the commands below

## 1) Start the example

```sh
cd examples/framework-component
amber run .
```

Amber prints the exported `admin_http` URL. The example uses `http://127.0.0.1:18080` below, but
use the URL Amber printed if it differs.

Keep `amber run` running in that terminal.

## 2) Inspect the authored templates

In another terminal:

```sh
curl http://127.0.0.1:18080/ | jq
curl http://127.0.0.1:18080/templates | jq
curl http://127.0.0.1:18080/templates/exact_worker | jq
curl http://127.0.0.1:18080/templates/bounded_worker | jq
curl http://127.0.0.1:18080/templates/open_worker | jq
```

Notice what `GET /templates/<name>` does and does not show:

- exact and bounded templates expose authored manifest refs
- the open template exposes only `mode: "open"`
- none of the templates list `config.label` yet, because that field belongs to the concrete worker
  manifest contract rather than the authored partial application

## 3) Resolve concrete contracts

Grab the two frozen manifest URLs from the bounded template:

```sh
BLUE_MANIFEST=$(curl -s http://127.0.0.1:18080/templates/bounded_worker | jq -r '.manifest.manifests[0].url')
GREEN_MANIFEST=$(curl -s http://127.0.0.1:18080/templates/bounded_worker | jq -r '.manifest.manifests[1].url')
```

Now resolve each template mode:

```sh
curl http://127.0.0.1:18080/resolve/exact_worker | jq
curl -G http://127.0.0.1:18080/resolve/bounded_worker --data-urlencode "manifest=$BLUE_MANIFEST" | jq
curl -G http://127.0.0.1:18080/resolve/open_worker --data-urlencode "manifest=$GREEN_MANIFEST" | jq
```

At this point the resolved response includes `config.label` as an open field, because Amber now
knows which concrete worker manifest is being used.

## 4) Create children and provision a capability

Create one child of each template mode:

```sh
curl -G http://127.0.0.1:18080/create/job-exact \
  --data-urlencode 'template=exact_worker' \
  --data-urlencode 'label=hello-from-exact' | jq

curl -G http://127.0.0.1:18080/create/job-bounded \
  --data-urlencode 'template=bounded_worker' \
  --data-urlencode "manifest=$BLUE_MANIFEST" \
  --data-urlencode 'label=hello-from-bounded' | jq

curl -G http://127.0.0.1:18080/create/job-open \
  --data-urlencode 'template=open_worker' \
  --data-urlencode "manifest=$GREEN_MANIFEST" \
  --data-urlencode 'label=hello-from-open' | jq
```

Each successful create response now includes two parts:

- the normal `framework.component` child publication result
- a `provisioned_capability` section showing that the admin component shared its own `http`
  capability to the newly created child as a live delegated grant

Then inspect the live children:

```sh
curl http://127.0.0.1:18080/children | jq
curl http://127.0.0.1:18080/children/job-bounded | jq
curl http://127.0.0.1:18080/snapshot | jq '.scenario.manifest_catalog | keys'
```

`/children/<name>` shows the output handles that `framework.component` published for that child.
This example focuses on the control-plane API, so the admin helper does not proxy the child HTTP
endpoint itself. The snapshot response is much larger than that one `jq` filter suggests; this
example only extracts the frozen manifest catalog keys to keep the walkthrough readable.

Now inspect the delegated capability from the `job-bounded` worker itself. `worker-blue.json5`
uses port `18081`, so that child is listening on `http://127.0.0.1:18081`.

```sh
curl http://127.0.0.1:18081/held | jq

BOUND_HELD_ID=$(curl -s http://127.0.0.1:18081/held | jq -r '.held[] | select(.entry_kind == "delegated_grant") | .held_id')
BOUND_HANDLE=$(curl -s http://127.0.0.1:18081/materialize \
  -H 'content-type: application/json' \
  -d "{\"held_id\":\"$BOUND_HELD_ID\"}" | jq -r '.url')

curl -s http://127.0.0.1:18081/call-url \
  -H 'content-type: application/json' \
  -d "{\"url\":\"$BOUND_HANDLE\",\"suffix\":\"/id\"}"
```

That final call returns `admin`, which proves the new child rediscovered its delegated grant,
materialized it locally, and used the resulting handle to call back into the admin component.

## 5) Destroy the children

```sh
curl -i http://127.0.0.1:18080/destroy/job-open
curl -i http://127.0.0.1:18080/destroy/job-bounded
curl -i http://127.0.0.1:18080/destroy/job-exact
curl http://127.0.0.1:18080/children | jq
```

## Files

- `scenario.json5`: root manifest with one admin component and three dynamic child templates
- `admin.json5`: direct component that receives `framework.component`
- `admin.py`: helper service that exposes friendly tutorial routes and provisions `admin.http` to
  each new child
- `worker-red.json5`, `worker-blue.json5`, `worker-green.json5`: concrete child manifests
- `worker.py`: tiny worker process used by the dynamic children, including `/held` and
  `/materialize` helpers for the delegated capability demo

## Notes

- This is intentionally a control-plane tutorial, not a full app architecture example.
- `framework.component` is the supported public interface for dynamic children.
- The dynamic-capability provisioning in this example happens after the child is live, which is the
  intended split between create-time bindings and post-create capability transfer.
- The worker manifests in this directory use fixed demo ports, so destroy a child before creating
  another copy of the same manifest variant.
