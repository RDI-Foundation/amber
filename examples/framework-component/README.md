<!--
amber-docs
summary: Inspect exact, bounded, and open child templates and create dynamic children through `framework.component`.
-->
# `framework.component` tutorial

This example keeps everything on the direct runtime and focuses on the supported public control
surface for dynamic children.

The root manifest gives the `admin` component a `framework.component` binding. `admin` can then:

- list authored child templates
- inspect an authored template
- resolve a concrete contract for exact, bounded, or open templates
- create and destroy children under the root realm
- snapshot the live graph

The scenario defines three template modes on purpose:

- `exact_worker`: fixed manifest, runtime config still open
- `bounded_worker`: choose one manifest from a frozen allowed set
- `open_worker`: supply any absolute manifest URL at create or resolve time

The worker manifests all require one config field, `label`, and export one `http` capability. That
lets the example show the API split clearly:

- `GET /v1/templates/{name}` returns the authored partial application
- `POST /v1/templates/{name}/resolve` returns the concrete contract once a manifest is known

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

## 4) Create children

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
- `admin.py`: small helper service that exposes friendly tutorial routes over HTTP
- `worker-red.json5`, `worker-blue.json5`, `worker-green.json5`: concrete child manifests
- `worker.py`: tiny worker process used by the dynamic children

## Notes

- This is intentionally a control-plane tutorial, not a full app architecture example.
- `framework.component` is the supported public interface for dynamic children.
- The worker manifests in this directory use fixed demo ports, so destroy a child before creating
  another copy of the same manifest variant.
