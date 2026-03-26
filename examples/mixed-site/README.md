<!-- amber-docs
summary: Run one app across a direct local process and a Docker Compose service, attach an outside HTTP dependency at run time, and call exported entrypoints on localhost through `amber run`.
-->

# Mixed-site local dev: direct + Compose with one outside service

This example runs one app across two local runtimes:

- `web` runs as a direct process on the host
- `api` runs in Docker Compose

It also keeps one upstream HTTP service outside the Amber scenario so the whole boundary is easy to
see:

- root config comes from outside the app
- one upstream HTTP service stays outside the app
- the app exports named HTTP entrypoints back out to localhost

That gives one compact walkthrough for:

- externalized config
- externalized slots
- externalized exports
- direct local execution
- Compose local execution

## Requirements

- Amber
- Python 3 on the host
- Docker with Compose

## 1) Start the outside service

One thing in this example is intentionally not part of the Amber scenario: a tiny catalog service.

In one terminal:

```sh
cd examples/mixed-site
python3 mock-catalog.py
```

It listens on `http://127.0.0.1:9100`.

Keep that terminal running.

## 2) Run the app

In another terminal:

```sh
cd examples/mixed-site
amber run .
```

On a first interactive run, Amber may:

- read `.env` if one already exists
- prompt for any missing required root config
- prompt for the outside service URL for this run
- start the scenario
- expose the exported entrypoints on localhost
- print the final URLs

Example:

```text
config.tenant: acme-local
config.catalog_token: ********
slot.catalog_api: http://127.0.0.1:9100

Ready.
  app  http://127.0.0.1:18080
  api  http://127.0.0.1:18081

Reuse:
  amber run . --env-file /path/to/generated.env
```

Your addresses may differ.

Keep that terminal running.

## 3) Call it

Use the URLs Amber printed.

With the example values above:

```sh
curl http://127.0.0.1:18080/
curl http://127.0.0.1:18080/chain
curl http://127.0.0.1:18081/debug
```

Expected `/chain` shape:

```json
{
  "site": "direct",
  "api": {
    "site": "compose",
    "tenant": "acme-local",
    "catalog": {
      "source": "external",
      "item": "amber mug"
    }
  }
}
```

That response proves the whole path:

- the request entered through a named exported entrypoint on localhost
- the direct `web` component called the Compose `api` component
- the Compose `api` component called the outside `catalog_api` service you attached at run time

## 4) Reuse the same config later

After a successful interactive start, Amber prints an explicit replay command such as:

```sh
amber run . --env-file .amber-runs/runs/<run-id>/root-config.env
```

That generated env file contains the root config values Amber collected for that run. It does not
replace your own project `.env`; it is just the explicit reuse path Amber gives you immediately.

External slot values are still runtime inputs. If you do not provide them in an existing `.env` or
an explicit `--env-file`, Amber may prompt for them again on the next interactive run.

## 5) Stop the outside service and start it again

While `amber run` is still running, stop `mock-catalog.py` and call `/chain` again:

```sh
curl http://127.0.0.1:18080/chain
```

The app should still answer, but the catalog section should report that the outside service is
unavailable.

Now start `mock-catalog.py` again and repeat the same request. The next request should pick the
outside service back up.

That is why the root binding for `catalog_api` is weak: outside services can come and go while the
scenario stays up.

## How the edges work

This example uses three kinds of outside-facing values.

**Config**  
Values that come from outside the app and are forwarded into components.

**External slots**  
Services that the app calls, but Amber does not start.

**Exports**  
Capabilities that the app exposes back out to the outside world.

The top-level manifest brings those together:

```json5
{
  manifest_version: "0.3.0",

  config_schema: {
    type: "object",
    properties: {
      tenant: { type: "string" },
      catalog_token: { type: "string", secret: true },
    },
    required: ["tenant", "catalog_token"],
    additionalProperties: false,
  },

  slots: {
    catalog_api: { kind: "http" },
  },

  components: {
    web: {
      manifest: "./web.json5",
      config: {
        tenant: "${config.tenant}",
      },
    },
    api: {
      manifest: "./api.json5",
      config: {
        tenant: "${config.tenant}",
        catalog_token: "${config.catalog_token}",
      },
    },
  },

  bindings: [
    { to: "#web.api", from: "#api.http" },
    { to: "#api.catalog_api", from: "slots.catalog_api", weak: true },
  ],

  exports: {
    app: "#web.http",
    api: "#api.http",
  },
}
```

A few details matter here:

- `config_schema` is the part Amber asks for at run time if values are missing
- `slots.catalog_api` is an upstream service that stays outside the app
- `exports` are the named entrypoints Amber makes reachable from outside the app
- the `catalog_api` binding is `weak` because that service is attached at run time rather than
  started as part of the scenario

## Why this is mixed-site without extra site syntax

This example does not assign sites inside the manifest.

It uses Amber's normal local placement rules:

- `web.json5` uses `program.path`, so Amber runs it as a direct local process
- `api.json5` uses `program.image`, so Amber runs it in Docker Compose locally

If you want to inspect or override that layout explicitly, there is also a
`local-placement.json5` in this directory. You do not need it for the default local loop.

## Need explicit control later?

The flow above is the friendly attached interactive path.

If you want explicit control instead:

- use `amber compile` to inspect the run plan or generated artifacts
- use `amber run --detach` for a managed background run
- use `amber proxy` for explicit outside-world wiring

Those are the same concepts with more ceremony, not a different model.
