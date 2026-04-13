# Observability Debug Tutorial

This example is for reading a scenario the way a user experiences it.

The scenario has two components and one external upstream:

- `public -> /server`
- `/client.server_api -> /server.api`
- `/client.ext_api -> external.ext_api`

The important output is Amber's interaction trace stream. `amber run`, `amber attach`, and
`amber logs` render that stream for humans, and the same data is persisted for tooling in
`observability/events.ndjson` under the run root.

## Prereqs

- Docker + Docker Compose v2
- `amber` CLI on `PATH`
- `python3` on the host

## 1) Start the local upstream

```sh
python3 examples/observability-debug/upstream-sse.py --port 38081
```

## 2) Start Amber

Run the scenario in the foreground:

```sh
cd examples/observability-debug
amber run .
```

When Amber prompts for the `ext_api` slot, provide:

```text
http://127.0.0.1:38081
```

Amber prints the run id, run root, exported localhost URLs, and then tails the interaction stream.

If you prefer a managed background run:

```sh
cd examples/observability-debug
amber run . --detach
amber attach <run-id>
```

`amber ps` lists active runs, `amber logs <run-id>` replays the persisted interaction story, and
the run root contains `observability/events.ndjson` for machine tooling.

If you are validating local runtime image changes, set `AMBER_DEV_IMAGE_TAGS` before `amber run`.
For router-only changes, `router=<tag>` is usually enough. If you changed provisioning or generated
mesh metadata too, also include `provisioner=<tag>`.

## 3) Generate host traffic

In another terminal, use the `public` URL printed by Amber:

```sh
curl -sS \
  -H 'x-amber-tutorial: host-export' \
  http://127.0.0.1:<public-port>/rpc
```

Expected response:

```json
{"jsonrpc":"2.0","id":"server-static","method":"tools/list","result":{"source":"server","ok":true}}
```

The `client` also generates traffic in a loop, so the interaction stream should cover all three
manifest-level stories.

## 4) Read the interaction story

Look for these edges:

- `public`
- `/client.server_api -> /server.api`
- `/client.ext_api -> external.ext_api`

You should see protocol-aware lines such as:

- `get agent card`
- `list tools`
- `call tool ...`
- `progress update`

Useful things to verify:

- related events share a trace id
- the renderer uses scenario edges and components instead of mesh/router internals
- request, response, and stream phases are still visible, but secondary to the semantic action

If you started the run detached, `amber logs <run-id>` shows the same interaction stream from the
persisted `events.ndjson` file.

## Cleanup

For a foreground run, press `Ctrl-C` in the `amber run` terminal.

For a detached run:

```sh
amber stop <run-id>
```

Then stop the upstream process if it is still running.
