# Amber

Amber is a compiler and runner for systems built from many small parts: agents, model gateways,
web apps, tool servers, evaluators, environments, and sandboxes. You describe the parts once,
connect them explicitly, and Amber can run the system locally across multiple runtimes or compile
it into artifacts you can inspect and ship.

Amber is most useful once a project stops fitting in one process. It does not replace your agent
framework or your orchestrator. It handles the layer around them: how parts are connected, what is
allowed to talk to what, what stays outside the system, and how the same setup moves from a laptop
to something more reproducible.

## Use Amber when

- one system spans more than one runtime
- you want a local executable, a container, and a VM to behave like one app
- you want to swap an agent, evaluator, or model gateway without rewriting glue code
- you care which component can reach which service, especially for agentic systems
- you want the same system description to be runnable, inspectable, and shareable

## Start with `amber run`

The main thing to try in Amber today is one system description, one command, and multiple local
runtimes.

Install from npm if you want `amber run` locally:

```sh
npm install -g @rdif/amber@^0.3
amber --help
```

For zero-install `check`, `compile`, or `docs`, use the Dockerized CLI:

```sh
docker run --rm -v "$PWD":/work -w /work ghcr.io/rdi-foundation/amber-cli:v0.3 --help
```

If you are working on Amber itself:

```sh
cargo build -q -p amber-cli
./target/debug/amber --help
```

The quickest first run is [`examples/mixed-site`](examples/mixed-site/README.md). It runs one app
across two local runtimes:

- `web` runs as a local process
- `api` runs in Docker Compose
- `catalog_api` stays outside Amber and is attached at run time

In one terminal:

```sh
cd examples/mixed-site
python3 mock-catalog.py
```

In another:

```sh
cd examples/mixed-site
amber run .
```

On a first interactive run, Amber may read an existing `.env`, prompt for missing config values,
prompt for the external catalog URL, start the local process and Compose service, and print the
localhost URLs for the entrypoints the system exposes.

Example:

```text
Ready.
  app  http://127.0.0.1:18080
  api  http://127.0.0.1:18081
```

Then call it:

```sh
curl http://127.0.0.1:18080/
curl http://127.0.0.1:18080/chain
curl http://127.0.0.1:18081/debug
```

That example shows the default Amber loop:

- one app can span multiple runtimes
- config still comes from outside the app
- outside services can stay outside the app
- Amber gives you stable localhost entrypoints for what the app chooses to expose

For background runs and persisted logs, `amber run --detach`, `amber ps`, `amber logs`, and
`amber stop` give you a managed local workflow without requiring generated artifacts.

## Core ideas

Amber is easier to read once a few terms are clear.

**Manifest**  
An Amber manifest is a description of one part of the system.

**Component**  
A component is one reusable part. It might be a runnable workload, or a parent that contains other
components.

**Capability**  
A capability is a named interface a component offers, such as HTTP, MCP, A2A, LLM, or storage.

**Slot**  
A slot is a named dependency a component expects its parent to supply.

**Binding**  
A binding is a declared connection from one component's capability to another component's slot.

**Export**  
An export is a capability the parent chooses to expose outside the system.

**Site**  
A site is one runtime environment, such as the direct local runtime, Docker Compose, a VM runtime,
or Kubernetes.

**Scenario**  
A scenario is the fully linked system after Amber resolves and validates the whole manifest tree.

The important design choice is that wiring belongs to the parent. A child says what it needs and
what it offers; it does not hardcode where dependencies come from. That is what makes components
reusable.

## Why the capability model matters

A lot of agent systems end up with too much ambient authority. A tool runner can reach whatever is
on localhost. A helper service can guess ports. A component can accidentally depend on something
that happens to be nearby instead of something it was deliberately given.

Amber pushes in the other direction.

- A component can only use a named dependency if it declares a slot for it and the parent binds
  something into that slot.
- A capability can be available to another component without automatically being available to the
  host. Host-visible entrypoints are explicit exports.
- The resulting reachability is visible in the system description instead of being spread across ad
  hoc port conventions, shell scripts, and environment files.

That matters for ordinary software, and it matters even more for agents. If an agent or tool gets
tricked into doing something destructive, the blast radius should depend on the connections it was
given, not on whatever it can discover by poking around the machine.

Amber does not replace application-level auth, review, or careful tool design. What it does give
you is a concrete reachability model that is easier to inspect, test, and reason about.

The clearest example in this repo is [`examples/direct-security`](examples/direct-security/README.md):
`allowed` is given access to a secret service and succeeds; `denied` is not, and tries to guess the
secret's TCP port anyway. On Linux direct runs, that bypass is blocked.

[`examples/vm-network-storage`](examples/vm-network-storage/README.md) shows the same idea in a VM
setting: the bound VM can reach the API it was given, and the unbound VM stays blocked.

## How Amber works

At a high level, Amber does four things.

1. **You describe the parts and their edges.**  
   Each part says how it runs, what it offers, and what it needs.

2. **Amber resolves and validates the graph.**  
   It follows child manifests, checks that bindings make sense, and turns the authored tree into
   one linked system.

3. **Amber places runnable parts into sites.**  
   For local runs, Amber already has sensible defaults: local executables go to the direct runtime,
   container images go to Docker Compose, and VM workloads go to the VM runtime. When you want
   explicit control, you add a placement file.

4. **Amber runs or compiles the result.**  
   `amber run` starts the sites, wires cross-site links, attaches outside services, and exposes
   selected entrypoints on localhost. `amber compile` emits inspectable artifacts when you want
   them.

Start with `amber run`; use `amber compile` when you want explicit artifacts, custom placement, or
more control over how the system is launched.

## Things to try

- **Mixed local development across runtimes**  
  [`examples/mixed-site`](examples/mixed-site/README.md) keeps the whole boundary small and easy to
  inspect.

- **External services that stay external**  
  [`examples/externalized-slots`](examples/externalized-slots/README.md) and
  [`examples/slot-forwarding`](examples/slot-forwarding/README.md) show how to attach host or
  remote services at run time instead of baking them into the system.

- **Agent, evaluator, and model-router stacks**  
  [`examples/tau2`](examples/tau2/README.md) wires an environment, evaluator, agent, and
  LiteLLM-backed routes into one graph.

- **Capability-driven security demos**  
  [`examples/direct-security`](examples/direct-security/README.md) and
  [`examples/vm-network-storage`](examples/vm-network-storage/README.md) are the best places to
  see explicit reachability and isolation in practice.

- **Observability by graph edge**  
  [`examples/observability-debug`](examples/observability-debug/README.md) shows logs and telemetry
  in terms of the user-facing connections in the scenario, not just container names.

## Common commands

Most people will spend most of their time in `amber run`:

```sh
amber run .
amber run path/to/root
amber run path/to/root --detach
amber ps
amber logs <run-id>
amber stop <run-id>
```

Use `amber check` when you want validation without starting anything:

```sh
amber check path/to/root
```

Use `amber compile` when you want explicit artifacts:

```sh
amber compile path/to/root --run-plan /tmp/amber-run-plan.json
amber compile path/to/root --docker-compose /tmp/amber-compose
amber compile path/to/root --kubernetes /tmp/amber-k8s
amber compile path/to/root --direct /tmp/amber-direct
amber compile path/to/root --vm /tmp/amber-vm
amber compile path/to/root --bundle /tmp/amber-bundle
```

Use `amber proxy` when you already have compiled output and want to bridge exports or outside
services yourself:

```sh
amber proxy /tmp/amber-compose --export public=127.0.0.1:18080
amber proxy /tmp/amber-compose \
  --slot ext_api=127.0.0.1:38081 \
  --export public=127.0.0.1:38080
```

## Local runtime notes

- Direct local execution needs a sandbox backend:
  - Linux: `bwrap` and `slirp4netns`
  - macOS: `/usr/bin/sandbox-exec`
- VM execution also needs local QEMU tooling.
- The mixed-site example uses Docker Compose because one component is a container image.

## Learn more

- `amber docs manifest` — detailed authoring reference
- `amber docs examples` — list embedded examples
- `amber docs examples <example>` — dump one embedded example from the CLI
- [`examples/`](examples/) — end-to-end scenarios in this repo
- [`compiler/manifest/README.md`](compiler/manifest/README.md) — full manifest reference
- [`examples/mixed-site/README.md`](examples/mixed-site/README.md) — best first walkthrough

If you arrive here from a search result and only try one thing, start with
[`examples/mixed-site`](examples/mixed-site/README.md) and run `amber run .`.

