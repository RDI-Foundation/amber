# Target UX for `amber run` in mixed-site local development

This document is for engineers implementing the next iteration of `amber run`.

It has three jobs:

1. Define the product behavior we want.
2. Capture the architectural constraints that matter in this codebase today.
3. Prevent well-intentioned misunderstandings that would move Amber in the wrong direction.

The product goal is straightforward:

- `amber run` should be the normal way developers enter the Amber system.
- `amber compile` should remain the explicit and inspectable path, but it should not be mandatory
  for a first successful local run.

The developer experience goal is equally straightforward:

- first-time users should be able to run `amber run <manifest>` and succeed without learning the
  compiler outputs first
- experienced users should still have an explicit, scriptable, non-interactive path

The implementation goal is not to invent a second model. The convenient path and the explicit path
must be the same system with different levels of ceremony.

---

## Product direction

`amber run` is the entrypoint to Amber.

That means:

- `amber run <manifest>` must work
- the interactive attached path should be the most convenient path
- `amber compile` remains valuable for inspection, generated docs, explicit artifact workflows, and
  advanced control
- first-time success matters more than preserving the current daemon-like behavior of mixed-site
  `amber run`

This is intentionally a significant behavior change from the current mixed-site implementation.

---

## What already works in the codebase

The current implementation already has important pieces we should build on rather than replace.

- mixed-site run plans already exist
- local placement defaults already do the right thing for the common case:
  - `program.path` -> `direct_local`
  - `program.image` -> `compose_local`
  - `program.vm` -> `vm_local`
- mixed-site runs already have run receipts and run ids
- `amber stop <run-id>` already exists
- runtime metadata already exposes root config inputs, external slots, and exports
- routers already support dynamic external slot registration and export peer registration
- `amber proxy` can already resolve a mixed-site run from a run id instead of only from an artifact
  path

These are real advantages. The implementation should lean on them.

---

## What does not work yet

The current implementation also has important gaps and one important modeling problem.

### Gaps

- mixed-site `amber run` currently behaves more like a coordinator that starts the run, prints
  `run_id` / `run_root`, and exits
- `amber run` does not currently load `.env`
- `amber run` does not currently support `--env-file`
- `amber run` does not currently prompt for missing root config
- `amber run` does not currently prompt for missing external slot values
- `amber run` does not currently auto-start the outside-world proxy
- `amber ps` does not exist
- `amber logs` does not exist

### Modeling problem

Current proxying is site-scoped in a way that leaks the internal run topology into the user-facing
surface.

That is not the right product model.

The external world is modeled as a site.
It peers with the other sites in the run.
There should be one outside-world proxy surface for a run, not one user-visible proxy surface per
internal site.

If the implementation needs to consult multiple site routers internally, that is fine.
That is an implementation detail.
It must not become the user-facing model for the happy path.

This point is critical:

- do not design the interactive `amber run` convenience layer as "start one proxy per site"
- do not treat `--site` as the main product abstraction for exposing a running scenario

---

## Core design principles

### 1. `amber run` must work directly from a manifest

The user should not have to run `amber compile` first just to find out what config they need or how
to start the app.

For `amber run <manifest>`:

- Amber may compile in memory
- Amber may materialize temporary run artifacts under the run root as needed
- Amber must not require the user to first inspect generated output directories

### 2. Interactivity and detach are different axes

Do not conflate them.

Interactivity answers:

- may Amber prompt?
- should Amber optimize for convenience?

Detach answers:

- does this command remain the foreground session owner?
- does this command stream logs and own Ctrl-C teardown?

This distinction should be visible in the implementation structure.

### 3. The friendly path is attached and interactive

This is the magical first-run path:

- prompt when needed
- start the scenario
- auto-start the outside-world proxy
- print the final URLs
- stay attached
- stream logs
- tear everything down on Ctrl-C

### 4. Non-interactive means "assume everything is ready"

Non-interactive runs must not prompt.

They should:

- load config from explicit sources
- fail clearly if required values are missing
- avoid convenience behaviors that are hard to control in scripts

### 5. `amber compile` remains the explicit path

This change is not a rejection of `amber compile`.

It remains the right path for:

- inspecting run plans
- reading generated README material
- artifact-driven workflows
- debugging what Amber resolved
- advanced control and automation

The product goal is to remove it from the first-run critical path, not to devalue it.

### 6. Keep persistence policy separate from prompting

Prompting for missing config is a usability feature.
Persisting prompted values is a policy decision.

These concerns should be separated in the implementation so the persistence behavior can change
without rewriting the startup flow.

---

## Locked decisions

These are the decisions this implementation should assume are settled.

### A. `amber run <manifest>` is required

This is not optional.

### B. Interactive attached `amber run` should auto-start the outside-world proxy

Reducing the number of tools a new user must learn is a core part of the value of this change.

### C. The outside world is one site

User-facing proxying should model one outside-world site for the run.

Do not build a product surface that requires users to think in terms of "proxy this site" versus
"proxy that site" for the common path.

### D. Default local placement stays simple

No inline site assignment syntax is needed for the happy path.

The default local behavior remains:

- `program.path` => direct local execution
- `program.image` => Compose local execution
- `program.vm` => VM local execution

If users need more than that, they use an explicit placement file.

### E. No Amber-native file watching

Amber supervises commands.
It does not become a file watcher.

For the mixed-site example, simplicity and broad portability matter more than showing watcher
integration.

### F. Detached and non-interactive are orthogonal

Do not write code that assumes:

- detached implies non-interactive
- attached implies interactive

Those assumptions are wrong.

### G. Do not make logs depend on observability being configured

Observability can enrich the experience.
It must not be the only way to get logs.

Interactive `amber run` needs a baseline log path whether OTLP is configured or not.

---

## Behavior spec

The behavior is easiest to reason about as two axes.

### Axis 1: interactivity

**Interactive**

- stdin and stdout are attached to a terminal
- Amber may prompt
- Amber should optimize for first-run convenience

**Non-interactive**

- no prompts
- Amber assumes configuration should already be provided
- errors should clearly describe what is missing

### Axis 2: session ownership

**Attached**

- `amber run` remains in the foreground
- it owns the user session
- it streams logs
- Ctrl-C tears the run down cleanly

**Detached**

- `amber run` starts the run and returns a handle
- it does not remain the foreground session owner
- log inspection happens through follow-up commands

---

## Input classes

The implementation should distinguish three broad input classes.

### 1. Local manifest or scenario directory

This is the primary first-run UX surface.

Examples:

```sh
amber run .
amber run path/to/root.json5
```

For this input class, Amber may apply project-local convenience:

- read a nearby `.env` if it exists
- accept one or more explicit `--env-file` values
- prompt for missing root config in interactive mode

### 2. Bundle input

Bundle inputs may support the same interactive prompting behavior as manifests, but they should not
assume the same project-local `.env` semantics unless the bundle itself establishes them clearly.

The important requirement is:

- bundle support must not block `amber run <manifest>`

### 3. Run plan or compiled artifact input

This is the explicit path.

Examples:

```sh
amber run /tmp/amber-run-plan.json
amber run /tmp/amber-direct
amber run /tmp/amber-vm
```

For this input class:

- support explicit `--env-file`
- do not infer a project `.env`
- do not try to behave like a scenario-directory UX

This keeps the explicit path explicit.

---

## Config and env behavior

### 1. Root config loading

For local manifest or scenario-directory inputs:

- load any nearby `.env` if present
- load any explicit `--env-file`
- apply later sources over earlier ones
- apply schema defaults

For explicit run-plan or artifact inputs:

- load only explicit `--env-file` inputs and ambient environment

### 2. Prompting for missing root config

In interactive mode:

- prompt only for missing required root config values
- do not prompt for values already supplied
- do not prompt for fields that can be satisfied by defaults
- secret values may be masked, but this is a UI detail rather than a product decision

In non-interactive mode:

- do not prompt
- fail with a clear list of missing required root config variables

### 3. Persistence of prompted root config

This is intentionally less locked down than the original draft.

The implementation must separate:

- collecting missing root config values
- deciding whether and where to persist them

The minimum product requirement is:

- after a successful interactive startup, Amber should provide an explicit reuse path for the next
  run

Acceptable initial implementations include:

- offer to save collected root config to `.env` for local manifest inputs
- write a generated env file under the run root and print the exact follow-up command using
  `--env-file`
- do both

Important constraints:

- do not make the rest of the design depend on automatic `.env` mutation
- if persistence happens automatically, prefer doing it only after successful startup rather than
  before the run is known-good
- implement persistence behind a narrow interface so the policy can change later

### 4. External slot values

For this UX pass:

- interactive mode may prompt for missing external slot values for the current run
- non-interactive mode must not prompt
- explicit follow-up proxying must still allow slot overrides

Do not let the rest of the design depend on external slot persistence being settled.

---

## Proxy behavior

### 1. Interactive attached `amber run`

This is the convenience path.

When `amber run` is both attached and interactive, it should:

1. resolve config inputs
2. prompt for missing required root config
3. prompt for missing external slot values needed for the current session
4. start the scenario
5. start one outside-world proxy for the run
6. bind exports on random free loopback ports
7. print the final URLs in a short ready block
8. stay attached and stream logs

The key modeling rule is:

- there is one outside-world proxy surface for the run

### 2. Detached runs

Detached runs do not own the foreground session.

That means:

- they return a run handle
- they do not auto-start the session-scoped interactive proxy
- they do not print the final random export URLs as though they were a foreground dev session

If detached mode is invoked from an interactive terminal, it may still use prompts before startup.
That is an interactivity decision, not a detach decision.

### 3. Non-interactive runs

Non-interactive runs must not prompt.

They should:

- resolve config from explicit sources
- fail clearly if required values are missing
- avoid automatic proxy/session behaviors that are meant for the friendly attached path

### 4. Explicit `amber proxy`

`amber proxy` remains the peeled-back layer.

It should support:

- reconnecting to a running scenario by run handle
- explicit external slot overrides
- explicit export bind addresses

The current code already supports some run-id-based targeting.
The product direction is to finish that path and remove internal-layout spelunking from the user
experience.

The important outcome is:

- users should not have to discover artifact directories under the run root just to expose a
  running scenario

---

## Logs and lifecycle

Interactive attached `amber run` should feel like the main process for local development.

That means:

- it should stream logs while it is attached
- it should persist enough log information for later inspection
- Ctrl-C should tear the run down cleanly

The lifecycle commands that should align with this model are:

- `amber run`
- `amber run --detach`
- `amber ps`
- `amber logs <run-handle>`
- `amber stop <run-handle>`

Important constraint:

- do not make `amber logs` depend entirely on OTLP or other optional observability plumbing

---

## Output shape

Keep interactive output short.

Good:

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

Also good if `.env` persistence is chosen:

```text
config.tenant: acme-local
config.catalog_token: ********
slot.catalog_api: http://127.0.0.1:9100

Saved root config to .env

Ready.
  app  http://127.0.0.1:18080
  api  http://127.0.0.1:18081
```

Bad:

- long explanatory prose
- internal artifact paths that the user should not need
- site-by-site proxy instructions in the happy path
- verbose narration about router internals

---

## Incorrect paths to avoid

The implementation should explicitly avoid these directions.

### 1. Do not require `amber compile` for first-run success

It remains valuable, but it must not be mandatory for the simple local-dev path.

### 2. Do not expose site-scoped proxying as the main model

The common path is one run, one outside-world surface.

### 3. Do not make `--detach` imply non-interactive

These are separate concepts.

### 4. Do not make non-interactive runs prompt "just a little"

If it is non-interactive, it must be scriptable and predictable.

### 5. Do not hardwire automatic `.env` mutation into startup logic

Persistence policy should be easy to change later.

### 6. Do not make the happy path depend on generated README output

For `amber run <manifest>`, Amber must know enough from the in-memory compile result to guide the
run without requiring the user to read a generated artifact README first.

### 7. Do not add Amber-native file watching

The example should stay simple and portable.

### 8. Do not make logs contingent on optional observability infrastructure

Baseline logging must work without OTLP.

---

## Target `examples/mixed-site/README.md`

This is the end-user README we want the implementation to make true.

````md
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

One thing in this example is intentionally **not** part of the Amber scenario: a tiny catalog
service.

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

Amber should provide an explicit reuse path for future runs.

Depending on the final persistence policy, that may be:

- a generated env file plus an `--env-file` command
- a saved `.env` for the scenario
- both

The important thing is that a successful interactive run gives you a clear path to the next
non-interactive or less-interactive run.

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
````

---

## Acceptance criteria

### Attached interactive run from a local manifest

Given:

- no previously prepared compile output
- `mock-catalog.py` is running
- the user runs `amber run .` in a terminal

Expected:

- Amber can compile from the manifest directly
- Amber prompts for missing required root config
- Amber prompts for the outside slot value for the current run
- Amber starts the scenario
- Amber starts one outside-world proxy surface for the run
- Amber publishes exported entrypoints on random free loopback ports
- Amber prints the final URLs
- Amber stays attached and streams logs
- Ctrl-C tears the run down cleanly

### Interactive detached run

Given:

- the user runs `amber run . --detach` from a terminal

Expected:

- Amber may still prompt for missing config because the run is interactive
- Amber starts the scenario
- Amber returns the run handle
- Amber does not act like an attached foreground dev session
- Amber does not auto-start the attached session-scoped proxy behavior

### Non-interactive attached run

Given:

- stdin/stdout are not interactive
- the user does not pass `--detach`

Expected:

- Amber does not prompt
- Amber fails clearly if required config is missing
- if configuration is complete, Amber may remain attached and stream logs
- Amber does not enable interactive-only convenience behaviors just because it is attached

### Explicit replay after a successful interactive run

Given:

- the user has already completed one successful interactive run

Expected:

- Amber provides a clear reuse path for the next run
- that reuse path is explicit enough for non-interactive use
- the implementation does not require the user to reconstruct the config manually from memory

---

## Final note

The core principle in this UX change is not "hide the model."

The core principle is:

- make the first path pleasant
- keep the underlying model coherent
- keep the explicit path available

If an implementation makes first-time success easier but hardcodes the wrong user-facing model
around proxying, lifecycle, or persistence, it is not a successful implementation.
