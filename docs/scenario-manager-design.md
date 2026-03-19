# Amber Scenario Manager

## Status

Design proposal based on a codebase review of `amber1` and the decisions made during the present discussion.

This document is intentionally explicit about both the recommended design and the paths that were considered and rejected. The goal is that an implementer who did not participate in the discussion can understand not just what to build, but why.

## Objective

Add a production-quality single-machine scenario manager for Amber.

The manager should:

- accept a root manifest URL plus scenario-instance configuration and metadata
- compile the scenario with Amber
- run it on the same machine via Docker Compose
- keep it running
- restore it after daemon restart or machine reboot
- support pause, resume, delete, and upgrade
- preserve persistent storage as safely as possible
- keep scenario-instance metadata durably
- expose tracing in a way that works both for single-user local debugging and for forwarding into an external multi-user telemetry system

The manager is not meant to be a general scheduler or a distributed control plane.

## Non-Goals

The first version should not try to be any of the following:

- a cluster scheduler
- a multi-host orchestrator
- a tracing backend
- a policy engine for user authorization
- a new Amber manifest format
- a new backend-neutral IR beyond the existing `ScenarioIr`

## Current Amber Behavior Relevant To This Feature

The proposed manager is grounded in the current Amber implementation rather than in hypothetical future cleanup.

### Amber already provides the right compiler boundary

Amber today already exposes public library APIs that are enough to build the manager core:

- `amber_compiler::Compiler` can compile a root manifest reference, including a URL
- `amber_compiler::reporter::CompiledScenario::from_compile_output` converts compile output into a reporter-friendly form
- `ScenarioIrReporter` can emit `ScenarioIr`
- `CompiledScenario::from_ir` can recreate a compiled scenario from stored IR
- `DockerComposeReporter` can emit Compose artifacts from that compiled scenario

This is the key point: the manager does not need Amber to invent a new machine-readable format. `ScenarioIr` is already the right deployment snapshot to store.

### `ScenarioIr` already contains the manager’s core view of the world

The emitted IR includes:

- components and monikers
- parent-child structure
- programs
- config and config schema
- slots, provides, and resources
- bindings, including `resource` and `external`
- exports
- manifest component metadata
- resolved URLs when the IR is emitted from a real compile

That is enough for the manager to derive:

- which root config leaves exist
- which external slots must be bound
- which exports exist
- which storage resources are mounted and how they are routed
- which component metadata exists

The manager can walk the IR directly. It does not need Amber to precompute a separate manager-specific graph artifact.

### Compose output already contains the runtime structure

Amber’s Compose reporter already emits:

- program containers
- sidecar routers
- a top-level router when needed
- a provisioner
- an OTEL collector
- stable storage volume keys derived from logical storage identity
- embedded proxy metadata in `x-amber`

The manager should use Amber’s Compose reporter for runtime artifact generation. It should not synthesize Compose on its own.

### `amber proxy` already solves the host-bridge problem

Amber already has a host-side bridge for:

- exposing scenario exports on local host ports
- bridging external slots through a host-local proxy when direct container reachability is not appropriate

That behavior now lives in the `amber-proxy` crate, so the manager can use the same logic in-process instead of supervising a separate CLI subprocess.

### Current OTEL support is narrower than a generic telemetry policy system

Amber currently supports:

- per-scenario OTEL collector injection in Compose and Kubernetes
- fixed OTLP HTTP forwarding through `AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT`
- built-in Amber resource attributes like scenario run id, scenario scope, component moniker, and service name

Amber does not currently expose a first-class model for:

- per-scenario auth headers
- arbitrary per-scenario OTEL resource attributes
- per-scenario sampling policies beyond the generated defaults
- an explicit disabled mode in the generated Compose runtime

The manager design must reflect that instead of assuming a richer telemetry contract than Amber actually has.

## Recommended Design

Build `amber-scenario-manager` as a single-machine Rust daemon with a thin CLI wrapper.

The daemon owns:

- a local SQLite database
- a local state directory
- one fixed Compose project name per scenario
- one active `ScenarioIr` snapshot per revision
- optional stored bundles per revision
- manager-supervised `docker compose` processes
- manager-owned proxy tasks backed by `amber-proxy` when needed

The CLI is just a client for the daemon API.

This is a deliberately small design:

- one daemon
- one database
- one local Docker host
- one reconcile loop

It is not a distributed architecture.

## Core Model

There are two reasonable persistence models for a manager whose input is always a URL.

### Option A: store only the source URL

The manager persists the URL and always re-fetches it when it needs to restart or upgrade.

Pros:

- simpler state model
- minimal storage footprint

Cons:

- restart becomes network-dependent
- reboot recovery becomes non-deterministic
- scenario behavior can drift even without an explicit upgrade action

### Option B: store the source URL and the compiled `ScenarioIr`

The manager persists the URL for future refreshes and also stores the compiled IR snapshot for each successful revision. Restart and reboot recovery use stored IR. Re-fetching the URL happens only on explicit upgrade or refresh.

Pros:

- restart and reboot recovery are local and deterministic
- the manager can recreate the same scenario revision without needing the source URL to be reachable
- the manager still supports explicit refresh from the source URL

Cons:

- slightly more local state
- revisions become explicit objects the manager must keep track of

### Recommendation

Use Option B.

This matches the discussion outcome:

- the input contract is a URL
- reproducibility from old source contents is not mandatory
- `ScenarioIr` is the required stored artifact
- bundle retention is optional and useful, but not required

## Runtime Shape

For each scenario, the manager persists:

- `source_url`
- active revision number
- `ScenarioIr` for each stored revision
- optional bundle for each stored revision
- root config JSON
- external slot binding config
- export publication config
- arbitrary scenario metadata JSON
- telemetry forwarding override
- fixed Compose project name
- desired state
- observed state

For each active revision, the manager also stores generated runtime artifacts:

- Compose output directory
- runtime env file
- proxy launch parameters when applicable

## Concrete API

Use HTTP+JSON over a local socket or TCP listener, with a thin CLI wrapper.

### `POST /v1/sources/inspect`

Purpose:

- preflight a source URL
- discover required config and wiring before creation or upgrade

Request:

```json
{
  "source_url": "https://example.com/scenario.json5"
}
```

Response:

```json
{
  "root_config_schema": { "...": "..." },
  "root_config_leaves": [
    {
      "path": "api_key",
      "required": true,
      "secret": false,
      "env_var": "AMBER_CONFIG_API_KEY",
      "default": null
    }
  ],
  "external_slots": {
    "ext_api": {
      "required": true,
      "kind": "http",
      "url_env": "AMBER_EXTERNAL_SLOT_EXT_API_URL"
    }
  },
  "exports": {
    "public": {
      "protocol": "http"
    }
  },
  "component_metadata": {
    "/worker": { "...": "..." }
  }
}
```

### `POST /v1/scenarios`

Purpose:

- create a new scenario record
- compile the source URL
- start the scenario if requested

Request:

```json
{
  "source_url": "https://example.com/scenario.json5",
  "root_config": {
    "api_key": "abc123",
    "system_prompt": "You are an agent."
  },
  "external_slots": {
    "ext_api": {
      "mode": "direct",
      "url": "https://api.example.com"
    },
    "local_dev_api": {
      "mode": "host_proxy",
      "upstream": "127.0.0.1:38081"
    }
  },
  "exports": {
    "public": {
      "listen": "127.0.0.1:18080"
    }
  },
  "metadata": {
    "creator": "alice",
    "team": "evals"
  },
  "telemetry": {
    "upstream_otlp_http_endpoint": "http://otel-gateway.internal:4318"
  },
  "store_bundle": false,
  "start": true
}
```

Response:

```json
{
  "scenario_id": "scn_01J...",
  "revision": 1,
  "source_url": "https://example.com/scenario.json5",
  "desired_state": "running",
  "observed_state": "starting",
  "compose_project": "amber_scn_01j..."
}
```

Semantics:

- `root_config` is structured JSON matching the root config schema
- `external_slots.mode = direct` means the manager will set the router env var directly before Compose start
- `external_slots.mode = host_proxy` means the manager will use `amber-proxy` to publish that slot bridge
- `exports` always use manager-owned `amber-proxy` listeners
- `telemetry.upstream_otlp_http_endpoint` maps to Amber’s currently supported collector override

### `GET /v1/scenarios`

Purpose:

- list scenario summaries

### `GET /v1/scenarios/{id}`

Purpose:

- return current scenario state and configuration

Response includes:

- source URL
- active revision
- desired state
- observed state
- metadata
- root config
- external slot bindings
- export bindings
- telemetry override
- compose project name
- retained storage identities
- whether a bundle is stored for the active revision

### `POST /v1/scenarios/{id}/pause`

Effect:

- set `desired_state = paused`
- stop proxy tasks
- run `docker compose down --remove-orphans`
- keep persistent storage

### `POST /v1/scenarios/{id}/resume`

Effect:

- set `desired_state = running`
- regenerate Compose from stored IR if needed
- run `docker compose up -d`
- restart proxy tasks if needed

### `POST /v1/scenarios/{id}/upgrade`

Purpose:

- create a new revision from either a new URL or a refresh of the same URL

Request:

```json
{
  "source_url": "https://example.com/scenario-v2.json5",
  "root_config": {
    "api_key": "abc123"
  },
  "external_slots": {
    "ext_api": {
      "mode": "direct",
      "url": "https://api-v2.example.com"
    }
  },
  "exports": {
    "public": {
      "listen": "127.0.0.1:18080"
    }
  },
  "metadata": {
    "creator": "alice",
    "team": "evals"
  },
  "telemetry": {
    "upstream_otlp_http_endpoint": "http://otel-gateway.internal:4318"
  },
  "store_bundle": true
}
```

If `source_url` is omitted, the manager re-fetches the existing URL and creates a new revision from that content.

Effect:

- compile the new source URL
- store a new `ScenarioIr`
- optionally store a new bundle
- compute storage identity changes
- regenerate Compose
- apply the new revision with the same Compose project name
- restart proxy wiring if needed

### `DELETE /v1/scenarios/{id}?destroy_storage=false`

Effect:

- stop proxy
- stop Compose
- delete the scenario record
- preserve or destroy tracked storage according to the flag

### `GET /v1/scenarios/{id}/revisions`

Recommended in the first version.

Response includes:

- revision number
- source URL used for that revision
- whether bundle storage exists
- timestamps
- basic status

## CLI Surface

The CLI should be a thin wrapper around the daemon API.

Recommended commands:

- `amber-scenario-manager inspect URL`
- `amber-scenario-manager create URL --config-file root.json --slot ext_api=https://... --export public=127.0.0.1:18080 --metadata-file meta.json`
- `amber-scenario-manager list`
- `amber-scenario-manager status ID`
- `amber-scenario-manager pause ID`
- `amber-scenario-manager resume ID`
- `amber-scenario-manager upgrade ID [URL]`
- `amber-scenario-manager delete ID [--destroy-storage]`

## How The Manager Uses Amber

### Create path

1. Compile the source URL with `amber_compiler::Compiler`.
2. Emit `ScenarioIr`.
3. Optionally build and store a bundle.
4. Walk the IR to discover:
   - root config schema
   - external slots
   - exports
   - storage resources and mounts
   - component metadata
5. Generate Compose with `DockerComposeReporter`.
6. Write the runtime env file.
7. Start Compose.
8. Start the required `amber-proxy` listeners if exports or host-proxy slots are configured.

### Resume path

1. Load the active stored `ScenarioIr`.
2. Recreate `CompiledScenario` from IR.
3. Regenerate or reuse Compose output.
4. Start Compose.
5. Restart proxy wiring if needed.

### Upgrade path

1. Compile the new source URL.
2. Emit and store a new `ScenarioIr`.
3. Optionally store a new bundle.
4. Compare old and new storage identities.
5. Regenerate Compose under the same Compose project name.
6. Apply with `docker compose up -d --remove-orphans`.
7. Restart proxy wiring if needed.

## Config Handling

The manager should accept root config as structured JSON, not as raw env vars.

Internally it should:

- validate the JSON against the root config schema from the IR
- flatten leaf values into Amber env vars using current public config helpers
- preserve the structured JSON in the database

This keeps the external API readable while still matching Amber’s runtime input model.

Secrets should be treated as a separate storage concern in the manager because the config schema already marks secret leaves.

## External Slots

The manager should support two modes because Amber supports two relevant runtime paths today.

### Direct URL mode

Use when the router container can directly reach the upstream URL.

The manager writes the appropriate `AMBER_EXTERNAL_SLOT_*_URL` value into the runtime env before Compose start.

### Host proxy mode

Use when the upstream is host-local or when the manager explicitly wants a host-side bridge.

The manager uses `amber-proxy` with the equivalent slot binding configuration.

This uses current Amber behavior as-is rather than inventing a new bridge.

## Exports

Exports should be published through manager-owned `amber-proxy` listeners.

The manager stores requested host listeners like:

- export name
- host address
- port

On start or resume, the manager restarts the proxy with those bindings.

## Storage Model

The manager should track logical storage identities itself rather than trying to infer only from Docker runtime state.

The identity rule should match current Amber behavior:

- if a program mounts `resources.X`, the identity is `(owner_moniker, X)`
- if a program mounts `slots.Y`, follow binding edges until the source `resources.X`; the identity is `(resource_owner_moniker, X)`

Operational rules:

- same logical identity plus same Compose project name means the same Docker volume is reused
- additive storage changes create new volumes
- removed storage identities are retained but detached
- the manager should never silently delete detached storage on upgrade
- storage destruction happens only on explicit delete with `destroy_storage=true`

This is intentionally conservative.

The first version should not attempt automatic content migration between different logical storage identities.

## Compose Project Naming

Each scenario gets one fixed Compose project name at creation time.

That project name must remain stable across upgrades and restarts.

This stability matters for:

- Docker volume reuse
- router discovery
- OTEL scenario run labels
- predictable process supervision

## Telemetry

The manager should expose only the telemetry configuration that current Amber actually supports cleanly.

Recommended API shape:

```json
{
  "telemetry": {
    "upstream_otlp_http_endpoint": "http://otel-gateway.internal:4318"
  }
}
```

Semantics:

- if omitted, use the manager’s node default
- if set, write `AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT` for that scenario

The manager should not pretend current Amber already supports:

- per-scenario OTEL auth headers
- per-scenario sampling policy configuration
- arbitrary user-supplied OTEL resource attributes
- a built-in trace storage system

Those may be useful future extensions, but they are not the current Amber behavior and should not be baked into the first design.

## Observed State Model

Keep the runtime state model simple and aligned with what Amber actually guarantees.

Recommended states:

- `starting`
- `running`
- `degraded`
- `paused`
- `failed`

Meaning:

- `running` means long-lived containers are running and required proxy tasks are running
- `degraded` means desired state is running, but one or more long-lived containers or required proxy tasks are down or repeatedly failing
- the manager should not claim full application-level readiness beyond that

This matches Amber’s current runtime semantics better than inventing deep health claims.
## Truly Essential Amber Changes

None.

The manager can be implemented robustly enough with current Amber because:

- compile from URL already exists
- stored `ScenarioIr` is sufficient to recreate the same Compose scenario revision
- Compose generation from IR already exists
- config helpers already exist
- the manager can use the existing `amber-proxy` crate
- the manager can walk IR directly for the metadata it needs

## Additional Amber Changes

No additional Amber changes are required for a robust first implementation.

The only Amber-side cleanup that materially simplified the manager was extracting proxy functionality into a reusable Rust library, and that work has already landed as `runtime/proxy`.

Everything else discussed as an Amber change remains optional cleanup, not a blocker.

## Key Discussion Pivots And Rejected Paths

This section records the main places where the discussion changed direction, because those pivots matter for future implementation decisions.

### Pivot: do not invent a new manager-specific IR

At one point the discussion drifted toward the idea that the manager might need a new Amber-specific machine-readable artifact beyond `ScenarioIr`.

That was rejected.

Reason:

- `ScenarioIr` already contains the right linked scenario graph
- the manager can walk it directly
- Compose can already be recreated from it

Conclusion:

- `ScenarioIr` is the correct required stored artifact
- no new Amber IR should be introduced for this feature

### Pivot: do not over-index on source reproducibility

At one point the discussion overemphasized source provenance, bundle retention, and reconstructing a scenario from the original source bytes.

That was corrected.

The actual requirement is:

- the manager accepts a URL
- if the URL contents change later, it is acceptable that future refreshes do not recreate the old scenario from source
- what must be stored to recreate the same deployed revision is `ScenarioIr`

Conclusion:

- store the URL
- always store `ScenarioIr`
- optionally store a bundle
- do not make bundle storage mandatory

### Pivot: keep the manager single-machine and small

At one point the discussion drifted toward a larger “platform” architecture.

That was rejected.

Reason:

- the feature request is for a same-machine Docker Compose manager
- a single daemon, a local DB, and local process supervision are enough
- anything larger is unnecessary complexity in the first version

Conclusion:

- one daemon
- one local DB
- one local Docker host
- no distributed control plane

### Pivot: be precise about current OTEL behavior

At one point the discussion incorrectly described a richer per-scenario telemetry policy model than Amber currently implements.

That was corrected by checking the code.

Current Amber supports:

- per-scenario collector injection
- one upstream OTLP HTTP endpoint override

It does not currently support:

- scenario-specific auth headers as a first-class contract
- arbitrary resource attributes as a first-class contract
- explicit disabled mode in the generated Compose runtime
- scenario-specific sampling configuration through a manager contract

Conclusion:

- keep the manager telemetry API narrow and grounded in current Amber behavior

### Pivot: provenance is not required

At one point provenance was treated as more important than it really is for the manager.

That was rejected.

Reason:

- provenance is not needed for the core lifecycle manager
- the manager needs the linked scenario graph and runtime configuration, not a full source-audit model

Conclusion:

- provenance can remain incidental
- it is not a required part of the manager design

### Pivot: no essential Amber features are missing

At one point the design discussion assumed the manager needed Amber-side feature work before it could be built cleanly.

That turned out to be too strong.

Conclusion:

- the manager can be built now
- the one Amber-side simplification that mattered most was proxy factoring
- that simplification has already landed, so no additional Amber work is required before implementation

## Final Recommendation

Implement `amber-scenario-manager` now as a Rust daemon that:

- accepts a source URL
- compiles it with Amber
- stores `ScenarioIr` for every active revision
- optionally stores bundles
- generates Compose from the stored IR
- reconciles Compose and runs `amber-proxy` in-process for host bridging
- persists desired state and scenario metadata
- restarts from stored IR after reboot
- upgrades by recompiling the source URL into a new revision
- preserves storage conservatively by logical identity and fixed Compose project name

That is the smallest design that is:

- concrete
- grounded in current Amber behavior
- implementable now
- operationally robust on a single machine
