# Amber Scenario Manager

## Status

Design proposal updated after a codebase review of `amber` and follow-up discussion.

This version makes the chosen integration contract explicit:

- the manager is built against Amber’s current compiler/reporter/runtime boundaries
- the manager derives most of its own facts from `ScenarioIr`
- Amber planner and lowering internals remain private
- no new Amber public API is required for the first implementation

This document is intentionally explicit about both the chosen route and the routes that were considered and rejected, so an implementer who did not participate in the discussion can understand not just what to build, but why.

## Objective

Add a production-quality single-machine scenario manager for Amber. It manages multiple scenarios.

The manager should:

- accept a root manifest URL plus scenario-instance configuration and metadata
- compile the scenario with Amber
- run it on the same machine via Docker Compose
- keep it running
- restore it after daemon restart or machine reboot
- support inspect, pause, resume, delete, and upgrade
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
- a public Amber lifecycle API
- a public Amber planner API for mesh, storage, or config lowering

## Current Amber Behavior Relevant To This Feature

The proposed manager is grounded in the current Amber implementation rather than in hypothetical future cleanup.

### Amber already provides the right compiler boundary

Amber today already exposes public library APIs that are enough to build the manager core:

- `amber_compiler::Compiler` can compile a root manifest reference, including a URL
- `Compiler::resolve_tree` and `Compiler::compile_from_tree` already exist for the optional bundle-retention path
- `amber_compiler::reporter::scenario_ir::scenario_ir_from_compile_output` produces a `ScenarioIr` snapshot from real compile output and populates `resolved_url`
- `amber_compiler::reporter::CompiledScenario::from_ir` recreates a compiled scenario from stored IR and rebuilds the derived config analysis Amber reporters need
- `amber_compiler::reporter::DockerComposeReporter` emits Compose runtime artifacts from that compiled scenario
- `runtime/proxy::ProxyCommand` exposes proxy behavior as a Rust library rather than requiring supervision of a separate CLI subprocess

Two important clarifications from the code review:

- `ScenarioIrReporter` is a renderer for a JSON IR document; it is not itself a typed inspect API
- if the manager wants `resolved_url` retained in stored IR, it should store IR derived from real compile output, not a raw `ScenarioIr::from(&Scenario)` snapshot

This is the key point: the manager does not need Amber to invent a new machine-readable deployment artifact. `ScenarioIr` is already the right scenario snapshot to store.

### `ScenarioIr` already contains the manager’s core view of the scenario

The emitted IR includes:

- components and monikers
- parent-child structure
- programs
- config and config schema
- slots, provides, and resources
- bindings, including `resource`, `framework`, `component`, and `external`
- exports
- component metadata
- resolved URLs when the IR is emitted from real compile output

That is enough for the manager to derive, directly or with existing public helpers:

- the root config schema
- root config schema leaves
- which external slots are present and which ones are required
- which exports exist
- export protocol, by following the export’s provider into the provider component’s program endpoint information
- which storage resources are mounted and how they are routed
- which component metadata exists

The manager can walk the IR directly. It does not need Amber to expose its private planners.

### Some currently generated facts are narrower than raw IR facts

Amber’s private execution-guide code computes a narrower set of root config inputs than “all schema leaves”: it filters root leaves through private config/runtime planning.

That distinction matters.

For the first manager version, the inspect surface should be based on **IR-level facts**, not on Amber’s private planner-level notion of “runtime-used root inputs.”

Chosen route:

- the manager exposes the full root config schema
- the manager exposes the full set of root schema leaves, annotated with `required`, `secret`, env var name, and default

Not chosen in the first version:

- depending on private `ConfigPlan` semantics to reproduce Amber’s execution-guide-specific filtering of runtime-used root inputs
- asking Amber to expose a new public inspect API just for this manager

If Amber later grows a generally useful public derived-facts surface for multiple consumers, the manager could use it. This design does not assume that.

### Planner logic remains private

The current Amber implementation has real internal planning logic for:

- mesh routing
- config lowering
- storage lowering
- backend rendering

That logic is intentionally not treated as the manager’s public dependency surface.

Chosen route:

- the manager depends on `ScenarioIr`, current public config helpers, and existing tooling-readable output metadata

Not chosen:

- exposing `MeshPlan`, `ConfigPlan`, `StoragePlan`, or similar internals as public Amber APIs
- having the manager depend directly on private planner logic

If Amber ever exposes more public tooling facts in the future, the right pattern is to expose **facts**, not planner internals.

### Compose output already contains runtime structure and tooling metadata

Amber’s Compose reporter already emits:

- program containers
- sidecar routers
- a top-level router when needed
- a provisioner
- an OTEL collector
- stable storage volume keys derived from logical storage identity
- embedded proxy metadata in `x-amber`

That `x-amber` metadata is explicitly intended for tooling. The manager may rely on it where convenient.

The manager should use Amber’s Compose reporter for runtime artifact generation. It should not synthesize Compose on its own.

### `amber-proxy` already solves the host-bridge problem

Amber already has a host-side bridge for:

- exposing scenario exports on local host ports
- bridging external slots through a host-local proxy when direct container reachability is not appropriate

That behavior lives in the `runtime/proxy` crate, so the manager can use the same logic in-process instead of supervising a separate CLI subprocess.

The manager can either:

- derive inspect-time facts from IR, and then
- hand generated runtime output plus requested bindings to `amber-proxy`

or, where helpful, read the generated tooling metadata that the proxy itself already consumes.

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
- manager-supervised `docker compose` operations
- manager-owned proxy tasks backed by `amber-proxy` when needed
- a manager-owned secret store for secret config leaves

The CLI is just a client for the daemon API.

This is a deliberately small design:

- one daemon
- one database
- one local Docker host
- one reconcile loop

It is not a distributed architecture.

## Chosen Amber Integration Contract

The manager is intentionally built on the smallest Amber surface that already exists.

The manager depends on:

- `Compiler::compile` for the simple compile path
- `Compiler::resolve_tree` plus `Compiler::compile_from_tree` for the optional bundle path
- stored `ScenarioIr` snapshots derived from real compile output
- `CompiledScenario::from_ir` to recreate reporter input from stored IR
- `DockerComposeReporter` for Compose generation
- `amber_config` public helpers such as `collect_leaf_paths`, `env_var_for_path`, and `encode_env_value`
- public tooling-facing metadata such as `x-amber` and `amber-proxy.json`
- `amber-proxy` as a library

The manager does **not** depend on:

- a new Amber inspect API
- public storage-planner APIs
- public mesh-planner APIs
- public config-planner APIs
- a manager-specific IR
- new Amber daemon or lifecycle hooks

That is the central design choice of this document.

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

This matches both Amber’s current compiler boundary and the product requirement:

- the input contract is a URL
- reproducibility from old source contents is not mandatory
- `ScenarioIr` is the required stored deployment artifact
- bundle retention is optional and useful, but not required

Important implementation detail:

- when the manager stores IR for a real compile, it should store IR produced from compile output so that `resolved_url` is retained

## Derived Facts Model

The manager needs some derived facts for inspect, create validation, upgrade validation, storage tracking, and runtime wiring.

The chosen rule is:

- derive persistent scenario facts from `ScenarioIr`
- derive runtime wiring facts from generated runtime artifacts and tooling metadata when that is the natural source of truth

### Facts derived from IR

The manager derives the following from `ScenarioIr`:

- root config schema
- root config schema leaves
- external slot declarations and whether they are required
- exports and their protocols
- component metadata
- storage identities

This avoids coupling the manager to Amber internals that are better left private.

### Facts taken from generated runtime output

The manager treats the generated runtime output as the source of truth for things like:

- actual Compose files
- `x-amber` proxy metadata
- actual generated storage volume names that should later be cleaned up on explicit destruction

This is also intentional. Some runtime identifiers are backend artifacts, not stable IR concepts, so the manager should record them from the emitted artifact rather than reimplementing private naming logic.

### Facts intentionally not exposed as public Amber planner APIs

The first version does **not** require Amber to expose:

- a new public “inspect” API
- a public storage planner
- a public mesh planner
- a public config planner

That route was considered and rejected for now.

## Runtime Shape

For each scenario, the manager persists:

- `source_url`
- active revision number
- `ScenarioIr` for each stored revision
- optional bundle for each stored revision
- non-secret root config JSON
- separately stored secret root config leaves
- external slot binding config
- export publication config
- arbitrary scenario metadata JSON
- telemetry forwarding override
- fixed Compose project name
- desired state
- observed state

For each active revision, the manager also stores generated runtime artifacts and bookkeeping:

- Compose output directory
- runtime env file or equivalent runtime-input materialization
- proxy launch parameters when applicable
- tracked logical storage identities
- tracked generated Docker volume names for those identities

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
      "secret": true,
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

Semantics:

- `root_config_leaves` enumerate **root schema leaves**, not a private runtime-pruned subset
- the manager derives this response from `ScenarioIr` plus current public config helpers

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
- the manager validates structured config against the root schema before accepting it
- secret leaves are accepted in the same structured request but are stored separately from non-secret config
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
- non-secret root config with secret leaves redacted or omitted
- which secret root config paths are currently set
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
- rematerialize the runtime env from stored non-secret and secret config
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

### Inspect path

1. Compile the source URL with Amber.
2. Convert compile output into a stored/reportable `ScenarioIr` snapshot.
3. Walk the IR directly to discover:
   - root config schema
   - root config schema leaves
   - external slots
   - exports
   - storage resources and mounts
   - component metadata
4. Return those facts through the manager’s inspect API.

Chosen route:

- inspect is an IR-derived manager feature

Not chosen:

- adding a manager-specific Amber inspect API as a prerequisite for implementation

### Create path

1. Compile the source URL.
2. If `store_bundle=true`, use the resolved tree path: resolve the tree, optionally build the bundle from that tree, then compile from the tree.
3. Convert compile output into `ScenarioIr` and store it.
4. Validate and store config, with secret leaves split from non-secret leaves.
5. Walk the IR to discover:
   - root config schema
   - external slots
   - exports
   - storage identities
   - component metadata
6. Recreate a `CompiledScenario` from IR.
7. Generate Compose with `DockerComposeReporter`.
8. Record generated runtime metadata such as actual Compose files, `x-amber` metadata, and generated volume names.
9. Materialize the runtime env file.
10. Start Compose.
11. Start the required `amber-proxy` listeners if exports or host-proxy slots are configured.

### Resume path

1. Load the active stored `ScenarioIr`.
2. Recreate `CompiledScenario` from IR.
3. Regenerate or reuse Compose output.
4. Rematerialize the runtime env from stored config and secrets.
5. Start Compose.
6. Restart proxy wiring if needed.

### Upgrade path

1. Compile the new source URL.
2. Emit and store a new `ScenarioIr`.
3. Optionally store a new bundle.
4. Compare old and new storage identities.
5. Regenerate Compose under the same Compose project name.
6. Record any new generated storage volume names.
7. Apply with `docker compose up -d --remove-orphans`.
8. Restart proxy wiring if needed.

## Config Handling

The manager should accept root config as structured JSON, not as raw env vars.

Internally it should:

- validate the JSON against the root config schema from the IR
- enumerate schema leaves with Amber’s public config helpers
- map each leaf to the corresponding Amber env var name
- encode leaf values using Amber’s current env encoding rules
- preserve non-secret structured JSON in the database
- store secret leaves separately in a manager-owned secret store
- redact or omit secret leaves from read APIs

Chosen route:

- one structured config API for users
- internal env materialization for Amber runtime compatibility
- manager-owned secret storage for the first version

Not chosen:

- exposing raw `AMBER_CONFIG_*` env vars as the manager API
- storing all secrets inline in the main scenario record
- requiring an external secret manager in the first version

Assumption and constraint uncovered during design:

- Amber currently exposes the leaf/path/env helpers needed for this flow, but not a single public “structured config JSON to env map” helper; the manager should do this materialization itself in the first version

## External Slots

The manager should support two modes because Amber supports two relevant runtime paths today.

### Direct URL mode

Use when the router container can directly reach the upstream URL.

The manager writes the appropriate `AMBER_EXTERNAL_SLOT_*_URL` value into the runtime env before Compose start.

### Host proxy mode

Use when the upstream is host-local or when the manager explicitly wants a host-side bridge.

The manager uses `amber-proxy` with the equivalent slot binding configuration.

This uses current Amber behavior as-is rather than inventing a new bridge.

The manager derives slot existence from IR and uses generated runtime output plus proxy metadata to drive actual runtime wiring.

## Exports

Exports should be published through manager-owned `amber-proxy` listeners.

The manager stores requested host listeners like:

- export name
- host address
- port

On start or resume, the manager restarts the proxy with those bindings.

The manager may determine export protocol either:

- directly from IR by following the export provider into the provider component’s program endpoint, or
- from Amber’s current tooling metadata where that is the more convenient source

Chosen route:

- the manager does not require Amber to expose a new public export-planning API

## Storage Model

The manager should track logical storage identities itself rather than trying to infer only from Docker runtime state.

The identity rule should match compiled-scenario semantics:

- if a program mounts `resources.X`, the identity is `(owner_moniker, X)`
- if a program mounts `slots.Y`, follow the binding edge to the source `resources.X`; the identity is `(resource_owner_moniker, X)`

This is derived from the compiled scenario graph, not from a public Amber storage planner API.

Operational rules:

- same logical identity plus same Compose project name means the same Docker volume is reused
- additive storage changes create new volumes
- removed storage identities are retained but detached
- the manager should never silently delete detached storage on upgrade
- storage destruction happens only on explicit delete with `destroy_storage=true`
- the manager records the actual generated Docker volume names from emitted runtime artifacts so it can later destroy them without depending on private Amber naming helpers

This is intentionally conservative.

The first version should not attempt automatic content migration between different logical storage identities.

Not chosen:

- exposing Amber’s private storage lowering logic as a public API dependency for the manager

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
- the resolved-tree path already exists for optional bundle retention
- stored `ScenarioIr` is sufficient to recreate the same Compose scenario revision
- Compose generation from IR already exists
- current public config helpers are enough for root-config materialization
- the manager can walk IR directly for the metadata it needs
- the manager can use existing tooling metadata where that is the natural source of truth
- the manager can use the existing `amber-proxy` crate

## Additional Amber Changes

No additional Amber changes are required for a robust first implementation.

The first implementation should **not** wait on any of the following:

- a new public inspect API
- a public storage-planner API
- a public mesh-planner API
- a public config-planner API
- a new manager-specific IR

Possible future Amber cleanup that could be useful if justified by multiple consumers, but is **not assumed by this design**:

- a small public derived-facts reporter for general tooling
- a public structured-config-to-env helper

Those are optional future cleanups, not blockers.

## Assumptions And Constraints Made Explicit

This section records constraints that are now explicit in the design.

### The manager is an Amber consumer, not an Amber planner extension

The manager builds on Amber’s stable scenario and reporter boundaries. It does not assume Amber will expose its private lowering logic.

### Inspect is based on IR-level facts

The manager’s inspect API reports what is derivable from `ScenarioIr` and public helpers.

In particular:

- root config leaves are schema leaves
- inspect does not attempt to reproduce Amber’s private runtime-pruned execution-guide behavior

### Tooling metadata is a real contract

The manager may depend on `x-amber` and `amber-proxy.json` because those are already intended to be read by tooling.

### Actual generated runtime identifiers should be recorded, not recomputed through private logic

Where the runtime output generates concrete names, such as volume names, the manager records those outputs rather than coupling itself to private helper functions.

### Secrets are a manager concern

Amber’s config schema can mark secret leaves, but secret-at-rest handling belongs to the manager. The first version uses local manager-owned secret storage rather than requiring an external secret manager.

### Optional bundle retention must use the resolved-tree path

If the manager stores bundles, it should do so from the resolved tree before or alongside compilation. Bundles are not reconstructed from stored IR.

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

### Pivot: derive manager facts from IR and current tooling metadata

At one point the discussion drifted toward the idea that Amber needed to expose new public inspect and planning APIs for the manager.

That was rejected for the first version.

Reason:

- the manager can derive its persistent facts from `ScenarioIr`
- where runtime artifacts already carry tooling metadata, that metadata can be consumed directly
- exposing private planner logic would create a broader and less stable Amber API surface than is necessary

Conclusion:

- derive facts from IR when possible
- use current tooling metadata where appropriate
- do not block the manager on new public Amber planner APIs

### Pivot: keep planner logic private

At one point the discussion considered exposing Amber’s storage logic directly because the manager cares about storage identity.

That was rejected.

Reason:

- planner internals are not the right public dependency surface
- if Amber later exposes anything here, it should expose stable facts, not private lowering structures

Conclusion:

- planner logic stays private
- the manager tracks storage using compiled-scenario semantics and emitted runtime artifacts

### Pivot: distinguish IR-level inspect from private runtime-pruned config facts

At one point the discussion risked conflating “all root config leaves” with Amber’s narrower execution-guide notion of runtime-used root inputs.

That was corrected.

Reason:

- the execution-guide behavior depends on private config planning semantics
- the manager does not need that narrower contract for the first version

Conclusion:

- inspect exposes root schema leaves
- the manager does not depend on private runtime-pruned config analysis for its public API

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

### Pivot: no essential Amber features are missing

At one point the design discussion assumed the manager needed Amber-side feature work before it could be built cleanly.

That turned out to be too strong.

Conclusion:

- the manager can be built now
- no Amber public API expansion is required for the first version
- future Amber cleanups remain optional and should only be exposed publicly if they are generally useful beyond this manager

## Final Recommendation

Implement `amber-scenario-manager` now as a Rust daemon that:

- accepts a source URL
- compiles it with Amber
- stores `ScenarioIr` for every active revision
- optionally stores bundles
- derives inspect and storage facts from stored IR
- generates Compose from the stored IR
- consumes current tooling metadata where runtime artifacts are the natural source of truth
- reconciles Compose and runs `amber-proxy` in-process for host bridging
- persists desired state, scenario metadata, and non-secret configuration
- stores secret config leaves separately and redacts them from read APIs
- restarts from stored IR after reboot
- upgrades by recompiling the source URL into a new revision
- preserves storage conservatively by logical identity and fixed Compose project name

That is the smallest design that is:

- concrete
- grounded in current Amber behavior
- implementable now
- consistent with Amber’s current compiler-like architecture
- operationally robust on a single machine

