# Mixed-Site Execution and Direct `amber run`

## Status

Design proposal based on discussion and a codebase review of the current compiler, reporters, and runtimes.

This document is intentionally detailed. It records both the proposed design and the paths we explicitly decided not to take, so that later implementation work does not silently drift back toward rejected assumptions.

## Objective

Amber should evolve from a tool that mostly emits artifacts into a tool that can directly execute a scenario manifest.

The primary user-facing objective is:

- `amber run <manifest>` should execute a manifest directly.
- The manifest accepted by `amber run` should be able to contain any mix of runnable program kinds in any topology.
- The manifest should continue to describe what the scenario is, not how it is scheduled.
- The first version should support a human-authored placement file, with local automatic placement as the default when no placement file is provided.
- `amber compile` should remain available, but its primary runtime-bearing output should be a lowered mixed-site run plan rather than final Compose or Kubernetes artifacts.

The core technical objective is:

- introduce an explicit execution planning layer between `ScenarioIr` and the current backend-specific plans and artifacts.

That layer must support a scenario where, for example, a container depends on a VM which depends on another container which depends on a direct host program, even when those components are assigned to different runtime sites.

## Problem Statement

Amber's current architecture already has an important semantic split:

- the compiler core resolves, links, validates, and optimizes manifests into a backend-neutral `Scenario`
- `ScenarioIr` serializes that backend-neutral graph
- backend-specific reporters then lower the scenario into direct, VM, Docker Compose, or Kubernetes outputs

This split is visible in the code:

- `compiler/src/lib.rs` compiles to `CompileOutput`
- `compiler/scenario/src/ir.rs` defines `ScenarioIr`
- `compiler/src/reporter/mod.rs` converts compile output into `CompiledScenario`
- backend-specific lowering then happens in:
  - `compiler/src/targets/direct/mod.rs`
  - `compiler/src/targets/vm/mod.rs`
  - `compiler/src/targets/mesh/docker_compose/mod.rs`
  - `compiler/src/targets/mesh/kubernetes/mod.rs`

The current limitation is not in the manifest format or the linker. The limitation appears later, during backend-specific planning.

Today Amber effectively assumes:

- one compiled runtime artifact corresponds to one runtime environment
- one runtime environment contains the entire runnable scenario
- all runnable components in that artifact must be supported by one reporter/backend

This assumption leaks into:

- `ProgramSupport` and `RuntimeAddressResolution` in `compiler/src/targets/program_config.rs`
- mesh peer addressing in `compiler/src/targets/mesh/mesh_config.rs`
- mesh provisioning in `compiler/src/targets/mesh/provision.rs`
- direct and VM runtime startup in `cli/src/main.rs` and `cli/src/vm_runtime.rs`
- proxy metadata and `amber proxy` target resolution in `compiler/src/targets/mesh/proxy_metadata.rs` and `cli/src/main.rs`

`amber run` is also currently much narrower than the desired future behavior:

- it only dispatches to direct or VM artifacts
- it does not compile manifests as part of the run path
- it does not know how to manage Docker Compose or Kubernetes sites

## Current Code Findings

The design is grounded in a review of the current code structure.

### Backend-neutral pieces that already exist

These are good foundations and should be preserved:

- `compiler/src/lib.rs`
  - `Compiler::compile_from_tree` produces backend-neutral `CompileOutput`
- `compiler/scenario/src/ir.rs`
  - `ScenarioIr` is graph-only
- `compiler/src/reporter/mod.rs`
  - `CompiledScenario` remains a thin wrapper around scenario data
- `compiler/src/targets/mesh/plan.rs`
  - `build_mesh_plan` resolves runnable components, bindings, exports, and strong dependencies without enforcing one backend for the entire scenario

### Where homogeneity is currently enforced

The current "one output backend for the whole runnable scenario" rule is introduced later by runtime planning:

- `compiler/src/targets/program_config.rs`
  - `ProgramSupport::{Image, Path, Vm}`
  - `RuntimeAddressResolution::{Static, Deferred}`
  - `build_config_plan`
  - `build_program_plan`

Each current reporter passes one global support mode for the entire scenario:

- direct reporter uses `Path` plus deferred runtime address resolution
- VM reporter uses `Vm` plus deferred runtime address resolution
- Compose reporter uses `Image` plus static address resolution
- Kubernetes reporter uses `Image` plus static address resolution

This is why the new execution-planning layer belongs above backend-specific site lowering but below `ScenarioIr`.

### Why mixed execution cannot be bolted on only in `amber run`

The current local runtimes already assume that the entire mesh for an artifact is local:

- direct runtime allocates local ports and rewrites peer addresses in `cli/src/main.rs`
- VM runtime does the same in `cli/src/vm_runtime.rs`

Meanwhile proxy logic assumes one target artifact and one router:

- proxy target loading and router resolution happen in `cli/src/main.rs`
- proxy metadata is still single-router metadata in `compiler/src/targets/mesh/proxy_metadata.rs`

These are not merely CLI problems. They are consequences of the missing execution-planning layer.

### Observability is already present, but it is backend-asymmetric

The current code already has a substantial observability stack:

- `runtime/mesh/src/telemetry.rs`
  - shared OTLP trace and log initialization
  - common resource attributes such as run id, component moniker, and scenario scope
- `runtime/router/src/main.rs` and `runtime/router/src/lib.rs`
  - router-side spans and logs for HTTP exchanges across Amber mesh edges
- `runtime/helper/src/main.rs`
  - helper-side OTLP initialization for helper-launched programs
- `cli/src/main.rs`
  - OTLP initialization for `amber proxy`
- `compiler/src/targets/mesh/docker_compose/mod.rs`
  - per-scenario OpenTelemetry collector service for Compose output
  - OTLP environment injection for routers and programs
  - Docker log collection and forwarding
- `compiler/src/targets/mesh/kubernetes/mod.rs`
  - per-scenario OpenTelemetry collector deployment or daemonset for Kubernetes output
  - OTLP environment injection for routers and programs
  - Kubernetes pod log collection and forwarding

That means the observability problem is not "how do we add telemetry from scratch".

The real problem is that current observability is not uniform across runtimes:

- Compose and Kubernetes already materialize site-local collectors and inject OTLP configuration into the runtime.
- Direct and VM runtimes currently do not have an equivalent first-class collector path.
- The direct runtime clears process environments down to `PATH`, `HOME`, `TMPDIR`, plus explicitly supplied variables, so observability configuration cannot simply leak through ambient shell state.
- The helper runtime also intentionally drops most ambient environment variables for child programs, so any future mixed-site observability setup must be injected explicitly into runtime plans and helper payloads.

This asymmetry matters for mixed-site execution. If left alone, the system would have one collection model for Compose and Kubernetes and a different, weaker one for direct and VM.

## Design Summary

The first version introduces six distinct concepts:

1. `ScenarioIr`
   - backend-neutral graph IR
   - represents the scenario itself
   - does not describe site assignment

2. placement file
   - human-writable in the first version
   - versioned and separate from the manifest
   - may also be generated by tooling
   - intentionally simpler than the future cost-aware graph-placement system

3. normalized placement
   - explicit assignment of runnable components to concrete sites
   - produced from a placement file or from local automatic placement
   - consumed by `RunPlan` construction
   - may later be exposed directly as a placement lock

4. `RunPlan`
   - the concrete serialized form of the mixed-site execution plan
   - lower than `ScenarioIr`, but higher than `DirectPlan`, `VmPlan`, Compose YAML, or Kubernetes YAML
   - contains site plans, cross-site routing requirements, discovery requirements, and coordinator-visible runtime metadata

5. launch bundle
   - a machine-bound, exact prelaunch materialization of what `amber run` will execute
   - lower than `RunPlan`
   - contains rendered site artifacts plus exact commands, launch specs, generated files, and concrete local values Amber chose before start
   - is an internal IR in the first version, but can be emitted for debugging

6. site managers
   - runtime adapters that materialize and manage a site
   - direct and VM remain internal
   - Compose and Kubernetes are delegated to native tooling

The resulting first-version pipeline becomes:

`manifest or bundle -> Scenario -> ScenarioIr -> placement file or local automatic placement -> normalized placement -> RunPlan -> launch bundle -> site managers -> running scenario`

The future pipeline can later grow richer placement inputs, but the first version should keep the authored placement file intentionally simple and human-writable while keeping the normalization kernel explicit.

## Design Decisions Already Made

### Decision: placement must not inherit from the component tree

This was discussed explicitly and rejected.

The manifest/component structure is a tree, but scheduling is not tree-shaped. Scheduling overlays the runnable component dependency graph onto a site graph. A valid placement can assign:

- component `A` to site `S1`
- component `B` to site `S2`
- component `C` to site `S1`

even when the dependency structure is `A -> B -> C`.

Therefore:

- placement cannot be modeled as simple parent-to-child inheritance
- tree-locality may still matter for names, manifests, and some routing structure, but it is not a valid scheduling model

Any design that uses manifest-tree inheritance as the core assignment mechanism is impermissible.

### Decision: do not put placement in the manifest

The manifest should continue to describe what exists, not how it is scheduled.

Putting runtime placement in the manifest would:

- mix execution policy into scenario semantics
- make third-party manifests harder to reuse
- blur the boundary between author intent and operator/site-specific deployment decisions
- make future automatic placement harder to express cleanly

Placement must remain separate from the manifest.

### Decision: do not put placement into `ScenarioIr`

`ScenarioIr` is currently the backend-neutral representation of the scenario graph. That property is valuable and should be preserved.

Placement is lower-level and more operational than `ScenarioIr`. It depends on:

- site availability
- site capabilities
- site cost
- site connectivity
- operator policy

Those are not intrinsic properties of the scenario graph.

Therefore:

- `ScenarioIr` stays graph-only
- execution planning happens below `ScenarioIr`

### Decision: restore a human-authored placement file, but keep an explicit placement kernel

We previously discussed dropping placement files from the first version and relying only on local automatic placement.

That decision should be walked back.

Without a placement file, Amber cannot deliberately choose Kubernetes instead of Compose on a machine that has both, cannot target KinD predictably in tests, and cannot force heterogeneous test topologies such as Compose plus Kubernetes plus VM plus direct.

The corrected first-version design should therefore:

- support a human-authored placement file
- keep local automatic placement as the default when no placement file is provided
- keep the authored placement file intentionally simple rather than trying to solve the full future graph-placement problem
- normalize placement into an explicit component-to-site assignment before `RunPlan` construction
- leave room for richer future placement inputs and for optimizer-generated placement later
- leave open whether that normalized form remains internal or is later exposed as a placement lock

What remains rejected is forcing first-version users to deal with a heavy profile-plus-lock UX before the simple authored path exists.

### Decision: the outside world is a site

This was a meaningful design correction during discussion.

The outside world should be modeled as a site, not as a special top-level mesh router owned by `amber run`.

That means:

- `amber proxy` is conceptually an outside-world site manager
- `amber proxy` starts a router peer like any other site
- `amber proxy` may be started and stopped independently of `amber run` and independently of internal site lifecycles
- external slot binding and export exposure are site-to-site connectivity problems, not special top-level control-plane hacks
- `amber proxy` should attach the outside-world site through the same site-link stitching path that ordinary sites use
- exports and external slots remain the author-facing boundary vocabulary of the scenario
- ordinary internal site-to-site routing must not be modeled as synthetic exports and external slots

This pushes the design away from a special supervisor mesh router.

### Decision: `amber run` is a coordinator, not a mesh peer

Once the outside world is modeled as a site, `amber run` no longer needs to be a top-level router.

Instead, `amber run` should be a coordinator that:

- compiles manifests
- runs local automatic placement
- builds the `RunPlan`
- launches site managers
- discovers site router link URLs and control handles
- wires sites together
- persists run receipts
- stops sites it owns

This is a control-plane role, not a data-plane routing role.

### Decision: first-version mixed-site Kubernetes reachability is Amber-supervised local forwarding

For the first managed mixed-site version, Kubernetes sites should be reached from the coordinating machine through a host-local Amber-supervised forwarding process, expected to be `kubectl port-forward` initially.

This means:

- first-version managed mixed-site runs do not require self-living Kubernetes site-to-site reachability
- automatic `NodePort`, `LoadBalancer`, or ingress creation is out of scope for the first version
- first-version Kubernetes mixed-site runs stay close to the current namespace-scoped local-Kubernetes model
- future self-living Kubernetes reachability remains open, but the first version should not depend on it

### Decision: Amber should delegate to Compose and Kubernetes tooling

Amber should not reimplement Docker Compose or Kubernetes lifecycle logic.

Instead:

- direct and VM sites are managed internally because Amber has no existing orchestrator to delegate to
- Compose sites are managed by shelling out to `docker compose` or another compatible compose driver
- Kubernetes sites are managed by shelling out to `kubectl` initially

Amber remains the mixed-site orchestrator and planner, but it does not become a second container orchestrator.

### Decision: the primary compiled runtime output is `RunPlan`

In a heterogeneous-site world, compiling directly to `--compose` or `--k8s` is not the foundational lowering anymore.

The primary runtime-bearing compile output should be a mixed-site `RunPlan` that is as lowered as possible while still preserving the coordinator's ability to start sites, discover endpoints, and stitch site routers together.

### Decision: exact launch debugging should come from the real launch path

Users debugging mixed-site runs need to see what Amber will actually launch, not just a higher-level plan and not just what happened after a run finished.

That means the debug surface should not be a separate reporter that guesses at runtime behavior.

Instead:

- `amber run` should internally materialize a machine-bound launch bundle from the `RunPlan`
- the actual launch path should consume that same launch bundle
- any debug-bundle or dry-run output should serialize that same internal launch bundle

This avoids the most damaging failure mode for debuggability: a debug view that drifts away from the real launcher.

In the first version, the launch bundle should remain an internal IR rather than a first-class public input accepted by `amber run`.

This avoids making `amber compile` produce final single-environment artifacts when the actual scenario may require multiple environments.

### Decision: preserve homogeneous unmanaged UX explicitly, not implicitly

There is a real usability concern here.

If a homogeneous container scenario can only be run through `amber run`, then using the compiled output on a machine without Amber would become harder than it is today.

The design should therefore distinguish:

- the primary compiled runtime artifact, which is `RunPlan`
- optional unmanaged exports for homogeneous scenarios, such as raw Compose or raw Kubernetes output

Those unmanaged exports may remain as compatibility conveniences or move to a separate export surface, but they should be treated as homogeneous exports derived from the same planning pipeline, not as the core meaning of compilation.

## Goals

- `amber run` accepts manifests directly
- mixed-site execution is first-class
- manifests remain placement-agnostic
- human-authored placement is workable in the first version
- the first version works without a placement file
- the placement kernel normalizes every run to an explicit assignment before `RunPlan` construction
- placement can later be generated by tooling without changing the rest of the runtime pipeline
- users can inspect the exact machine-bound launch Amber is about to perform without starting heavy workloads
- Compose and Kubernetes remain native site runtimes, not emulations inside Amber
- proxying and outside-world interaction continue to work with the site model
- direct and VM observability are raised to the same first-class level as Compose and Kubernetes as part of this change
- managed observability is explicit opt-in rather than enabled by default
- the design remains compatible with future cost-aware and topology-aware placement
- the primary compiled runtime artifact is a versioned `RunPlan`

## Non-Goals

- solving the future cost-aware placement optimization problem here
- designing the full future optimizer-facing placement language in the first version
- forcing users to author a fully explicit component-to-site map for every run
- exposing every internal runtime artifact as a first-class public CLI input in the first version
- defining exact heuristics for "chatty" components
- defining the entire future site capability schema in exhaustive detail

The design must leave space for those later concerns without forcing them into the first usable implementation.

## Constraints

### Constraint: placement is a graph-on-graph problem

The future optimizer is conceptually overlaying the runnable component graph onto a site graph.

The site graph captures things such as:

- latency between sites
- bandwidth between sites
- monetary or operational cost
- CPU, GPU, memory, storage, and accelerator constraints
- local versus remote reachability

The component graph captures things such as:

- dependency edges
- capability flow
- future communication intensity hints
- resource needs

This is an optimization problem, but the first version deliberately does not solve it. The design only needs to avoid foreclosing a future richer placement file.

### Constraint: the current code assumes static peer addresses per artifact

Current mesh planning lowers links into the existing Noise-over-TCP router layer and expects peer addresses to be fully known inside a compiled artifact.

That breaks down for mixed-site execution because:

- direct and VM sites discover local runtime ports at launch time
- Compose sites may not have published router ports known until startup
- Kubernetes sites may require service discovery, port-forwarding, or externally reachable router addresses that are not known at pure compile time

Therefore the mixed execution plan cannot assume that all routed links are fully materialized during compile, and it should not bake socket-shaped link materialization into its higher layers.

Links remain URLs in the lowered execution model. The first mixed-site implementation may still lower those URLs into the current Noise-over-TCP router layer, with Kubernetes in the first version using host-local port-forwarding only as a reachability mechanism for that same current layer.

Future router work may change the lowest link layer uniformly to HTTP(S), but the planning model should not require Amber to preserve one protocol for inter-site links and another for intra-site links.

### Constraint: proxy behavior currently assumes one target artifact and one router

The current proxy model assumes one output directory with one router block in proxy metadata.

That is insufficient for a world of multiple sites.

The new design must allow:

- `amber proxy` to act as an outside-world site
- `amber run` to provide enough non-authoritative discovery metadata for the proxy site to discover and peer with the required internal sites

### Constraint: first-version local placement must be deterministic

Without a placement file, `amber run` cannot guess arbitrarily among multiple equivalent local site choices.

The first-version local automatic placement policy must therefore be:

- deterministic
- easy to explain
- conservative when required tooling is missing

It should not hide major placement choices behind opaque heuristics.

### Constraint: first-version storage placement is site-local to storage consumers

Storage is not just another routable network capability.

Amber already carries storage resource parameters such as:

- `size`
- `retention`
- `sharing`

Mixed-site execution must preserve the manifest's storage-routing intent rather than silently relocating storage to an arbitrary site.

For the first version, storage should only be materialized on the site or sites that contain its mounted consumers.

That implies:

- Amber must not place storage on a third site that does not contain the consuming workload
- if multiple consumers of one storage object are allowed by the manifest's sharing mode, they must still be co-located on one site in the first version
- if placement would spread one mounted storage object across multiple sites, planning must fail

The future optimizer may later move storage more intelligently or introduce richer storage-placement semantics, but the first version should stay strictly consumer-local.

### Constraint: direct and VM runtimes currently own the whole local mesh

The direct and VM runtimes currently:

- provision all mesh identities locally
- allocate local runtime ports
- rewrite peer addresses assuming all peers are local

That only works when the entire runnable scenario is inside the direct or VM artifact.

In a mixed-site design, direct and VM site runtimes must be able to manage only their local site while leaving remote site peers as remote peers.

### Constraint: router identity and mesh scope must become stable across site types

Current backends derive router identity and mesh scope in backend-specific ways.

That is not acceptable once sites need to peer with one another across backends.

The mixed-site design needs:

- one stable scenario mesh scope, computed before any backend-specific transformation
- stable site router identities derived from the site identity, not from backend flavor

## Terminology

### Site

A site is a concrete placement target and runtime instance.

It is not just a backend kind such as "Compose" or "Kubernetes". It is one specific instance of a runtime environment with its own identity, connectivity, and storage locality.

Examples:

- one specific direct-execution machine
- one specific VM host or VM provider instance
- one specific Docker Compose environment on one machine
- one specific Kubernetes cluster or namespace
- the outside world, as represented by `amber proxy`

That means a run may legitimately contain multiple sites of the same kind, for example:

- two different direct machines
- two different Kubernetes clusters
- two different namespaces in the same cluster
- two different Compose environments on different hosts

A site is not the same thing as a manifest environment. The manifest already uses `environment` for manifest resolution. This design uses `site` to avoid that collision.

### Site manager

A site manager is the runtime adapter responsible for materializing and managing one site.

Examples:

- direct site manager
- VM site manager
- Compose site manager
- Kubernetes site manager
- proxy/outside-world site manager

### Local automatic placement

The fallback built-in policy that assigns runnable components to local sites after tool detection when no placement file is provided.

### Placement file

A human-authored planning file that influences execution planning without changing scenario semantics.

In the first version, this file should stay deliberately simple, but it must be strong enough to:

- choose major backends such as whether `program.image` components run via Compose or Kubernetes
- force specific mixed-site layouts for development and smoke tests
- target local Kubernetes environments such as KinD predictably

It should not try to be the final optimizer-facing placement language yet.

Although a future optimizer may generate this file, it must remain workable for humans to write and review directly.

### Normalized placement

The explicit placement result produced by resolving either:

- a human-authored placement file
- local automatic placement
- a future richer placement input

This normalized form assigns every runnable component to one concrete site and resolves the concrete site definitions needed by planning.

The rest of the execution pipeline should depend on this normalized form rather than on the authored placement syntax directly.

### Placement lock

A placement lock is an optional serialized form of normalized placement.

The kernel should be designed so that normalized placement could be emitted and later re-consumed as a placement lock without changing `RunPlan` construction.

Whether the first version exposes placement locks as a first-class user artifact remains open, but the internal model should already support that split.

### RunPlan

A compiled plan describing:

- which components run at which sites
- how cross-site routing works
- what site plans must be materialized
- what discovery information must be resolved at launch time
- what site managers are responsible for each site

### Launch bundle

A machine-bound prelaunch artifact derived from a `RunPlan`.

It is lower than `RunPlan` and is intended to answer the practical debugging question "what exactly will Amber launch on this machine if I proceed?"

It should contain things such as:

- rendered Compose and Kubernetes artifacts
- exact `docker compose` and `kubectl` invocations Amber will use
- exact direct-process launch specs, including argv, non-secret env, mounts, and generated files
- exact VM launch specs, including QEMU argv, disks, forwards, and generated files
- concrete local ports, temp paths, control paths, and other machine-bound values Amber chose during prelaunch materialization

In the first version it is an internal IR. Amber may emit it for debugging, but it should not yet be a first-class public input accepted by `amber run`.

## First-Version Placement File, Normalization, and Local Automatic Placement

The first version should have a human-authored placement file.

When a placement file is present, the planner should honor it.

When a placement file is absent, the planner should:

- detect locally available site managers
- construct a deterministic local placement

This keeps the developer UX simple for trivial local runs without making mixed-site planning untestable or forcing machine-default backend choices.

### Why the kernel needs an explicit normalized placement step

The authored first-version placement file is intentionally simple.

That simplicity should not leak into the execution-planning kernel.

The planner should always normalize placement into an explicit assignment before `RunPlan` construction because that gives Amber:

- one stable internal shape regardless of whether placement came from a file or from local automatic placement
- deterministic planning inputs for debugging and testing
- a clean growth path for richer future placement inputs
- a clean growth path for machine-generated placement, whether that reuses the authored file format or emits a separate placement lock

This is the key design point that keeps the first version simple for humans without making the core planning pipeline ad hoc.

### Post-placement site compatibility validation

Normalized placement is not the final compatibility check.

After placement normalization and before `RunPlan` emission, Amber must validate that each assigned site can actually realize its assigned subset under first-version constraints.

This validation pass is required because the current lowerers still encode backend-specific assumptions and the first-version site kinds are not yet perfectly interchangeable.

At minimum it should validate:

- backend-specific program support restrictions that still exist in the current direct, VM, Compose, and Kubernetes lowerers
- site-manager capability mismatches discovered only after the concrete site set is known
- first-version storage-locality and residency constraints
- first-version reachability constraints such as Kubernetes mixed-site runs using Amber-supervised local forwarding

Clear diagnostics from this are part of the feature. The planner must not pretend that every normalized placement is realizable and leave incompatibilities to fail later deep inside site renderers.

### Placement file shape and versioning

Even the simple first-version placement file should be explicitly versioned.

The recommended shape is the same style used for `ScenarioIr` and `RunPlan`:

- a stable schema identifier
- a monotonically increasing integer version

For example:

- schema: `amber.run.placement`
- version: `1`

An illustrative first-version shape is:

```json
{
  "schema": "amber.run.placement",
  "version": 1,
  "sites": {
    "compose_local": { "kind": "compose" },
    "kind_cluster": { "kind": "kubernetes", "context": "kind-amber" },
    "vm_local": { "kind": "vm" },
    "direct_local": { "kind": "direct" }
  },
  "defaults": {
    "path": "direct_local",
    "vm": "vm_local",
    "image": "compose_local"
  },
  "components": {
    "/root/api": "kind_cluster",
    "/root/worker": "vm_local",
    "/root/tool": "direct_local"
  }
}
```

This is only illustrative, but it shows the minimum capability the first version needs:

- declaring named sites
- selecting each site's manager kind
- allowing simple site-specific settings such as a Kubernetes context
- allowing defaults by program kind
- allowing explicit component-to-site overrides

Those last two points are what make deliberate mixed-site tests possible.

This should not use semver in the first version.

Semver would suggest a stronger compatibility contract than Amber needs for an execution-planning file that is consumed by one toolchain. A schema plus integer version is simpler and matches the existing IR story better.

It also should not use a compatibility date. This is a structured local planning artifact, not a time-based policy surface.

The compiler should accept supported older placement-file versions and normalize them into the current internal representation just as it does for older `ScenarioIr` versions when feasible.

### Two reasonable ways to surface generated placement later

There are two reasonable long-term shapes here.

1. One placement file format serves both authored and generated uses.

Pros:
- simpler public surface
- fewer artifact kinds to explain

Cons:
- pressure to make the authored file more verbose over time
- harder to keep human-authored and machine-normalized concerns separate

2. Authored placement file plus placement lock.

Pros:
- keeps the human-authored surface focused on intent
- gives tooling and debugging a deterministic explicit artifact
- avoids rerunning placement normalization when the user already wants a frozen assignment

Cons:
- more public surface area
- more naming and UX choices to make

Recommendation:

- design the kernel around normalized placement now
- keep the first-version authored placement file simple
- leave open whether normalized placement stays internal for a while or is exposed as a placement lock once that adds enough value

That recommendation matches the original intent: simple human authoring now, solid placement kernel underneath, and room for later machine generation without redesigning the pipeline.

### Illustrative normalized-placement shape

Even if the first version does not expose it directly, the internal normalized form should look much closer to this:

```json
{
  "schema": "amber.run.placement.lock",
  "version": 1,
  "sites": {
    "compose_local": { "kind": "compose" },
    "kind_cluster": { "kind": "kubernetes", "context": "kind-amber" },
    "vm_local": { "kind": "vm" },
    "direct_local": { "kind": "direct" }
  },
  "assignments": {
    "/root/api": "kind_cluster",
    "/root/worker": "vm_local",
    "/root/tool": "direct_local",
    "/root/web": "compose_local"
  }
}
```

This is the level of explicitness that `RunPlan` construction should consume, regardless of whether Amber got there from a hand-written placement file, local automatic placement, or a future optimizer.

### Why the placement file is needed in the first version

The placement file is not just a future ergonomics feature. It is needed immediately for correctness, testing, and explainability.

Concrete examples:

- a machine may have both Compose and Kubernetes available, and Amber needs a human way to say which backend should run image components
- KinD-based tests need to force Kubernetes placement rather than relying on whatever automatic default Amber would otherwise choose
- mixed-site smoke tests need to force scenarios such as Compose plus Kubernetes plus VM plus direct
- manual debugging of a mixed scenario often requires a stable, explicit placement that can be checked into the repo and rerun

### Tool detection

The planner should detect at least:

- direct local capability
  - the existing direct runtime requirements still apply
- VM local capability
  - QEMU or libvirt-backed VM runtime requirements
- Compose local capability
  - `docker compose` or an equivalent compose-capable local runtime
- Kubernetes local capability
  - `kubectl`

Tool detection exists for two reasons:

- to know what the machine can run locally
- to produce clear diagnostics when a scenario cannot be locally placed

### First-version default placement policy

When no placement file is provided, the fallback policy should be explicit and deterministic:

- `program.path` components go to the local direct site
- `program.vm` components go to the local VM site
- `program.image` components go to the local Compose site

This policy is intentionally simple.

It avoids a much harder unresolved question: if both Compose and Kubernetes are locally available, should container-image components default to Compose or Kubernetes? The first version should not guess.

The recommendation is:

- default image components to local Compose
- do not auto-place image components onto Kubernetes in the first version
- keep Kubernetes available for explicit homogeneous export and for the placement file

This preserves determinism and keeps the first version understandable.

### First-version placement-file override policy

The placement file should override the default local policy where it says something explicit.

In the first version, the key supported controls should be:

- naming the available sites
- selecting each site's manager kind
- setting program-kind defaults such as image to Compose or image to Kubernetes
- overriding specific components onto named sites

That means:

- without a placement file, `program.image` defaults to Compose
- with an image default pointing at a Compose site, the result is the same as the fallback but explicit
- with an image default pointing at a Kubernetes site, `program.image` components target Kubernetes instead
- with explicit component overrides, the user can force mixed layouts for testing or debugging

This gives `amber compile --run-plan` and `amber run` a simple, human-authored, versioned way to avoid machine-default ambiguity without dragging in the full future placement design.

### Failure behavior

If the local machine lacks a required site manager for some component kind, planning should fail with a direct diagnostic.

Examples:

- scenario contains `program.vm`, but local VM runtime prerequisites are missing
- scenario contains `program.image`, but no Compose-capable runtime is available
- scenario contains `program.path`, but the direct runtime prerequisites are missing

These diagnostics should be framed as placement failures, not as deep backend errors.

### Future extension point

The architecture must still leave room for a richer human-authored placement file.

That richer input should still normalize into the same explicit placement kernel before `RunPlan` construction, rather than introducing a second unrelated planning pipeline.

Likely future growth areas include:

- ordered selector rules
- named groups
- same-site or different-site constraints
- site capability requirements
- soft cost hints for later optimizers

Those should be treated as future authored-input features over the same normalization kernel, not as a replacement for the kernel.

## RunPlan and Site Planning

### High-level structure

The `RunPlan` contains:

- scenario identity and stable mesh scope
- detected local sites, each with a site manager kind
- component-to-site assignments
- normalized-placement provenance
- site-local storage requirements
- local site dependency information
- cross-site dependency information
- local site router requirements
- cross-site routing links
- site materialization data
- launch-time discovery requirements
- predeclared outside-world attachment information

An illustrative shape is:

```text
RunPlan
  scenario_id
  mesh_scope
  normalized_placement_digest
  sites[]
    site_id
    site_manager
    site_plan
    local_components[]
    local_storage[]
    local_router
    local_dependencies[]
    cross_site_ingress[]
    cross_site_egress[]
    discovery_requirements[]
  external_interface
```

This is intentionally above backend-specific direct/VM/Compose/Kubernetes artifacts. It is the mixed-site plan, not the final single-site plan.

An illustrative serialized shape is:

```text
RunPlan
  version
  scenario_id
  mesh_scope
  normalized_placement_digest
  planner_kind
  planner_inputs
  sites[]
    site_id
    site_manager_kind
    assigned_components[]
    site_router
      identity_id
      exposure_policy
      control_policy
    local_site_plan
    local_dependency_edges[]
    cross_site_inbound_edges[]
    cross_site_outbound_edges[]
    discovery_requirements[]
  outside_world_interface
    outside_world_site_id
    supported_exports[]
    supported_external_slots[]
```

The `RunPlan` should be serializable and versioned. Even if it is initially an internal artifact used by `amber run`, it is still a real IR and should be treated like one.

The outside-world site should be predeclared in the `RunPlan` even if it is attached later by `amber proxy`. That keeps later proxy attachment as a continuation of the same site connectivity model rather than a separate ad hoc mode.

### Relationship to the launch bundle

The `RunPlan` is still not the exact thing that gets launched.

It may still contain:

- symbolic discovery requirements
- symbolic cross-site stitching intent
- site plans that have not yet been rendered into backend-native files
- values that become concrete only when Amber chooses machine-local ports, paths, project names, or similar launch-time details

Before starting any heavy workload, `amber run` should materialize the `RunPlan` into a launch bundle.

That launch bundle is the exact prelaunch debugging surface and the exact internal input to the launcher.

This split is important:

- `RunPlan` is the stable mixed-site execution IR
- launch bundle is the machine-bound exact launch artifact

The first version should keep the launch bundle internal, but the architecture should treat it as a real IR rather than as an ad hoc dump.

### Site plans

Each site plan is site-manager specific.

Examples:

- direct site plan
- VM site plan
- Compose site plan
- Kubernetes site plan

These are the plans the site managers actually know how to materialize and run.

The `RunPlan` is the mixed wrapper around those site plans.

### Relationship to current direct and VM plans

The current direct and VM plans are already low-level execution plans.

In the new design they become:

- special cases of site plans
- no longer equivalent to "the entire runnable scenario"

They need to be refactored so they can represent only a single local site plus remote peer references.

### Relationship to Compose and Kubernetes output

Compose YAML and Kubernetes manifests are still valid site-manager outputs.

They should not be treated as the primary compile result in the mixed-site design.

Instead:

- a Compose site plan materializes into Compose artifacts
- a Kubernetes site plan materializes into Kubernetes artifacts
- `amber run` asks the corresponding site manager to use those artifacts
- optional unmanaged homogeneous exports, if preserved, should be derived from the same planning pipeline

## Mixed-Site Storage

### Storage remains part of scenario semantics

If the manifest routes storage through a resource binding and a mounted storage slot, Amber should preserve that intent.

Mixed-site planning must not treat storage as disposable local scratch space that can be recreated anywhere convenient. Storage identity and storage routing remain part of the scenario meaning.

### Current storage model already carries storage policy

Amber resources already carry storage parameters such as:

- `size`
- `retention`
- `sharing`

The mixed-site design must honor the existence of that storage policy rather than assuming all mounted storage is always exclusive.

### First-version storage locality rule

For the first version, storage is always materialized on the consumer site.

More precisely:

- a direct site materializes storage as direct local state under its storage root
- a VM site materializes storage as local VM-attached disk images
- a Compose site materializes storage as site-local Compose volumes
- a Kubernetes site materializes storage as site-local persistent volume claims or equivalent cluster-local storage objects

Amber should not attempt in the first version to place storage on a separate storage-only site, to replicate it across sites, or to mount it remotely across site boundaries.

### Shared storage in the first version

The manifest may already describe storage-sharing policy.

The first-version mixed-site rule should be:

- if one storage object is consumed by mounted workloads on one site, it may be placed on that site
- if one storage object is shared by multiple mounted workloads, those workloads must all land on the same site in the first version
- if planning would place mounted consumers of one storage object on different sites, planning fails

This rule is intentionally conservative. It preserves correctness without inventing cross-site storage protocols.

### Storage and site identity

Because a site is a concrete runtime instance, storage locality is tied to that concrete site identity, not just to a backend kind.

For example:

- a PVC in Kubernetes cluster A is not the same site-local storage as a PVC in Kubernetes cluster B
- a Compose volume on machine X is not the same site-local storage as a Compose volume on machine Y
- a direct storage root on machine M is not the same storage location as a direct storage root on machine N

That is why the `RunPlan` and placement file must operate on concrete site identities rather than on backend kinds alone.

### Storage lifecycle belongs to site bootstrap

Storage provisioning is part of site bootstrap rather than workload startup.

Examples include:

- creating local directories for direct sites
- creating disk images for VM sites
- creating named volumes for Compose sites
- creating persistent volume claims for Kubernetes sites

This is one reason storage bindings are excluded from the startup-wave dependency graph: storage provisioning is infrastructure, not a routed service startup dependency.

## Site Managers

### Why site managers exist

Amber needs a uniform abstraction for launching and observing heterogeneous sites without pretending that all sites are managed the same way.

The site manager abstraction should answer:

- how to materialize the site plan
- how to bootstrap site infrastructure
- how to start a subset of the site's components
- how to observe that those components have started
- how the site remains alive after top-level `amber run` exits
- how to stop the site if Amber owns it
- how to discover the site router endpoint
- how to discover the site router control handle, if any
- how later Amber commands reconnect to a running supervised site and query its live discovery state
- how to report site bootstrap readiness

An important concept here is site residency after commit:

- some sites are self-living once started
- some sites require a detached Amber supervisor to stay alive

The top-level `amber run` coordinator should not itself become that long-lived supervisor.

An illustrative interface is:

```text
enum SiteResidency {
  SelfLiving { locator },
  AmberSupervised { supervisor_locator }
}

trait SiteManager {
  fn materialize(site_plan, workspace) -> MaterializedSite;
  fn bootstrap(materialized_site, run_context) -> BootstrappedSite;
  fn wait_site_ready(site) -> ReadySite;
  fn start_components(site, component_ids);
  fn wait_components_started(site, component_ids, deadline);
  fn discover_router(site) -> RouterDiscovery;
  fn handoff(site) -> SiteResidency;
  fn stop(locator);
}
```

The exact language-level API is open, but the responsibilities are not.

### Normative bootstrap handoff contract

Once a site is bootstrapped and ready for stitching, the site manager must be able to return a concrete router-discovery record for that run.

At minimum, that record must contain:

- the concrete `site_id`
- the router identity id for that site
- a concrete router link URL that peer sites can target for this run
- a concrete router control handle that the coordinator can use for stitching
- the site's anticipated residency mode after commit

Conceptually:

```text
struct RouterDiscovery {
  site_id
  router_identity_id
  router_link_url
  router_control_handle
  residency_mode
}
```

The exact reachability materialization may differ by site type even while the routed link model stays uniform:

- local Amber-managed sites may expose host-local reachability to the current link layer directly
- Compose may publish reachability to that same current link layer through the container runtime
- Kubernetes in the first version reaches that same current link layer through host-local forwarded reachability
- later Kubernetes reachability modes may expose the same link model differently

Future router work may change the lowest link layer uniformly from the current Noise-over-TCP implementation to HTTP(S), but the coordinator should still consume one link abstraction here rather than per-site protocols.

But the semantic contract is the same: by the time a site reports router discovery, the coordinator must have enough concrete information to stitch that site into the run.

### Compose site manager

The Compose site manager should:

- materialize Compose artifacts from the Compose site plan
- choose a project name
- invoke `docker compose` or equivalent
- bootstrap site infrastructure before component workloads
- start component services for each global startup wave via targeted Compose operations
- wait for site router readiness
- report the reachable site router endpoint back to the coordinator
- normally hand the committed site off as self-living
- tear the site down when Amber owns the run

Amber should not reimplement Compose behavior itself.

### Kubernetes site manager

The Kubernetes site manager should:

- materialize Kubernetes artifacts from the Kubernetes site plan
- invoke `kubectl` initially
- create or use the appropriate namespace or labels
- bootstrap site infrastructure first
- establish and supervise the local forwarding processes needed to reach the site router from the coordinator machine in the first version
- apply component workloads in startup-wave batches rather than relying on Kubernetes to express Amber ordering natively
- wait for site router readiness through that supervised reachability path
- hand the committed site off as Amber-supervised in the first version, because the forwarding helper must stay alive after top-level `amber run` exits

For the first mixed-site managed version, the only required Kubernetes reachability mode is a host-local Amber-supervised forwarding path, expected to be `kubectl port-forward` initially.

Amber should not require self-living cluster-routable reachability in v1, and it should not automatically create `NodePort`, `LoadBalancer`, or ingress resources just to make mixed-site runs work.

Future self-living Kubernetes reachability remains open, but it should be treated as a later extension rather than as a prerequisite for the first implementation.

### Direct site manager

The direct site manager remains internal to Amber.

Its runtime must be refactored so that:

- it manages only the local direct site
- remote peers are left as remote peers
- it does not assume that every mesh peer exists in the local runtime directory
- it hands the committed site off to a detached Amber supervisor rather than requiring top-level `amber run` itself to remain alive
- it can start component workloads wave by wave

### VM site manager

The VM site manager also remains internal.

It has the same mixed-site requirement as the direct site manager:

- local management only
- remote peers must remain remote peers
- runtime URL resolution must continue to produce local slot listener addresses for programs, while site-router peer connectivity is handled separately
- local VM sites hand off to a detached Amber supervisor in the first version
- future self-living cloud-VM-backed sites may later use self-living residency instead
- component workloads must be launchable wave by wave

### Proxy or outside-world site manager

`amber proxy` acts as the outside-world site manager.

It should:

- create a router for the outside-world site
- discover whichever internal site routers are relevant for the selected run
- attach its outside-world site to those internal sites through the same stitching contract used for any other site link
- bind exports to local listeners
- bridge external slots to local upstreams
- stop independently when the developer terminates that outside-world site

This is cleaner than treating proxy as a special top-level mechanism.

## Startup and Failure Semantics

### Strong bindings define startup order

Amber already has a precise notion of startup-order dependencies.

Today that is derived from the strong-dependency graph:

- non-weak component-to-component bindings
- excluding storage bindings

Mixed-site startup should preserve that meaning globally.

That implies:

- cross-site strong bindings remain legal
- startup order is defined over the global strong-dependency DAG, not per site
- weak bindings do not gate startup

This is important because requiring cross-site bindings to become weak would make placement leak into scenario semantics.

### Startup uses global waves, not a distributed transaction protocol

Amber does not need a full 2PC-style protocol.

The coordinator is assumed to remain alive through startup, and runs are immutable after creation. That means startup can be a coordinated barrier rather than a general-purpose distributed transaction system.

The recommended startup protocol is:

1. assign a `run_id`
2. materialize all sites
3. bootstrap all site infrastructure in parallel
4. compute global startup waves from the strong-dependency DAG
5. start components wave by wave across all sites
6. after all waves are started, activate exports and commit the run

Site infrastructure bootstrap includes things such as:

- site router
- observability plumbing
- networks, namespaces, services, or storage claims
- mesh or config materialization

It does not mean "every component workload is already live".

### Startup waves are the main complexity-reduction device

The key simplification is that Amber only needs to preserve startup ordering, not arbitrary application health semantics.

That means the coordinator does not need to prove that a provider is semantically healthy before starting its consumers.

It only needs to preserve the same level of guarantee Amber effectively has today:

- providers in strong dependencies start before consumers

Therefore the compiler or planner should compute startup waves from the strong-dependency DAG.

Then the coordinator should:

- start all components in wave 0
- wait until they are minimally started
- then wave 1
- and so on

This keeps the distributed protocol small and keeps the meaning aligned with existing Amber behavior.

### "Started" is intentionally weaker than full readiness

Amber's current startup semantics are ordering-only.

Direct and VM runtimes use a topological startup order. Compose uses startup ordering via `depends_on` with `service_started`. None of those are true end-to-end health checks.

Mixed-site startup should keep that same semantic level.

So for startup waves, "started" should mean the minimal site-manager-specific condition that the workload has actually been launched.

Examples:

- direct: the child process was spawned and did not immediately exit
- VM: the guest process or VM launch was initiated successfully and did not immediately fail
- Compose: the container for that service reached running state
- Kubernetes: the component Pod or main container reached started or running state

This is deliberately not:

- HTTP health checking
- application-specific readiness logic
- proof that traffic can already flow end to end

If Amber later wants richer startup readiness semantics, that should be a separate feature with explicit meaning rather than being smuggled into strong bindings.

### Lower to native site-manager primitives as much as practical

The design should lower startup ordering to each site manager's native primitive as much as practical, but not depend on every site manager having the same expressivity.

That means:

- direct and VM use their existing explicit startup sequencing
- Compose starts services for each wave via targeted `docker compose up`
- same-site Compose `depends_on` can remain as an optimization, but correctness should not depend on it
- Kubernetes applies site infrastructure first, then applies component workloads wave by wave

That last point is important.

Kubernetes does not have a general startup-ordering primitive for arbitrary Amber dependency graphs across Deployments. Amber should not fight `kubectl`, add controllers, or invent CRDs just to get one.

Instead, the Kubernetes site manager should simply apply the relevant component workloads in wave-sized batches. Kubernetes still schedules within each batch however it wants. Amber is only deciding when each batch becomes part of the world.

### Pre-commit failure handling

Startup should have an explicit timeout.

`amber run` should wait for all site bootstrap steps and all startup waves to complete before that timeout.

If startup fails before commit:

- default behavior is best-effort teardown of every reachable started site
- `--no-cleanup` suppresses that automatic teardown
- the command should still surface the `run_id` so later cleanup is possible

This is the right point for aggressive cleanup because the run has not yet committed and external visibility should not have been enabled.

### Post-commit failure handling

After commit, the scenario should not have a permanent centralized controller.

Therefore:

- later failure of one site does not automatically tear down the whole scenario
- failures matter when they are observed by dependent traffic, proxying, or operator tooling
- explicit teardown later happens through `amber stop`

This matches the decentralized runtime model better than a permanent keepalive coordinator would.

### What stays alive after top-level `amber run` exits

After commit, top-level `amber run` should be free to exit.

The run stays alive only through the residency model of each site.

Each committed site must end up in exactly one of two states:

1. self-living
   - the runtime environment keeps the site alive without any long-lived Amber process on the machine that initiated the run
2. Amber-supervised
   - a detached Amber site supervisor must remain alive because the site depends on host-local Amber-managed processes

This keeps the model clean:

- `amber run` is always a startup-time coordinator
- long-lived ownership is a per-site property, not a property of the top-level command

Examples in the first version:

- Compose sites are normally self-living once `docker compose up` has committed the project
- first-version Kubernetes mixed-site sites are Amber-supervised because their inter-site reachability depends on a host-local Amber-managed forwarding helper
- direct sites are Amber-supervised in the first version because their processes and routers are local Amber-managed child processes
- local VM sites are Amber-supervised in the first version because the local QEMU processes, routers, and related helpers still need a host-side Amber supervisor

Future conditional:

- Kubernetes sites may later become self-living once Amber has a truly self-living reachability mode for them
- VM sites backed by self-living cloud VMs may later become self-living if the workloads, routers, and reachability mechanisms all live with the site rather than with a local Amber process

The consequence for `amber stop` is straightforward:

- self-living sites are stopped by reconciling against the site's own durable resources
- Amber-supervised sites are stopped through the recorded supervisor locator or by discovering their supervisor-owned resources by `run_id`

If an Amber-supervised site's detached supervisor dies unexpectedly, that site may die with it. That is acceptable and much cleaner than pretending the top-level coordinator itself should stay alive forever.

### No global authoritative state backend

Amber should avoid Terraform-style global authoritative local or remote state.

That does not mean mixed-site runs can avoid local authoritative state entirely.

The corrected rule is:

- site-native durable resources remain the source of truth for self-living sites where the runtime already gives Amber durable identifiers and discovery
- Amber-supervised sites have local authoritative supervisor state, because the detached supervisor is itself the site-local control plane
- every successful run persists a per-run receipt keyed by the global `run_id`

This keeps Amber out of the business of maintaining a separate global state backend while still admitting the local state that supervised sites actually need.

The receipt and supervisor state must distinguish:

- the global `run_id` for the mixed-site run
- per-site instance locators such as a Compose project name, Kubernetes namespace, or supervisor locator

For Amber-supervised local sites, later commands should reconnect through the persisted supervisor locator and query live site-runtime discovery or introspection from the supervisor rather than relying on duplicated dynamic fields in the receipt.

Router-owned facts should remain router-owned.

Later commands should discover current site-runtime facts such as lifecycle status, router link URL, and router control handle through the supervisor or site-native discovery path, then query the router control plane itself for router identity and boundary metadata when those facts are needed.

The receipt should let later Amber commands stop, inspect, or attach to the run without recompiling mutable manifests, but it should do so primarily by pointing those commands at the right live control planes rather than by caching a large scenario snapshot.

### `amber stop`

The natural companion to the startup model is an explicit `amber stop` command.

`amber stop` should:

- take a `run_id` or an equivalent local convenience handle
- load the local run receipt when available
- use recorded site instance locators and supervisor locators first
- obtain the current site-runtime view where available before issuing stop
- use site-native discovery by `run_id` as a fallback or supplement for self-living resources
- issue idempotent stop operations to every reachable site
- report partial cleanup when some sites are partitioned or unreachable

If the receipt is missing, Amber may still do best-effort site-native cleanup by `run_id`, but Amber-supervised local sites may not be fully recoverable in that degenerate case.

This makes cleanup retryable without pretending that local supervisors can be managed with no local state at all.

## Observability

### Objective

Observability in a mixed-site run must answer one simple question reliably:

"How do traces, logs, and metrics from every participating runtime site end up in one coherent run-level view?"

That includes:

- Amber routers and sidecars
- helper-launched programs
- application programs that emit OTLP directly
- application stdout or stderr when the program does not emit OTLP itself
- VM guest logs that only exist through host-visible serial output or similar host capture
- `amber run` lifecycle events
- `amber proxy` and outside-world routing activity

The design must collect from all of those without requiring the scenario author to think about telemetry topology.

### Design constraint: observability must be out-of-band from the mesh

Observability transport should not ride on the Amber service mesh.

That path is attractive at first glance because every component already has a sidecar and a router, but it is the wrong abstraction.

If telemetry depended on the mesh, then:

- telemetry bootstrap would depend on the very network being debugged
- failures in mesh bring-up could hide the evidence needed to debug them
- telemetry traffic would recursively instrument its own transport path
- non-program sources such as Docker log files, Kubernetes pod logs, direct child stdout or stderr, and VM serial logs would still need a separate collection path

Therefore telemetry must remain out-of-band.

Amber should use OTLP and collector topology directly, not mesh routes, to move observability data.

### Observability modes

`amber run` should expose explicit observability policy knobs.

The first version should support two enabled modes, with observability off by default:

1. local managed mode
   - enabled by `--observability=local`
   - `amber run` starts a host-local run collector
   - site-local collectors and local runtime processes send to that run collector

2. explicit endpoint mode
   - enabled by `--observability=<url>`
   - the supplied endpoint becomes the root sink for the run
   - site-local collectors forward directly to that endpoint
   - local runtime processes emit directly to that endpoint or to a site-local shipper that forwards there

Without `--observability`, Amber does not start the managed telemetry pipeline.

That means:

- Amber does not start managed collectors
- Amber does not inject OTLP configuration into runtime processes
- normal terminal logging and native runner logs may still exist, but they are not gathered into a managed run-level telemetry pipeline

This separation matters because the best topology depends on where the sites are.

If all sites are local and the user asks for local observability, the host-local run collector is the best root sink.

If the `amber run` machine is merely coordinating remote production sites, then the user-supplied endpoint should become the root sink instead.

### Recommended topology when observability is enabled

The recommended enabled topology is:

- one root sink for the run
- site-local collectors only for site kinds that need local log harvesting inside the site environment
- site-local collectors forward to the root sink
- local runtime processes either emit directly to the root sink or emit to a site-local shipper that forwards there

In other words:

`runtime sources -> site-local collector when needed -> root sink`

Where the root sink is:

- the host-local run collector in local managed mode
- the explicit user-supplied endpoint in explicit endpoint mode

This gives the system one stable run-scoped convergence point without forcing every site kind to expose raw native logs over the same mechanism.

### Why local managed mode needs a run collector

In local managed mode, the run collector gives `amber run` a single run-scoped observability endpoint that exists regardless of how many site managers participate.

That is useful because:

- direct, VM, and proxy processes already run on the host and can emit directly to a host-local endpoint
- Compose and Kubernetes site-local collectors can forward to the same place
- run lifecycle events from the coordinator have an obvious destination
- the system no longer depends on a separately started dashboard just to have one place to send telemetry
- unmanaged site exports and managed mixed-site runs can have different observability UX without changing the internal telemetry model
- the local observability mode remains useful without requiring the user to provision an OTLP sink first

The run collector is a coordinator-owned runtime utility. It is not a mesh router and it does not change the earlier decision that `amber run` is a coordinator rather than a data-plane site.

### CLI surface

`amber run` should grow:

- `--observability=local`
- `--observability=<url>`

The intent is:

- omit `--observability` when the user wants no managed telemetry
- use `--observability=local` when the user wants Amber to own a local root sink
- use `--observability=<url>` when the user wants every participating site to feed a specific sink

This policy belongs to `amber run`, not to the manifest and not to the semantic meaning of `RunPlan`.

`RunPlan` may record the observability capabilities required by the selected site plans, but the actual observability mode and endpoint selection are runtime inputs.

### What each source emits

The mixed-site design should collect three classes of telemetry.

#### 1. Native OTLP traces, logs, and metrics

Amber runtime components already know how to emit OTLP when given the right environment:

- `OTEL_EXPORTER_OTLP_ENDPOINT`
- `AMBER_SCENARIO_RUN_ID`
- `AMBER_SCENARIO_SCOPE`
- `AMBER_COMPONENT_MONIKER` for component-scoped processes

Mixed-site execution should standardize that injection across all site kinds.

Routers, helper-launched programs, proxy, and OTLP-aware application processes should emit directly in OTLP rather than being observed only through text logs.

#### 2. Native runtime logs from environments that are not OTLP-aware

Not every source is a structured OTLP emitter.

The system still needs to collect:

- Docker container logs
- Kubernetes pod logs
- direct child stdout and stderr
- VM serial logs or equivalent host-visible guest output

These should be collected by the site manager that owns that runtime environment or by a collector it launches.

#### 3. Coordinator and site-manager lifecycle events

`amber run` itself should emit telemetry for:

- placement decisions
- site detection
- materialization start and finish
- site startup and readiness
- discovery failures
- teardown

Those are part of the user-visible operational story. They should land in the same run-level sink as scenario telemetry.

### Per-site collection responsibilities

#### Compose sites

Compose already has most of the right shape today.

The Compose site manager should continue to materialize a site-local collector in the Compose network.

That collector should:

- receive OTLP directly from Compose routers and programs at an in-network endpoint such as `http://amber-otelcol:4318`
- tail Docker container logs
- add run and site metadata
- forward everything to the selected root sink

This is a small change from the current code, which already creates a per-scenario collector and currently forwards to an externally configured OTLP HTTP endpoint.

#### Kubernetes sites

Kubernetes also already has most of the right shape today.

The Kubernetes site manager should continue to materialize a site-local collector inside the cluster.

That collector should:

- receive OTLP directly from routers and programs through its in-cluster service
- collect pod logs from the nodes
- enrich records with Kubernetes metadata
- add run and site metadata
- forward everything to the selected root sink

The main change from the current code is again the upstream target. Instead of assuming the dashboard endpoint directly, managed mixed-site runs should target the root sink selected by `amber run`.

#### Direct sites

In local managed mode, direct sites do not need a separate site-local collector process if they are already running on the same host as `amber run`.

Instead, the direct site manager should:

- inject OTLP configuration into every router and every program execution path
- explicitly inject observability variables into helper payloads and direct-exec environments
- tee child stdout and stderr into per-component log files under the direct runtime workspace
- configure the selected local collector or shipper to ingest those per-component log files

This is a required change from the current direct runtime, which clears process environments and presently only streams child logs to the terminal.

Without this change, direct sites would remain second-class in observability.

In explicit endpoint mode, a direct site may still need a lightweight local shipper if the runtime must translate native text logs into OTLP before forwarding to the configured endpoint.

#### VM sites

VM sites need both host-side and guest-side collection.

The VM site manager should:

- inject OTLP configuration for host-side routers
- expose a host-reachable OTLP endpoint to the guest so OTLP-aware guest processes can emit directly
- capture guest serial logs or equivalent host-visible guest logs
- feed those logs into the selected root sink with component identity

The exact guest-reachable endpoint does not need to be fixed in this document, but it should be out-of-band and host-reachable rather than mesh-routed.

The important point is that VM observability cannot stop at "the QEMU process wrote to a serial log file somewhere". That serial output must become part of the run-level observability stream.

#### Proxy and outside-world site

`amber proxy` should emit telemetry directly to the selected root sink, just as the coordinator does.

That includes:

- proxy router spans and logs
- export binding failures
- external slot bridging activity

This keeps the outside-world site visible in the same run-level view as internal sites.

### Resource identity and correlation

Mixed-site observability needs stable identity across collectors and site managers.

The current runtime telemetry layer already sets useful attributes such as:

- `service.name`
- `amber.observability.entity_kind`
- `amber.component.moniker`
- `amber.scenario.scope`
- `amber.scenario.run_id`

The mixed-site design should add stable site identity as well:

- `amber.site.id`
- `amber.site.kind`
- `amber.site.manager.kind`

These attributes are necessary so that one run-level view can answer:

- which site emitted this record
- whether the record came from a router, a program, the proxy, or the coordinator
- which component the record belongs to

They should be attached by the site manager or collector, not inferred later from naming conventions.

### How collection reaches "all sources"

With the recommended topology, the system collects from all sources as follows.

For Amber runtime components:

- routers, proxy, helper-launched programs, and OTLP-aware applications emit OTLP directly to a site-local collector or to the selected root sink

For native environment logs:

- Compose uses a site-local collector to tail Docker logs
- Kubernetes uses a site-local collector to tail pod logs
- direct runtime writes process stdout and stderr to files that a local collector or shipper tails
- VM runtime writes or captures guest-visible logs on the host, and a local collector or shipper tails those files

For control-plane lifecycle:

- `amber run` and the site managers emit OTLP logs and spans directly to the selected root sink

That is the whole collection story. Amber does not need packet capture, log scraping from arbitrary machines, or recursive mesh routing of telemetry to make the first version work.

### Unmanaged exports versus managed runs

Managed runs and unmanaged exports should not have identical observability behavior.

For managed mixed-site runs:

- plain `amber run` does not start the managed telemetry pipeline
- `amber run --observability=local` starts the local run collector and uses it as the root sink
- `amber run --observability=<url>` uses the supplied endpoint as the root sink
- when observability is enabled, site managers forward into whichever root sink the run selected

For unmanaged homogeneous exports such as raw Compose or raw Kubernetes output:

- the exported artifact should keep its site-local collector model
- the export should continue to accept an explicitly configured upstream OTLP endpoint
- there is no requirement that unmanaged exports reproduce the full managed-run observability experience without Amber present

This avoids a usability regression for export users while still giving mixed-site `amber run` a coherent model.

### Alternatives considered

#### Alternative: a single host-local collector and no site-local collectors

Pros:

- conceptually simple
- one obvious endpoint for everything

Cons:

- Compose and Kubernetes native logs do not live on the host in a uniform way that Amber can count on
- Kubernetes pod log enrichment needs in-cluster context
- future remote sites would become awkward immediately

This is not a good general model.

#### Alternative: only site-local collectors, forwarding straight to the dashboard or external sink

Pros:

- close to what Compose and Kubernetes already do today
- no host-local run collector required

Cons:

- direct, VM, proxy, and coordinator telemetry still need a special case
- there is no run-local convergence point owned by `amber run`
- the system remains coupled to whichever external sink the user happened to start

This is better than the first alternative, but it keeps too much runtime asymmetry.

#### Recommended alternative: an optional selected root sink plus site-local collectors where the runtime demands them

Pros:

- one run-level convergence point
- fits local automatic placement
- preserves existing Compose and Kubernetes collector logic with minimal conceptual change
- gives direct, VM, proxy, and coordinator telemetry a first-class home
- cleanly separates site-local native log harvesting from run-level aggregation
- allows remote-site scenarios to feed a user-provided endpoint directly
- keeps observability off unless the user explicitly asks for it

Cons:

- local managed mode introduces one more managed process in `amber run`

This is the recommended design.

## Cross-Site Routing

### Core idea

Programs should continue to see local slot listener addresses.

This is one of the key benefits of Amber's mesh sidecar model. Mixed-site execution does not require a new program-facing connectivity model.

Instead:

- local sidecars continue to expose local slot listeners
- cross-site routing is handled between site routers and sidecars

The canonical cross-site path is:

`component -> local sidecar router -> local site router -> remote site router -> remote sidecar router -> remote component`

That path should remain an implementation detail beneath the program-facing slot abstraction, but it is still part of the architecture. Amber is routing links through routers in a transportation network, not treating inter-site connectivity as a separate special mechanism.

### One link model across sites

Once the scenario is lowered to execution, Amber should think in terms of components connected by links over a computational substrate.

Sites are placement and materialization details. They are not distinct routing protocols.

That means:

- Amber should maintain one routed link model across intra-site and inter-site connectivity
- links should be modeled as URLs
- the current implementation may lower those URLs into the existing Noise-over-TCP router layer
- Kubernetes in the first mixed-site version may use host-local port-forwarding only as a reachability mechanism for that same current layer
- when HTTP(S) link materialization is ready, Amber should cut over that lower layer uniformly rather than maintaining two long-lived meshing strategies

This keeps the program-link abstraction and the lower link-link abstraction aligned: programs still talk to local sidecars, while the routed links beneath them remain architecturally uniform even as the lowest transport changes over time.

### Local binding

When both consumer and provider are on the same site:

- keep existing local site routing behavior
- no special cross-site logic is needed

### Cross-site binding

When the provider is on another site:

- the consumer's local slot still resolves to a local listener
- the local site router or sidecar must forward toward the remote site's router
- the remote site's router forwards to the local provider sidecar or route

The exact gateway route shape is a site-routing concern, not a manifest concern.

The design intentionally does not fix the exact route-id naming or whether the first hop is always a local site router versus, in some site types, a direct remote-router peer. What is fixed is the semantic requirement:

- program-visible slot URLs stay local
- cross-site forwarding happens below the program layer
- site routers are the cross-site boundary objects

### Why the outside world as a site matters here

Once the outside world is a site:

- exports become ordinary cross-site outbound flows toward the outside-world site
- external slots become ordinary cross-site inbound flows from the outside-world site

That unifies the model and reduces the amount of special proxy logic.

It does not mean that ordinary internal site boundaries should be rewritten as synthetic exports or external slots. Those remain the public boundary vocabulary of the scenario, not the architectural mechanism for all internal site links.

## Site Connectivity and Discovery

### Why compile-time static addressing is not sufficient

Current backend lowering generally assumes that peer addresses can be rendered statically per artifact.

That is not reliable in mixed-site execution because:

- local runtime ports are chosen at launch time
- Compose router publication may depend on project and startup state
- Kubernetes reachability may depend on port-forwarding or cluster-specific endpoint discovery

Therefore the `RunPlan` must allow symbolic site references to survive until launch.

### Discovery requirements

Each site in the `RunPlan` should declare what other sites need from it at runtime.

At minimum:

- router identity id
- router link URL or a discovery method for that URL
- router control handle or a discovery method for that handle

### What may remain symbolic until launch

The `RunPlan` is allowed to leave some facts symbolic until site bootstrap, but only a narrow class of facts:

- references to other sites by `site_id`
- cross-site route intent such as "site A needs provider X from site B"
- discovery methods for router link URLs or router control handles
- exposure policies such as "this site is reached through port-forward" in the first version or "this site is reached through ingress" in a later version

The following must become concrete before component waves can begin:

- each bootstrapped site's router identity id
- each bootstrapped site's concrete router link URL for this run
- each bootstrapped site's concrete router control handle for this run

That line is important. Symbolic placement and symbolic discovery survive into planning, but not past the stitching barrier.

### Minimal normative stitching contract

The control plane needs one explicit contract for mixed-site stitching.

That contract should be:

1. the `RunPlan` carries symbolic cross-site stitching intent
2. each site manager bootstraps far enough to return concrete router discovery
3. the coordinator resolves the symbolic stitching intent into concrete cross-site router updates
4. the coordinator applies those updates through the router control handle for each site
5. only after all required updates are acknowledged does startup move on to component waves

The coordinator therefore needs to inject, at minimum:

- remote peer identity
- remote peer link URL
- the cross-site route set or route intents that should target that remote peer

The recommended normative mechanism is a router control API with idempotent upsert semantics.

That means Amber should think in terms of operations like:

- upsert remote peer
- upsert cross-site route
- acknowledge applied configuration

More concretely, the semantic contract should be:

- stitching is desired-state upsert rather than imperative one-shot mutation
- each upsert targets one local site's attachment to one remote site for one run
- the payload contains the remote site identity, the remote link URL or discovery result, and the route intents that should target that remote site
- replaying the same payload is a no-op
- reapplying the same attachment with new contents replaces the prior desired state for that attachment
- stale or mismatched updates for another `run_id` or mesh scope are rejected
- acknowledgment means startup may proceed on the assumption that the attachment is installed

Mutable config files or hot-reload implementations are not forbidden as local implementation details, but they should not be the architectural contract. If a site manager chooses to implement stitching through mutable config under the hood, it should still present the same effective control-plane contract to the coordinator.

### What "router ready" means

A site router is ready for stitching when:

- the router process or service for that site is running
- the router identity for that site has been loaded
- the router link URL for that run is known
- the router control handle is reachable
- the router can accept peer or route updates

This is deliberately weaker than "all remote peers have already been stitched" and stronger than "a process was spawned somewhere".

The startup barrier should therefore be:

- bootstrap every site until routers are ready for stitching
- stitch all required cross-site router state
- only then start component waves

That is the minimal normative ordering that mixed-site execution depends on.

### Coordinator responsibilities

Because of discovery, `amber run` must do more than "compile then invoke managers".

It must:

1. materialize site plans
2. bootstrap sites far enough that their routers become discoverable
3. discover router endpoints
4. stitch site routers together
5. start component workloads in global strong-dependency waves
6. activate exports and commit the run
7. hand each site off into self-living or Amber-supervised residency
8. persist run receipts, then exit

This is why `amber run` is a coordinator.

This also implies that some `RunPlan` fields must remain symbolic until launch. For example:

- "the local Compose site needs the router link URL for the local VM site"
- "the local Kubernetes site reaches the current link layer through managed port-forward"

Those are plan facts, even though the final address values are only known when the managers run.

### Minimal receipt for later outside-world attachment by `amber proxy`

Every successful `amber run` should persist a thin immutable per-run receipt keyed by the global `run_id`.

The design target is that later Amber commands reconnect to live supervisors or self-living site resources from that receipt rather than treating the receipt itself as a cached scenario snapshot.

The required receipt contents should therefore stay minimal.

At minimum it should contain:

- `run_id`
- the predeclared outside-world site id or attachment point
- for each active site:
  - `site_id`
  - site manager kind or site kind
  - residency mode
  - site instance locator for self-living sites
  - supervisor locator for Amber-supervised sites

Everything else that is dynamic at runtime should be discovered live where possible.

In particular, Amber should prefer to query live supervisors or site-native discovery for current site-runtime facts such as:

- lifecycle status
- current router link URL
- current router control handle

Amber should then prefer to query the router control plane itself for router-owned facts such as:

- router identity
- export and external-slot boundary metadata needed for later attachment

Amber should persist only the minimum local state needed to reconnect to local supervisors and to avoid recompiling mutable inputs for later commands.

It should not turn receipts into a general scenario manager or persist large launch artifacts gratuitously when a small immutable receipt and live discovery will do.

This is the minimum needed for later proxy attachment because `amber proxy` must be able to:

- discover which internal sites exist for the run
- reconnect to their live control planes
- reach their routers
- start its own outside-world site router
- attach the outside-world site through the same stitching contract used for ordinary site links
- expose the correct exports and external-slot bindings

Ordinary internal site links must already have been stitched before component waves begin. The special late-attachment path is only for the predeclared outside-world site.

`amber proxy` is therefore not a special host-side attachment shim.

It is the site manager for one ordinary site whose lifecycle is controlled manually by the developer rather than by `amber run`.

The receipt is not a Terraform-style global state backend. It is required local run metadata plus connection information. It is authoritative for Amber-supervised local facts such as supervisor locators, while site-native resources remain authoritative for their own durable identifiers and live runtime state.

### Minimal live introspection surface for later commands

Thin receipts require a corresponding live introspection contract.

That contract should be specified semantically, not as a commitment to a particular HTTP path layout, supervisor RPC transport, or provider-specific API shape.

Later commands such as `amber stop`, `amber proxy`, and future inspection commands must be able to obtain two runtime views.

The first is a site-runtime view.

At minimum, later commands must be able to learn:

- `run_id`
- `site_id`
- lifecycle status such as `starting`, `running`, `stopping`, `stopped`, or `failed`
- the current router link URL
- the current router control handle, if the site router exposes one
- an idempotent stop capability for that site

This view is answered by:

- the detached Amber supervisor for Amber-supervised sites
- site-native discovery or control logic for self-living sites

The second is a router-boundary view.

At minimum, later commands must be able to learn:

- router identity
- the exports exposed by that router and their relevant boundary protocol information
- the external slots exposed by that router and their relevant boundary protocol information

This view should be answered by the router control plane itself, or by a site-native control path that transparently fronts the router when a site type cannot expose the router control plane directly.

Amber should not duplicate router-owned boundary metadata into receipts or supervisor state when the running router can answer it live.

This keeps the authority boundary clean:

- receipts tell later commands where to reconnect
- supervisors or site-native managers answer site-runtime questions
- routers answer router-boundary questions

That separation is what lets Amber keep receipts thin without making later commands blind.

## Stable Scenario Identity

Mixed-site execution requires a stable scenario mesh identity that is not backend-specific.

The current code can derive mesh scope from backend-visible transformed scenarios. That is not acceptable in the mixed-site design because different site planners must agree on the same mesh scope.

Therefore:

- scenario identity and mesh scope must be computed once from the backend-neutral scenario or `ScenarioIr`
- site-specific lowerers must consume that stable identity rather than re-derive it in backend-specific ways

Similarly, site router identities must be stable and derived from site identity, not from backend flavor labels such as "direct router" or "vm router".

## `amber compile` and `amber run`

### Primary compile output

`amber compile` should primarily produce:

- graph outputs such as `ScenarioIr`, DOT, and metadata
- one runtime-bearing output format: `RunPlan`

The `RunPlan` should be a versioned JSON artifact with its own schema identity, for example:

- schema: `amber.run.plan`
- version: `1`

The `RunPlan` is the main lowered artifact that makes `amber run` easy.

It should already contain:

- the detected site set
- component-to-site assignments
- per-site lowerings
- cross-site routing requirements
- discovery requirements

It should not be a final single-environment artifact unless the scenario itself happens to collapse to one site and the user explicitly asks for an unmanaged export.

### Recommended CLI surface

The recommended CLI shape is:

- keep graph outputs explicit
- add an explicit runtime-bearing output flag for the `RunPlan`

For example:

- `amber compile path/to/root.json5 --scenario-ir /tmp/scenario.json`
- `amber compile path/to/root.json5 --run-plan /tmp/run-plan.json`
- `amber compile path/to/root.json5 --placement local-k8s.json --run-plan /tmp/run-plan.json`
- `amber run path/to/root.json5 --dry-run --emit-launch-bundle /tmp/amber-launch`

This is clearer than overloading one output flag with two different levels of lowering.

If current CLI compatibility requires keeping `--output` for `ScenarioIr`, that is fine. The important change is that `RunPlan` becomes an explicit first-class compile target.

The launch bundle should not be added as a first-class `amber compile` output in the first version.

It is machine-bound and belongs to the `amber run` prelaunch path rather than to the portable compile surface.

### Site-Aware Graphviz output

The existing DOT output is a semantic scenario view.

Mixed-site execution should also have a placement-aware DOT view derived from the resolved `RunPlan` or the placed scenario just before execution.

This should be a distinct visualization, not a mutation of the existing semantic DOT output, because the two views answer different questions:

- semantic DOT shows scenario structure
- site-aware DOT shows where the scenario was placed

The site-aware DOT should:

- group placed nodes by site using Graphviz clusters of the form `subgraph cluster_<site_id>`
- label each cluster with the site id and site kind
- render cross-site edges across those clusters
- make it easy to visually identify cross-site zig-zags and site boundary crossings

`amber run` should expose an option or mode to write that output, for example a `--site-dot <path>`-style flag.

The exact flag name is open, but the behavior should be:

- perform normal resolution and placement
- render the placed graph with site clusters
- optionally continue to execution if the command is otherwise a normal run

This is an important debugging and explainability tool for mixed-site placement.

### Exact prelaunch debugging surface

Mixed-site execution needs a first-class way to inspect what Amber is about to launch without actually starting heavy workloads.

The important thing to inspect is not merely the `RunPlan`.

Users often need to see:

- the generated Compose YAML
- the generated Kubernetes YAML
- the exact `docker compose` and `kubectl` invocations Amber would use
- the exact direct-process argv, env shape, mounts, and generated files
- the exact VM launch specs such as QEMU argv, disks, and forwards

So the recommended debugging surface is:

- a dry-run or debug-bundle mode on `amber run`
- implemented by emitting the same internal launch bundle that the real launch path consumes

This is stronger than a separate inspect reporter because it guarantees that the debugging surface and the real launcher cannot drift apart.

The emitted debug bundle should redact secrets by default while still showing the exact non-secret launch shape.

### What `amber run` accepts

Conceptually, the new `amber run` should accept:

- a manifest path or URL
- a bundle
- a `ScenarioIr`
- a `RunPlan`
- an optional placement file when planning is still required
- later, optionally a placement lock if Amber decides to expose normalized placement directly

When given:

- a manifest or bundle
  - it resolves, compiles, applies the placement file if provided or auto-places locally, normalizes placement, produces a `RunPlan`, and executes it
- a `ScenarioIr`
  - it skips manifest resolution but still applies the placement file if provided or auto-places locally, normalizes placement, and performs `RunPlan` construction
- a `RunPlan`
  - it skips planning and executes directly

The first version may retain support for legacy direct or VM artifacts as a compatibility shim, but those should no longer define the conceptual model.

The first version should not add a public `amber run <launch-bundle>` mode.

Instead:

- `amber run` should internally materialize a launch bundle from the `RunPlan`
- an optional debug or dry-run flag may emit that launch bundle for inspection
- the actual launcher should still consume that same internal bundle

That keeps the implementation honest without adding another first-version public runtime artifact to support.

### Shared implementation model

`amber compile` and `amber run` should not each own their own copy of backend logic.

They are two frontends over one shared planning and site-lowering backend:

- `amber compile`
  - resolves input
  - builds a backend-neutral scenario
  - optionally lowers to a `RunPlan`
  - optionally writes unmanaged export artifacts
- `amber run`
  - resolves input when given a manifest or bundle
  - builds or loads the same `RunPlan`
  - hands that plan to site managers for execution

The implementation split should therefore be:

1. semantic compilation
   - manifest or bundle to `CompileOutput`, `CompiledScenario`, and `ScenarioIr`
2. execution planning
   - backend-neutral scenario plus placement input or local automatic placement to normalized placement and then `RunPlan`
3. launch materialization
   - `RunPlan` to machine-bound launch bundle
4. site rendering
   - site-specific plans to Compose manifests, Kubernetes manifests, direct launch specs, or VM launch specs
5. site management
   - materialized launch bundle inputs to started or stopped sites

This keeps the code-sharing story clean:

- `amber compile --run-plan` and `amber run <manifest>` both call the same execution planner
- `amber compile --compose` and `amber run` both call the same Compose site renderer
- `amber compile --k8s` and `amber run` both call the same Kubernetes site renderer
- direct and VM continue to use shared site rendering and shared runtime code rather than one path for compile and another for run

The current code does not yet have this split. Today the direct, VM, Compose, and Kubernetes reporters each mix together several responsibilities:

- graph-to-runtime planning
- machine-bound launch materialization
- backend-specific site rendering
- artifact assembly
- execution-guide generation

Mixed-site execution is a good reason to separate those concerns cleanly instead of copying reporter logic into `amber run`.

The recommended refactoring is:

- keep the compiler core as the source of `CompiledScenario`
- add a shared `RunPlan` builder below `ScenarioIr`
- add a shared launch-bundle materializer below `RunPlan`
- turn current whole-scenario reporters into site renderers that operate on one site's plan
- make unmanaged export commands reuse those site renderers instead of bypassing them
- make `amber run` consume the shared `RunPlan`, shared launch-bundle materializer, and the same site renderers rather than owning a separate lowering stack

This also answers the artifact question more cleanly:

- `ScenarioIr` remains the portable semantic artifact
- `RunPlan` is the primary public lowered execution artifact
- launch bundle is the exact machine-bound prelaunch artifact
- `amber run` is not a second compiler backend; it is a coordinator and launcher over the same planner, materializer, and renderers that `amber compile` uses

### Homogeneous export UX

There is a genuine UX concern for homogeneous scenarios.

If a homogeneous container scenario previously compiled to raw Compose or Kubernetes artifacts, requiring `amber run` everywhere would be a usability regression for users who only want the unmanaged site artifact.

The recommended model is:

- `amber compile` primarily emits `RunPlan`
- unmanaged raw Compose or raw Kubernetes output is an explicit homogeneous export path
- if the CLI keeps `--compose` or `--k8s`, they should be understood as export conveniences derived from the same planning pipeline
- those exports should either:
  - succeed only when the resolved run plan is homogeneous in the requested site kind
  - or require an explicit homogeneous planning mode

What should not happen is:

- treating raw Compose or raw Kubernetes output as the foundational meaning of compilation in the mixed-site architecture

In practice, that means a user should be able to do both of the following:

- `amber run path/to/root.json5`
- `amber compile path/to/root.json5 --run-plan /tmp/run-plan.json && amber run /tmp/run-plan.json`

and get the same runtime behavior.

### Streamlining recommendation

Because Amber is still pre-1.0, the design should be streamlined rather than preserving every current artifact-centric mode as a first-class concept.

The recommendation is:

- make `RunPlan` the primary runtime-bearing compile artifact
- keep graph outputs as they are
- treat raw Compose or Kubernetes output as explicit exports, not as the conceptual center of `amber compile`
- if a separate export surface is added, prefer that to keeping every old artifact mode in `amber compile`

## Where the Current Code Can Be Reused

The current code already contains reusable pieces:

- the compiler core remains valid
- `ScenarioIr` remains valid
- mesh binding resolution remains conceptually valid
- backend-specific site materialization logic remains valuable

The main new layer belongs:

- below `ScenarioIr`
- above backend-specific site plans

The key insertion point is above the current global `ProgramSupport` and `RuntimeAddressResolution` assumptions in `compiler/src/targets/program_config.rs`.

The site planners should not pass one scenario-wide backend support mode for every component. They should operate per site or per assigned component set.

In other words:

- the compiler core should continue producing one scenario graph
- local automatic placement should produce one assignment of runnable components to local sites
- `RunPlan` construction should partition runtime lowering by site
- site materializers should lower each site independently
- the coordinator should manage discovery and stitching across sites

## Broad Technical Plan

The broad technical work required to realize the design is:

### 1. Introduce `RunPlan` as a versioned IR

Add a serializable, versioned `RunPlan` type that captures:

- stable scenario identity
- stable mesh scope
- detected site managers and site ids
- placement result
- per-site plans
- per-site storage requirements
- cross-site routing requirements
- site discovery requirements
- predeclared outside-world attachment information
- external interface metadata needed for proxying

This is the main new runtime-bearing compiler output.

### 2. Add placement parsing, normalization, and local automatic placement

Add planner logic that:

- detects direct runtime availability
- detects Compose availability
- detects VM availability
- detects Kubernetes tooling availability
- parses and validates the versioned placement file when provided
- constructs normalized placement from the file when provided
- falls back to the deterministic first-version local placement policy when the file is absent
- normalizes that fallback placement into the same explicit placement kernel
- validates post-placement site compatibility before emitting a `RunPlan`
- enforces first-version storage-locality rules before emitting a `RunPlan`
- produces clear diagnostics when the scenario cannot be locally placed

### 3. Split current backend reporters into site planners and optional exporters

Refactor the current direct, VM, Compose, and Kubernetes lowering code so it can operate on:

- only the subset of components assigned to a site
- remote peer references that remain symbolic until launch

This is the step that turns current whole-scenario artifact lowerers into per-site planners.

This refactoring should also separate three concerns that are currently interleaved in each reporter:

- execution planning
- site rendering
- user-facing artifact packaging

After the split:

- the planner produces `RunPlan` and site plans
- site renderers turn site plans into backend-native manifests or runtime inputs
- `amber compile` optionally writes those rendered outputs for homogeneous unmanaged exports
- `amber run` uses the same rendered outputs transiently when starting managed sites
- storage provisioning stays site-local and is emitted inside the owning site plan

### 4. Introduce the internal launch-bundle materializer and debug-bundle mode

Add a machine-bound launch-bundle materialization step below `RunPlan` that:

- renders exact site artifacts and launch specs without yet starting heavy workloads
- chooses concrete local values such as ports, temp paths, project names, and control paths where Amber controls them
- records the exact `docker compose` and `kubectl` invocations Amber will use
- records the exact direct and VM launch specs Amber will use
- is consumed by the actual launcher rather than existing only for debugging
- can be emitted through a dry-run or debug-bundle mode on `amber run`

This is the layer that makes "show me exactly what Amber will run" trustworthy.

### 5. Refactor direct and VM runtimes to partial-site mode

The current direct and VM runtimes assume that all peers are local.

They must be changed so that:

- they manage only their local site's routers and components
- they no longer rewrite every peer as a local ephemeral address
- remote peers remain remote peers
- runtime slot interpolation for programs still uses local listener addresses

### 6. Add the `amber run` coordinator and site-manager abstraction

Add the coordinator path that:

- accepts manifests, bundles, `ScenarioIr`, or `RunPlan`
- creates or loads a `RunPlan`
- materializes the launch bundle from that `RunPlan`
- materializes sites through site managers
- bootstraps site infrastructure
- waits for site routers to become discoverable
- resolves symbolic cross-site stitching intent into concrete router updates
- stitches site routers together through the router control contract
- computes global startup waves from the strong-dependency DAG
- starts component workloads wave by wave
- enforces startup timeout and `--no-cleanup`
- activates exports and commits the run
- hands each site off into self-living or Amber-supervised residency
- persists run receipts containing the minimal later-attachment fields
- exposes the minimal live site-runtime introspection needed for later commands on Amber-supervised sites
- supports `amber stop` discovery by `run_id`
- exits after successful handoff rather than remaining as a permanent top-level supervisor

### 7. Add the run-level observability stack and close the direct or VM gap

Add the managed observability path that:

- adds an opt-in observability policy to `amber run` with `local` and explicit-endpoint modes
- starts the host-local run collector in local managed mode
- rewires Compose and Kubernetes site-local collectors to forward into the selected root sink
- injects OTLP configuration into direct and VM runtime processes explicitly rather than relying on ambient environment
- writes direct stdout or stderr and VM guest-visible logs into collector-readable files
- emits coordinator and site-manager lifecycle telemetry
- adds stable site identity attributes to run records

This is part of the feature, not a later cleanup. Mixed-site execution should not ship with direct and VM observability left behind.

### 8. Rework proxy integration around the site model

Refactor `amber proxy` so that it operates as the outside-world site manager.

That requires:

- a run receipt written by `amber run`
- live site-runtime discovery for already-running sites
- router-boundary discovery from the running router control plane
- an outside-world site router started by `amber proxy` itself
- ordinary site-link attachment semantics between the outside-world site and internal sites
- site-aware export and external-slot connection logic

### 9. Reframe unmanaged Compose and Kubernetes outputs as homogeneous exports

If raw unmanaged outputs remain supported, they should be emitted from the same planning pipeline rather than bypassing it.

That means:

- plan first
- verify homogeneity or explicit export compatibility
- emit the requested unmanaged artifact

### 10. Add a site-aware DOT renderer for placed runs

Add a DOT renderer over placed execution state that:

- consumes the `RunPlan` or equivalent placed graph
- groups component nodes into `cluster_<site_id>` subgraphs
- labels site clusters clearly
- renders cross-site edges explicitly
- is callable from `amber run` as a debugging output

This should reuse as much of the existing DOT infrastructure as practical, but it is conceptually a different renderer from the semantic scenario DOT.

## Testing Strategy

The testing strategy should follow the architecture rather than the old artifact boundaries.

### Planner and IR tests

Add unit tests for:

- local capability detection
- deterministic local automatic placement
- placement-file-driven site assignment and defaults
- placement-file parsing, schema checks, and version checks
- placement-file normalization for supported older versions
- normalized-placement construction from authored placement
- normalized-placement construction from local automatic placement
- placement-file overrides such as forcing Kubernetes instead of Compose for image components
- post-placement site compatibility validation
- storage-locality validation that rejects storage spanning multiple sites in the first version
- failure diagnostics for missing required local managers
- `RunPlan` serialization and versioning
- launch-bundle materialization from a `RunPlan`
- per-site partitioning of components and dependency edges
- cross-site route classification
- router-discovery normalization from bootstrapped site managers
- stitching-plan resolution from symbolic cross-site intent to concrete router updates
- global startup-wave computation from strong dependencies
- site-aware DOT rendering from placed execution state

### Lowering tests

Update or add unit tests for:

- direct site planning from a partial-site assignment
- VM site planning from a partial-site assignment
- Compose site planning from a partial-site assignment
- Kubernetes site planning from a partial-site assignment
- site-local storage lowering for direct, VM, Compose, and Kubernetes site plans
- site residency classification for self-living versus Amber-supervised sites
- router-ready versus not-yet-stitchable site-manager states
- exact direct launch-spec rendering
- exact VM launch-spec rendering
- exact Compose and Kubernetes command rendering
- site bootstrap artifacts separated from component-wave artifacts where applicable

The key regression to catch is accidental continued reliance on "the whole runnable scenario is in this one artifact."

### Observability tests

Add unit and integration tests for:

- run-collector startup and shutdown
- no `--observability` flag disabling managed collectors and OTLP injection
- `--observability=local`
- `--observability=<url>` overriding the root sink
- Compose collector forwarding to the selected root sink
- Kubernetes collector forwarding to the selected root sink
- explicit OTLP environment injection for direct execution and helper execution paths
- direct runtime log-file capture for stdout and stderr
- VM runtime log capture from guest-visible host files
- site identity attributes on emitted telemetry

The key regression to catch here is reintroducing backend asymmetry, especially by leaving direct or VM as terminal-only logging while Compose and Kubernetes remain collector-backed.

### CLI and UI tests

Add or update CLI/UI tests for:

- `amber run <manifest>` using local automatic placement
- `amber run <manifest> --placement <file>` using explicit placement
- `amber run <scenario-ir>`
- `amber run <run-plan>`
- `amber run --dry-run --emit-launch-bundle <dir>` producing an exact prelaunch debug bundle without starting heavy workloads
- site-aware DOT output from `amber run`
- top-level `amber run` exiting after commit while leaving committed sites alive through site residency
- receipt persistence and re-consumption for later commands
- later `amber proxy` attachment using the receipt plus live discovery from an already-committed run
- startup timeout cleanup on pre-commit failure
- `amber run --no-cleanup` leaving pre-commit resources behind
- `amber stop <run-id>` using the receipt plus site-native discovery to stop a run
- `amber run --observability=local`
- `amber run --observability=<url>`
- missing-tool diagnostics for direct, Compose, or VM requirements
- rejection or clear handling of unmanaged export requests for heterogeneous run plans
- homogeneous unmanaged export success when the resolved run plan is compatible with the requested export kind

### Live smoke tests

The live smoke tests should be upgraded to exercise the new user model rather than the old compile-then-run-artifact model.

In particular:

- existing direct smoke tests should run through `amber run <manifest>` where appropriate
- existing VM smoke tests should run through `amber run <manifest>` where appropriate
- Kubernetes smoke tests should run through `amber run` with a placement file that forces a KinD-backed Kubernetes site
- any live tests that currently validate runtime startup via precompiled artifacts should be updated to validate the `RunPlan` path or direct manifest path

### Mixed-site smoke test

New mixed-site live smoke tests should be added.

These tests should prove:

- multiple local site managers are used in one run
- cross-site router stitching works
- global strong-dependency startup ordering is preserved across site boundaries
- routers are stitched before any component wave begins
- proxying still works through the site model
- telemetry from all participating sites reaches the selected root sink
- placement files can force non-default site choices deterministically
- the top-level coordinator can exit while the committed run remains alive through per-site residency
- the emitted launch bundle matches the actual launcher inputs rather than being a separate approximate reporter

A strong first target is a scenario that uses at least three site kinds locally, for example:

- one `program.image` component on the local Compose site
- one `program.vm` component on the local VM site
- one `program.path` component on the local direct site

with at least one dependency chain that crosses sites, such as:

- image -> vm -> direct

Another important target is a KinD-backed mixed test that explicitly forces both Compose and Kubernetes sites in the same run, because that is the case local automatic placement cannot express on its own.

The broader goal is to have coverage for:

- KinD-forced Kubernetes placement
- Compose plus Kubernetes plus VM plus direct in one scenario
- explicit placement-file-driven runs as a first-class execution path
- rejection of mixed-site plans that would place one mounted storage object across multiple sites
- direct and local-VM runs surviving top-level `amber run` exit through detached Amber supervisors

This directly exercises the key architectural claim that mixed-site execution is not tree-shaped and that routing survives across heterogeneous site boundaries.

The mixed-site smoke coverage should also assert that:

- the direct component emits logs that are visible in the run-level sink
- the container component emits logs that are visible in the run-level sink
- the VM component emits logs that are visible in the run-level sink

## What Definitely Does Not Work

This section records rejected or invalid paths explicitly.

### Rejected: top-level supervisor router

We considered the idea of adding a host-local supervisor router to join all sites.

We explicitly moved away from that after deciding that the outside world should itself be modeled as a site.

The remaining supervisor process is the `amber run` coordinator, not a mesh data-plane peer.

### Rejected: tree-based placement inheritance

We considered making placement inherit down the component tree to improve ergonomics.

That was explicitly rejected because placement is over the runnable dependency graph onto a site graph, not over the component tree.

### Rejected: putting scheduling in the manifest

This would violate the separation between scenario semantics and deployment policy.

### Rejected: treating the authored placement file as the whole placement kernel

That would make the first-version syntax too sticky and would blur together:

- human-authored intent
- automatic fallback placement
- explicit normalized assignment

The corrected design keeps the authored placement file simple, but still normalizes all placement sources into one explicit internal form before `RunPlan` construction.

Whether that normalized form is later exposed as a placement lock is a public-surface question, not a kernel question.

### Rejected: forcing first-version users to author only a full explicit assignment map

That would make manual authoring too painful for transitive dependencies and would make it harder to provide useful tooling before a real optimizer exists.

### Rejected: reimplementing Compose or Kubernetes lifecycle in Amber

Amber should delegate to native tooling for those site types.

### Rejected: requiring cross-site strong bindings to become weak

That would make placement change scenario semantics.

Strong startup dependencies should remain strong even when placement later puts the components on different sites.

The startup protocol must handle that case rather than outlawing it.

### Rejected: partitioning the placed run into synthetic mini-scenarios joined by exports and external slots

We considered treating each site partition as its own mini-scenario and synthesizing exports and external slots at the boundaries.

That is rejected because:

- it overloads outside-world boundary machinery for ordinary internal site-to-site routing
- it obscures the original placed graph
- it makes startup ordering, storage locality, and observability harder to reason about
- it creates an unnecessary gap between the scenario the user authored and the one Amber actually runs

Amber may still reuse some of the same router implementation techniques internally, but the architecture remains one placed scenario partitioned across sites, not many synthetic subscenarios.

### Rejected: keeping proxy as a single-artifact single-router special case

That model does not survive mixed-site execution. Proxy must become the outside-world site manager and peer with internal sites through normal site connectivity.

### Rejected: routing observability through the Amber mesh

Telemetry must remain out-of-band.

Trying to move OTLP through the Amber mesh would create bootstrap recursion, make failures harder to debug, and still would not solve collection of native runtime logs such as Docker logs, Kubernetes pod logs, direct stdout or stderr, or VM serial output.

### Rejected: Terraform-style global authoritative state backend

Amber should not require a global authoritative local or remote state backend or lock service.

That does not prohibit local authoritative supervisor state for Amber-supervised sites or a per-run receipt keyed by `run_id`. Those are normal local control-plane inputs, not a separate global state system.

## Open Technical Questions That Are Intentionally Deferred

These are real questions, but they do not need to be fully solved for the design to be valid.

- how to encode future communication-intensity or "chatty" hints
- how the human-authored placement file should grow beyond simple defaults and exact pins
- whether and when normalized placement should be exposed as a first-class placement lock
- how rich the site capability schema should be initially
- what later self-living Kubernetes reachability modes should look like once the first Amber-supervised forwarding-based version exists
- whether the first Kubernetes site manager supports only `kubectl` or later grows a direct API implementation
- what exact local receipt format `amber run` should write for convenience and for `amber proxy`
- what the final CLI spelling for the launch-bundle debug mode should be
- whether the internal launch bundle should ever later become a first-class public input
- whether `amber run --observability=local` should automatically start a UI such as `amber dashboard`, or only expose connection details for an already-running sink

These do not change the core design.

## Final Recommendation

Amber should adopt the following model:

- `ScenarioIr` remains backend-neutral and placement-agnostic
- the first version supports a simple human-authored placement file and falls back to built-in local automatic placement when no file is provided
- all placement sources normalize to one explicit internal placement form before `RunPlan` construction
- that normalized form may later be exposed directly as a placement lock without changing the rest of the pipeline
- `RunPlan` is the primary runtime-bearing compile artifact
- `amber run` internally materializes and launches from a machine-bound launch bundle that can also be emitted for exact prelaunch debugging
- execution planning is a new layer below `ScenarioIr`
- execution planning produces a mixed-site `RunPlan`
- sites are concrete runtime instances, not just backend kinds
- `amber run` becomes a coordinator over site managers
- Compose and Kubernetes remain native site managers invoked by Amber
- direct and VM remain internal site managers
- the outside world is modeled as a site, and `amber proxy` is that site's manager
- routed links are modeled uniformly as URLs across intra-site and inter-site connectivity
- the first mixed-site implementation may still lower those links to the current Noise-over-TCP layer, with Kubernetes v1 using port-forward only as a reachability mechanism for that same layer
- future router work may cut that lower layer over uniformly to HTTP(S) rather than preserving dual meshing strategies
- exports and external slots remain the public boundary vocabulary rather than the mechanism for ordinary internal site links
- first-version storage stays consumer-local to concrete sites and is rejected when one mounted storage object would span multiple sites
- post-placement compatibility validation is required before `RunPlan` emission
- startup preserves the global strong-dependency ordering by bootstrapping sites first and then starting component workloads in global waves
- top-level `amber run` exits after commit, while each site is handed off as either self-living or Amber-supervised
- first-version Kubernetes managed mixed-site runs use Amber-supervised local forwarding rather than requiring self-living Kubernetes reachability
- pre-commit startup failure cleans up by default, with `--no-cleanup` as an explicit escape hatch
- cleanup later is driven by persisted run receipts plus site-native discovery rather than by a Terraform-style global state backend
- observability is opt-in and collected out-of-band through a selected root sink, with `--observability=local` using a local run collector and site-local collectors only where native runtime log harvesting requires them

This design keeps the semantic compiler layers clean, gives users a narrow first version with direct manifest execution and simple human-authored placement, preserves room for a richer future placement file, and avoids treating final single-environment artifacts as the fundamental compile product in a mixed-site architecture.
