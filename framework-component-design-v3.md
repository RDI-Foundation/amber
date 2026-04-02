# Formal Design: Dynamic Components via `framework.component`

## Status

Design proposal for dynamic components in Amber.

This document is the implementation contract for the first complete version of dynamic components in
Amber. It is intentionally specific about semantics, authority boundaries, data/control-plane shape,
frozen-source rules, protocol shape, determinism, and recovery behavior. It leaves room for ordinary
implementation judgment, but it does not leave room for materially different interpretations of the
feature.

The feature replaces the Docker-specific experimental control surface with a backend-neutral
realm-management capability.

### How to read this document

This document uses two kinds of statements:

- **Requirement** means externally meaningful behavior that the implementation must preserve for
  correctness, security, recovery, determinism, or interoperability.
- **Recommended v1 realization** means the preferred implementation structure for this version
  because it reduces risk or complexity. An equivalent structure is acceptable only if it preserves
  all stated requirements.

---

## 1. Objectives / Goals

### 1.1 Primary objective

Add the equivalent of a realm capability to Amber by introducing `framework.component`.

A holder of this capability can manage the component realm where that capability originated:

- create ordinary Amber child components under that realm
- destroy those children
- inspect templates, bindable inputs, children, and child outputs
- snapshot the resulting live graph into a static-equivalent replay artifact

### 1.2 Functional goals

The implementation must satisfy all of the following.

1. **Dynamic creation is still ordinary Amber components.**  
   A dynamically created child is an ordinary Amber component instance. It may itself contain any
   internal component graph and resources described by its manifest. There must not be a distinct
   user-visible concept for “single-component child” versus “subgraph child”.

2. **There is one scenario graph and one root.**  
   Dynamic children are inserted into the existing scenario graph. The creator is their parent,
   exactly as if the child had been declared statically.

3. **The capability model matches static Amber.**  
   Parents grant capabilities they have, pass config to the child root, and receive the child
   root’s exports. Dynamic children obey ordinary Amber routing and isolation rules.

4. **All backends are first-class.**  
   Compose, Kubernetes, Direct, and VM must all participate with the same semantics.

5. **Templates bound what may be created without making authoring painful.**  
   Manifest authors can declare child templates ranging from strict to open. The common case
   should feel like partial application of an ordinary component declaration rather than a new,
   separate policy language.

6. **Placement stays operator-controlled.**  
   Manifests do not specify placement. Dynamic placement continues to come from the placement/run
   plan world.

7. **Snapshot/replay yields a static-equivalent scenario.**  
   At any point, Amber can emit a replayable `ScenarioIr` plus effective placement such that rerun
   produces the same structural scenario: the same nodes, edges, component definitions, child
   templates, frozen template manifest catalog, and concrete placements, except for in-memory state
   and ephemeral filesystem state.

8. **The design stays compatible with future dynamic binding.**  
   Dynamic components may later become densely meshed into the existing graph. The design must not
   assume that dynamic children are only capability-subordinate to their parent.

9. **Creation/destruction overhead is low.**  
   The hot path should be fragment-local instantiation and targeted live routing updates, not whole
   scenario regeneration.

10. **The runtime remains deterministic.**  
    Given the same frozen run inputs and the same dynamic operations, Amber must compute the same
    placements, participant identities, live graph, and snapshot output.

### 1.3 Non-goals

This document does not design:

- runtime creation of brand-new sites during an already-running scenario
- arbitrary reactive edits to already-running components or programs
- a final design for future post-creation dynamic offers/bindings
- the `amber-node` meta-router beyond keeping the design compatible with it

This feature is a realm-management surface, not a general graph editor.

---

## 2. Terminology

### Authority realm

The realm controlled by a particular `framework.component` capability instance.

If a parent forwards its realm capability to a child, the child acts on the parent’s realm, not on
its own.

### Origin realm

The realm where a `framework.component` capability originated. In this document, “origin realm” and
“authority realm” are the same concept viewed from different angles: the capability controls the
realm where it originated.

### Transport caller

The live component instance currently making a request over the mesh.

### Logical scenario graph

Amber’s authoritative user-visible graph model: components, resources, parent/child relationships,
child templates, frozen template manifest catalog, and capability bindings. This graph exists even
when the realized deployment does not literally encode that hierarchy.

### Realized execution graph

The deployed routers, sidecars, workloads, and backend resources that implement the scenario at
runtime. This graph is about transport and execution, not about preserving logical containment.

### Child template

A manifest-declared description of what child component root may be created and how much of that
root is already partially applied by the parent.

### Partial application

Pre-filling part of a child template so the creating program does not have to supply it at runtime.
Examples:

- fixed config values
- pre-bound root slots
- preselected visible export subset

### Exact template

A template whose child manifest is fixed and fully known ahead of creation time.

### Bounded template

A template whose child manifest is fixed or selected from a finite frozen catalog, but which allows
bounded variation such as open config fields or later slot binding.

### Open template

A template whose child manifest is selected at create time from a frozen manifest catalog.

### Template interface

The externally visible root contract of a child template:

- root config inputs
- root capability inputs (grants to root slots)
- root exports
- child-template catalog carried by the resulting child root

### Component Capability Server (CCS)

A privileged participant that serves the `framework.component` protocol. A CCS is distinct from the
site router and may be reached through the mesh.

### Capability instance

A single routed instance of a `framework.component` capability binding.

A capability instance has at least:

- a stable opaque identifier
- an authority realm
- a bound recipient identity or recipient set
- a transport endpoint

Forwarding a realm capability creates another capability instance with the same authority realm but
with a different recipient binding.

### Bindable source set

The set of capability/resource sources that may legally be bound into an open child-root slot for a
given authority realm at a given generation of live state.

### External site

Amber’s root-only external capability world. If the scenario has a root program, the scenario root
may bind from externally provided capabilities/resources that live outside Amber-managed sites.

### Weak binding

A binding whose absence is permitted by Amber’s runtime semantics. Weak bindings may still be absent
when a child becomes live.

### Authoritative control-state service

The single authoritative source of truth for dynamic component control state for a run.

It stores:

- the frozen base `ScenarioIr` captured at run start
- the frozen effective placement offer/default set captured at run start
- the capability-instance table
- the durable control journal
- materialized live-state indexes derived from that journal

Snapshot, authorization, create, destroy, and recovery operate from this service. On-disk authored
manifests and placement files are not reread after the run begins.

### Control journal

The append-only durable log inside the authoritative control-state service.

The journal stores:

- operation history for create/destroy
- enough state transitions to support recovery
- enough history to support later provenance export without redesigning the core storage model

### Live-state index

Materialized state derived from the control journal and maintained by the authoritative control-state
service for efficient list/snapshot/recovery. It includes at least live child records, active
overlay ownership, capability-instance records, and any canonical-to-backend identity mappings.

### Site router

Amber’s per-site router, responsible for ordinary capability transport and router-to-router mesh
communication.

### Site actuator

A backend-specific control surface that realizes or destroys local workloads/resources on a site.
It is not directly exposed to user components.

### Dynamic export

A capability exported from a dynamically created child root back into the authority realm. Dynamic
exports become available as bindable sources for future child creation and may also be surfaced to
programs as runtime handles for convenience.

### Standby site

A site that is brought up and meshed even though it initially hosts no user workload, because the
current scenario plus child templates plus placement may later require it.

### Static-equivalent snapshot

A replay artifact consisting of:

- a live `ScenarioIr` for the current user-visible scenario, including child templates and frozen
  template manifest catalog entries needed by those templates
- effective placement data for that scenario

It excludes runtime-internal deployment machinery and excludes in-memory and ephemeral filesystem
state.

---

## 3. Architectural constraints from Amber

Amber’s current model already constrains the solution.

1. **Containment and capability routing are separate.**  
   The current scenario model already separates `parent/children` from binding edges. Dynamic
   components must preserve this split.

2. **Placement is outside manifests.**  
   Amber already treats placement as operator-supplied data. Dynamic components must extend that
   same placement/run-plan model rather than smuggling placement into manifests.

3. **Routers are per-site and already own cross-site data transport.**  
   Dynamic creation should reuse the existing mesh pattern rather than inventing a second cross-site
   data plane.

4. **Framework capabilities are compiler-known today.**  
   `framework.docker` already demonstrates that Amber can recognize and specially lower a framework
   capability. `framework.component` should be treated as a first-class framework capability, but it
   must not inherit Docker-specific semantics.

5. **The current router control plane is immature.**  
   Existing ad hoc dynamic hooks are not enough for long-lived dynamic topology mutation. The design
   must account for real live routing control.

6. **Runs currently materialize sites based on static usage.**  
   That is insufficient once a currently empty site may later host a dynamic child.

7. **Realized execution is not the logical scenario graph.**  
   Once manifests are realized into running routers, sidecars, containers, VMs, and processes, the
   execution topology is just a graph of participants and routes. Logical parent/child structure is
   a control-plane concept, not a thing that must literally exist in the realized execution graph.

8. **Logical optimization cannot erase realm semantics.**  
   Amber may flatten or optimize routing-only structure today, but dynamic components require some
   logical nodes to remain semantically present even when they do not correspond to special runtime
   workloads.

These constraints explain why some superficially plausible designs are wrong for Amber.

---

## 4. High-level architecture and major design choices

### 4.1 Conceptual model

Dynamic creation is a mutation of the logical scenario graph.

- The child root is inserted under the authority realm component.
- The child may internally contain any component/resource graph allowed by its manifest.
- Grants are resolved from capabilities/resources already available in the authority realm, plus any
  runtime handles explicitly supplied.
- The resulting live graph remains a single Amber scenario.

The external mental model is therefore the same as for static Amber components:

```text
parent realm
  grants caps + config
  creates child root
  receives child exports
```

The only difference is that the child root is instantiated at runtime rather than at authoring
time.

### 4.2 Runtime requirements for v1

The following are hard requirements for the first implementation.

1. **Single source of truth.**  
   There must be exactly one authoritative control-state service per run.

2. **Mesh-authenticated control endpoint.**  
   `framework.component` must terminate at a privileged endpoint reached through ordinary Amber
   routing. Programs must not talk directly to routers, actuators, or control-state storage.

3. **Cross-site transport remains router-mediated.**  
   Cross-site capability transport must continue to use site routers. Dynamic components do not
   introduce a second capability transport plane.

4. **Privileged actuation stays off the application surface.**  
   Backend actuation for Direct/Compose/Kubernetes/VM must not be directly exposed to user programs.

5. **Dynamic-enabled active sites must be control-capable.**  
   Any site that is active at run start and may later host dynamic workloads must have the routing
   and privileged control presence required to create there later, even if it starts with zero user
   workloads.

6. **Endpoint-to-capability-instance mapping is one-to-one.**  
   The delivered `framework.component` endpoint must identify exactly one capability instance. Two
   distinct capability instances must not be indistinguishable at the application surface.

### 4.3 Recommended v1 realization

The following are the recommended structures for this version.

- **singleton CCS per active site**
- **single runner-local authoritative control-state service**, reached by CCSs over a private
  control path
- **host-local actuator helper** per site, reached by CCS over private IPC

These are recommendations, not semantic requirements. Equivalent structures are acceptable only if
they preserve the requirements above.

### 4.4 Why this architecture fits Amber

It fits Amber for six reasons.

1. **It preserves capability-based security.**  
   Possession of a binding is authorization. No extra application token scheme is introduced.

2. **It matches Amber’s mesh model.**  
   A capability provider may be remote. Sidecars already mediate all communication.

3. **It keeps routers and controllers separate.**  
   The router remains a transport component. The CCS remains a privileged control participant.

4. **It keeps backend actuation off the application surface.**  
   User programs never receive Docker, Kubernetes, VM, or host-process control APIs.

5. **It gives one source of truth for live state.**  
   Snapshot, authorization, recovery, and journal replay all read from the same authoritative
   control-state service rather than from a mixture of runtime scraping and on-disk source files.

6. **It is compatible with later `amber-node` expansion.**  
   A future meta-router can dispatch to site-local CCS instances without changing the application
   surface.

### 4.5 Major architectural alternatives

#### A. Local per-caller cap server in the sidecar

**Pros**
- simple mental model for the caller
- easy to attach to the local program lifecycle

**Cons**
- overcommits the implementation to one topology
- mixes untrusted local transport machinery with privileged realm control
- makes it too easy to accidentally treat the sidecar as authority rather than as transport

**Decision**  
Rejected as the architectural requirement. A local proxy may exist as an optimization, but the
security model must not depend on it.

#### B. Reuse the site router as the CCS

**Pros**
- fewer injected participants
- potentially fewer IPC hops

**Cons**
- conflates data plane and privileged control plane
- weakens least privilege
- makes router recovery and testing more complex

**Decision**  
Rejected.

#### C. Host-only controller outside the mesh

**Pros**
- simple in a single-host toy implementation
- central place for bookkeeping

**Cons**
- wrong for decentralized cross-site scenarios
- ignores Amber’s capability system as the security boundary
- does not fit self-living workloads that initiate requests remotely

**Decision**  
Rejected.

#### D. Per-site CCS + separate router + separate actuator + single authoritative control-state service

**Pros**
- matches Amber’s mesh and capability model
- preserves least privilege between transport, policy, and backend actuation
- provides a clean home for crash recovery, snapshot state, and capability-instance state
- avoids multiple sources of truth

**Cons**
- more moving parts
- requires a real control protocol and authoritative state model

**Decision**  
Recommended v1 realization.

---

## 5. Per-component / feature technical specification

### 5.1 Manifest authoring surface

#### 5.1.1 `framework.component`

Amber adds a new framework capability source:

```json5
{ "from": "framework.component" }
```

It is a typed capability of kind `component`.

Rules:

- it may only bind to a slot of capability kind `component`
- it is routed through the Amber mesh like any other routed capability
- it is not mountable
- once bound into the graph, it may be forwarded, exported, or granted like any other capability,
  subject to ordinary Amber routing rules

This last point is essential. If a parent forwards its `framework.component` capability to a child,
that child must be able to act in the parent’s realm.

#### 5.1.2 Capability kind and transport profile

Amber adds `CapabilityKind::Component`.

Its runtime transport profile is:

- **delivery shape:** routed endpoint URL provided to the program
- **wire protocol:** HTTP/JSON, versioned under `/v1`
- **mountability:** non-mountable
- **routing treatment:** routed point-to-point capability, like other URL-delivered caps today
- **semantic meaning:** not a generic HTTP endpoint; a typed realm-management capability

A program typically receives it in environment or config exactly the same way it would receive a
URL-like capability today, for example:

```json5
{
  slots: {
    realm: { kind: "component" },
  },
  program: {
    path: "./orchestrator",
    env: {
      AMBER_REALM_URL: "${slots.realm.url}",
    },
  },
}
```

##### Alternatives

| Option | Pros | Cons | Decision |
|---|---|---|---|
| New typed capability carried as routed URL/HTTP endpoint | Reuses current runtime plumbing; concrete and implementable now | Semantic typing lives above the transport | Recommended |
| New binary/handle transport | Cleaner type story on paper | Requires much more new runtime plumbing | Rejected for this feature |
| Mountable filesystem capability | Familiar to some systems | Wrong abstraction; unsafe; not how Amber routes framework control | Rejected |

#### 5.1.3 Child templates are keyed by name

Child templates are declared as a map keyed by local template name.

A second explicit `id` field is not required. The canonical template identity used internally for
journaling, diagnostics, and snapshot reconstruction is derived from:

- the owning component identity in the logical graph
- the local child-template key

This keeps manifest authoring human-friendly while still giving the runtime a stable identity.

#### 5.1.4 Child templates only on components that can create children

A manifest may declare `child_templates` only if it can actually hold a `component` capability.

Rule:

- a manifest with `child_templates` must declare at least one slot of capability kind `component`

There is no point in defining child-creation policy on a component that cannot create children.

#### 5.1.5 Template shape: partial application first, constraints second

The authoring model should feel like partial application of ordinary component syntax.

A child template must support at least:

- `manifest`: one fixed child manifest
- `allowed_manifests`: an open/bounded manifest selection rule
- root `config`: open, partially prefilled, or fully prefilled
- root `bindings`: open, partially prefilled, or fully prefilled
- optional export masking
- child limits such as naming/cardinality
- optional site-kind request hints for open templates

The default should be **unconstrained** unless the author opts into more structure.

#### 5.1.6 Partial application semantics

For each child-root config field or slot, the template may choose one of three shapes.

**Config**
- **open:** caller must or may provide the value at create time
- **prefilled:** template provides the value; caller cannot change it
- **future bounded set:** reserved for a later extension, not required in the first version

**Root bindings**
- **open:** caller may bind any authority-realm-visible compatible source
- **prefilled:** template already binds that slot from a specific realm-relative source
- **future allowlist:** reserved for a later extension, not required in the first version

**Root exports**
- **default:** all root exports are visible to the authority realm as ordinary exports of the child
- **optional mask:** template may choose to hide a subset for auditability; this is useful but not
  required for the first version

Dynamic export delegation/attenuation belongs to the future dynamic-capability story and should not
become mandatory syntax now.

#### 5.1.7 No extra policy layer for giving a child `framework.component`

A child should receive `framework.component` only if the parent gives it that capability through the
ordinary capability system.

There is no need for a second policy layer that says whether `framework.component` is allowed. If it
should not be available, do not bind it.

#### 5.1.8 Open-template site-kind hints

Open templates may optionally declare the kinds of sites they might require, expressed as sets, for
example:

```json5
possible_backends: ["direct", "compose"]
```

This is **not placement** and it is not a promise that all those sites will be used. It is only an
upper bound used to determine which standby sites may need to be activated if placement offers them.

#### 5.1.9 Authoring examples

Exact template:

```json5
{
  slots: {
    realm: { kind: "component" },
    db: { kind: "url" },
  },

  child_templates: {
    worker: {
      manifest: "./worker.json5",
      config: {
        mode: "batch",
      },
      bindings: {
        db: "slots.db",
        realm: "slots.realm",
      },
    },
  },

  program: {
    path: "./orchestrator",
    env: {
      AMBER_REALM_URL: "${slots.realm.url}",
    },
  },
}
```

Open template over a selector-expanded catalog:

```json5
{
  slots: {
    realm: { kind: "component" },
  },

  child_templates: {
    arbitrary_job: {
      allowed_manifests: {
        root: "./jobs",
        include: ["**/*.json5"],
        exclude: ["**/*.test.json5"],
      },
      possible_backends: ["direct", "vm"],
    },
  },
}
```

#### Alternatives considered for template authoring

| Option | Pros | Cons | Decision |
|---|---|---|---|
| No constraints at all; every slot/config open | Lowest manifest overhead | Less static legibility; fewer optimization and audit opportunities | Insufficient as the only model |
| Fully baked child only; no runtime choice | Maximum static clarity | Too restrictive for real orchestrators; poor ergonomics for dynamic use | Rejected as the only model |
| Partial application with unconstrained defaults and optional future narrowing | Familiar authoring model; good ergonomics; preserves a path to stronger policy later | Less static knowledge in the unconstrained case | Recommended |
| Mandatory allowlists/masks everywhere | Strongest explicitness | High cognitive overhead; forces authors to care when they may not want to | Rejected |
| Extra component-capability policy field for child re-grant | Explicit on paper | Redundant with the capability system; wrong abstraction | Rejected |

### 5.2 `ScenarioIr` extension and frozen template source model

#### 5.2.1 `ScenarioIr` version bump

`ScenarioIr` must be extended and version-bumped.

The new frozen scenario representation for runs and snapshots must include:

- `child_templates` on components
- a frozen manifest catalog for those templates

Recommended shape:

```text
ScenarioIr {
  schema: "amber.scenario",
  version: 5,
  root: ComponentId,
  components: Map<ComponentId, ComponentIr>,
  bindings: [BindingIr],
  exports: Map<ExportName, ExportIr>,
  manifest_catalog: Map<CatalogKey, ManifestCatalogEntryIr>,
}
```

```text
ComponentIr {
  ...existing fields...
  child_templates: Map<TemplateName, ChildTemplateIr>,
}
```

#### 5.2.2 `ChildTemplateIr`

Recommended frozen IR shape:

```text
ChildTemplateIr {
  // Exactly one of manifest or allowed_manifests must be present.
  manifest: CatalogKey?
  allowed_manifests: [CatalogKey]?

  // Partial application fields. Omitted entry means open.
  config: Map<FieldName, TemplateConfigFieldIr>
  bindings: Map<SlotName, TemplateBindingIr>

  // Optional visibility narrowing. Omitted means all root exports visible.
  visible_exports: [ExportName]?

  limits: ChildTemplateLimitsIr?
  possible_backends: [BackendKind]?
}
```

```text
TemplateConfigFieldIr =
  { mode: "prefilled", value: JsonValue }
  | { mode: "open", required: bool }

TemplateBindingIr =
  { mode: "prefilled", selector: RealmSelector }
  | { mode: "open", optional: bool }

ChildTemplateLimitsIr {
  max_live_children: integer?
  name_pattern: string?
}
```

Rules:

- exactly one of `manifest` or `allowed_manifests` must be present
- `allowed_manifests` must be non-empty
- child-template keys are unique per component
- `config` and `bindings` only specify prefilled entries; omitted entries remain open by default
- `visible_exports` is a mask, not a second export namespace

#### 5.2.3 Frozen manifest catalog

The frozen manifest catalog is the runtime and snapshot source of truth for template manifest
selection.

Recommended shape:

```text
ManifestCatalogEntryIr {
  source_ref: string
  digest: string
  manifest_ir: FrozenManifestIr
}
```

Where `FrozenManifestIr` is the parsed/canonicalized manifest representation sufficient to compile or
instantiate the child fragment without rereading disk.

Rules:

- exact templates point at one catalog entry
- open/bounded templates point at a finite set of catalog entries
- catalog keys are stable, deterministic strings derived from normalized `source_ref`
- selector-based `allowed_manifests` in authored manifests are expanded at run start into a finite,
  lexicographically ordered set of catalog entries and stored in the frozen base scenario
- runtime `CreateChild` for an open template selects one catalog key, not a file path
- two catalog entries may share a digest and still remain distinct if their normalized `source_ref`
  differs

#### 5.2.4 What is frozen and what may be re-derived

The following must be frozen at run start and persisted in authoritative control state:

- base `ScenarioIr` v5
- manifest catalog
- effective placement offer/default set

The following may be re-derived deterministically from frozen and live authoritative state:

- standby-site activation set
- bindable source set
- canonical participant identities
- live graph materialization from base scenario plus live child records

The following are runtime internal and need not be stable across replay:

- transport endpoint URLs
- transaction ids
- backend-native object ids
- opaque runtime handles

#### 5.2.5 Open template source alternatives

##### A. Reread the filesystem or source tree at create time

**Pros**
- simple on paper
- no frozen catalog needed

**Cons**
- violates determinism
- violates the single-source-of-truth rule
- makes snapshot/replay dependent on whatever happens to be on disk later

**Decision**  
Rejected.

##### B. Store only original file refs and reread them on replay

**Pros**
- compact frozen state

**Cons**
- replay is no longer self-consistent
- different file contents later can silently change behavior

**Decision**  
Rejected.

##### C. Expand authored refs/selectors into a finite frozen manifest catalog at run start

**Pros**
- deterministic
- self-consistent for runtime and snapshot
- supports open templates without runtime disk access

**Cons**
- more upfront freezing work
- selector expansion must be well-defined

**Decision**  
Recommended.

### 5.3 Realm-significant logical nodes and optimization barriers

#### 5.3.1 Realm-significant nodes

A logical component is **realm-significant** if any of the following are true:

- it declares `child_templates`
- it directly holds a slot/provide/export of capability kind `component`
- it forwards or re-exports a capability of kind `component`
- it is the scenario root and a root program may bind from the external site

Realm-significant nodes are authority boundaries and template owners.

#### 5.3.2 Optimization rule

Realm-significant nodes must remain explicit logical nodes in the frozen base scenario and in live
logical graph state.

They may still compile to no dedicated runtime workload if they have no program, but they must not be
flattened away in any optimization pass that would erase:

- their identity
- their child-template catalog
- their role as the parent of dynamic children
- their role as the authority realm of a `framework.component` capability instance

#### Alternatives

##### A. Preserve realm-significant nodes as logical optimization barriers

**Pros**
- simplest semantic model
- easy to reason about snapshot, authority, and parenthood
- avoids split ownership state

**Cons**
- some logical nodes remain even if they are routing-only

**Decision**  
Recommended.

##### B. Flatten them away and reconstruct authority/template ownership from side tables

**Pros**
- potentially more aggressive optimization

**Cons**
- splits the semantic model
- makes snapshot, recovery, and authorization harder to reason about
- easier to get wrong

**Decision**  
Rejected.

### 5.4 Authority, bindable source set, and request authentication

#### 5.4.1 The capability controls the origin realm

A `framework.component` capability always controls the realm where it originated.

If a parent forwards its realm capability to a child, then:

- the transport caller is the child
- the authority realm remains the parent’s realm

All realm-relative request selectors must resolve against the authority realm, not the transport
caller.

#### 5.4.2 The authority-realm bindable source set

For an authority realm `R` at live-state generation `G`, the bindable source set is the union of:

1. **static slots visible in `R`**
2. **static provides visible in `R`**
3. **Amber-legible resources visible in `R`**
4. **live dynamic exports that have entered `R` from live children**
5. **if `R` is the scenario root and a root program exists, root-visible external-site sources**
6. **runtime handles that resolve to one of the above**

Important points:

- runtime handles are a convenience reference into this set, not a second semantic namespace
- when a child becomes live, its visible exports enter this set for the authority realm
- when a child is destroyed or its export is removed from the graph, that source leaves the set
- for non-root realms, external-site sources are not directly bindable unless they have already
  entered the realm through ordinary Amber bindings

This set is what open child-root slots draw from.

#### 5.4.3 Realm selectors

Realm selectors are the stable textual way to refer to entries in the bindable source set.

Required selector forms:

- `slots.<name>`
- `provides.<name>`
- `resources.<name>`
- `children.<child-name>.exports.<export-name>`
- `external.<name>` — only valid when the authority realm is the scenario root and the source is
  root-visible

The implementation may internally use a structured representation, but it must preserve these
selector semantics.

#### 5.4.4 Template metadata exposed to programs

The create API must expose template metadata in a user-friendly way so programs can discover:

- which config fields are already prefilled
- which config fields are open
- which root slots are already bound
- which root slots are still open
- the kinds of sources compatible with each open slot
- the current concrete candidate sources from the authority-realm bindable source set
- the child root’s exports

This keeps the “partially applied template” legible to the program without forcing the author to
repeat every possible constraint in the manifest.

#### 5.4.5 Sidecars are transport, not authority

Programs and sidecars are not trusted to mint new realm authority.

A sidecar may be compromised or share a network namespace with a malicious program. Therefore the
CCS must never authorize a request solely because it came from “some sidecar on the right site” or
because the request payload names a realm.

Authority must come from a real bound capability instance.

#### 5.4.6 Capability-instance model

Every routed binding of a `framework.component` capability becomes a distinct capability instance.

A capability-instance record contains at least:

- `cap_instance_id`: opaque stable identifier
- `authority_realm_id`: the realm this instance controls
- `recipient_component_id` or allowed recipient identity set
- current route generation / epoch
- endpoint metadata needed for routing and diagnostics

Forwarding a realm capability creates a **new** capability instance with:

- the same `authority_realm_id`
- a different recipient binding

##### Endpoint mapping requirement

From the application’s perspective, each delivered `framework.component` endpoint identifies exactly
one capability instance. The application never supplies a separate capability-instance id in the
request body.

An implementation may realize this as:

- a unique URL per capability instance
- a shared service URL plus an opaque instance token embedded in the path or authority component of
  that URL

But the mapping must remain one-to-one at the application surface.

This is the key mechanism that prevents sidecars from minting framework authority for arbitrary
components.

#### 5.4.7 Where capability-instance records live

Capability-instance records are authoritative control state and must live in the same
authoritative control-state service as:

- frozen run inputs
- live child records
- active overlay ownership
- the control journal

They must not be split into a second authoritative store.

##### Alternatives

| Option | Pros | Cons | Decision |
|---|---|---|---|
| Keep capability-instance state local to each CCS | Simple local reads | Fragments authority across sites; harder forwarding/recovery; multiple sources of truth | Rejected |
| Encode capability-instance state only in the journal log and reconstruct on every request | Minimal materialized state | Slow, awkward for hot-path authorization | Rejected |
| Store capability-instance state in the same authoritative control-state service as live child and journal state | Single source of truth; simple recovery; coherent auth model | Requires one real control-state service | Recommended |

#### 5.4.8 Chosen request-authentication algorithm

Every `framework.component` request must be authorized by the CCS using the following algorithm.

1. The program calls the opaque endpoint it received from Amber.
2. The local sidecar transports that request through the normal mesh path.
3. The CCS obtains the authenticated mesh peer identity from the transport.
4. The CCS extracts or resolves `cap_instance_id` from the endpoint being invoked.
5. The CCS looks up `cap_instance_id` in the authoritative control-state service.
6. The CCS verifies that the authenticated mesh peer identity is the currently bound recipient for
   that capability instance.
7. The CCS loads `authority_realm_id` from the capability-instance record.
8. The CCS executes the operation relative to `authority_realm_id`, not relative to any realm named
   by the caller.

The request payload MUST NOT contain an untrusted “target realm” field that can override this.

#### 5.4.9 Security consequences of this algorithm

This model provides the following guarantees.

1. **A sidecar cannot mint a new graph-visible framework capability.**  
   Creating a new capability instance requires controller-managed graph mutation and route
   publication, not just sending a network request.

2. **A sidecar cannot claim arbitrary realm authority.**  
   The authority realm comes from the capability-instance record, not from request input.

3. **A sidecar cannot impersonate another component merely by guessing an endpoint.**  
   The CCS validates the authenticated mesh peer identity against the capability-instance record.

4. **A malicious holder can still exercise the capabilities it actually possesses.**  
   This is inherent to capability systems. If a component legitimately holds a realm capability, it
   can use it. What it cannot do is convince Amber that some other component now holds that
   capability without a real binding.

#### 5.4.10 Destruction authority

Only holders of the relevant realm authority may destroy children in that realm.

That means:

- the parent can destroy its child
- a delegate holding the parent’s forwarded realm capability can also destroy that child
- unrelated components cannot

This is not “creator process only”. It is realm-authority only.

#### Alternatives considered for security and authority

| Option | Pros | Cons | Decision |
|---|---|---|---|
| Authorize relative to transport caller | Easy to implement | Breaks forwarded realm capability; wrong semantics | Rejected |
| Let request payload name the target realm | Simple API shape | Sidecar/program could attempt authority confusion; wrong trust boundary | Rejected |
| Authenticate on mesh peer identity alone | Uses existing transport auth | Not enough; does not bind the call to a specific framework-capability instance | Rejected |
| Authenticate on `(mesh peer identity, cap_instance_id)` and derive authority realm from stored state | Robust to sidecar compromise within the intended threat boundary; supports forwarding correctly | Requires a real capability-instance table | Recommended |
| Separate bearer token/session layer on top | Familiar RPC pattern | Redundant with Amber capabilities; more attack surface and state | Rejected |

### 5.5 Placement, standby sites, and run-plan state

#### 5.5.1 Placement remains outside manifests

Placement stays entirely in the placement/run-plan world.

That includes:

- site definitions
- site offers/availability
- defaults by program kind
- explicit static assignments
- standby-site activation policy

Child templates must not name concrete sites.

#### 5.5.2 No item-level placement overrides in this feature

This feature does **not** introduce per-template or per-child placement overrides in the placement
file.

Reasons:

- Amber’s current placement files are human-authored and work better as sets and defaults than as
  many item-specific rules
- child template identities are scoped to their owning component and are not the right operator
  abstraction for this first feature
- the feature does not currently need template-specific override machinery to satisfy its goals

Dynamic child placement in this feature uses the same ordinary placement algorithm Amber already
uses, applied to the instantiated child fragment against the currently active offered sites.

#### 5.5.3 Runtime run-plan representation

For execution, the frozen effective run plan must contain at least:

- `offered_sites`: all sites the operator makes available to the run
- `defaults`: ordinary placement defaults by program kind
- `initial_active_sites`: the sites that will be started at run launch, including standby sites
- `active_site_capabilities`: enough information to know which active sites are capable of later
  hosting dynamic components and cross-site routing

A site in `initial_active_sites` may start with zero user workloads.

#### 5.5.4 Standby-site activation rule

Standby-site activation is a function of:

- sites required by the static scenario
- sites requested by analyzable exact/bounded templates
- site-kind upper-bound requests from open templates
- site offers in the placement file

At run start, Amber activates:

1. sites needed by the static scenario
2. sites required by analyzable exact/bounded templates
3. sites requested by open-template hints, intersected with placement offers
4. any control-plane-only sites required by the architecture

Amber must **not** activate every offered site merely because a template is open.

#### 5.5.5 Chosen analysis algorithm for site activation

At run-plan construction time:

1. Freeze the base scenario and the placement file’s offered site set/defaults into the authoritative
   control-state service.
2. Add sites required by statically placed components.
3. Scan all child templates reachable in the scenario.
4. For each exact/bounded template whose manifest(s) are statically known:
   - load the referenced frozen catalog entries
   - examine the runnable program kinds/resources in that fragment
   - run the ordinary deterministic placement resolver against the offered site set
   - union the required site kinds/sites into the standby request set
5. For each open template:
   - union any declared `possible_backends`/program-kind hints into the standby request set
6. Intersect requested standby site kinds with the placement file’s offered sites.
7. The result becomes `initial_active_sites`.

If no placement file is provided, the CLI may synthesize a reasonable local offer set. If a
placement file is provided, Amber must respect it rather than silently adding cheap defaults.

#### 5.5.6 Templates without a fixed program

A template without a fixed root program is valid.

Cases:

1. **Exact template with known internal graph**  
   Amber can analyze the entire fragment and compute required sites.

2. **Open template or otherwise insufficiently analyzable fragment**  
   Amber does not activate every site “just in case”. Only sites requested by templates and offered
   by placement are activated. If a later create request requires a non-active site, the request
   fails deterministically with an operator-actionable error.

#### 5.5.7 Snapshot relation to standby sites

Standby-site activation state is not independent mutable state that must be snapshotted directly.
It is derived from:

- the snapshotted `ScenarioIr`, which includes child templates and frozen catalog entries
- the frozen effective placement output, which includes the site offer set and defaults

Replaying the snapshot recomputes the same standby site set from those inputs.

#### Alternatives considered for placement

| Option | Pros | Cons | Decision |
|---|---|---|---|
| Put concrete placement in child templates | Easy author-local reasoning | Violates Amber separation of concerns | Rejected |
| Add per-template placement overrides now | Precise operator control for some cases | Item-level leakage into human-authored placement; unclear user need; more complexity than needed | Rejected for this feature |
| Activate every offered site for open templates | Avoids some create-time failures | Lets author intent silently impose operator cost | Rejected |
| Use ordinary deterministic placement resolution over the instantiated fragment and active offered sites | Reuses existing model; keeps placement set-based | Requires clear standby analysis and good create-time errors | Recommended |

### 5.6 Runtime participants and authoritative control state

#### 5.6.1 Component Capability Server (CCS)

Each dynamic-enabled site should host a singleton privileged participant that:

- serves `framework.component`
- authenticates requests using the capability-instance algorithm above
- validates create/destroy against the authority realm’s templates and bindable source set
- coordinates local and remote work for multi-site operations
- drives local router-control updates
- drives local site-actuator work
- persists operation intent and outcome to the authoritative control-state service

Equivalent structures are acceptable if they preserve the runtime requirements in section 4.2.

#### 5.6.2 Site actuator alternatives

##### A. Actuator in-process with the CCS

**Pros**
- fewer boundaries
- fewer hops on the happy path

**Cons**
- policy engine and privileged backend actuation share one failure domain
- more backend-specific code inside the CCS
- harder to test actuation separately

##### B. Host-local helper reached by private IPC

**Pros**
- clean separation between realm/control policy and backend actuation
- privileged host integration remains off the mesh and off the application surface
- easy to keep a common logical API while using backend-specific host integrations

**Cons**
- one more boundary and protocol
- requires private IPC setup on each site type

##### C. Separate mesh participant actuator component

**Pros**
- uniform “everything is a participant” mental model
- actuator could in principle be remote

**Cons**
- expands the privileged mesh surface unnecessarily
- more injected scenario machinery
- weaker least privilege than a host-local helper

**Decision**  
Recommend **B: host-local helper reached by private IPC**.

#### 5.6.3 Authoritative control-state service alternatives

##### A. Memory-only controller state

**Pros**
- simplest to start
- fast

**Cons**
- no crash recovery
- no reliable snapshot basis
- no coherent capability-instance persistence
- poor operational debugging story

##### B. Disk-backed append-only journal with materialized in-memory indexes

**Pros**
- robust crash recovery
- reliable basis for snapshot, auth, and future provenance export
- single source of truth
- practical complexity for this feature

**Cons**
- requires durable write discipline and compaction/checkpointing
- needs a designated place to live

##### C. Fully replicated distributed control store

**Pros**
- strongest availability story
- resilient to control-node loss

**Cons**
- much higher complexity than needed now
- significant implementation and operational burden

**Decision**  
Recommend **B: disk-backed append-only journal with materialized in-memory indexes**, packaged as
the authoritative control-state service.

#### 5.6.4 Service placement alternatives

##### A. Per-site local control stores

**Pros**
- local reads/writes

**Cons**
- multiple sources of truth
- awkward forwarding and cross-site recovery
- hard to implement global snapshot safely

**Decision**  
Rejected.

##### B. Single per-run runner-local authoritative service reached by CCSs over a private control path

**Pros**
- one source of truth
- easy to freeze run inputs once
- simple recovery and snapshot semantics
- does not require any realm “home” in the realized execution graph

**Cons**
- control availability depends on runner-local service availability
- requires private connectivity from CCSs to the service

**Decision**  
Recommended v1 realization.

##### C. Colocate authoritative state with one CCS chosen from the live scenario

**Pros**
- everything stays “inside the scenario”

**Cons**
- awkward if that site is remote or less stable
- creates an unnecessary semantic link between authority and store placement

**Decision**  
Rejected.

#### 5.6.5 What the authoritative control-state service stores

The authoritative control-state service must store, durably:

- frozen base `ScenarioIr` captured at run start
- frozen effective placement offer/default set captured at run start
- capability-instance records
- append-only control journal
- live child records
- active overlay ownership/indexes
- deterministic participant identity mappings if backend-native identifiers differ from canonical
  Amber identities

This is the only authoritative source of dynamic control truth for the run. Snapshot, create,
destroy, authorization, and recovery must derive from it. No dynamic operation should reread
authored manifests or placement files from disk after run start.

#### 5.6.6 Availability behavior

If the authoritative control-state service is unavailable:

- **write-dependent mutating operations** (`CreateChild`, `DestroyChild`, forwarding that creates a
  new capability instance, or any other graph mutation) must fail without committing new graph
  state
- **read-dependent control operations** (list children, inspect templates, snapshot) may fail with a
  `control_state_unavailable` error
- **existing already-live capability traffic** continues according to the last published router and
  sidecar state; Amber does not retroactively retract live routes merely because control state is
  temporarily unavailable

#### 5.6.7 Provenance support without making snapshot depend on it

The journal should be append-only and event-oriented enough to support later provenance export. A
practical structure is:

- append-only operation log: `create_requested`, `create_prepared`, `create_committed_hidden`,
  `create_live`, `destroy_requested`, `destroy_retracted`, `destroy_committed`, etc.
- checkpointed live-state indexes keyed by live child root and capability instance

Snapshot uses the live-state indexes. Provenance export can later read the operation log. This
avoids forcing provenance fields into `ScenarioIr` while still keeping the design
provenance-friendly.

### 5.7 Router control plane and determinism

#### 5.7.1 Requirements

The router/sidecar control plane must support dynamic changes that are:

- declarative, not just imperative one-route-at-a-time mutations
- owned by a specific dynamic child instance or binding set
- revocable as a unit
- introspectable and replayable after restart
- applicable to both component sidecars and site routers

#### 5.7.2 Alternatives

##### A. Ad hoc imperative patch endpoints

Examples: “add peer”, “override slot”, “register export”.

**Pros**
- easy to prototype

**Cons**
- hard to revoke precisely
- hard to replay after restart
- hard to reason about partial failure and ownership

##### B. Journal-only route deltas with no runtime ownership objects

**Pros**
- simple persistent representation

**Cons**
- routers still need to reconstruct who owns what
- runtime introspection and selective revoke are clumsy

##### C. Instance-owned route-set overlays

Each dynamic child or binding set owns one or more overlay objects containing the additional route
state needed beyond the static config.

**Pros**
- precise revoke semantics
- natural fit for prepare/publish/revoke
- easy replay: routers recompute `effective = static + active overlays`

**Cons**
- requires a more structured control API than today

**Decision**  
Recommend **C: instance-owned route-set overlays**.

#### 5.7.3 Overlay object shape

An overlay object should contain at least:

- `overlay_id`
- `owner_child_id` or `owner_binding_set_id`
- target participant identity (sidecar or site router)
- generation/epoch
- route additions or issuer additions
- publish state: `prepared`, `active`, or `revoked`

Routers and sidecars should treat the static config plus all active overlays as the effective live
route set.

#### 5.7.4 Canonical participant identity

Overlay computation is simplest and most deterministic if participant identities are known before
publication.

##### Alternatives

| Option | Pros | Cons | Decision |
|---|---|---|---|
| Deterministic canonical identity derived from `(run_id, site_id, logical_component_id, role)` | Overlays can be computed up front; highly deterministic; easier recovery | Requires every backend to respect or map to the canonical identity | Recommended |
| Allocate identities during prepare, then compute overlays afterward | Works even if backend-generated ids are opaque | Adds an extra allocation subphase; more moving parts | Acceptable fallback only if strictly necessary |
| Use backend-native random ids directly | Easy for some backends | Weak determinism; awkward recovery; harder snapshot/debugging | Rejected |

**Chosen rule**  
Amber defines a deterministic canonical participant identity for every sidecar/router/control
participant. If a backend cannot literally use that string as its object name, it must still map the
backend-native identifier to the canonical Amber identity inside the authoritative control-state
service. Overlay computation and live graph semantics use the canonical identity.

#### 5.7.5 What must remain stable, and what need not

**Stable within a run, including recovery:**

- child local names
- child ids
- capability-instance ids
- canonical participant identities
- selected manifest catalog keys
- overlay ids and ownership

**Stable across snapshot/replay of the same scenario:**

- logical component structure
- parent/child relationships
- child template keys
- manifest catalog contents and catalog keys
- child local names
- concrete placement assignments
- realm selectors and binding topology

**Not required to remain stable across replay:**

- transaction ids
- opaque runtime handles
- transport endpoint URLs
- backend-native object ids

This is the determinism contract for the feature.

#### 5.7.6 Publication barrier and weak bindings

A newly created child may observe **weak** bindings as absent. It must not observe **nonweak**
bindings as missing once it becomes live from the program’s perspective.

##### Alternatives

| Option | Pros | Cons | Decision |
|---|---|---|---|
| Delay workload/program start until nonweak overlays are active | Strong semantics, simple reasoning | Some backends may make delayed start awkward | Preferred where practical |
| Start sidecar/workload earlier but gate readiness and nonweak capability availability until publish completes | Works across more backends; preserves semantics | More runtime coordination logic | Acceptable and often necessary |
| Allow all bindings to race and let programs cope | Simplest implementation | Wrong semantics for nonweak bindings | Rejected |

**Chosen rule**  
Before a child becomes `create_live`, all nonweak declared bindings visible to the child must be
published and available from the child program’s perspective. Weak bindings may still be absent.
This may be implemented either by delaying program start or by gating readiness/nonweak capability
availability until publication completes.

### 5.8 `framework.component` application protocol

#### 5.8.1 Transport

The `component` capability serves an HTTP/JSON protocol over the routed endpoint URL.

The URL is opaque to the caller. The caller does not get to infer authority realm, site, or
internal topology from it.

#### 5.8.2 Operations

The required application-facing operations are:

- `GET /v1/templates`
- `GET /v1/templates/{template}`
- `GET /v1/children`
- `GET /v1/children/{name}`
- `POST /v1/children`
- `DELETE /v1/children/{name}`
- `POST /v1/snapshot`

`POST /v1/snapshot` returns the full scenario snapshot. It is allowed only when the authority realm
of the capability instance is the scenario root. Otherwise the request fails with
`scope_not_allowed`.

#### 5.8.3 Template listing and description

`GET /v1/templates` returns summaries of the child templates in the authority realm.

Recommended response shape:

```json
{
  "templates": [
    {
      "name": "worker",
      "mode": "exact",
      "possible_backends": ["compose"]
    },
    {
      "name": "arbitrary_job",
      "mode": "open",
      "possible_backends": ["direct", "vm"]
    }
  ]
}
```

`GET /v1/templates/{template}` returns a detailed description of the template interface as seen from
the current authority realm generation.

Recommended response shape:

```json
{
  "name": "worker",
  "manifest": {
    "mode": "exact",
    "catalog_key": "catalog/worker",
    "digest": "sha256:..."
  },
  "config": {
    "mode": { "state": "prefilled", "value": "batch" },
    "count": { "state": "open", "required": true }
  },
  "bindings": {
    "db": {
      "state": "prefilled",
      "selector": "slots.db"
    },
    "seed": {
      "state": "open",
      "optional": false,
      "compatible_kind": "url",
      "candidates": [
        "provides.api",
        "children.prev-job.exports.result"
      ]
    }
  },
  "exports": {
    "visible": ["result"]
  },
  "limits": {
    "max_live_children": 64
  }
}
```

Rules:

- `candidates` are computed from the authority-realm bindable source set at request time
- for open templates, `manifest.mode = "open"` and the response includes the allowed catalog keys
- the transport caller never chooses from sources outside the candidate set and type-compatibility
  rules

#### 5.8.4 `CreateChild` request and response

Recommended request shape:

```json
{
  "template": "worker",
  "name": "job-1",
  "config": {
    "count": 5
  },
  "bindings": {
    "seed": { "selector": "provides.api" }
  }
}
```

Open-template variant:

```json
{
  "template": "arbitrary_job",
  "name": "job-2",
  "manifest": { "catalog_key": "catalog/jobs/reporter" },
  "bindings": {
    "input": { "selector": "children.prev-job.exports.result" }
  }
}
```

Rules:

- `name` is required in this feature
- for exact templates, `manifest` must be absent
- for open templates, `manifest.catalog_key` must be present and must be one of the template’s
  allowed catalog keys
- each binding value must specify exactly one of:
  - `selector`
  - `handle`
- `selector` is a realm selector
- `handle` is an opaque convenience token previously returned by this protocol and still valid in
  the authority-realm bindable source set

Recommended success response:

```json
{
  "child": {
    "name": "job-1",
    "selector": "children.job-1"
  },
  "outputs": {
    "result": {
      "selector": "children.job-1.exports.result",
      "handle": "h_01HV..."
    }
  }
}
```

The `selector` is the stable Amber-legible representation. The `handle` is a convenience alias.

##### Handle validity

A returned handle is valid only while the referenced source remains in the authority-realm bindable
source set. If the source is removed from that set, later use of the handle must fail with
`binding_source_not_found`.

#### 5.8.5 Child inspection and list

`GET /v1/children` lists the live direct children of the authority realm.

Recommended response shape:

```json
{
  "children": [
    {
      "name": "job-1",
      "state": "live"
    }
  ]
}
```

`GET /v1/children/{name}` returns inspection metadata.

Recommended response shape:

```json
{
  "name": "job-1",
  "state": "live",
  "outputs": {
    "result": {
      "selector": "children.job-1.exports.result",
      "handle": "h_01HV..."
    }
  }
}
```

#### 5.8.6 Destroy

`DELETE /v1/children/{name}` destroys the named direct child of the authority realm.

Rules:

- destroy is idempotent success if the child is already fully gone
- destroy is authorized by authority-realm possession, not by “caller process was the creator”

#### 5.8.7 Snapshot

`POST /v1/snapshot` returns:

```json
{
  "scenario": { "...": "ScenarioIr v5" },
  "placement": { "...": "effective placement" }
}
```

Rules:

- allowed only when the authority realm of the capability instance is the scenario root
- if the request is made through a forwarded root realm capability, it is still allowed because the
  authority realm is the scenario root

#### 5.8.8 Mutation serialization

Mutating operations must be linearized in authoritative control state.

Required minimum rule:

- operations are serialized per authority realm
- operations that touch the same direct-child name under one authority realm are strictly
  single-writer

Consequences:

- concurrent `CreateChild` on the same authority realm and child name deterministically produce one
  success and the rest `name_conflict`
- `CreateChild` and `DestroyChild` on the same direct child are observed in a single authoritative
  order
- snapshot sees a consistent generation, not a mix of two concurrent mutations

The implementation may use a coarser serialization domain if desired, but not a weaker one.

#### 5.8.9 Error model

All protocol errors return a structured body:

```json
{
  "code": "name_conflict",
  "message": "child 'job-1' already exists",
  "details": { "...": "optional" }
}
```

Required error codes:

- `unauthorized`
- `unknown_template`
- `unknown_child`
- `name_conflict`
- `manifest_not_allowed`
- `invalid_config`
- `invalid_binding`
- `binding_source_not_found`
- `binding_type_mismatch`
- `placement_unsatisfied`
- `site_not_active`
- `scope_not_allowed`
- `control_state_unavailable`
- `prepare_failed`
- `publish_failed`

The implementation may map these onto ordinary HTTP status codes, but the code names above are the
semantic contract.

### 5.9 Chosen create algorithm

#### 5.9.1 Alternatives

##### A. Best-effort create with cleanup attempts

**Pros**
- easiest to implement initially

**Cons**
- half-created children are likely
- poor recovery semantics
- snapshot correctness becomes unreliable

**Decision**  
Rejected.

##### B. Full distributed two-phase commit across all sites and routers

**Pros**
- strongest theoretical atomicity

**Cons**
- high implementation and operational complexity
- unnecessary for the current problem if externally atomic semantics are sufficient

**Decision**  
Not recommended for this feature.

##### C. Journaled prepare / commit / publish with compensating rollback

**Pros**
- practical balance of correctness and complexity
- supports crash recovery
- gives externally atomic semantics to the user

**Cons**
- requires durable journal and recovery logic
- creates several internal states that must be handled carefully

**Decision**  
Recommended.

#### 5.9.2 Name uniqueness and visibility

- Child local names are unique among direct children of an authority realm while those children are
  live or in-flight.
- `CreateChild` with a duplicate live or in-flight child name must fail deterministically with a
  `name_conflict` error.
- Only `create_live` children are visible in ordinary list/snapshot operations.

#### 5.9.3 Transaction states

A create operation uses the following states:

- `create_requested`
- `create_prepared`
- `create_committed_hidden`
- `create_live`
- `create_aborted`

Only `create_live` children are visible in ordinary list/snapshot operations.

#### 5.9.4 Detailed create algorithm

1. **Ingress and authentication**
   - receive the request at a CCS endpoint
   - authenticate the mesh peer identity
   - resolve `cap_instance_id`
   - validate `(mesh peer identity, cap_instance_id)`
   - load `authority_realm_id`

2. **Template lookup**
   - resolve the named child template in the authority realm’s component definition
   - because template names are scoped to their owning component, lookup happens within the
     authority realm, not in a global namespace

3. **Request validation**
   - validate child name against template limits and direct-child uniqueness
   - if the template is open, validate the selected `catalog_key` against the template’s
     `allowed_manifests`
   - validate config inputs against the template’s open/prefilled fields
   - validate open root-slot bindings against the authority-realm bindable source set

4. **Load the child manifest from frozen sources**
   - exact template: load the single referenced catalog entry
   - open template: load the selected referenced catalog entry
   - do not read disk or source manifests outside the frozen catalog

5. **Render the child fragment**
   - assign the child root’s absolute logical moniker under the authority realm
   - materialize the entire child fragment as a logical scenario fragment
   - preserve the child manifest’s own `child_templates`

6. **Apply partial application**
   - apply prefilled config fields
   - apply prefilled root bindings
   - for each remaining open root slot:
     - if the caller supplied a realm-relative selector, resolve it in the authority realm
     - if the caller supplied a runtime handle, resolve it to a live bindable source
     - if the slot is optional and omitted, leave it absent
     - otherwise error

7. **Construct the final logical child record**
   - rewrite template-root imports into concrete binding edges
   - compute the child subtree’s components/resources/bindings as they will appear in the live graph
   - compute the child root’s visible exports and returned-handle map

8. **Resolve placement**
   - run the ordinary deterministic placement resolver on the rendered child fragment against the
     active offered site set
   - if no valid placement exists because a needed site is not active/offered, fail with a
     deterministic operator-actionable error

9. **Allocate deterministic participant identities**
   - derive canonical participant identities for all new sidecars/routers/control participants from
     `(run_id, site_id, logical_component_id, role)`
   - if a backend requires backend-native ids, record the mapping in authoritative control state

10. **Compute site-local subplans and overlays**
    - determine affected sites
    - compute site-local workload/resource realization plans
    - compute router/sidecar overlay objects for each affected participant using canonical
      participant identities

11. **Durably record prepare intent**
    - allocate `tx_id` and `child_id`
    - append a durable `create_prepared` record containing:
      - authority realm id
      - child id and child name
      - rendered logical fragment
      - concrete placements
      - canonical participant identities
      - overlay objects
      - cleanup tags/labels for every backend artifact to be created
    - fsync or equivalent durability barrier

12. **Prepare site-local artifacts**
    - send prepare requests to affected site actuators to create resources/workloads in hidden or
      unpublished form
    - send prepare requests to routers/sidecars to stage overlays in `prepared` state
    - collect acknowledgements

13. **Rollback if prepare fails**
    - if any prepare fails, issue rollback to all prepared sites
    - append `create_aborted`
    - leave no live child in the logical graph

14. **Durably commit the child**
    - append `create_committed_hidden`
    - at this point the journal guarantees that recovery will either finish publication or continue
      cleanup deterministically

15. **Publish overlays and satisfy the publication barrier**
    - instruct routers/sidecars to publish the prepared overlays
    - instruct site actuators to make the child workload/resources reachable
    - ensure the publication barrier is satisfied:
      - all nonweak declared bindings visible to the child are available from the child program’s
        perspective
      - weak bindings may remain absent

16. **Mark child live**
    - append `create_live`
    - update live-state indexes
    - return child reference and export handles to the caller

#### 5.9.5 Why the child becomes visible only at `create_live`

If snapshot/list were to include `create_committed_hidden`, a recovery event could expose half-live
children to users. Restricting visibility to `create_live` keeps user-visible state crisp while
still allowing the system to durably commit intent before publication.

#### 5.9.6 Recovery rules

On restart:

- `create_prepared` without later state => rollback prepared artifacts
- `create_committed_hidden` without `create_live` => continue publication until `create_live` or,
  if publication is impossible, transition through explicit cleanup rules
- `create_live` => ensure overlays and local artifacts are present; repair if necessary

### 5.10 Chosen destroy algorithm

#### 5.10.1 Alternatives

##### A. Immediate graph deletion then asynchronous cleanup

**Pros**
- simple user-facing semantics

**Cons**
- easy to leak routability or backend artifacts during races
- difficult crash recovery

**Decision**  
Rejected.

##### B. Cleanup first, remove from graph only at the very end

**Pros**
- conservative

**Cons**
- child remains visible/routable longer than desirable
- awkward UX for destroy requests

**Decision**  
Not preferred.

##### C. Journaled retract / cleanup / commit removal

**Pros**
- child becomes unreachable early
- recovery is straightforward
- aligns with Fuchsia-like destroy semantics

**Cons**
- requires internal deleting states and durable bookkeeping

**Decision**  
Recommended.

#### 5.10.2 Idempotency and visibility

- `DestroyChild` is idempotent success if the named child is already fully gone.
- Children in `destroy_retracted` are no longer visible in ordinary list/snapshot operations.

#### 5.10.3 Destroy transaction states

A destroy operation uses the following states:

- `destroy_requested`
- `destroy_retracted`
- `destroy_committed`

Children in `destroy_retracted` are no longer visible in ordinary list/snapshot operations.

#### 5.10.4 Detailed destroy algorithm

1. **Ingress and authentication**
   - authenticate `(mesh peer identity, cap_instance_id)`
   - load `authority_realm_id`

2. **Authority check**
   - verify that the named child is a direct child of the authority realm
   - load the child’s committed logical fragment, placement, overlay ids, canonical participant
     identities, and backend labels from authoritative state

3. **Compute the removal cut**
   - compute the owned subtree rooted at the child
   - compute all graph bindings and route overlays incident on that subtree, including bindings whose
     other endpoint lies outside the subtree
   - identify surviving consumers/providers that will remain in the graph after those incident
     bindings are removed

4. **Durably record destroy intent**
   - append `destroy_requested`

5. **Retract routability**
   - instruct affected routers/sidecars to revoke overlays owned by that child and any overlays
     representing bindings incident on the removed subtree
   - wait for acknowledgement that the child is no longer reachable through nonweak paths and that
     surviving participants no longer have those incident routes published

6. **Durably mark the child retracted**
   - append `destroy_retracted`
   - ordinary list/snapshot operations now exclude this child

7. **Cleanup local artifacts**
   - instruct site actuators to stop and destroy the child’s workloads/resources across all affected
     sites using the recorded labels and placement data
   - continue retrying until cleanup succeeds or is escalated to operator-visible failure handling

8. **Durably commit removal**
   - append `destroy_committed`
   - remove the child from the live-state index
   - remove incident bindings from the logical graph materialization
   - surviving consumers remain in the graph, but those bindings are gone

Amber does not fabricate replacement providers for surviving consumers. If a removed binding mattered
to them, they experience the ordinary consequences of that binding being absent.

#### 5.10.5 Recovery rules

On restart:

- `destroy_requested` without later state => continue retracting overlays
- `destroy_retracted` without `destroy_committed` => continue cleanup until removal can be committed
- `destroy_committed` => nothing remains in live state

#### 5.10.6 Whole-scenario teardown

Whole-scenario teardown must destroy all dynamic children as part of the scenario. Dynamic instances
must not outlive the run that created them.

The same labels/child ids used by the journaled create path must be sufficient to let the overall
teardown logic sweep all remaining dynamic artifacts even if a CCS is unavailable.

### 5.11 Snapshot, replay, and provenance-friendly storage

#### 5.11.1 Why snapshot cannot be derived from realized runtime participants

The realized execution graph does not preserve the logical scenario graph directly. Routers,
sidecars, and backend artifacts do not inherently know the logical parent/child tree or the template
structure that produced them.

Therefore snapshot must come from authoritative control-plane state, not from scraping the realized
runtime.

#### 5.11.2 Single-source-of-truth rule

Snapshot must be derived only from the authoritative control-state service.

In particular:

- it must use the frozen base `ScenarioIr` captured at run start
- it must use the frozen effective placement offer/default set captured at run start
- it must use live child records and live-state indexes derived from the control journal

It must **not** reread authored manifests or placement files from disk at snapshot time.

#### 5.11.3 Chosen storage model

The authoritative control-state service maintains:

1. **append-only control journal**
   - records create/destroy operations and state transitions

2. **checkpointed live-state indexes**
   - keyed by live child root, overlay ownership, and capability instance
   - used for fast list/snapshot and crash recovery

Each live child record contains at least:

- `child_id`
- `authority_realm_id`
- child local name
- fully rendered logical child fragment as absolute `ScenarioIr` fragment
- concrete placement assignments for the fragment
- canonical participant identities
- overlay ids
- backend cleanup labels
- selected manifest catalog key if the template was open

This model is enough for snapshot today and provenance later.

#### 5.11.4 Detailed snapshot algorithm

1. Acquire a consistent read at control-state generation `G`.
2. Load the frozen base `ScenarioIr` from the authoritative control-state service.
3. Load the frozen effective placement offer/default set from the same service.
4. Load all live child records from the live-state index as of `G`.
5. Start from the frozen base scenario graph.
6. For each live child record:
   - merge the child fragment’s components/resources into the graph by absolute moniker
   - merge the child fragment’s binding edges
   - preserve each created component’s own `child_templates`
7. Rebuild `children` lists from `parent` pointers for deterministic output.
8. Compute the set of manifest catalog keys referenced by all `child_templates` present in the
   resulting graph.
9. Copy exactly those catalog entries into the emitted `manifest_catalog`.
10. Normalize ordering of components, resources, children, bindings, and catalog keys.
11. Emit the resulting live `ScenarioIr`.
12. Emit effective placement data consisting of:
    - the frozen offered sites and defaults for the run
    - concrete assignments for every live runnable component/resource in the snapshotted graph

This is sufficient to reproduce the same structural scenario on replay.

#### 5.11.5 Open templates in snapshots

If a live child was created from an open template, the snapshot contains the **actual rendered child
component subtree**, not an abstract reference to the open template choice that was made at runtime.

The created component’s own `child_templates` are preserved in the emitted `ScenarioIr`, so the
replayed scenario has the same future dynamic affordances that follow from topology.

#### 5.11.6 What snapshot excludes

The snapshot excludes runtime-internal deployment machinery such as:

- site routers
- CCS instances
- site actuators
- private control-state service participants

These are regenerated by normal lowering on replay.

#### 5.11.7 Provenance support

Provenance is not the primary snapshot output, but the journal format should preserve the ability to
export it later without redesign.

A future provenance export can read the append-only operation log and report:

- who invoked a create/destroy
- through which capability instance
- what manifest was selected for an open template
- when the operation prepared, committed, and became live

That provenance export is separate from `ScenarioIr`.

#### Alternatives considered for snapshot

| Option | Pros | Cons | Decision |
|---|---|---|---|
| Reconstruct from realized runtime participants | No separate control-state model needed on paper | Realized graph does not preserve logical topology; brittle and incomplete | Rejected |
| Snapshot purely from operation-log replay every time | Simple storage story | Slow; awkward for steady-state snapshot/list | Not preferred alone |
| Materialized live child records with append-only log backing in a single authoritative control-state service | Fast snapshot, good recovery, provenance-friendly, single source of truth | Requires journal compaction/checkpointing | Recommended |

### 5.12 Worked cross-site example

Consider this static scenario:

- an orchestrator component runs on **Compose**
- it receives `framework.component` and a database capability
- it declares two child templates:
  - `job`: exact template whose rendered fragment spans **Kubernetes**, **Direct**, **VM**, and
    **Compose**
  - `collector`: exact template whose root runs on **Compose**

The placement/run plan:

- offers `compose`, `k8s`, `direct`, and `vm`
- has no static Direct user workload
- keeps Direct alive as a standby site because the reachable `job` template requires it

#### 5.12.1 Create `job-1`

The orchestrator calls `CreateChild(template="job", name="job-1")`.

The CCS:

1. authenticates the request using `(mesh peer identity, cap_instance_id)`
2. derives the authority realm: the orchestrator’s realm
3. loads the `job` template from that realm
4. loads the exact child manifest from the frozen manifest catalog
5. renders the exact child fragment:
   - root on Kubernetes
   - helper on Direct
   - worker on VM
   - result adapter on Compose
6. resolves the prefilled database binding from the authority realm
7. computes canonical participant identities
8. computes overlays for:
   - orchestrator -> child root interactions
   - child internal cross-site routes
   - child export publication back into the authority realm
9. appends `create_prepared`
10. prepares workloads and overlays on all affected sites
11. appends `create_committed_hidden`
12. publishes overlays and satisfies the nonweak publication barrier
13. appends `create_live`

At this point `job-1` exists as an ordinary child in the logical graph.

#### 5.12.2 Export enters the bindable source set

Suppose `job-1` exports `result`.

Once `job-1` becomes live:

- `children.job-1.exports.result` becomes part of the authority realm’s bindable source set
- the orchestrator may inspect that export through child/template metadata
- the orchestrator may also receive a runtime handle to it for convenience

#### 5.12.3 Create `collector-1` from that dynamic export

The orchestrator then calls `CreateChild(template="collector", name="collector-1")`, binding one
open root slot from `children.job-1.exports.result`.

The CCS resolves that slot from the authority realm’s bindable source set, not from any ad hoc
runtime-only namespace. The resulting binding becomes an ordinary logical graph edge from
`job-1.result` into `collector-1`.

#### 5.12.4 Destroy `job-1`

Later the orchestrator destroys `job-1`.

Destroy computes the removal cut:

- the entire `job-1` subtree
- all incident bindings, including the binding from `job-1.result` into `collector-1`

Destroy then:

- retracts overlays for `job-1` and that incident export binding
- marks `job-1` retracted
- cleans up Kubernetes/Direct/VM/Compose artifacts for `job-1`
- commits removal

`collector-1` remains in the graph, but the binding from `job-1.result` is gone. Amber does not
invent a replacement provider.

This example exercises:

- cross-site dynamic creation
- standby Direct site activation
- dynamic export entering the bindable source set
- binding a future child from a dynamic export
- correct destroy semantics when outside consumers depended on a removed child export

---

## 6. Implementation notes for the implementer

This section intentionally calls out likely pitfalls without forcing one exact code structure.

### 6.1 Preserve both authority-realm identity and capability-instance identity

Do not model `framework.component` merely as “route to some control endpoint”.

Forwarded realm capabilities only work correctly if internal state preserves both:

- the capability instance
- the authority realm that instance controls

### 6.2 Sidecars are a dangerous place to accidentally put trust

The sidecar may be compromised by the colocated program. Do not let the sidecar tell the CCS which
realm it is operating on. Do not authorize based on site-local reachability alone. The CCS must
derive authority from the capability-instance record.

### 6.3 Do not abuse `External` bindings for child-root imports

In today’s Amber lowering, scenario-root externals have specific router semantics.
Template-root imports are a different concept and must be rewritten at instantiation.

### 6.4 Keep control participants separate

Routers, CCS instances, the authoritative control-state service, and backend actuators may interact
closely, but they are different responsibilities. A design that merges them all into one thing may
look simple short-term but tends to reduce clarity and least privilege.

### 6.5 Remember that sites are currently materialized only when statically used

The existing run-plan machinery will need extension so that standby sites and realm-control
infrastructure can exist even when a site hosts no initial user workload.

### 6.6 Reuse existing site-slicing semantics where possible

Amber already knows how to derive per-site views and synthetic cross-site routing structures.
Do not invent a completely new cross-site model for dynamic components if the existing static model
can be reused incrementally.

### 6.7 The single-source-of-truth rule matters

Do not let the implementation drift into:

- some state in memory
- some state in the journal
- some state reconstructed from disk manifests
- some state scraped from runtime artifacts

That is asking for inconsistency. The authoritative control-state service must remain the source of
truth for dynamic control state and frozen run inputs.

### 6.8 Realm-significant nodes are logical, not necessarily runtime-heavy

A realm-significant component may have no dedicated workload. That does not mean it can be optimized
away logically. Preserve it in the frozen/live logical graph even if realized runtime participants
are attached only to its runnable descendants.

### 6.9 Normalize snapshot output

For replay tests and user-facing diffs, normalize:

- component ordering
- child ordering
- placement emission
- manifest catalog ordering

Otherwise semantically identical scenarios will not compare cleanly.

### 6.10 Open templates need explicit operator help

If the template is too flexible to analyze statically, fail clearly unless the run plan has enough
standby-site policy to support the request. Do not silently activate expensive backends because a
manifest happened to be permissive.

### 6.11 Whole-run teardown must own dynamic artifacts

Dynamic resources/workloads should be labeled/tagged by run identity and child identity so a full
scenario teardown can clean them even if a CCS died or became unreachable.

### 6.12 Efficiency should come from fragment-local work, not from skipping correctness

Amber compile is relatively cheap, but whole-scenario regeneration is still the wrong live create
shape. Prefer:

- template/fragment caching
- affected-site delta computation
- journaled prepare/commit
- route-set overlays
- pre-meshed standby sites

Do not trade away backend parity or graph correctness for micro-optimizations.

---

## 7. Testing plan

The testing plan is intentionally broad. This feature changes compiler surfaces, IR/schema,
run-plan behavior, router control, backend actuation, authoritative control state, and live graph
semantics.

### 7.1 Unit and compile/link tests

#### 7.1.1 Manifest/compiler tests

Add tests for:

- `framework.component` accepted only for capability kind `component`
- mount rejection for `framework.component`
- forwarding `framework.component` through slots/exports preserves authority-realm identity
- child-template schema validation
- `manifest` and `allowed_manifests` validation
- authored `allowed_manifests` selector expansion into deterministic frozen catalog entries
- partial-application validation for prefilled config and bindings
- placement-file validation for dynamic standby-site semantics

#### 7.1.2 IR/schema tests

Add tests for:

- `ScenarioIr` v5 round-trip with `child_templates`
- `ScenarioIr` v5 round-trip with `manifest_catalog`
- exact and open template encoding
- catalog-key stability and digest preservation
- snapshot emission of live `ScenarioIr` plus effective placement
- replay equivalence of normalized snapshots

#### 7.1.3 Graph tests

Add tests for:

- grafting a template fragment under an authority realm component
- rewriting template-root imports into concrete binding edges
- rejecting fragments that still contain scenario-root external semantics where child-root imports
  were expected
- dynamic exports entering and leaving the authority-realm bindable source set
- root-only external-site sources participating in the bindable source set at the scenario root
- destroy removing bindings from destroyed-child exports into surviving consumers

#### 7.1.4 Journal and recovery tests

Add tests for:

- recovery from `create_prepared`
- recovery from `create_committed_hidden`
- recovery from `destroy_requested`
- recovery from `destroy_retracted`
- capability-instance table persistence and restart correctness
- provenance-log append correctness

#### 7.1.5 Router-control tests

Add tests for:

- overlay application/revocation on component sidecars
- overlay application/revocation on site routers
- replay of overlays after restart
- ownership isolation between two independently created dynamic children
- publication barrier for nonweak bindings
- weak bindings permitted to be absent at child startup

### 7.2 Integration tests without full live backends

Use process-local or mock site controllers/routers where practical to test:

- create rollback on remote-site preparation failure
- destroy revoking routes before backend cleanup completes
- unauthorized caller rejection
- forwarded parent realm capability operating on parent resources/templates rather than caller’s own
  realm
- a sidecar attempting to present a capability instance that is not bound to its authenticated mesh
  identity
- a caller attempting to specify an arbitrary target realm in request payload and being ignored or
  rejected because realm comes from the capability instance
- duplicate child create producing deterministic `name_conflict`
- destroy being idempotent success once the child is fully gone
- control-state-service unavailability for reads and writes behaving as specified
- open-template `catalog_key` selection allowed only from the frozen allowed set

These tests should target the semantic contract, not backend details.

### 7.3 Required live test matrix: 16 cross-backend creations

A battery of live tests is required.

#### 7.3.1 Matrix

Run the following 16 logical cases in parallel where possible:

- creator site = Compose, child root site = Compose
- creator site = Compose, child root site = Kubernetes
- creator site = Compose, child root site = Direct
- creator site = Compose, child root site = VM
- creator site = Kubernetes, child root site = Compose
- creator site = Kubernetes, child root site = Kubernetes
- creator site = Kubernetes, child root site = Direct
- creator site = Kubernetes, child root site = VM
- creator site = Direct, child root site = Compose
- creator site = Direct, child root site = Kubernetes
- creator site = Direct, child root site = Direct
- creator site = Direct, child root site = VM
- creator site = VM, child root site = Compose
- creator site = VM, child root site = Kubernetes
- creator site = VM, child root site = Direct
- creator site = VM, child root site = VM

In every case, the dynamically created child must itself be a multi-component scenario that spans all
four site kinds somewhere in its internal structure or dependencies, so that every backend is tested
as both creator and hosted destination.

#### 7.3.2 Performance requirements for the matrix

These tests should be optimized for speed:

- compile once per fixture where possible
- reuse an existing Kubernetes cluster/context across cases
- for VM, use the base image only and do not perform guest provisioning
- boot the minimum VM footprint needed for the test and reuse it across related cases when the test
  harness allows
- start all 16 logical cases in parallel or as a small number of shared-fixture shards

The existing mixed-backend live test infrastructure should be reused where possible.

#### 7.3.3 Assertions

Each matrix case should assert at least:

- child create returns success
- child internal components come up on the expected sites
- cross-site bindings inside the created child are live
- parent can reach at least one child export
- child components can reach each other through their declared routes

### 7.4 Live test: standby Direct site with no static Direct component

Required live test:

- a Compose component declares a child template whose site-kind hints may require `direct`
- the initial static scenario contains no Direct user workload
- the placement/run plan offers Direct and therefore keeps a Direct site alive as standby
- the Compose component successfully creates a Direct-hosted dynamic child
- the resulting child is routable

This test exists specifically to prevent regressions where the run plan only materializes sites that
were statically present.

### 7.5 Live test: dynamic components tear down with the scenario

Required live test:

- create one or more dynamic children across multiple sites
- stop the overall scenario / coordinator
- assert all dynamic workloads/resources are cleaned up along with the static scenario
- assert no leftover Compose containers, VM workloads, Kubernetes objects, or Direct processes remain
  for that run id

### 7.6 Failure-case tests

These may be live or semi-live depending on harness cost.

Required cases:

1. **component cap server unreachable**
   - caller has `framework.component`
   - reachable CCS path is unavailable
   - request fails clearly and leaves no graph mutation

2. **remote-site component cap server unreachable**
   - create requires a remote site
   - remote site CCS or equivalent remote coordination path is unavailable
   - request fails clearly and leaves no committed child
   - any partial backend artifacts are cleaned up

3. **router-control publication failure**
   - backend workload creation succeeds but overlay publication fails
   - child must not become `create_live`

4. **authoritative control-state service restart during create or destroy**
   - operation recovers according to the journal state machine

5. **authoritative control-state service write outage**
   - create/destroy fail without committing new graph state

### 7.7 Security tests

Required security tests:

1. **No binding, no access**
   - a component without `framework.component` cannot use the capability
   - attempts to bypass normal routing must fail

2. **Sidecar cannot mint authority for another component**
   - a sidecar with one valid capability instance attempts to use or synthesize another
   - CCS rejects the request because `(peer identity, cap_instance_id)` does not match a real binding

3. **Dynamic children obey ordinary Amber capability isolation**
   - only components that receive a binding can reach the dynamic child’s capabilities
   - unrelated components are denied

4. **Only the relevant realm authority can destroy a child**
   - ordinary unrelated components cannot destroy it
   - the parent can destroy it
   - a delegate holding the parent’s forwarded realm capability can also destroy it

5. **Forwarded realm capability acts on the parent realm**
   - parent gives its realm capability to a child
   - child creates another child or modifies Amber-legible resources in the parent’s realm
   - resolution happens relative to the parent realm, not the caller’s own realm

### 7.8 Snapshot / replay tests

Required tests for static-equivalent snapshots:

1. create several dynamic components at different points in the scenario graph
2. use a variety of grants and returned export handles
3. snapshot the live scenario to `ScenarioIr` plus effective placement
4. assert the snapshot contains all added components, bindings, child templates, and required
   manifest catalog entries
5. rerun from the snapshot
6. assert the rerun produces the exact same scenario graph and placement
7. assert the same routability properties hold in the rerun

Normalization is critical here; the comparison should be semantic, not accidentally dependent on
unstable ordering.

### 7.9 Resource / realm authority test

Required test:

- a parent originates `framework.component`
- parent gives that capability to a child
- the child successfully modifies Amber-legible resources or creates components in the parent’s
  realm using that authority
- behavior matches Amber’s ordinary resource-binding intuition and Fuchsia’s realm-capability
  intuition, not the old Docker experimental capability behavior

---

## 8. Answers to specific design questions

### 8.1 How do manifest authors specify the component cap?

They declare a slot of capability kind `component` and bind it from `framework.component` or from an
upstream slot/provide that already carries that capability.

### 8.2 How do manifest authors create child templates?

They declare `child_templates` on the manifest whose realm they want to govern. Templates are keyed
by local name and use a partial-application style:

- fixed or allowed manifests
- prefilled or open config
- prefilled or open root bindings
- optional export masks
- optional site-kind hints for open templates

### 8.3 How do live components consume the component cap?

They receive it through an ordinary slot binding and call the component-control protocol on the
returned endpoint. The program does not need to know which site will ultimately host the child.

### 8.4 What if a child template does not specify a program or allows any manifest?

A template without a root program is valid. If the resulting fragment is statically analyzable,
Amber analyzes the whole fragment to decide which sites must be active.

If the template is open and Amber cannot know which sites will be needed, it does not activate all
sites automatically. Only statically required sites and explicitly derivable standby sites should be
kept alive.

### 8.5 Does `amber run` keep unused sites alive just in case?

Only when the run plan says there is a reason to do so:

- the site is statically required
- the site is required by analyzable templates
- the site is requested by template site-kind hints and offered by placement
- the control-plane architecture requires it

Manifest author intent alone is not enough to silently activate every backend.

### 8.6 Why does snapshot include child templates?

Because what children a component can spawn is part of the scenario. Replaying the current scenario
without preserving child templates would fail to preserve future dynamic affordances that arise from
the topology itself.

### 8.7 How does snapshot handle open-template instances?

By serializing the actual rendered child that exists now, and by preserving any remaining live
components’ child templates plus the frozen manifest catalog entries those templates need. Snapshot
does not serialize “the fact that an open choice was once made” as an abstract placeholder. It
serializes the resulting component subtree and the still-live template affordances.

---


## 9. Phased landing plan

This section describes the recommended landing sequence for the feature.

The purpose of phasing here is **not** to redefine the feature into smaller user-visible semantics.
The purpose is to sequence the work so that the implementation converges on the spec instead of
inventing local semantics along the way.

A phase may land as internal scaffolding or behind a non-user-facing guard. The feature should not
be treated as fully landed or supported until the final phase is complete and the full test battery
in Section 7 passes.

### 9.1 Landing guardrails

The following rules apply across all phases.

1. **The spec remains the semantic source of truth.**
   If an implementation decision would change semantics, security, recovery, determinism, or
   snapshot behavior, the document must be updated before that change lands.

2. **Do not expose partial semantics as the finished feature.**
   Intermediate phases may land scaffolding, but they must not create a second public meaning for
   `framework.component`.

3. **Do not add backend-specific user-visible shortcuts.**
   All public semantics must remain backend-neutral from the start. Backend-specific realization
   details are acceptable only behind the actuator boundary.

4. **Do not create a second source of truth.**
   Frozen run inputs, capability-instance records, live child records, and recovery state must all
   converge into the authoritative control-state service.

5. **Each phase has an exit gate.**
   A phase is complete only when its stated invariants hold and its required tests are in place.

6. **The end-to-end create/destroy path must stay journal-first.**
   No phase may introduce best-effort graph mutation that would need to be “cleaned up later” as a
   temporary architecture.

### 9.2 Recommended implementation sequencing

#### Phase 0: Lock the contract and machine-check the obvious parts

Goal: prevent semantic drift before substantial code is written.

Work:

- finalize the protocol surface in Section 5.8
- finalize the `ScenarioIr` v5 schema additions in Section 5.2
- finalize the frozen manifest catalog representation
- finalize the error taxonomy
- add machine-checkable schema fixtures and golden examples for:
  - `ScenarioIr` v5 with `child_templates`
  - `ScenarioIr` v5 with `manifest_catalog`
  - example `CreateChild` / `DestroyChild` / `Snapshot` payloads and responses

Exit gate:

- the doc, IR fixtures, and protocol fixtures all agree
- no remaining semantic TODOs about authority, snapshot, open templates, placement, or destroy
- implementers can point at a canonical schema/fixture set rather than inferring intent from prose

Why this phase exists:

- it prevents the compiler side, router side, and control-plane side from each inventing subtly
  different interpretations of the same feature

#### Phase 1: Land compiler and frozen-graph substrate

Goal: make the static model capable of expressing the feature correctly before any runtime mutation
is attempted.

Work:

- add `CapabilityKind::Component`
- add manifest support for `framework.component`
- add manifest/schema support for `child_templates`
- add `ScenarioIr` v5 support for:
  - `child_templates`
  - `manifest_catalog`
- implement selector expansion for open templates into a deterministic frozen manifest catalog
- implement the realm-significant optimization barrier so authority/template-owner nodes are not
  flattened away
- ensure compile/link/reporting paths preserve the new model correctly

Required invariants:

- an authored scenario plus frozen manifest catalog can be serialized and deserialized without losing
  child-template meaning
- realm-significant nodes remain explicit in the logical graph
- `framework.component` is typed, routed, and non-mountable

Exit gate:

- Section 7.1.1, 7.1.2, and the realm-significant-node portions of 7.1.3 pass
- the compiler can produce a correct frozen base scenario even though no runtime mutation exists yet

#### Phase 2: Land frozen run inputs and dynamic-aware run planning

Goal: make the run start with the right frozen inputs and site universe so later runtime mutation
has a correct substrate.

Work:

- freeze the base `ScenarioIr` and effective placement offer/default set at run start
- add run-plan state for:
  - initial active sites
  - standby sites
  - dynamic-enabled sites
  - control-only sites if needed by the chosen runtime realization
- teach run planning to analyze reachable exact/bounded templates and open-template site-kind hints
- materialize empty-but-alive standby sites when the plan requires them
- keep this state available to the later control-state service as frozen inputs

Required invariants:

- run planning is deterministic for the same frozen scenario and placement input
- sites that may be needed later exist in the initial plan when the rules require them
- a provided placement file is respected exactly; no hidden “cheap defaults” are added on top

Exit gate:

- site-activation analysis tests pass
- a scenario with no static Direct workload but a template requiring Direct can start with Direct as a
  standby site in the plan
- no dynamic create path exists yet, but the plan representation is sufficient to support it

#### Phase 3: Land authority, capability-instance state, and read-only protocol operations

Goal: make authorization and inspection correct before enabling mutation.

Work:

- implement the authoritative control-state service
- persist frozen run inputs into that service
- implement the capability-instance table in that service
- implement endpoint-to-`cap_instance_id` resolution
- implement CCS-side request authentication using `(mesh peer identity, cap_instance_id)`
- implement read-only protocol operations:
  - `GET /v1/templates`
  - `GET /v1/templates/{template}`
  - `GET /v1/children`
  - `GET /v1/children/{name}`
- expose current authority-realm bindable-source candidates in template inspection

Required invariants:

- forwarded `framework.component` still resolves actions relative to the origin realm
- the transport caller cannot choose or override the authority realm
- sidecars do not mint authority by inventing endpoints or request fields

Exit gate:

- auth/security tests for capability-instance handling pass
- template inspection shows correct candidates from the authority-realm bindable source set
- a CCS restart or control-state-service restart preserves capability-instance correctness

Why mutation is not enabled yet:

- incorrect auth is a deeper problem than incomplete mutation support; this phase isolates the
  security-critical part before create/destroy is added

#### Phase 4: Land router-control and actuator substrate across all backends

Goal: make the dynamic runtime primitives real before wiring them into create/destroy.

Work:

- implement canonical participant identity derivation
- implement backend-native mapping to canonical identities where needed
- implement instance-owned route-set overlays on:
  - component sidecars
  - site routers
- implement prepare / publish / revoke lifecycle for overlays
- implement the site-actuator interface and host-local helper realization for:
  - Compose
  - Kubernetes
  - Direct
  - VM
- implement the publication barrier and weak-binding behavior

Required invariants:

- overlays are revocable by owner child/binding-set
- overlays survive restart through authoritative replay
- nonweak bindings are present from the child program’s perspective before a child is made live
- the substrate exists for **all four backends** before the end-to-end create path is turned on

Exit gate:

- Section 7.1.4 router-control tests pass
- synthetic or harness-driven prepare/publish/revoke works on all backends
- no backend is relying on a different public semantic contract

Why this phase exists:

- it forces backend parity in the control substrate before user-visible create/destroy begins,
  preventing later backend-specific semantic drift

#### Phase 5: Land journaled create/destroy for exact templates end-to-end

Goal: prove the full journaled mutation path with the smallest dynamic manifest-selection surface,
without introducing a second public meaning for the feature.

Work:

- implement `POST /v1/children` and `DELETE /v1/children/{name}` for exact templates
- implement journaled create states:
  - `create_requested`
  - `create_prepared`
  - `create_committed_hidden`
  - `create_live`
  - `create_aborted`
- implement journaled destroy states:
  - `destroy_requested`
  - `destroy_retracted`
  - `destroy_committed`
- implement name uniqueness and destroy idempotency
- implement dynamic exports entering the bindable source set
- implement destroy removing incident bindings, including bindings from destroyed-child exports into
  surviving consumers
- implement recovery behavior for in-flight create/destroy

Required invariants:

- create is externally atomic according to the spec
- destroy retracts routes before final removal and is idempotent
- live child records are sufficient for later snapshot and replay
- all four backends participate with the same create/destroy semantics

Exit gate:

- exact-template create/destroy works across all backends
- recovery tests pass
- dynamic export and destroy-cut graph tests pass

Important note:

- this is still not the final feature landing point
- open-template selection and root snapshot remain to be implemented before the feature is complete
- however, no later phase should need to redesign the journal, capability-instance model, or
  overlay model if this phase was implemented to spec

#### Phase 6: Land open templates, manifest-catalog selection, and root snapshot/replay

Goal: complete the remaining semantic surface that depends on frozen-source handling.

Work:

- implement open-template `catalog_key` selection in `CreateChild`
- validate selection against the frozen manifest catalog
- store selected catalog keys in live child records
- implement `POST /v1/snapshot` for root-authority capability instances
- implement snapshot construction from frozen base scenario + live child records + frozen placement
- emit only the manifest catalog entries required by the resulting live graph
- implement replay from snapshot artifacts

Required invariants:

- open-template selection is deterministic and uses only frozen sources
- snapshot never rereads authored manifests or placement files from disk
- replay from snapshot yields the same structural graph and placement

Exit gate:

- open-template tests pass
- snapshot/replay tests pass
- root-only snapshot scope enforcement passes

#### Phase 7: Run the full live battery and fix the remaining integration issues

Goal: prove that the whole feature behaves correctly under realistic mixed-backend execution.

Work:

- run the 16-case live backend matrix from Section 7.3
- run the standby Direct test from Section 7.4
- run the full teardown test from Section 7.5
- run live or semi-live failure tests from Section 7.6
- run security and realm-authority tests from Sections 7.7 and 7.9
- fix any backend parity, determinism, teardown, or recovery issues exposed by those tests

Required invariants:

- every backend appears both as creator site and as hosted destination
- the standby-site story works in practice, not just in the planner
- teardown cleans dynamic artifacts even if a CCS is unavailable at the end
- no backend needs a semantic exception to pass

Exit gate:

- the full test battery in Section 7 passes consistently
- determinism issues in snapshot/replay and naming are resolved
- the feature is now ready to be treated as landed

#### Phase 8: Cut over the public feature surface

Goal: make `framework.component` the supported path and retire the old experimental surface without
leaving ambiguity for users or future implementers.

Work:

- switch examples and documentation to `framework.component`
- remove or explicitly retire the Docker-specific experimental dynamic-control path as a public
  recommendation
- ensure any temporary compatibility shims are clearly marked as legacy and do not accumulate new
  semantics

Required invariants:

- there is one clear supported way to do dynamic component creation in Amber
- the old experimental surface does not continue to evolve in parallel

Exit gate:

- public documentation and examples point to `framework.component`
- the team agrees the old experimental feature is removed or frozen as legacy

### 9.3 How this phasing minimizes divergence from the spec

This sequence is designed to keep the implementation from drifting in the most failure-prone ways.

1. **The feature’s static model lands before mutation logic.**
   That prevents runtime code from inventing a graph model that `ScenarioIr` and snapshots cannot
   represent.

2. **Authority/auth lands before create/destroy.**
   That prevents the mutation path from hardening around the wrong trust boundary.

3. **All-backend control substrate lands before end-to-end create.**
   That prevents a Compose-first or Direct-first implementation from accidentally becoming the de
   facto semantic model.

4. **Exact-template mutation lands before open-template selection.**
   That reduces surface area while preserving the eventual open-template architecture through the
   frozen manifest catalog introduced earlier.

5. **Snapshot lands only after the authoritative control-state service is already the source of
   truth.**
   That prevents multiple incompatible sources of truth from appearing.

6. **The full live battery is the gate for “feature landed”.**
   That prevents the feature from being declared done based on compiler-only or mock-only success.

### 9.4 What should not be parallelized

Some work can happen in parallel, but the following dependencies should be treated as hard:

- `ScenarioIr`/frozen catalog shape must be fixed before open-template runtime work begins
- capability-instance auth must be fixed before create/destroy work begins
- canonical participant identity and overlay model must be fixed before backend-specific dynamic
  route publication diverges
- all-backend actuator/control substrate must exist before the end-to-end feature is considered
  complete
- snapshot/replay should not be built from any source other than the authoritative control-state
  service

### 9.5 What may be implemented opportunistically without changing semantics

A competent implementer remains free to choose ordinary lower-level details where the spec already
fixes the semantics. Examples include:

- precise on-disk layout of the authoritative control-state service
- concrete HTTP framework / server library used by CCS implementations
- internal data structures for the live-state indexes
- exact private IPC transport between CCS and the host-local actuator helper
- checkpoint/compaction strategy for the journal
- internal caching of compiled template fragments

Those choices are intentionally not prescribed because they do not change the semantic contract when
implemented correctly.


## 10. Summary

The design is centered on one principle:

> `framework.component` gives authority over a realm in the existing Amber scenario graph.

Everything else follows from that:

- dynamic creation creates ordinary components, not a new graph kind
- template authoring is partial application first, constraints second
- control stays inside the Amber mesh and capability model
- sidecars do not mint realm authority; CCSs authorize on capability-instance records
- the authority-realm bindable source set is explicit and includes dynamic exports and root-only
  external-site sources where appropriate
- `ScenarioIr` grows to carry child templates and a frozen manifest catalog
- realm-significant logical nodes are preserved and not flattened away
- placement remains operator-owned in the run plan and stays set-based in this feature
- journaled prepare/commit drives create and destroy safely
- one authoritative control-state service prevents multiple sources of truth
- snapshots emit the current static-equivalent graph and frozen effective placement
- the same journal structure can later support provenance without redesign
- all backends participate with the same semantics

If the implementation preserves that model, it will fit Amber cleanly and leave room for future
dynamic binding and remote site selection without forcing another redesign.
