# Framework-Owned Resources and Storage Semantics

Status: accepted design, with storage resources implemented

Audience: Amber compiler/runtime maintainers and engineers working on manifests, lowering, and DX

## Summary

Amber currently treats `storage` inconsistently with the rest of the capability model.

In manifests, `storage` looks like an identity-bearing capability that is routed through the
graph, just like `http`.

In the implementation, `storage` is lowered as an abstract right to durable bytes, and each sink
gets a fresh backend storage object. That is true today across direct output, Docker Compose, and
Kubernetes.

This document proposes a new manifest declaration space, `resources`, to model framework-managed
objects explicitly.

The key idea is:

- `components` are owned child compute
- `provides` are capabilities implemented by the component's program
- `resources` are framework-managed objects owned by the component
- `bindings` route capabilities between them

For storage specifically, the implemented first step is:

- a component can declare a managed storage resource in `resources`
- bindings route that resource into child storage slots
- mounted storage must resolve from a resource, not from a root storage slot

This keeps the capability story coherent, avoids tying persistence to consumer moniker, and
creates a general abstraction that can later be reused for other framework-managed objects.

One part of the broader design remains deferred:

- identity-bearing external storage objects routed through root `storage` slots are not part of
  the first implementation

## Why This Design Work Exists

This design work did not start from theory. It started from trying to use the
`examples/storage/01-persistence` example like a first-time Amber user.

That exercise surfaced two separate issues:

- the example itself was demonstrating behavior by `exec`-ing into a container instead of going
  through declared bindings
- the implementation was implicitly choosing a storage semantic without naming it

Once the example was exercised manually in Compose and Kubernetes, and the lowering code was read,
the current storage model became much clearer:

- storage persists across simple redeploys if the lowered runtime shape stays the same
- storage identity is currently derived from implementation structure rather than from an explicit
  first-class object in the manifest
- structural refactors can move or replace storage accidentally
- parents do not have a first-class place to declare "I own a framework-managed storage object"

That is the underlying problem this document tries to solve.

## Current Behavior

### What manifests suggest

Today a manifest can write:

```json5
slots: {
  app_state: { kind: "storage" },
},
bindings: [
  { to: "#app.state", from: "self.app_state" },
],
```

This reads like normal capability routing:

- `self.app_state` is a capability
- it is routed to `#app.state`
- the identity of the capability is preserved

That is the same mental model developers naturally use for `http`, `llm`, and other slot kinds.

### What the implementation actually does

The current lowering does not preserve storage identity. It allocates one backing store per
consumer.

Observed in code:

- direct output stores state under a path derived from the consumer component plus root slot
- Docker Compose names volumes from the consumer component plus root slot
- Kubernetes gives each consumer its own `StatefulSet` and `volumeClaimTemplates`
- Kubernetes PVC access mode is currently hard-coded to `ReadWriteOnce`
- the manifest has no `readOnly` or sharing bit for storage mounts, so the backend is not deriving
  that mode from any manifest-level signal

So the actual current semantic is not:

- "route this concrete storage object through the graph"

It is closer to:

- "this sink is entitled to durable storage, so allocate some here"

That semantic may be defensible, but today it is implicit, not explicit.

### Why that is a problem

This mismatch causes several problems.

1. The capability model becomes inconsistent.

`http` routes identity. `storage` currently routes an abstract idea of storage.

2. Persistence is tied to structure.

If storage identity is derived from consumer structure, refactoring the scenario can misplace
persistent data.

3. Migration is not explicit.

There is no first-class way to say "this new storage object should adopt the bytes that used to
belong to that old scenario shape."

4. Parent visibility is weak.

A component 100 nodes deep can effectively cause durable storage to appear, but the parent does not
have a first-class declaration that says "this is the storage object I own for that subtree."

5. Storage planning happens conceptually too late.

Some storage invariants were previously enforced in backend lowering rather than near manifest/link
validation. That hurts both DX and maintainability.

## Design Goals

- Make storage semantics explicit rather than implicit.
- Preserve a coherent capability model across runtimes.
- Let developers move from local development to production without having to re-architect manifests.
- Avoid tying persistence identity to consumer moniker or flattened runtime structure.
- Give parents a clean way to own storage near the subtree that needs it.
- Make structural refactors and storage migration feasible and explicit.
- Give developers and parents visibility into storage demand and allocation decisions.
- Keep the model general enough to support future framework-managed resources beyond storage.

## Non-Goals

- Solve quota attenuation in this first design.
- Solve shared writable storage portably across every Kubernetes cluster in v1.
- Automatically migrate arbitrary storage layouts across incompatible scenario restructures.
- Finalize every future framework-managed resource shape now.

## Constraints and Assumptions Surfaced During Discussion

The conversation that led to this design relied on several assumptions. They should be explicit.

### Cross-runtime abstraction matters

Amber should not require developers to redesign their scenario just because they moved from direct
or Compose to Kubernetes.

This does not mean every backend must expose the same operational knobs. It does mean the semantic
model should not change silently between backends.

### Erroring too late is bad UX

A developer should not debug a scenario successfully in Compose and then discover at deployment
time that Kubernetes interprets the same graph very differently.

### Parents should not have to manage an unreasonable number of root volumes

A pure identity-only storage model pushes too much operational burden to the root manifest for large
graphs.

### Storage is not cheap

Storage demand needs to be visible, diagnosable, and right-sized. It should not be whatever a leaf
component implicitly causes to appear.

### Structural refactors are normal

We should assume components move, get renamed, or are restructured. The storage model must survive
that without requiring developers to preserve dead routing-only structure just to retain bytes.

### DCE and flattening should not change persistence identity

Optimizer passes are allowed to rewrite execution structure. They should not silently change what
Amber considers to be the identity of persistent storage.

### Bindings should remain edges

Bindings already mean "route a capability from here to there." They should not also become the
place where object instantiation and long-lived persistence identity live.

### Attenuation and instantiation are different concepts

This was an important design point.

- instantiation answers "create a new object with these properties"
- attenuation answers "route an existing object with reduced authority"

Those should not be collapsed into one field.

### Fan-out is a real semantic question, not just a backend detail

Storage fan-out cannot remain undefined.

Even if we eventually add use-count attenuation, sharing modes, or subpath attenuation, Amber needs
an explicit answer for what fan-out means.

## Approaches Considered

Several approaches were discussed. The final recommendation borrows useful parts from them but does
not fully adopt any of the first three.

## Approach 1: Treat `framework.storage` as a fresh-on-route framework capability

Shape:

```json5
bindings: [
  { to: "#app.state", from: "framework.storage" },
]
```

Meaning:

- every time `framework.storage` is routed to a sink, Amber allocates fresh storage there

Pros:

- simple
- cross-runtime friendly
- natural fresh allocation semantics
- analogous to the current behavior of `framework.docker`, where the capability effectively creates
  a component-scoped virtual namespace rather than routing a single global identity

Cons:

- no clean place for stable storage identity
- no clean place for migration metadata
- binds long-lived persistence semantics to a routing edge
- does not give parents a declaration that says "I own this storage object"
- makes it difficult to summarize subtree storage ownership

Why it was not chosen:

It solves fresh allocation, but it does not solve stable identity or migration cleanly.

## Approach 2: Do nothing and keep routed `storage` abstract

Meaning:

- `storage` continues to look routed in manifests
- the implementation continues to allocate per consumer

Pros:

- smallest short-term change
- keeps the current implementation broadly intact
- can be made to work across runtimes

Cons:

- capability model remains inconsistent
- migration remains implicit and brittle
- persistence identity remains structure-derived
- developers keep thinking storage works like `http` because the manifest gives that impression

Why it was not chosen:

The semantic mismatch is too large to leave implicit.

## Approach 3: Make `storage` always identity-preserving

Meaning:

- a root `storage` slot is one real storage object
- routing preserves that identity exactly like `http`

Pros:

- very clean capability story
- migration from existing host directories / volumes / PVCs is natural
- same semantic model as other routed capabilities

Cons:

- root manifests may need to manage many storage objects
- fan-out becomes operationally difficult
- shared storage support is backend-sensitive, especially on Kubernetes
- no built-in story for "please allocate fresh storage for this subtree"

Why it was not chosen:

This model is clean, but too operationally heavy on its own. It still needs a separate notion of
framework-managed fresh allocation.

## Approach 4: Introduce a new declaration space for framework-managed objects

Initial phrasing in the discussion used `allocations`, but that was rejected because it sounded
storage-specific and one-off.

The better name is `resources`.

Meaning:

- `components` are owned child compute
- `provides` are locally implemented capability origins
- `resources` are locally owned framework-managed objects

Pros:

- clean ownership point
- stable identity can live on a declaration, not a binding edge
- gives parents a real place to own storage near the subtree that needs it
- generalizes beyond storage
- fits both current and future framework-managed resources

Cons:

- introduces a new top-level manifest field
- needs a careful explanation in docs and errors because it is a new concept

Why it was chosen:

It is the only approach discussed that simultaneously gives:

- coherent semantics
- stable identity
- explicit migration
- good optimization boundaries
- a general framework abstraction rather than a storage-only special case

## Why `resources` Is Analogous to Existing Amber Concepts

This was an important part of the design discussion.

The new field should not exist unless it fits the system conceptually.

### Present-day analogies

`components`

- named
- owned by a component
- lifecycle managed by that component
- other graph edges can refer to them indirectly

`provides`

- named
- originate locally
- routable elsewhere

`environments`

- named declaration space
- not a runtime program
- affects how other things are instantiated

`resources` fits as the missing third bucket:

- named
- owned locally
- lifecycle managed locally
- routable as capability sources
- implemented by the framework rather than by the program

The simplest teaching frame is:

- `components`: child compute
- `resources`: child infrastructure
- `provides`: capability origins implemented by the program
- `bindings`: wiring

### Future analogies

Once `resources` exists, it can plausibly host:

- storage allocations
- buckets
- queues
- topics
- certificates
- identities
- service-account-like handles
- dynamic child groups
- future cleaned-up forms of other framework-managed objects

So this is not only about storage. Storage is the first use case.

## Recommended Design

Introduce a `resources` field on manifests.

Each resource:

- has a local name
- has a `kind`
- has a `from` source, initially expected to be framework-managed
- has framework-specific `params`
- may have migration metadata

Bindings can then route from `resources.<name>` just as they already route from `self.<slot>` or
`self.<provide>`.

Resources are local to whatever component declares them. They are not root-only.

That is an important part of the design:

- roots can own storage when the whole scenario should reason about it there
- intermediate parents can own storage for their subtree
- leaf components can own framework-managed resources when that is the cleanest ownership point

This is how the design avoids forcing the root manifest to manage every durable object in a large
scenario.

## Representative Syntax

This is recommended syntax, not merely illustrative pseudocode.

```json5
{
  manifest_version: "0.1.0",

  resources: {
    user_db: {
      kind: "storage",
      params: {
        size: "50Gi",
        retention: "retain",
        sharing: "exclusive",
      },
    },
  },

  components: {
    app: "./app.json5",
  },

  bindings: [
    { to: "#app.state", from: "resources.user_db" },
  ],
}
```

Child:

```json5
{
  manifest_version: "0.1.0",

  slots: {
    state: {
      kind: "storage",
      request: {
        min_size: "20Gi",
        sharing: "exclusive",
        retention: "retain",
      },
    },
  },

  program: {
    image: "python:3.12-alpine",
    mounts: [
      { path: "/var/lib/app", from: "slots.state" },
    ],
  },
}
```

This means:

- the parent owns a framework-managed storage resource called `user_db`
- the resource is routed into the child's `state` slot
- the child mounts `slots.state`, not `resources.user_db`
- the child only sees the capability boundary, not the framework object directly

## External Identity-Bearing Storage Still Exists

`resources` does not replace root `storage` slots.

External storage remains important for:

- attaching existing host directories in direct mode
- attaching existing named volumes in Compose
- attaching existing PVCs or similar objects in Kubernetes

Example:

```json5
{
  manifest_version: "0.1.0",

  slots: {
    existing_data: { kind: "storage" },
  },

  components: {
    app: "./app.json5",
  },

  bindings: [
    { to: "#app.state", from: "self.existing_data" },
  ],
}
```

In this model:

- `self.existing_data` means "a concrete storage object comes from outside Amber"
- `resources.user_db` means "Amber should allocate a new framework-managed storage object here"

That split is intentional and desirable.

## Resource Identity

The logical identity of a resource must come from the authored declaration site, not from the
consumer component and not from lowered runtime structure.

Recommended logical identity:

- `(authored component path, resource name)`

Example logical ids:

- `/resources/root_cache`
- `/backend/resources/user_db`
- `/backend/api/resources/request_log`

This identity must be computed before MIR/DCE/flattening and then carried through lowering as
metadata.

That means:

- optimization may flatten routing structure
- runtime component layout may change
- logical resource identity must not change unless the authored owner or resource name changes

This is the single biggest reason to prefer a declaration field over binding-edge identity.

## Rejected Identity Anchors

The discussion surfaced several places where persistent identity could have been anchored. They
should be recorded explicitly because they are tempting, but wrong.

### Rejected: consumer moniker

This is effectively what the current implementation trends toward.

Problems:

- refactors move data accidentally
- flattening and DCE make identity fragile
- a resource's identity changes when the consumer structure changes, which is backward

### Rejected: binding name

This would make storage identity something like `(parent component, binding name)`.

Problems:

- makes binding names effectively required in some cases
- turns routing edges into long-lived identity anchors
- creates poor interactions with optimization and refactoring
- makes ownership harder to discover than a named declaration

### Rejected: root slot name alone

This only works for externally supplied identity-bearing storage objects. It does not solve
framework-managed fresh allocation.

Problems:

- not all storage should have to be rooted at the scenario root
- does not give subtree parents a clean ownership point
- still leaves no declaration for framework-managed storage objects

## Migration

Structural refactors are expected. The design needs an explicit migration story.

Recommended resource shape:

```json5
resources: {
  user_db: {
    kind: "storage",
    params: {
      size: "50Gi",
      retention: "retain",
      sharing: "exclusive",
    },
    migrate_from: [
      "/api/resources/user_db",
    ],
  },
},
```

Meaning:

- this resource is the successor to the previous logical resource id
- on first deploy, Amber should adopt old storage if the new resource does not yet exist
- if both exist, Amber should stop and require explicit operator resolution

This is much better than preserving dead routing-only parents just to keep monikers stable.

Expected migration behavior:

- unchanged declaration owner and name: automatic reuse
- rename or move: add `migrate_from`
- split or merge: explicit data migration step outside this mechanism

## Fan-Out and Sharing

Fan-out was identified early as the hardest unresolved part.

The design recommendation is:

- allocated resources default to `sharing: "exclusive"`
- exclusive resources may have exactly one live sink consumer
- forwarding nodes do not count as consumers
- actual terminal sink use does count

Valid:

```json5
resources: {
  data: {
    kind: "storage",
    params: {
      size: "10Gi",
      sharing: "exclusive",
    },
  },
},

bindings: [
  { to: "#router.state", from: "resources.data" },
  { to: "#leaf.state", from: "#router.state" },
],
```

Invalid:

```json5
resources: {
  data: {
    kind: "storage",
    params: {
      size: "10Gi",
      sharing: "exclusive",
    },
  },
},

bindings: [
  { to: "#a.state", from: "resources.data" },
  { to: "#b.state", from: "resources.data" },
],
```

Why default to exclusive:

- it is the least deceptive portable behavior
- it avoids silently allocating private stores for each consumer
- it avoids silently relying on shared writable storage assumptions that may fail on Kubernetes

Future extensions should remain possible:

- `sharing: "shared_ro"`
- `sharing: "shared_rw"`
- use-count attenuation on bindings
- subpath attenuation on concrete storage identity

But v1 should not pretend those are solved.

## Storage Requests

The team explicitly wanted a way to stop storage from becoming "whatever some component 100 nodes
deep wants."

Recommended shape:

```json5
slots: {
  state: {
    kind: "storage",
    request: {
      min_size: "5Gi",
      sharing: "exclusive",
      retention: "retain",
    },
  },
},
```

Meaning:

- the sink expresses what it needs
- the parent chooses how to satisfy it
- the compiler validates compatibility
- the reporter can show both request and allocation

This keeps the request close to the consumer while still giving parents visibility.

Example compatibility check:

- slot requests `min_size: 20Gi`
- bound resource declares `size: 10Gi`
- compile-time error

Example satisfied case:

- slot requests `min_size: 20Gi`
- bound resource declares `size: 50Gi`
- valid

## Resource Params vs Attenuation

This distinction should be kept sharp in the design.

Resource params:

- shape the newly created object
- example: `size`, `retention`, `sharing`, `class`

Attenuation:

- narrows an already existing capability during routing
- future example: use-count limit, subpath restriction, read-only view

These are not the same thing.

Recommended v1 rule:

- `params` exist on resource declarations
- attenuation, if/when added, exists on bindings

## Why Binding Names Should Not Become Storage Identity

One early idea was to make resource identity something like `(parent, binding_name)`.

This was rejected.

Problems:

- makes binding names effectively mandatory in some cases
- upgrades a routing edge into a persistence identity anchor
- interacts badly with optimization and refactoring
- makes ownership less obvious than a named declaration

Bindings should remain edges. Resource identity should live on declarations.

## Backend Lowering

Once resources exist, backends should materialize storage from logical resource id rather than from
consumer moniker.

### Direct output

- resource-backed storage should live under a path derived from logical resource id
- no consumer-specific subdirectory should be part of identity
- resource metadata should be written so migration and inspection are possible

### Docker Compose

- one named volume per logical resource id
- volume labels should include the logical resource id and declaring component path
- no consumer-moniker-derived storage identity

### Kubernetes

- one PVC per logical resource id for exclusive storage
- PVC metadata should include the logical resource id and declaring component path
- no per-consumer `volumeClaimTemplates` when the resource, not the consumer, owns identity

This is a major change from the current per-consumer `StatefulSet`-oriented lowering.

### Access mode

Current code hard-codes `ReadWriteOnce`.

That is acceptable only as an implementation detail of the current exclusive-per-consumer model. It
is not a correct semantic answer for the proposed design.

Recommended direction:

- exclusive allocated storage can lower naturally to single-writer semantics
- shared storage modes should not be claimed until Amber has a deliberate cross-runtime strategy

This document does not try to solve shared writable Kubernetes storage in v1.

## Compiler and DX Behavior

The compiler should make the storage plan visible.

Generated artifacts and diagnostics should answer:

- what storage resources exist
- where they are declared
- which slots requested them
- which bindings route them
- what their effective size / retention / sharing settings are
- whether any resource is being migrated from a previous id

Example summary shape:

- resource `/backend/resources/user_db`
- kind: `storage`
- params: `size=50Gi retention=retain sharing=exclusive`
- consumed by: `/backend/api.state`
- satisfies request: `min_size=20Gi sharing=exclusive`

This is important because storage is expensive and otherwise hard to diagnose.

## Interaction With Optimization

This was a major implicit concern in the discussion.

Today, relying on parent moniker stability to preserve storage through restructures would be too
fragile because MIR/DCE/flattening can rewrite routing structure.

Recommended rule:

- optimization may rewrite execution structure
- optimization may not rewrite logical resource identity

Implementation implication:

- resources must exist as first-class graph entities before optimization
- passes must preserve resource metadata and identity
- any pass that deletes a resource must do so only when the resource is truly dead

## What This Design Does Not Yet Solve

The design is intentionally honest about unresolved parts.

Open questions:

- exact schema and typing rules for resource `params`
- whether resources can be exported directly or only routed into slots/provides first
- when and how to support shared storage modes portably
- whether `migrate_from` is sufficient or whether a future explicit `stable_id` is needed
- whether future framework capabilities such as dynamic child groups should use `resources` from
  day one

## Phased Rollout

This design should be implemented incrementally.

### Phase 1: make semantics explicit

- add `resources` to manifests
- support managed storage resources
- support routing from `resources.<name>`
- compute stable logical ids from declaration site
- stop deriving storage identity from consumer moniker
- add compile-time fan-out error for exclusive resources
- add storage request validation
- add reporting of resource ownership and consumers

### Phase 2: migration support

- add `migrate_from`
- add backend metadata to discover old logical ids
- document explicit migration workflows

### Phase 3: richer sharing and attenuation

- shared read-only modes
- shared read-write modes where backend support is explicit and deliberate
- possible use-count attenuation
- possible subpath attenuation

## Final Recommendation

Adopt `resources` as a new manifest declaration space for framework-managed objects.

For storage:

- keep external root `storage` slots as concrete identity-bearing storage objects
- add managed storage resources
- route resource-backed storage via normal bindings
- key persistence by logical resource identity, not consumer structure
- default allocated storage to exclusive single-consumer semantics
- add slot requests and migration metadata as first-class concepts

This is the design that best matches the discussion's priorities:

- consistent capability semantics
- good local-to-prod story
- no silent semantic drift between backends
- explicit migration path
- parent visibility into expensive resources
- a general abstraction that can support more than storage later
