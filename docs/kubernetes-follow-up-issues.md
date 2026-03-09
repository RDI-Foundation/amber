# Kubernetes Follow-Up Issues

This note captures Kubernetes-specific issues surfaced while implementing storage
resources and the `examples/storage/02-migration` structural migration example.

The immediate correctness fix is in the backend: workloads now wait for their
mounted mesh config to match the current scenario scope before starting. That
fix prevents pods from booting against stale provisioned secrets.

That solves the proximate bug, but it does not resolve the larger lifecycle and
operational questions below.

## Why This Doc Exists

The storage migration example uncovered a backend race that was easy to miss in
simple upgrades:

- mesh secrets use stable names
- the provisioner job updates those secrets asynchronously
- `kubectl apply -k` creates consuming Deployments immediately

That let a new pod start with old mesh config if the secret already existed from
the previous revision. The current init-step fix makes startup correct, but it
is still compensating for deeper Kubernetes lifecycle gaps.

The items below are the bigger issues worth resolving later.

## 1. Mesh Secret Lifecycle Is Still Implicit

### Motivation

The current model uses stable secret names like `amber-router-mesh` and
`cN-component-mesh`. That is convenient, but it means secret lifecycle is
decoupled from workload revision lifecycle.

This is exactly what caused the stale-startup bug:

- old secret contents remained valid enough for Kubernetes to mount
- the new pod could start before the provisioner had rewritten them

The init wait enforces correctness at pod startup, but the lifecycle model is
still implicit.

### Longer-term question

Should mesh secrets remain stable mutable objects, or should they become
revisioned objects with explicit handoff and cleanup?

### Candidate directions

1. Keep stable secret names
- Pros: simpler names, no secret churn, no cleanup system needed.
- Cons: requires startup validation or some other synchronization mechanism.

2. Use revisioned secret names
- Pros: pods can only mount the intended revision.
- Cons: requires ownership and cleanup of superseded secrets, otherwise old
  secrets accumulate indefinitely.

3. Change deployment orchestration entirely
- Example: stage provisioning separately from workload rollout, or hand off
  lifecycle to a higher-level release tool.
- Pros: could make revision sequencing more explicit.
- Cons: larger product/UX decision; would change how Amber presents Kubernetes
  deployment as a workflow.

### Recommendation

Treat this as a real architectural decision, not just an implementation detail.
The current startup validation is acceptable as the short-term invariant, but it
should not hide the fact that secret revision lifecycle is not yet a first-class
concept.

## 2. Structural Migrations Do Not Have A Clean Prune Story

### Motivation

A structural migration can remove workloads from the generated manifests. Plain
`kubectl apply -k` does not delete objects that disappeared from the new output,
so old Services, Deployments, and NetworkPolicies remain in the namespace.

For the migration example, that means v1 objects like `c1-app` can survive after
the v2 apply unless they are explicitly removed.

### Why this matters

- first-time users can end up with mixed old/new runtime state
- old objects can confuse debugging
- documentation becomes awkward because “apply the new version” is not the whole
  truth

### Candidate directions

1. Keep emitting plain Kustomize and document explicit cleanup
- Pros: smallest product surface.
- Cons: poor UX for structural changes; easy to get wrong.

2. Lean on `kubectl apply --prune`
- Pros: closer to what users expect.
- Cons: still presented by kubectl as alpha/incomplete; not a great foundation
  for Amber’s main guidance.

3. Emit a higher-level deployment flow
- Example: generated scripts, staged apply/delete flow, or integration with a
  release manager.
- Pros: Amber can define a coherent lifecycle story.
- Cons: more product surface and more maintenance.

4. Integrate with an existing release manager
- Example: render Helm inputs or shell out to Helm.
- Pros: pushes pruning/history concerns onto a tool built for them.
- Cons: larger product choice; Amber would need to define the boundary between
  scenario compilation and release management.

### Recommendation

This needs an explicit product decision. The current backend can be correct at
pod startup and still leave structural-migration cleanup ergonomics unresolved.

## 3. Provisioned Mesh Inputs And Workload Rollout Are Coupled Too Loosely

### Motivation

Today the provisioner Job and the consuming Deployments are all created from the
same `kubectl apply -k`, but Kubernetes does not enforce the ordering Amber
really wants:

1. provision or refresh mesh secrets
2. start workloads that consume them

The init wait restores correctness for startup, but rollout is still split
across independent Kubernetes mechanisms.

### Why this matters

- rollout observability is harder to explain
- failures show up as pods waiting in init rather than as a single explicit
  “provision then deploy” phase
- the backend is still relying on composition of separate primitives rather than
  one explicit lifecycle model

### Recommendation

Keep the init wait for now, but treat “what is Amber’s Kubernetes release model?”
as an open question. If Amber wants stronger guarantees and cleaner UX, it may
need a more explicit deploy orchestration layer than “render manifests and let
kubectl race them”.

## 4. Storage Migration Is Only Solved For Stable Resource Identity

### Motivation

The new migration example demonstrates the structural change Amber can preserve
today:

- the resource owner path stays the same
- the resource name stays the same
- the consuming component moves behind a new intermediate component

That is useful, but it is still only one slice of the broader migration problem.

Amber still does not have a manifest-level migration mechanism for:

- renaming a storage resource
- moving ownership of a storage resource
- splitting one resource into several
- merging several resources into one

### Recommendation

Keep documenting the current invariant honestly:

- storage continuity currently follows resource owner path plus resource name

But storage migration remains a broader design problem beyond the current
example.

## 5. Kubernetes Storage Lifecycle Is Still Minimal

### Motivation

The current storage backend intentionally keeps the MVP small:

- PVCs are emitted directly
- access mode is fixed
- retention behavior is implicit in namespace/object lifecycle

That is enough for the example and for local validation, but it does not yet
give authors a full resource lifecycle story.

### Longer-term questions

- should storage retention be explicit in manifest/backend terms?
- should access semantics be derived from future storage sharing semantics?
- should Amber expose a cleaner teardown path that deletes runtime objects while
  preserving retained storage?

## Summary

The current fixes are aimed at correctness:

- do not let pods start with stale mesh config
- make the migration examples honest about what Amber can preserve today

The larger unresolved topics are lifecycle topics:

- revisioning and cleanup of provisioned mesh state
- pruning of removed objects across structural migrations
- the degree to which Amber should own rollout orchestration versus delegating
  it to another Kubernetes release tool
- richer storage migration and storage lifecycle semantics

Those are the areas worth revisiting once the immediate resource model and
example work are settled.
