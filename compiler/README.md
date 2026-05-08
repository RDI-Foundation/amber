# amber-compiler

Compiles a root component manifest into a linked `Scenario` plus provenance and diagnostics. This crate coordinates resolution, semantic validation, and optional MIR optimization.

## Pipeline
- Resolve the manifest tree and environments (`frontend`), producing a `ResolvedTree` and storing sources/digests.
- Link and validate cross-manifest semantics (`linker`) to build a `Scenario`.
- Collect manifest lints and linker diagnostics.
- Run optional MIR optimizations (`mir`) such as binding canonicalization, pure-routing flattening, and dead-code elimination.
- Apply scenario overlays during compile/run-plan flows, or during explicit overlay-applied checks.

## Key types
- `Compiler`: entry point; `compile` returns `CompileOutput` (linked `Scenario`, `Provenance`, `DigestStore`, diagnostics, and config analysis), while `check` returns `CheckOutput`.
- `CompileOutput` / `CheckOutput`: compiler results for artifact generation vs validation-only flows.
- `CompileOptions` / `CheckOptions` / `ResolveOptions`: control resolution limits,
  optimization behavior, and whether check executes scenario overlays.
- `DigestStore`: digest-keyed manifest store plus source/spans for diagnostics.
- `Provenance`: resolution provenance per component instance: authored moniker, declared ref, resolved/observed URL, digest.
- `ResolverRegistry`: host-provided resolvers referenced by manifest environments.
- `BundleBuilder` / `BundleLoader`: generate and load manifest bundles for offline, digest-preserving compilation.

## Module map
- `frontend`: async resolver with caching, cycle detection, and environment handling.
- `linker`: schema validation, binding resolution, and export verification.
- `mir`: linked-scenario optimization pipeline (canonicalization + optional flatten/DCE) plus post-optimization binding interpolation verification.
- `targets`: target-family planners and reporters (mesh-family planning + Docker Compose/Kubernetes directory artifacts, plus direct/native and VM artifact planning).
- `reporter`: transforms `CompileOutput` into artifacts (scenario IR JSON, DOT, metadata JSON, Docker Compose directories, Kubernetes directories, direct/native output directories, and VM output directories); re-exports target reporters.
- `bundle`: bundle index parsing, manifest packing, and bundle-only resolver wiring.

## Feature docs
- [`OVERLAYS.md`](./OVERLAYS.md): overview and authoring guide for scenario overlays.
