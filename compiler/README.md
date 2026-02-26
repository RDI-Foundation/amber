# amber-compiler

Compiles a root component manifest into a linked `Scenario` plus provenance and diagnostics. This crate coordinates resolution, semantic validation, and optional MIR optimization.

## Pipeline
- Resolve the manifest tree and environments (`frontend`), producing a `ResolvedTree` and storing sources/digests.
- Link and validate cross-manifest semantics (`linker`) to build a `Scenario`.
- Collect manifest lints and linker diagnostics.
- Run optional MIR optimizations (`mir`) such as binding canonicalization, pure-routing flattening, and dead-code elimination.

## Key types
- `Compiler`: entry point; `compile` returns a `Scenario`, `Provenance`, and `DigestStore`, while `check` reports diagnostics without producing a scenario.
- `CompileOptions` / `ResolveOptions`: control resolution limits and optimization behavior.
- `DigestStore`: digest-keyed manifest store plus source/spans for diagnostics.
- `Provenance`: resolution provenance per component instance: authored moniker, declared ref, resolved/observed URL, digest.
- `ResolverRegistry`: host-provided resolvers referenced by manifest environments.
- `BundleBuilder` / `BundleLoader`: generate and load manifest bundles for offline, digest-preserving compilation.

## Module map
- `frontend`: async resolver with caching, cycle detection, and environment handling.
- `linker`: schema validation, binding resolution, and export verification.
- `mir`: linked-scenario optimization pipeline (canonicalization + optional flatten/DCE) plus post-optimization binding interpolation verification.
- `targets`: target-family planners and reporters (e.g., mesh-family planning + Docker Compose/Kubernetes reporters).
- `reporter`: transforms `CompileOutput` into artifacts (e.g., scenario IR JSON, DOT, Docker Compose YAML, Kubernetes YAML); re-exports target reporters.
- `bundle`: bundle index parsing, manifest packing, and bundle-only resolver wiring.
