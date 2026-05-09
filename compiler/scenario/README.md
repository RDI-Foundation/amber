# amber-scenario

Data model for the fully linked scenario produced by the compiler.

## Core types
- `Scenario`: linked component tree with resolved bindings and an exported interface; contains the root id and can normalize order for deterministic output.
- `Component`: instance metadata (moniker path, manifest digest, config, config schema, program definition, slots, provides, user-defined metadata).
- `BindingEdge`, `BindingFrom`, `ProvideRef`, `SlotRef`: capability wiring edges; sources may be component provides, framework capabilities, or externalized root slots.
- `ScenarioExport`: named export mapping to a resolved provide (with capability).
- `ScenarioIr`: serde-friendly JSON IR wrapper with schema/version headers and conversions to/from `Scenario`.
- `ScenarioIrError`: validation errors when loading IR into a `Scenario`.

User-loaded Scenario IR follows the same framework capability ownership rules as manifests:
component, Docker, and KVM capability providers are framework-owned. User-authored IR should
represent those sources as framework bindings (`framework.component`, `framework.docker`, or
`framework.kvm`), not as component `provides` entries.

## Graph utilities
- `graph::topo_order`: dependency ordering by non-weak component bindings with cycle detection (framework and external bindings do not introduce component dependencies).
- `graph::component_path[_for]`: stable path strings for diagnostics.
- `graph::providers_of`: direct dependency lookup.
