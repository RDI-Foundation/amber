# amber-scenario

Data model for the fully linked scenario produced by the compiler.

## Core types
- `Scenario`: linked component tree with resolved bindings and an exported interface; contains the root id and can normalize order for deterministic output.
- `Component`: instance metadata (moniker path, manifest digest, config, program presence).
- `BindingEdge`, `ProvideRef`, `SlotRef`: capability wiring edges.
- `ScenarioExport`: named export mapping to a resolved provide (with capability).

## Graph utilities
- `graph::topo_order`: dependency ordering by non-weak bindings with cycle detection.
- `graph::component_path[_for]`: stable path strings for diagnostics.
- `graph::providers_of`: direct dependency lookup.
