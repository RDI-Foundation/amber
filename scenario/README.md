# amber-scenario

Data model for the fully linked component graph produced by the compiler.

## Core types
- `Scenario`: components + bindings; owns the root id and normalizes child order.
- `Component`: instance metadata (moniker path, manifest digest, config, program presence).
- `BindingEdge`, `ProvideRef`, `SlotRef`: capability wiring edges.

## Graph utilities
- `graph::topo_order`: dependency ordering by non-weak bindings with cycle detection.
- `graph::component_path[_for]`: stable path strings for diagnostics.
- `graph::providers_of`: direct dependency lookup.
