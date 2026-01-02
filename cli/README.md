# amber-cli

Command-line front-end for the compiler. It resolves a root manifest, runs compile/check, and renders diagnostics and artifacts.

## Responsibilities
- Wire `amber-compiler` and `amber-resolver` for compile/check flows.
- Render diagnostics via `miette`, including treating selected warnings as errors.
- Emit report artifacts (currently Graphviz DOT).

## Where to look
- `src/main.rs`: command flow, diagnostics policy, and output selection.
- `amber_compiler::reporter`: reporter implementations.

## Extending
- Add new reporters by implementing `Reporter` and wiring into `EmitKind`.
- Update `print_diagnostics`/`DenySet` when changing warning policy.
