# amber-cli

Command-line front-end for the compiler. It resolves a root manifest, runs compile/check, and renders diagnostics and artifacts.

## Responsibilities
- Wire `amber-compiler` and `amber-resolver` for compile/check flows.
- Render diagnostics via `miette`, including treating selected warnings as errors.
- Write the primary compile output (scenario IR JSON) plus optional side artifacts (e.g. Graphviz DOT via `--dot`).
- Detect bundle inputs and emit bundle directories via `--bundle`.

## Where to look
- `src/main.rs`: command flow, diagnostics policy, and output paths.
- `amber_compiler::reporter`: reporter implementations.

## Extending
- Add new reporters by implementing `Reporter` and wiring into `CompileArgs` as an output flag.
- Update `print_diagnostics`/`DenySet` when changing warning policy.
