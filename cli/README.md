# amber-cli

Command-line front-end for the compiler. It resolves a root manifest, runs compile/check, and renders diagnostics and artifacts.

## Responsibilities
- Wire `amber-compiler` and `amber-resolver` for compile/check flows.
- Render diagnostics via `miette`, including treating selected warnings as errors.
- Keep `amber --help` and nested `--help` pages useful enough that users can discover the CLI
  surface without reading the source.
- Write compile outputs only when requested; `amber compile` requires at least one output flag (`--output`, `--dot`, `--docker-compose`/`--compose`, `--metadata`, `--kubernetes`, `--direct`, or `--bundle`).
- Detect bundle and Scenario IR inputs and emit bundle directories via `--bundle`.
- Run compiled direct artifacts via `amber run <output-dir>` (delegates to the direct init runtime).
  - Direct mode requires a local sandbox backend: `bwrap` plus `slirp4netns` on Linux, or `/usr/bin/sandbox-exec` on macOS.
  - Direct mode only supports explicit `program.path` executables; it does not resolve bare program names through `PATH`.
- Surface the manifest README via `amber docs manifest`.
- Surface embedded project docs via `amber docs readme`, `amber docs manifest`, and
  `amber docs examples [example]`.

## Where to look
- `src/main.rs`: command flow, diagnostics policy, output paths, and clap help text.
- `amber_compiler::reporter`: reporter implementations.

## Extending
- Add new reporters by implementing `Reporter` and wiring into `CompileArgs` as an output flag.
- Update `print_diagnostics`/`DenySet` when changing warning policy.
