* Always write simple, maintainable, DRY code that works. Do not write excessively verbose, defensive, clever, or DRY code.
* Write efficient, idiomatic Rust, taking advantage of the latest syntax and stdlib functions.
    - Prefer to use serde derive macros instead of writing custom de/serialization code
    - Prefer not to allocate. If you see allocation, especially in a tight loop, investigate whether it is necessary
* Use crates from crates.io when it saves complexity or lines of code, but only when the crate is well-maintained and very widely used in the ecosystem OR already in use somewhere in this workspace as a direct or indirect dependency.
* Add a dependency to the cargo workspace root if and only if it is used by more than one crate in the workspace.
* NEVER attempt to preserve backwards compatibility or preserve "legacy" interfaces unless explicitly requested. You can assume that there are no versioning or compatibility guarantees.
* Run `cargo fmt`, `cargo clippy`, and `cargo test` after any non-trivial change.
* There may be other agents working on this repo concurrently
* Always keep READMEs up-to-date
