* Write efficient, idiomatic Rust, taking advantage of the latest syntax and stdlib functions.
    - Prefer to use serde derive macros instead of writing custom de/serialization code
    - Prefer not to allocate. if you see allocation, especially in a tight loop, investigate whether it is necessary
* Use crates from crates.io when it saves a lot of complexity, but only when the crate is very heavily used in the ecosystem.
* NEVER attempt to preserve backwards compatibility or preserve "legacy" interfaces unless explicitly requested.
* Run `cargo fmt`, `cargo clippy`, and `cargo test` after any non-trivial change.
