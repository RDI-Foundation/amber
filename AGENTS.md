* Always write simple, maintainable, DRY code that works. Do not write excessively verbose, defensive, clever, or DRY code.
* Write efficient, idiomatic Rust, taking advantage of the latest syntax and stdlib functions.
    - Prefer to use serde derive macros instead of writing custom de/serialization code
    - Prefer not to allocate. If you see allocation, especially in a tight loop, investigate whether it is necessary
* Use crates from crates.io when it saves complexity or lines of code, but only when the crate is well-maintained and very widely used in the ecosystem OR already in use somewhere in this workspace as a direct or indirect dependency.
* Add a dependency to the cargo workspace root if and only if it is used by more than one crate in the workspace.
* NEVER attempt to preserve backwards compatibility or preserve "legacy" interfaces unless explicitly requested. You can assume that there are no versioning or compatibility guarantees.
* Run `cargo test --workspace --all-features`, `cargo clippy --all-targets`, and cargo fmt` after any non-trivial change to the Rust code.
* There may be other agents working on this repo concurrently. Don't fret if you see files created or changed that you didn't create or change yourself. Just ignore them and carry on unless they directly conflict with your work, in which case stop and seek guidance.
* Always keep READMEs up-to-date with information that is helpful to expert developers who are not familiar with Amber. When making updates to the READMEs, don't just find and replace isolated snippets–ensure that each line, paragraph, section, etc. is useful in the context of the whole document.
* Make error messages and spans as helpful to devs as possible. Rust error messaging is a great example of usability
    - Create UI tests whenever adding a new error type or variant. From the perspective of a dev using the software, ensure that the error is helpful.
* When adding new crates, make sure to update the dockerfiles
* The compiler should try to support older versions of the manifest format and scenario IR as long as it would not introduce an undue amount of complexity or legacy code to maintain.
    - If supporting previous versions is feasible, later versions of the compiler take the old versions but output the later version of compiler outputs.
* When a breaking change is made, you may need to bump versions of any of: the manifest format, the IR, the docker/images.json version series. If you bump the CLI docker image series, also update README.md to have the latest floating version.
    - Do not update versions in tests or examples unless they changed in a breaking way and NEED the newer version.
