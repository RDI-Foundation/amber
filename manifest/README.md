# Amber Component Manifest (JSON5) Format

This document defines the **manifest file format** and the **validation performed by `manifest/src/lib.rs`**.

A manifest describes **one component**. A component may:

* Run a `program` (container image + args/env + optional network endpoints).
* Contain named child `components` (each points at another manifest).
* Declare required inputs (`slots`) and produced outputs (`provides`).
* Wire capabilities into slots (`bindings`).
* Expose a public surface to its parent (`exports`).

Manifests are written as **JSON5** (comments/trailing commas allowed) and parsed as a **single JSON object**.

---

## Quick start

Minimal leaf component exporting an HTTP API:

```json5
{
  manifest_version: "0.1.0",
  program: {
    image: "ghcr.io/acme/hello:v1",
    args: "--port 8080",
    network: {
      endpoints: [{ name: "http", port: 8080 }],
    },
  },
  provides: {
    api: { kind: "http", endpoint: "http" },
  },
  exports: { api: "api" },
}
```

---

## Validation stages

### Parse-time validation (this crate)

This crate **parses JSON5**, deserializes into Rust types, and validates:

* `manifest_version` must be valid SemVer and **satisfy `^0.1.0`**.
* No dots (`.`) in:

  * child instance names (`components` keys)
  * capability names (`slots`/`provides` keys, binding slot/capability names, and export target names)
  * export names (keys in `exports`)
  * child refs (`#<name>`) in bindings and export targets
* A name cannot be declared in **both** `slots` and `provides`.
* `exports` targets that point at `self` must refer to something declared in `slots` or `provides`.
* `exports` targets that point at `#child` must refer to a declared child.
* Each binding target `(<to>.<slot>)` may appear **only once**.
* Binding references must be locally well-formed:

  * `to: "self"` requires `slot` exist in `slots`
  * `from: "self"` requires `capability` exist in `provides`
  * `#child` used in a binding must exist in `components`
* Endpoint names in `program.network.endpoints[]` must be unique.
* Any `provides.*.endpoint` must refer to a declared endpoint name.

Unused declaration rule enforced by this crate:

* Every declared **slot** must be either:

  * **exported** (some export target points at `self.<name>` or `<name>`), or
  * **bound into `self`** (some binding has `to: "self"` and `slot: "<name>"`)
* Every declared **provide** must be either:

  * **exported** (some export target points at `self.<name>` or `<name>`), or
  * **used as a binding source from `self`** (some binding has `from: "self"` and `capability: "<name>"`)

### Link-time / resolution-time validation (NOT done by this crate)

This crate does **not** fetch child manifests and therefore does not validate cross-manifest semantics, such as:

* Whether an `exports` target like `#child.<name>` resolves to something actually exported by the child.
* Whether kinds/profiles match across bindings or forwarded exports.
* Whether a child has exported the slot/capability you’re trying to bind to/from.
* Validation of `components.<name>.config` against `config_schema`.

If your system resolves manifests, it should enforce those rules at link/resolve time.

---

## Top-level schema

Top-level object:

```json5
{
  manifest_version: "0.1.0",   // required

  program: { /* ... */ },      // optional
  components: { /* ... */ },   // optional; default {}
  config_schema: { /* ... */ },// optional
  slots: { /* ... */ },        // optional; default {}
  provides: { /* ... */ },      // optional; default {}
  bindings: [ /* ... */ ],      // optional; default []
  exports: { /* ... */ },       // optional; default {}
}
```

Notes:

* Duplicate keys are rejected in: `program.env`, `components`, `slots`, `provides`, `exports`.
* `bindings` are treated as **sets** internally:

  * order is not meaningful
  * exact duplicates may be deduplicated
* `exports` is a map (order is not meaningful; duplicate keys are rejected).

Unknown fields:

* `ManifestRef` object form is **strict** (unknown fields are rejected).
* `provides` entries are **strict** (unknown fields are rejected).
* Most other objects are **not strict** in this crate (unknown fields are ignored by serde).

---

## Manifest references (`ManifestRef`)

Child manifests are referenced by a URL.

Forms:

* URL string (sugar):

  * `"https://registry.example.org/pkg/v1"`
* Canonical object form (optionally pinned):

  * `{ url: "https://...", digest: "sha256:<base64>" }`

Rules enforced by this crate:

* `url` must be a string parseable as an absolute URL.
* `digest` (if present) must be:

  * algorithm `sha256`
  * `sha256:<base64>` where base64 decodes to **32 bytes**
* Unknown fields in the object form are invalid.

Example:

```json5
{
  url: "https://registry.agentbeats.dev/envs/tau2",
  digest: "sha256:5Ub0uXR5xZYFKKlTsOKvC43pM5gdAN1JRStAebbJ45U="
}
```

---

## `program`

```json5
program: {
  image: "ghcr.io/acme/my-component:v1", // required

  // args: optional; default [].
  // Either:
  // - a list of strings, or
  // - a single string tokenized with shlex rules.
  args: ["--port", "8080"],
  // args: "--port 8080",

  // env: optional; default {}.
  // Values support interpolation.
  env: {
    LOG_LEVEL: "debug",
    API_URL: "${slots.backend.url}",
  },

  // network: optional
  network: {
    // endpoints: optional; default []
    endpoints: [
      {
        name: "http",          // required; unique within endpoints
        port: 8080,            // required
        protocol: "http",      // optional; default "http" (http/https/tcp/udp)
        path: "/",             // optional; default "/"
      },
    ],
  },
}
```

### Interpolation in `args` and `env`

`args` elements and `env` values support `${...}` interpolation.

Supported sources:

* `${config.<path>}` reads from the component’s config value.
* `${slots.<path>}` reads from resolved slot values.

`<path>` is dot-separated for nested objects.

Examples:

* `${config.domain}`
* `${slots.llm.url}`

Notes:

* This crate **parses** interpolation syntax but does **not** validate that the referenced paths exist.

---

## `components` (child components)

`components` is a map: **instance name → component declaration**.

Instance name rules (enforced):

* Must be unique (duplicate keys rejected).
* Must not contain `.`.

Child declaration forms:

1. Manifest ref string:

```json5
components: {
  env: "https://registry.agentbeats.dev/envs/tau2/v2",
}
```

2. Manifest ref object:

```json5
components: {
  env: { url: "https://...", digest: "sha256:..." },
}
```

3. Object with per-instance config:

```json5
components: {
  evaluator: {
    manifest: "https://registry.agentbeats.dev/tau2-evaluator/v1.0.0",
    config: { domain: "airline", num_trials: 1 },
  },
}
```

Notes:

* `config` is accepted as any JSON value by this crate (commonly an object).
* This crate does not validate `config` against `config_schema` (link-time concern).

---

## `config_schema`

`config_schema` is a JSON Schema value describing acceptable `config` values when this manifest is instantiated under `components`.

Rules enforced by this crate:

* The schema must be a valid JSON Schema (syntactically valid for the `jsonschema` library).

Example:

```json5
config_schema: {
  type: "object",
  properties: {
    domain: { type: "string" },
    num_trials: { type: "integer", minimum: 1 },
  },
  required: ["domain", "num_trials"],
  additionalProperties: false,
}
```

---

## Capabilities: `slots`, `provides`, `exports`

### Capability declaration shape

Both slots and provides share:

* `kind`: `"mcp" | "llm" | "http" | "a2a"`
* `profile` (optional): string qualifier (often used for `"mcp"`)

Example:

```json5
{ kind: "mcp", profile: "openenv" }
```

### `slots`

`slots` declares what the component requires.

```json5
slots: {
  llm: { kind: "llm" },
  env: { kind: "mcp", profile: "openenv" },
}
```

Important rule (enforced):

* If a slot is **not exported** (no `exports` target points at it), it must be **bound into `self.<slot>`** by a binding in this manifest.
* If a slot is **exported** (via `exports`), it is an input the parent is expected to bind.

### `provides`

`provides` declares what the component offers.

A provide may include:

* `endpoint`: name of a `program.network.endpoints[].name` (must exist if set)

```json5
provides: {
  api: { kind: "http", endpoint: "http" },
  llm: { kind: "llm" },
}
```

Notes:

* This crate enforces only that `endpoint` (if present) refers to a declared endpoint name.
* To forward a child capability, use `exports` pointing at `#child.<name>`.

### `exports`

`exports` maps public names to internal capability targets visible to the parent.

```json5
exports: {
  llm: "llm",
  api: "self.api",
  tool: "#router.tool",
}
```

Rules enforced:

* Export names (keys) must not contain `.`.
* Targets must be one of:

  * `<name>` (shorthand for `self.<name>`)
  * `self.<name>`
  * `#<child>.<name>`
* Targets pointing at `self` must refer to a declared slot or provide.
* Targets pointing at `#child` must refer to a declared child.

---

## `bindings`

A binding wires a **target slot** to a **source provide**:

`(<to>.<slot>) <- (<from>.<capability>)`

Component refs:

* `"self"` for the current manifest
* `"#<child>"` for a key in `components`

Bindings forms:

### Explicit form

```json5
{
  to: "#evaluator",
  slot: "llm",
  from: "#router",
  capability: "llm",
  weak: true, // optional; default false
}
```

### Dot-sugar form

```json5
{ to: "#evaluator.llm", from: "#router.llm", weak: true }
```

Rules enforced by this crate:

* Target uniqueness: you cannot bind the same `(<to>.<slot>)` more than once.
* `to: "self"` requires `slot` exist in `slots`.
* `from: "self"` requires `capability` exist in `provides`.
* Any `#child` referenced in `to` or `from` must exist in `components`.
* Slot/capability names must not contain `.`.

`weak`:

* `weak: true` marks a binding as **non-ordering**: it does not participate in dependency ordering or cycle detection (i.e. weak bindings cannot create a dependency cycle), similar to `Arc` vs `Weak` in Rust.
* This crate parses and preserves `weak`, but does not implement dependency ordering or cycle checks.

---

## Limitation: no binding from local slots

This version does **not** allow binding from a local slot (`from: "self.<slot>"`). A binding source in `self.*` must refer to a **provide**, not a slot.

To pass a slot through to a child, export the child’s slot directly:

```json5
exports: { llm: "#child.llm" }
```

---

## Examples

### 1) Leaf component exporting an HTTP API (valid)

```json5
{
  manifest_version: "0.1.0",
  program: {
    image: "ghcr.io/acme/hello:v1",
    args: "--port 8080",
    network: { endpoints: [{ name: "http", port: 8080, path: "/" }] },
  },
  provides: {
    api: { kind: "http", endpoint: "http" },
  },
  exports: { api: "api" },
}
```

### 2) Component that requires an LLM slot from its parent (valid)

Because the component expects its **parent** to supply `llm`, it must export that slot.

```json5
{
  manifest_version: "0.1.0",
  config_schema: {
    type: "object",
    properties: { domain: { type: "string" } },
    required: ["domain"],
    additionalProperties: false,
  },
  program: {
    image: "ghcr.io/acme/evaluator:v1",
    args: ["--domain", "${config.domain}", "--llm", "${slots.llm.url}"],
  },
  slots: {
    llm: { kind: "llm" },
  },
  exports: { llm: "llm" },
}
```

### 3) Composite component: program + child wiring + forwarding (valid)

This component:

* runs a router (`program`)
* instantiates a `wrapper` child
* provides `admin_api` from a local endpoint and binds it into the child’s `admin_api` slot
* forwards the child’s `llm` provide upward as `llm`

```json5
{
  manifest_version: "0.1.0",
  program: {
    image: "docker.io/litellm/litellm:latest",
    network: {
      endpoints: [
        { name: "admin", port: 4000, path: "/api" },
      ],
    },
  },
  components: {
    wrapper: "https://registry.amber-protocol.org/litellm-wrapper/latest",
  },
  provides: {
    admin_api: { kind: "http", endpoint: "admin" },
  },
  bindings: [
    { to: "#wrapper.admin_api", from: "self.admin_api" },
  ],
  exports: { llm: "#wrapper.llm" },
}
```

### 4) Weak binding flag (non-ordering; breaks dependency cycles)

In this example, `a` and `b` both bind to each other. Marking one edge as `weak: true` breaks the dependency cycle for ordering purposes while still expressing the wiring intent.

```json5
{
  manifest_version: "0.1.0",
  components: {
    a: "https://registry.example.org/a/v1",
    b: "https://registry.example.org/b/v1",
  },
  bindings: [
    { to: "#a.peer", from: "#b.api" },
    { to: "#b.peer", from: "#a.api", weak: true },
  ],
}
```
