# Amber Component Manifest (JSON5) Format

This document defines the **manifest file format** and the **validation/linting performed by `compiler/manifest/src/lib.rs` and `compiler/manifest/src/lint.rs`**.

A manifest describes **one component**. A component may:

* Run a `program` (container image + entrypoint, native path + args, or VM guest config; required when providing capabilities).
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
  manifest_version: "0.3.0",
  program: {
    image: "ghcr.io/acme/hello:v1",
    entrypoint: "--port 8080",
    network: {
      endpoints: [{ name: "http", port: 8080 }],
    },
  },
  provides: {
    api: { kind: "http", endpoint: "http" },
  },
  exports: { api: "provides.api" },
}
```

---

## Validation stages

### Parse-time validation (this crate)

This crate **parses JSON5**, deserializes into Rust types, and validates:

* `manifest_version` must be valid SemVer and **satisfy `>=0.1.0, <1.0.0`**.
  New manifests should use `0.3.0`; older pre-1.0 manifests are still accepted.
* `experimental_features` entries must be known feature names.
* No dots (`.`) in:

  * child instance names (`components` keys)
  * capability names (`slots`/`provides` keys, binding slot/capability names, and export target names)
  * export names (keys in `exports`)
  * child refs (`#<name>`) in bindings and export targets
* A name cannot be declared in **both** `slots` and `provides`.
* `exports` targets that point at `slots` / `provides` must refer to something declared in those
  sections.
* Legacy `exports` targets that point at `self` are still accepted before 1.0, but they lint with
  an explicit replacement.
* `exports` targets that point at `#child` must refer to a declared child.
* Binding references must be locally well-formed:

  * `to` must reference a child component (`#<child>`)
  * `from: "slots"` requires `capability` exist in `slots`
  * `from: "provides"` requires `capability` exist in `provides`
  * legacy `from: "self"` is still accepted before 1.0, but it lints with an explicit replacement
  * `from: "framework"` requires a known framework capability name
  * `#child` used in a binding must exist in `components`
* `framework` is only valid as a binding source; it cannot appear in `to` or `exports`.
* Endpoint names in `program.network.endpoints[]` must be unique.
* Each `provides` entry must declare an `endpoint`, and it must refer to a declared endpoint name.

### Linting (this crate)

This crate also provides `manifest::lint::lint_manifest` for non-fatal checks:

* Every declared **slot** should be either:

  * **referenced by the program** (via `${slots.<name>...}` in `program.entrypoint` or `program.env`), or
  * **mounted by the program** (via `program.mounts: [{ from: "slots.<name>", ... }]` for storage slots), or
  * **exported** (some export target points at `slots.<name>`, or legacy `self.<name>` / `<name>`), or
  * **used as a binding source from `slots`** (some binding has `from: "slots"` and `capability: "<name>"`, or legacy `from: "self"` for the same slot)
* Every declared **provide** should be either:

  * **exported** (some export target points at `provides.<name>`, or legacy `self.<name>` / `<name>`), or
  * **used as a binding source from `provides`** (some binding has `from: "provides"` and `capability: "<name>"`, or legacy `from: "self"` for the same provide)
* If a **`program`** is declared, it should be referenced by a **provide binding or export** (otherwise the program is likely unused).
* Resolver names in each environment should be unique.
* `config_schema` properties should be referenced by `${config.*}` in `program` or in child `components.<name>.config` templates (unused properties are linted). If the schema contains `$ref` cycles or unresolvable refs, the unused-property lint is incomplete and a warning is emitted; unsupported schema features are rejected at parse time.

### Link-time / resolution-time validation (NOT done by this crate)

This crate does **not** fetch child manifests and therefore does not validate cross-manifest semantics, such as:

* Whether an `exports` target like `#child.<name>` resolves to something actually exported by the child.
* Whether kinds/profiles match across bindings or forwarded exports.
* Whether a child has exported the capability you’re trying to bind from.
* Whether multiple bindings target a child slot that is not declared with `multiple: true`.
* Validation of `components.<name>.config` against `config_schema`.
* Whether every parent manifest has enabled the experimental features required by each child
  manifest (`child.experimental_features ⊆ parent.experimental_features`).

If your system resolves manifests, it should enforce those rules at link/resolve time.

---

## Top-level schema

Top-level object:

```json5
{
  manifest_version: "0.3.0",   // required
  experimental_features: ["docker"], // optional; default []

  program: { /* ... */ },      // optional
  components: { /* ... */ },   // optional; default {}
  config_schema: { /* ... */ },// optional
  slots: { /* ... */ },        // optional; default {}
  resources: { /* ... */ },    // optional; default {}
  provides: { /* ... */ },      // optional; default {}
  bindings: [ /* ... */ ],      // optional; default []
  exports: { /* ... */ },       // optional; default {}
  metadata: { /* ... */ },      // optional
}
```

### `experimental_features`

`experimental_features` is an opt-in list for unstable manifest behavior.

Current values:

* `"docker"`

Rules:

* Unknown feature names are rejected at parse time.
* Duplicate entries are ignored during parsing.
* Parent-child enforcement is done by the resolver/linker: every child manifest feature must also
  be listed by its parent manifest.

Notes:

* Duplicate keys are rejected in: `program.env`, `components`, `slots`, `provides`, `exports`.
* `bindings` are an ordered list:

  * declaration order is preserved
  * repeated bindings to the same child slot are preserved so `multiple: true` slots can fan in
    more than one source
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
  * `"./child.json5"` (relative to the manifest's own `file://` URL)
* Canonical object form (optionally pinned):

  * `{ url: "https://...", digest: "sha256:<base64>" }`

Rules enforced by this crate:

* `url` must be a string parseable as an absolute URL or a relative reference.
  Relative references are only resolved against `file://` base URLs by the compiler.
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

`program` is a tagged union with three variants:

### Container program (`image` + `entrypoint`)

```json5
program: {
  image: "ghcr.io/acme/my-component:v1", // required for container programs

  // entrypoint: required for image programs.
  // Either:
  // - a list of strings, or
  // - a single string tokenized with shlex rules.
  // Individual argv strings may also come from sidecar files:
  // entrypoint: ["python3", "-c", { file: "./server.py" }],
  entrypoint: ["--port", "8080"],
  // entrypoint: "--port 8080",

  // shared fields (env/mounts/network) are available on image and path programs:
  env: {
    LOG_LEVEL: "debug",
    API_URL: "${slots.backend.url}",
  },
  mounts: [
    { path: "/run/config.json", from: "config.app" },
    { path: "/run/secret.txt", from: "config.api.token" },
  ],
  network: {
    endpoints: [
      { name: "http", port: 8080, protocol: "http" },
    ],
  },
}
```

### Native program (`path` + `args`)

```json5
program: {
  path: "/usr/bin/env", // required for native programs

  // args: optional; default [].
  // Same parsing rules as entrypoint.
  args: ["python3", "-m", "http.server", "8080"],
  // args: "python3 -m http.server 8080",
  //
  // Args and entrypoint items may also contain `when`-guarded argv items.
  // The whole `argv` array is omitted when the `when` path is absent or null.
  // Presence is not truthiness: false, 0, and "" still count as present.
  //
  // args: [
  //   {
  //     when: "config.profile",
  //     argv: "--profile ${config.profile}",
  //   },
  // ],

  env: {
    // Env values may also be conditional.
    // The whole env entry is omitted when the `when` path is absent or null.
    // Presence is not truthiness: false, 0, and "" still count as present.
    //
    // PROFILE: {
    //   when: "config.profile",
    //   value: "${config.profile}",
    // },
    LOG_LEVEL: "debug",
  },

  // reads: optional.
  // Direct mode infers the same local source-tree reads it supported before when this field is
  // omitted. If it is present, Amber replaces that legacy source-tree read access with these
  // manifest-relative or absolute read-only paths instead. Amber still keeps the executable
  // support path and platform runtime defaults readable so the process can start.
  //
  // reads: [".", "../shared-config"],

  network: {
    endpoints: [
      { name: "http", port: 8080, protocol: "http" },
    ],
  },
}
```

### VM program (`vm`)

```json5
program: {
  vm: {
    image: "${config.base_image}", // guest image path or other resolved base image string
    cpus: 2,
    memory_mib: 1024,
    mounts: [
      { path: "/var/lib/app", from: "slots.state" },
    ],
    network: {
      endpoints: [
        { name: "http", port: 8080, protocol: "http" },
      ],
      egress: "none",
    },
    cloud_init: {
      user_data: { file: "./user-data.yaml" },
    },
  },
}
```

Sidecar file references:

* Any inline string accepted in `program.entrypoint`, `program.args`, or `program.env` may be
  written as `{ file: "./relative/or/absolute/path" }` instead.
* Relative `file` paths are resolved relative to the manifest file for `file://`-backed manifests.
* The compiler inlines file contents before validation and digesting, so changing a sidecar file
  changes the manifest digest.
* VM cloud-init strings use the same form:

```json5
program: {
  vm: {
    image: "/tmp/base.qcow2",
    cpus: 2,
    memory_mib: 1024,
    cloud_init: {
      user_data: { file: "./user-data.yaml" },
      vendor_data: { file: "./vendor-data.yaml" },
    },
  },
}
```

Rules:

* `program` must declare exactly one of `image`, `path`, or `vm`.
* `program.entrypoint` is only valid with `program.image`.
* `program.args` is only valid with `program.path`.
* `program.reads` is only valid with `program.path`.
* `program.env` is only valid with `program.image` or `program.path`. VM guest startup should be configured through `program.vm.cloud_init`.
* `program.network` and `program.mounts` are only valid with `program.image` or `program.path`. VM programs use `program.vm.network` and `program.vm.mounts`.
* `program.path` must be an explicit absolute path or a relative path containing a separator
  such as `./bin/server`; direct execution does not search `PATH`.

### `program.mounts` and `program.vm.mounts`

For image/path programs, `program.mounts` mounts config values as files inside the runtime
environment, or mounts routed storage as a directory. VM programs use the same mount entry shape
under `program.vm.mounts`. Each entry has:

* `path` (required): absolute path inside the container or VM guest.
* `from` (required): source value.
* `name` (optional): identifier for diagnostics.

Supported `from` sources (current):

* `config` or `config.<path>`: mount the component config (whole object or a path), including
  paths marked `secret: true` in the component’s config schema.
* `slots.<name>`: mount a storage slot as a directory. The referenced slot must exist and have
  `kind: "storage"`.
* `framework.docker`: requires `experimental_features: ["docker"]`. In Docker Compose output, this
  injects a Docker socket mount backed by the framework docker gateway.

Reserved (not implemented yet):

* `framework.<capability>` other than `framework.docker`

Mount value formatting:

* leaf values (string/number/bool) -> text
* objects/arrays -> JSON
* null -> empty string

Notes:

* Mount paths must be absolute and must not include `..`.
* Secret-marked config is mounted with the same `config.<path>` syntax as any other config path.
* `resources.<name>` mounts a storage resource owned by the same component.
* `slots.<name>` mounts storage routed in from another component. Use a directory path such as
  `/var/lib/app`, not a single file path.

Example:

```json5
resources: {
  state: { kind: "storage" },
},
program: {
  image: "ghcr.io/acme/app:v1",
  entrypoint: ["app", "--state-dir", "/var/lib/app"],
  mounts: [
    { path: "/var/lib/app", from: "resources.state" },
  ],
}
```

The important mental model is that storage is a directory capability, not a string and not a
URL-shaped object. Programs consume it by mounting it into their filesystem namespace, either from
`resources.<name>` when they own the storage locally or from `slots.<name>` when the storage is
routed in from elsewhere.

### Interpolation in `image`/`path`, `entrypoint`/`args`, and `env`

`image` (or `path`), command arguments (`entrypoint` or `args`), and `env` values support `${...}` interpolation.

Supported sources:

* `${config.<path>}` reads from the component’s config value.
* `${slots.<path>}` reads from resolved slot values.
* `${item.<path>}` reads the current item inside a repeated `each` expansion.

`<path>` is dot-separated for nested objects.

Examples:

* `${config.domain}`
* `${slots.llm.url}`

Notes:

* Slots expose virtual objects. URL-shaped slots expose a `url` field, so use
  `${slots.<slot>.url}` for the URL string or `${slots.<slot>}` to interpolate the object as JSON.
* Storage slots are different virtual objects. They are not URL-shaped and cannot be interpolated
  with `${slots...}`; mount them with `program.mounts`.
* Repeated slots declared with `multiple: true` must be expanded through `each`; plain
  `${slots.<slot>}` and `${slots.<slot>.url}` are rejected for repeated slots.
* Repeated slots declared with `multiple: true` must be expanded through `each`; plain
  `${slots.<slot>}` and `${slots.<slot>.url}` are rejected for repeated slots.
* `manifest_version: "0.2.0"` or newer is required for object items in `program.entrypoint` /
  `program.args` and object values in `program.env`, such as
  `{ when: "config.profile", argv: [...] }` or
  `{ when: "config.profile", value: "${config.profile}" }`.
* `manifest_version: "0.3.0"` or newer is required for repeated slot expansion objects:

  * `{ each: "slots.<slot>", argv: [...] }`
  * `{ each: "slots.<slot>", arg: "..." }`
  * `{ each: "slots.<slot>", value: "...", join: "," }`
* `when` is supported in `program.entrypoint`, `program.args`, and `program.env`.
* `when` accepts `config.<path>` or `slots.<path>`.
* Slot `when` checks whether the referenced slot query is present. Today that means
  `slots.<slot>` and `slots.<slot>.url` are both valid.
* `when: "slots.<slot>"` and `when: "slots.<slot>.url"` are mainly useful for `optional: true`
  slots and `multiple: true` fan-in slots. For repeated slots, `when: "slots.<slot>"` means
  "the fan-in is non-empty". Amber lints conditions on required singular slots when the queried
  value is guaranteed to be present after linking.
* This crate **parses** interpolation syntax but does **not** validate that the referenced paths
  exist. The compiler validates `${config.*}` against `config_schema` and `${slots.*}` against
  declared slots and supported fields. `${item.*}` is only valid inside repeated `each`
  expansions.

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

* `config` accepts any non-null JSON value; `null` is treated as omitted.
* This crate does not validate `config` against `config_schema` (link-time concern).

---

## `config_schema`

`config_schema` is a JSON Schema value describing acceptable `config` values when this manifest is instantiated under `components`.

Rules enforced by this crate:

* The schema must be valid JSON Schema (as accepted by the `jsonschema` library).
* The schema must conform to Amber's `config_schema` profile (a deterministic subset that Amber tooling supports):
  * If `$schema` is present, it must be Draft 2020-12 (`https://json-schema.org/draft/2020-12/schema`, with optional `#` and optional `http://`).
  * Root schema must be object-shaped (`type: "object"` or `type: ["object", ...]`).
  * Schema objects with `properties` or `required` must also include `"object"` in `type`.
  * Property names (and `required` entries) must match `^(?!.*__)[a-z][a-z0-9_]*$`.
  * `$ref` is allowed, but must be local-only JSON pointers (`#` or `#/...`).
  * `additionalProperties` must be a boolean when present (schema-form `additionalProperties` is not supported).
  * `secret` is allowed as a boolean annotation; if set on a schema node, that value (and its descendants) are treated as secret.
  * `x-*` annotations are allowed on schema objects. Amber ignores them for validation semantics, but preserves them when carrying the schema forward.
  * `default` is supported. Amber applies defaults when materializing root runtime config and when resolving component config objects. Defaults fill in absent values; they do not overwrite explicit values.
  * Unsupported keywords include: `anyOf`, `oneOf`, `not`, `if`/`then`/`else`, `patternProperties`, `propertyNames`, `dependentSchemas`, `dependentRequired`, `unevaluatedProperties`, `unevaluatedItems`, `$dynamicRef`, `$recursiveRef`.

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

To mark a value as secret, add `secret: true` to its schema entry:

```json5
config_schema: {
  type: "object",
  properties: {
    api_key: { type: "string", secret: true },
    model: { type: "string", "x-example-hide": true },
  },
}
```

---

## Capabilities: `slots`, `resources`, `provides`, `exports`

### Capability declaration shape

Both slots and provides share:

* `kind`: `"mcp" | "llm" | "http" | "docker" | "a2a" | "storage"`
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
  state: { kind: "storage" },
}
```

Important rule (enforced at link time):

* Slots are inputs to the component. Each slot must be satisfied by a binding in the **parent**
  manifest into `#<child>.<slot>` (unless the slot is `optional`).

`optional` (default `false`) allows a slot to be left unbound:

```json5
slots: {
  api: { kind: "http", optional: true },
}
```

Optional slots can be used to break slot-forwarding cycles; if a required slot is part of a cycle,
linking fails.

Root URL-shaped slots are still external inputs. Storage is different: mounted storage must
ultimately come from a `resources.<name>` binding, not from a root storage slot.

`multiple` (default `false`) allows the same slot to be bound more than once:

```json5
slots: {
  upstream: { kind: "http", optional: true, multiple: true },
}
```

This is Amber's fan-in shape for repeated slots:

* `multiple: true` means one or more bindings when `optional` is false.
* `optional: true, multiple: true` means zero or more bindings.
* Binding declaration order is preserved and becomes the expansion order for repeated `each`
  interpolation in program args and env values.

Note: scenario-level slot injection is not supported yet. Required slots on the root component will
fail to link because there is no parent to satisfy them.

### `resources`

`resources` declares framework-managed objects owned by the component.

Today the only supported resource kind is storage:

```json5
resources: {
  app_state: {
    kind: "storage",
    params: {
      size: "1Gi",
    },
  },
}
```

Rules enforced:

* `kind` must currently be `"storage"`.
* Storage resources are capability sources. A component can mount its own storage directly with
  `program.mounts: [{ from: "resources.<name>", ... }]`, or bind the resource into a child storage
  slot with `from: "resources.<name>"`.

Example:

```json5
resources: {
  app_state: {
    kind: "storage",
    params: {
      size: "1Gi",
    },
  },
},
program: {
  mounts: [
    { path: "/var/lib/app", from: "resources.app_state" },
  ],
}
```

### `provides`

`provides` declares what the component offers.

A provide must include:

* `endpoint`: name of a `program.network.endpoints[].name`

```json5
provides: {
  api: { kind: "http", endpoint: "http" },
  llm: { kind: "llm", endpoint: "llm" },
}
```

Notes:

* This crate enforces that each provide declares an `endpoint` and that it refers to a declared endpoint name.
* `provides` cannot declare `kind: "storage"`. Storage is routed through `slots` and `bindings`,
  then consumed via `program.mounts`.
* To forward a child capability, use `exports` pointing at `#child.<name>`.

### `exports`

`exports` maps public names to capabilities in this manifest (provides or slots) or to child
exports.

```json5
exports: {
  llm: "provides.llm",
  api: "slots.api",
  tool: "#router.tool",
}
```

Rules enforced:

* Export names (keys) must not contain `.`.
* Targets must be one of:

  * `provides.<provide>`
  * `slots.<slot>`
  * `#<child>.<export>`
* Legacy `self.<provide-or-slot>` syntax is still accepted before 1.0, but it lints with an
  explicit replacement.
* Bare export shorthand like `<name>` is still accepted, but `provides.<name>` / `slots.<name>`
  is the canonical spelling.
* Targets pointing at `slots` / `provides` must refer to a declared slot or provide.
* Targets pointing at `#child` must refer to a declared child.

---

## `bindings`

A binding wires a **target slot** to a **source capability** (provide, slot, resource, child
export, or framework):

`(<to>.<slot>) <- (<from>.<capability>)`

Component refs (for child-sourced `from`):

* `"#<child>"` for a key in `components`

Local capability refs (for current-manifest `from`):

* `"slots"` for the current manifest's slots
* `"provides"` for the current manifest's provides
* legacy `"self"` is still accepted before 1.0, but it lints with an explicit replacement

Framework refs (binding sources only):

* `"framework"` for runtime/framework-provided capabilities
* `"framework.<capability>"` in dot-sugar form

`framework` is **not** a component ref: it is only valid on the `from` side. `#framework` remains a
normal child ref.

To satisfy a child slot, create a binding with `to: "#<child>.<slot>"` and a source capability
(`from: "provides.<provide>"`, `from: "slots.<slot>"`, `from: "resources.<name>"`, or
`from: "#<other>.<export>"`).

Forwarding a slot to a child:

```json5
slots: { api: { kind: "http" } },
bindings: [
  { to: "#gateway.api", from: "slots.api" },
],
exports: { public_api: "slots.api" },
```

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

* `to` must reference a child (`#<child>`).
* `from: "slots"` requires `capability` exist in `slots`.
* `from: "provides"` requires `capability` exist in `provides`.
* Legacy `from: "self"` is still accepted before 1.0, but it lints with an explicit replacement.
* `from: "resources"` requires the named resource exist in `resources`.
* `from: "framework"` requires a known framework capability name (see below).
* `framework` is only valid as a binding source; it cannot appear in `to` or `exports`.
* Any `#child` referenced in `to` or `from` must exist in `components`.
* Slot/capability names must not contain `.`.

Multiplicity note:

* This crate preserves repeated bindings to the same `(<to>.<slot>)`.
* The linker later checks the resolved child slot declaration:

  * singular slots reject repeated bindings
  * `multiple: true` slots accept repeated bindings and preserve their declaration order

Framework capabilities are a fixed compiler-known list.

Current framework capabilities:

* `docker` (`framework.docker`) — requires `experimental_features: ["docker"]` in the same
  manifest.

`weak`:

* `weak: true` marks a binding as **non-ordering**: it does not participate in dependency ordering or cycle detection (i.e. weak bindings cannot create a dependency cycle), similar to `Arc` vs `Weak` in Rust.
* In the compiler, `weak` also means the consumer tolerates the provider being unavailable; unbound root slots whose entire binding chain is weak are treated as external inputs and routed through the per-scenario router.
* This crate parses and preserves `weak`, but does not implement dependency ordering or cycle checks.

---

## `metadata`

Optional user-defined JSON value that Amber passes through to the Scenario IR without interpreting.
Useful for application-specific data such as agent registry identifiers that downstream tools
can discover by walking the IR graph.

```json5
metadata: {
  my_special_id: "...",
}
```

Amber does not interpret the contents. `metadata` is excluded from the manifest digest.

---

## Examples

### 1) Leaf component exporting an HTTP API (valid)

```json5
{
  manifest_version: "0.3.0",
  program: {
    image: "ghcr.io/acme/hello:v1",
    entrypoint: "--port 8080",
    network: { endpoints: [{ name: "http", port: 8080 }] },
  },
  provides: {
    api: { kind: "http", endpoint: "http" },
  },
  exports: { api: "provides.api" },
}
```

### 2) Component that requires an LLM slot from its parent (valid)

Because the component expects its **parent** to supply `llm`, the parent must bind a provider into
`#child.llm` when it instantiates this component.

```json5
{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: { domain: { type: "string" } },
    required: ["domain"],
    additionalProperties: false,
  },
  program: {
    image: "ghcr.io/acme/evaluator:v1",
    entrypoint: ["--domain", "${config.domain}", "--llm", "${slots.llm.url}"],
  },
  slots: {
    llm: { kind: "llm" },
  },
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
  manifest_version: "0.3.0",
  program: {
    image: "docker.io/litellm/litellm:latest",
    network: {
      endpoints: [
        { name: "admin", port: 4000 },
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
    { to: "#wrapper.admin_api", from: "provides.admin_api" },
  ],
  exports: { llm: "#wrapper.llm" },
}
```

### 4) Allocate storage with `resources` and mount it (valid)

When the program and the storage resource live on the same component, mount the resource directly:

```json5
{
  manifest_version: "0.3.0",
  resources: {
    app_state: {
      kind: "storage",
      params: {
        size: "1Gi",
      },
    },
  },
  program: {
    image: "ghcr.io/acme/app:v1",
    entrypoint: ["app", "--state-dir", "/var/lib/app"],
    mounts: [
      { path: "/var/lib/app", from: "resources.app_state" },
    ],
  },
}
```

If the storage owner and the consuming program are different components, keep using a child
storage slot plus a binding from `resources.<name>`.

### 5) Weak binding flag (non-ordering; breaks dependency cycles)

In this example, `a` and `b` both bind to each other. Marking one edge as `weak: true` breaks the dependency cycle for ordering purposes while still expressing the wiring intent.

```json5
{
  manifest_version: "0.3.0",
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
