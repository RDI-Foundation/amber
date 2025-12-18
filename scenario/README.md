# Amber Component Manifest (JSON5) Format

An Amber component manifest describes **one component**. A component may:

- Run a `program` (a container image with args/env/network).
- Contain named child `components` (each child points at another manifest).
- Declare required inputs (`slots`) and produced outputs (`provides`).
- Wire components together (`bindings`) and choose what is visible to its parent (`exports`).

This is intentionally similar to the Fuchsia component manifest model: **components are recursive**. A component can have both a `program` and child `components`, and those children can themselves have programs and children, and so on.

Manifests are written as **JSON5** (comments/trailing commas allowed) and parsed as a single JSON object.

## Top-level fields

```json5
{
  manifest_version: "1.0.0",

  // Optional: describes how to run this component.
  program: { /* ... */ },

  // Optional: child component instances (recursive).
  components: { /* ... */ },

  // Optional: JSON Schema describing this component's `config` object.
  config_schema: { /* ... */ },

  // Optional: required capabilities for this component.
  slots: { /* ... */ },

  // Optional: capabilities provided by this component (or forwarded from a child).
  provides: { /* ... */ },

  // Optional: wiring between components' slots and capabilities.
  bindings: [ /* ... */ ],

  // Optional: capabilities this component exposes to its parent.
  exports: [ /* ... */ ],
}
```

Notes:

- `manifest_version` is a SemVer string (currently `"1.0.0"`).
- Duplicate keys in `program.env`, `components`, `slots`, and `provides` are invalid.
- Names must be unique across `slots` and `provides` (a name cannot be declared in both).
- `exports` entries must name something declared in `slots` or `provides`.
- Each binding target `(<to>.<slot>)` and binding source `(<from>.<capability>)` may only appear once.
- Every declared slot/provide must be either bound by a `binding` or listed in `exports`.

## Manifest references (`ManifestRef`)

Child components are referenced by a URL.

A manifest reference can be written as either:

- URL string (sugar): `"https://..."`
- Canonical form (optionally pinned):
  - `{ url: "https://...", digest: "<alg>:<hash-b64>" }`

`digest` is optional. If present, it is used to verify the bytes fetched from `url` by hashing them and comparing.

The digest string format is:

`<alg>:<hash-b64>`

`<alg>` can be `sha256`.

Examples:

- `https://registry.amber-protocol.org/litellm/v3.8.6`
- `https://registry.agentbeats.dev/envs/tau2`
- `{ url: "https://registry.agentbeats.dev/envs/tau2", digest: "sha256:5Ub0uXR5xZYFKKlTsOKvC43pM5gdAN1JRStAebbJ45U=" }`

## `program`

```json5
program: {
  image: "ghcr.io/acme/my-component:v1",

  // Optional; default [].
  // Either a list of strings, or a single string that will be shell-split.
  args: ["--port", "8080"],
  // args: "--port 8080",

  // Optional; default {}.
  env: {
    LOG_LEVEL: "debug",
    API_URL: "${slots.backend.url}",
  },

  // Optional.
  network: {
    endpoints: [
      {
        name: "http",
        port: 8080,
        protocol: "http", // optional; default "http"
        path: "/",        // optional; default "/"
      },
    ],
  },
}
```

### Interpolation in `args`/`env`

`args` elements and `env` values support `${...}` interpolation:

- `${config.<path>}` reads from the component’s config object.
- `${slots.<slot>.<path>}` reads from the bound value of a slot.

The `<path>` portion is dot-separated (for nested objects). Examples:

- `${config.domain}`
- `${slots.llm.url}`

## `components` (child components)

`components` is a map from **instance name** to a component declaration.

Each child can be declared as:

- A manifest reference string:
  - `my_child: "https://registry.amber-protocol.org/some/component/v1"`
- Or a manifest reference in canonical form:
  - `my_child: { url: "...", digest: "..." }`
- Or an object with per-instance config:
  - `my_child: { manifest: "...", config: { /* ... */ } }`
  - `my_child: { manifest: { /* ... */ }, config: { /* ... */ } }`

Example:

```json5
components: {
  env: "https://registry.agentbeats.dev/envs/tau2/v2",
  evaluator: {
    manifest: "https://registry.agentbeats.dev/tau2-evaluator/v1.0.0",
    config: { domain: "airline", num_trials: 1, num_tasks: 4 },
  },
}
```

## `config_schema`

`config_schema` is a JSON Schema object describing the config values a parent may pass when instantiating this component under `components`.

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

## Capabilities: `slots`, `provides`, `exports`

Capabilities are named entries in `slots` and `provides`. The shared shape is:

- `kind`: one of `"mcp"`, `"llm"`, `"http"`, `"a2a"`
- `profile` (optional): a string qualifier (commonly used for `"mcp"`)

Example:

```json5
{ kind: "mcp", profile: "openenv" }
```

### `slots`

`slots` declares what this component needs. A slot is fulfilled by a `binding`.
If a slot is not exported, it must be bound by a `binding` targeting `self.<slot>`.

```json5
slots: {
  llm: { kind: "llm" },
  env: { kind: "mcp", profile: "openenv" },
}
```

### `provides`

`provides` declares what this component makes available. A provide can be:

- Backed by one of this component’s own `program.network.endpoints` (via `endpoint`), and/or
- A forwarded capability from another component (via `from` + `capability`).

```json5
provides: {
  api: { kind: "http", endpoint: "http" },

  // Forward the `llm` capability exported by the `router` child.
  llm: { kind: "llm", from: "router", capability: "llm" },
}
```

If a provide is not exported, it must be used by a `binding` with `from: "self.<provide>"`.

If `provides.<name>.endpoint` is set, it must match a declared `program.network.endpoints[].name`.

### `exports`

`exports` chooses which local capability names (from `slots` and/or `provides`) are visible to the parent of this component.

To export a child capability, first give it a local name in `provides` using `from`/`capability`, then export that local name.

## `bindings`

`bindings` wire a `to` slot to a `from` capability:

`(<to>.<slot>) <- (<from>.<capability>)`

Binding targets and sources are single-use: you cannot bind the same `(<to>.<slot>)` or `(<from>.<capability>)` more than once.

Bindings are **strong** by default: the binding must exist and be stable at component startup.

Set `weak: true` to make a binding **weak**: the binding does not need to exist or be stable at component startup, and the component must tolerate the bound capability being down. This is useful for cyclic component graphs and flaky remote components.

The binding is declared in the parent that is doing the wiring:

- The `to` component must declare the `slot` in its `slots`.
- The `from` component must export the `capability` (a name from its `exports`).
- Component refs are either `self` or a child instance (`#<name>`).

Bindings can be written in either canonical form:

```json5
{
  to: "#evaluator",
  slot: "llm",
  from: "#router",
  capability: "llm",
  // Optional; default false.
  weak: true,
}
```

…or dot-notation sugar:

```json5
{ to: "#evaluator.llm", from: "#router.llm", weak: true }
```

In dot form, `to` is `<component-ref>.<slot>` and `from` is `<component-ref>.<capability>`.

Child refs use `#<name>` where `<name>` is a key of `components`. `self` refers to the component described by the current manifest.

## Examples

### 1) Leaf component exporting an HTTP API

```json5
{
  manifest_version: "1.0.0",
  program: {
    image: "ghcr.io/acme/hello:v1",
    args: "--port 8080",
    network: { endpoints: [{ name: "http", port: 8080, path: "/" }] },
  },
  provides: {
    api: { kind: "http", endpoint: "http" },
  },
  exports: ["api"],
}
```

### 2) Component that uses config + a required slot

```json5
{
  manifest_version: "1.0.0",
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
}
```

### 3) Composite component (program + child) with wiring and forwarding

This component runs a router, instantiates a `wrapper` child, wires the wrapper’s slot to the router’s admin API, then exports the wrapper’s `llm` capability upward.

```json5
{
  manifest_version: "1.0.0",
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
    llm: { kind: "llm", from: "wrapper", capability: "llm" },
  },
  bindings: [
    { to: "#wrapper.admin_api", from: "self.admin_api" },
  ],
  exports: ["llm"],
}
```

### 4) Pass-through slot (composite requires something its child needs)

This component doesn’t provide an LLM itself, but declares an `llm` slot, exports it upward, and passes it down into a child.

```json5
{
  manifest_version: "1.0.0",
  components: {
    evaluator: "https://registry.agentbeats.dev/tau2-evaluator/v1.0.0",
  },
  slots: {
    llm: { kind: "llm" },
  },
  bindings: [
    { to: "#evaluator.llm", from: "self.llm" },
  ],
  exports: ["llm"],
}
```

### 5) Weak binding (optional / tolerates downtime)

This component wires a child slot to another child’s capability, but does not require it to be up at startup.

```json5
{
  manifest_version: "1.0.0",
  components: {
    consumer: "https://registry.amber-protocol.org/consumer/v1",
    provider: "https://registry.amber-protocol.org/provider/v1",
  },
  bindings: [
    { to: "#consumer.backend", from: "#provider.api", weak: true },
  ],
}
```
