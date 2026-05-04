# Governance

Governance is an experimental compiler feature for rewriting the linked scenario with
policy-generated interposers.

Enable it with:

```json5
experimental_features: ["governance"]
```

This document defines the policy authoring contract:

- how a manifest declares policies
- what a policy process receives
- what it must return
- what validation the compiler applies

For field syntax, see [manifest/README.md](./manifest/README.md). For a complete working
example, see [../examples/governance-redaction/README.md](../examples/governance-redaction/README.md).

## The Model

A governed manifest can declare:

- `use`: governance-only helper components
- `policies`: ordered refs in `#use_name.export` form

Example:

```json5
{
  experimental_features: ["governance"],
  use: {
    policy: { manifest: "./policy.json5" },
  },
  policies: ["#policy.apply"],
}
```

Rules:

- `use` entries are resolved and validated like normal manifests
- `use` entries are kept out of the main compiled scenario
- only `use` entries referenced by `policies` are materialized into the synthetic governance
  artifact
- a `use` subtree must be self-contained:
  - no required root slots
  - no nested `use`
  - no nested `policies`
- each policy ref must resolve to an exported `http` provide with profile `policy`

## When Governance Runs

At compile time, Amber:

1. links the main scenario
2. builds a synthetic governance artifact from the referenced `use` entries
3. runs each declared policy on its governed realm
4. validates the returned policy output
5. rewrites the main scenario by inserting generated interposers

Each component that declares `policies` defines one governed realm rooted at that component's
moniker.

Governance-enabled compilation is supported through the CLI runtime path.

## Writing a Policy Manifest

A policy is just a component that exports an HTTP capability with profile `policy`.

Minimal example:

```json5
{
  program: {
    path: "/usr/bin/env",
    args: ["python3", { file: "./policy.py" }],
    network: {
      endpoints: [{ name: "api", port: 8120 }],
    },
  },

  provides: {
    apply: { kind: "http", profile: "policy", endpoint: "api" },
  },

  exports: {
    apply: "apply",
  },
}
```

Your program must:

- accept an HTTP `POST`
- read a JSON request body
- return a JSON response body

## What a Policy Receives

Policies receive:

```json
{
  "scope": {
    "components": [ ... ],
    "bindings": [ ... ],
    "imports": [ ... ],
    "exports": [ ... ]
  }
}
```

The `scope` field describes the governed realm.

### `scope.components`

All components inside the governed realm.

These are serialized `amber_scenario::Component` values from the linked scenario, so the policy
sees lowered program/config data, not the raw authored manifest text.

Key fields on each component:

- `parent`
- `moniker`
- `digest`
- `config`
- `config_schema`
- `program`
- `slots`
- `provides`
- `resources`
- `metadata`
- `children`

### `scope.bindings`

Edges whose source and target are both inside the governed realm.

Each entry has:

- `id`: `AttachmentId`
- `from`: source (`component`, `resource`, or `framework`)
- `to`: target slot
- `capability`: resolved capability carried by the edge

### `scope.imports`

Edges entering the governed realm from outside it.

Each entry has:

- `id`: `AttachmentId`
- `to`: in-realm target slot
- `capability`

### `scope.exports`

Edges leaving the governed realm.

This includes:

- bindings whose source is in the governed realm and target is outside it
- scenario exports whose source is in the governed realm

Each entry has:

- `id`: `AttachmentId`
- `from`: in-realm source
- `capability`

## What a Policy Must Return

Policies return:

```json
{
  "interpositions": [
    {
      "interposer": { ... },
      "attachments": [
        {
          "target": 0,
          "interposer_slot": "in",
          "interposer_provide": "out"
        }
      ]
    }
  ]
}
```

## Interposer Shape

Each `Interposition` contains:

- `interposer`: the generated component to insert
- `attachments`: the edges it should attach to

An interposer may declare:

- `program`
- `config`
- `config_schema`
- `slots`
- `provides`
- `resources`
- `metadata`

## How Rewriting Works

For each attachment:

- `target` chooses one edge from the request
- `interposer_slot` is where that edge is routed into the interposer
- `interposer_provide` is the edge that continues after the interposer

Generated interposers are inserted under the governed realm root.

If multiple policies or realms attach interposers to the same target, Amber chains them in a
deterministic order.

## Validation Rules

Amber validates policy output before rewriting anything.

Attachment checks:

- an interposition must attach to at least one target
- a target may only appear once within one interposition
- an interposer slot may only be attached once within one interposition
- every attachment target must exist in the request
- `interposer_slot` must exist in `interposer.slots`
- `interposer_provide` must exist in `interposer.provides`
- every non-optional interposer slot must be attached
- the attachment target capability must exactly match:
  - the interposer slot capability
  - the interposer provide capability

Interposer checks:

- `program` is required
- if `config` is present, `config_schema` is also required
- `config_schema` must be valid
- the lowered program must pass the same mount/program validation as ordinary linked components
- generated interposers may not rely on experimental features

## Config Interpolation in Governance `use` Config

Governance `use` config is composed against the governed realm's config template at link time.

### `${config.x}`

Normal config interpolation composes immediately against the governed realm root template.

If the composed value still depends on scenario-root config, the synthetic governance root schema
mirrors those root paths so the policy process receives values through normal `AMBER_CONFIG_*`
inputs.

### `$${config.x}`

Symbolic interpolation preserves the config reference instead of materializing the value during
governance execution.

This is what you use when the policy needs to thread a root config reference into a generated
interposer config. The policy sees the symbolic reference and can copy the literal
`${config.x}` template into the returned interposer config.

That is the mechanism used when an interposer needs a secret-backed runtime value without exposing
the concrete secret to the governance process itself.

## Interposer Provenance

- Policy-generated interposers do not yet carry distinct synthetic provenance/identity.
- They currently reuse the root scenario manifest digest as their component digest.
- They do not receive their own provenance / `resolved_url` entry.
- Because of that, downstream manifest attribution/reporting for generated interposers is
  imperfect, and relative program/file path resolution for generated interposers remains follow-up
  work.
