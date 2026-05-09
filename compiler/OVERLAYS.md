# Scenario overlays

A scenario overlay is an interposition layer produced by helper components at compile time. Helper
components receive a scoped view of the scenario graph and return plans for inserting interposers.
Amber validates, orders, and applies those plans to the base scenario.

Overlays are useful for adding cross-cutting concerns across selected edges in a scope, including
redaction, filtering, observability, threat monitoring, compromised-component containment, and
similar controls.

This document defines the overlay authoring contract:

- how a manifest declares overlays
- what an overlay helper component receives
- what it must return
- what validation the compiler applies

For field syntax, see [manifest/README.md](./manifest/README.md). For a complete working example,
see [../examples/overlay-redaction/README.md](../examples/overlay-redaction/README.md).

## The Model

A manifest that declares overlays uses:

- `use`: helper components that export overlay capabilities
- `overlays`: ordered refs to those capabilities in `#use_name.export` form

Example:

```json5
{
  manifest_version: "0.4.0",
  use: {
    overlay: { manifest: "./overlay.json5" },
  },
  overlays: ["#overlay.apply"],
}
```

## When Overlays Run

At compile time, Amber:

1. links the main scenario
2. builds a helper scenario from the referenced `use` entries
3. runs each declared overlay on its scope
4. validates the returned interposition plan
5. rewrites the main scenario by inserting generated interposers

The helper scenario contains the helper components needed to apply overlays. It is separate from the
main scenario: helper components run during compilation and are not launched as part of the final
scenario. Only interposers described by returned plans are added to the final scenario.

During CLI compilation, Amber runs the helper scenario with the same local run-plan
machinery used by `amber run`. `amber check` stays static by default and does not apply overlays;
use `amber check --apply-overlays` to apply overlays and validate the rewritten graph without
emitting artifacts.

## Rules

- `use` entries are resolved and validated like normal manifests
- `use` entries are kept out of the main compiled scenario
- only `use` entries referenced by `overlays` are included in the helper scenario
- a `use` subtree must be self-contained:
  - no required root slots
  - no nested `use`
  - no nested `overlays`
- each overlay ref must resolve to an exported `http` provide with profile `overlay`

## Writing an Overlay Manifest

An overlay helper component exports an HTTP capability with profile `overlay`.

Minimal example:

```json5
{
  manifest_version: "0.4.0",
  program: {
    path: "/usr/bin/env",
    args: ["python3", { file: "./overlay.py" }],
    network: {
      endpoints: [{ name: "api", port: 8120 }],
    },
  },

  provides: {
    apply: { kind: "http", profile: "overlay", endpoint: "api" },
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

## What an Overlay Receives

Overlay programs receive:

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

The `scope` field describes the overlay scope.

### `scope.components`

All components inside the overlay scope.

These are serialized `amber_scenario::Component` values from the linked scenario, so the overlay
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

Edges whose source and target are both inside the overlay scope.

Each entry has:

- `id`: `AttachmentId`
- `from`: source (`component`, `resource`, or `framework`)
- `to`: target slot
- `capability`: resolved capability carried by the edge

### `scope.imports`

Edges entering the overlay scope from outside it.

Each entry has:

- `id`: `AttachmentId`
- `to`: in-scope target slot
- `capability`

### `scope.exports`

Edges leaving the overlay scope.

This includes:

- bindings whose source is in the overlay scope and target is outside it
- scenario exports whose source is in the overlay scope

Each entry has:

- `id`: `AttachmentId`
- `from`: in-scope source
- `capability`

## What an Overlay Must Return

Overlay programs return an interposition plan:

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

Generated interposers are inserted under the overlay scope root.

If multiple overlays or scopes attach interposers to the same target, Amber chains them in a
deterministic order.

## Validation Rules

Amber validates the interposition plan before rewriting anything.

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
- storage targets cannot be interposed; storage mounts must remain bound directly from storage
  resources

Interposer checks:

- `program` is required
- if `config` is present, `config_schema` is also required
- `config_schema` must be valid
- the lowered program must pass the same mount/program validation as ordinary linked components
- generated interposers may not rely on experimental features

## Config Interpolation in Overlay `use` Config

Overlay `use` config is composed against the overlay scope's config template at link time.

### `${config.x}`

Normal config interpolation composes immediately against the overlay scope root template.

If the composed value still depends on scenario-root config, the helper scenario's root schema
mirrors those root paths so the overlay program receives values through normal `AMBER_CONFIG_*`
inputs.

### `$${config.x}`

Symbolic interpolation preserves the config reference instead of materializing the value during
overlay execution.

This is what you use when the overlay needs to thread a root config reference into a generated
interposer config. The overlay sees the symbolic reference and can copy the literal `${config.x}`
template into the returned interposer config.

That is the mechanism used when an interposer needs a secret-backed runtime value without exposing
the concrete secret to the overlay program itself.

## Interposer Provenance

- Overlay-generated interposers do not yet carry distinct synthetic provenance/identity.
- They currently reuse the root scenario manifest digest as their component digest.
- They do not receive their own provenance / `resolved_url` entry.
- Because of that, downstream manifest attribution/reporting for generated interposers is
  imperfect, and relative program/file path resolution for generated interposers remains follow-up
  work.
