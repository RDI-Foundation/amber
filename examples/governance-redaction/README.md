# Governance Redaction

A governance policy that injects a redactor interposer on every `a2a` edge in scope.

The root scenario has a `secret` config input (default: `"swordfish"`) that flows into both the
`caller` component and the `redaction` policy via `${config.secret}`. Because the policy is a `use`
entry, the compiler threads this dependency into the governance root schema — a single
`AMBER_CONFIG_SECRET` env var satisfies both.

At runtime the policy receives `PolicyInput`, selects every `a2a` edge, and emits a generated
interposer component (no authored manifest) that replaces the secret string with `[REDACTED]` in
both directions.

## Try it

```sh
amber run examples/governance-redaction/scenario.json5
# or: AMBER_CONFIG_SECRET=hunter2 amber run ...
```

Fetch the `status` export URL Amber prints — `sent_payload` contains the original secret,
`received_payload` shows it redacted.
