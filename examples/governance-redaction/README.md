# Governance Redaction

A governance policy that injects a redactor interposer on every `a2a` edge in scope.

The root scenario has a `secret` config input (default: `"swordfish"`) that flows into both the
`caller` component and the generated interposer config via `${config.secret}`. The policy itself
does not need the concrete secret at governance-execution time: it receives a symbolic
`policies[].args` template, then copies that template into the generated interposer config. The
compiled scenario therefore retains `${config.secret}` rather than the secret value itself.

At runtime the policy receives `PolicyRequest`, selects every `a2a` edge, and emits a generated
interposer component (no authored manifest) that replaces the secret string with `[REDACTED]` in both
directions.

## Try it

```sh
amber run examples/governance-redaction/scenario.json5
# or: AMBER_CONFIG_SECRET=hunter2 amber run ...
```

Fetch the `status` export URL Amber prints — `sent_payload` contains the original secret,
`received_payload` shows it redacted.
