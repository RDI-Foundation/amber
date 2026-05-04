# Governance Redaction

A governance policy that injects a redaction interposer on every `a2a` edge in the governed realm.

The root scenario has two secret-like config inputs, `launch_code` and `api_key`. The `caller`
uses them directly, and the governance `use` config passes them to the policy as a symbolic
`redaction_terms` list using `$${config...}`. The policy forwards those refs into the generated
interposer config, and the interposer resolves the concrete values later at normal runtime.

The policy lives in [policy.py](policy.py), with reusable request/response helpers in
[policy_lib.py](policy_lib.py) and the generated interposer builder in
[redactor_interposer.py](redactor_interposer.py).

At runtime, `caller` sends both secret values to `responder` over `a2a`, `responder` echoes the
payload back, and the policy injects a redaction interposer in between. The `status` export from
`caller` shows both the original payload it sent and the redacted payload it received back.

## Mechanics

The policy runs while Amber applies governance and returns an interposition plan for each governed
`a2a` edge. The generated interposer is then launched as part of the normal scenario runtime.

The scenario uses two interpolation forms intentionally:

- `${config...}` resolves config in the component that receives it, as in `caller`.
- `$${config...}` preserves a symbolic config reference while passing policy config into the
  generated interposer.

The redactor is intentionally simple: it decodes UTF-8 request and response bodies, replaces each
configured term with `[REDACTED]`, and forwards the result. It demonstrates governance-driven
interposition, not schema-aware secret detection.

## Try it

```sh
amber run examples/governance-redaction/scenario.json5
# or: AMBER_CONFIG_LAUNCH_CODE=alpha AMBER_CONFIG_API_KEY=beta amber run ...
```

Fetch the `status` export URL Amber prints. With the default config, the response should include:

```json
{
  "sent_payload": {
    "message": "my launch code is swordfish",
    "api_key": "hunter2"
  },
  "received_payload": {
    "message": "my launch code is [REDACTED]",
    "api_key": "[REDACTED]"
  },
  "error": null
}
```
