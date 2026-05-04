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

## Try it

```sh
amber run examples/governance-redaction/scenario.json5
# or: AMBER_CONFIG_LAUNCH_CODE=alpha AMBER_CONFIG_API_KEY=beta amber run ...
```

Fetch the `status` export URL Amber prints. `sent_payload` contains the original secret values;
`received_payload` shows the echoed response after redaction.
