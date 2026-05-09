# Redaction Overlay

A scenario overlay that injects a redaction interposer on every `a2a` edge in its scope.

The root scenario has two secret-like config inputs, `launch_code` and `api_key`. The `caller`
uses them directly, and the `use` config passes them to the overlay program as a symbolic
`redaction_terms` list using `$${config...}`. The overlay forwards those refs into the generated
interposer config, and the interposer resolves the concrete values later at normal runtime.

The overlay program lives in [overlay.py](overlay.py), with reusable request/response helpers in
[overlay_lib.py](overlay_lib.py) and the generated interposer builder in
[redactor_interposer.py](redactor_interposer.py).

At runtime, `caller` sends both secret values to `responder` over `a2a`, `responder` echoes the
payload back, and the overlay injects a redaction interposer in between. The `status` export from
`caller` shows both the original payload it sent and the redacted payload it received back.

## Mechanics

The overlay program runs while Amber applies overlays and returns an interposition plan for each
in-scope `a2a` edge. The generated interposer is then launched as part of the normal scenario
runtime.

The scenario uses two interpolation forms intentionally:

- `${config...}` resolves config in the component that receives it, as in `caller`.
- `$${config...}` preserves a symbolic config reference while passing overlay config into the
  generated interposer.

The redactor is intentionally simple: it decodes UTF-8 request and response bodies, replaces each
configured term with `[REDACTED]`, and forwards the result. It demonstrates overlay-driven
interposition, not schema-aware secret detection.

## Try it

```sh
amber run examples/overlay-redaction/scenario.json5
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
