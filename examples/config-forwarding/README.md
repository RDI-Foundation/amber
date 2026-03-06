<!-- amber-docs
summary: Forward root config into a child component.
-->

# Config forwarding

This example forwards root config into a child component and shows how parent-provided config
values become concrete component config fields.

## Files

- `scenario.json5`: root manifest with a config schema and a child component instance.
- `api-client.json5`: child manifest that requires `api_key` and `system_prompt`.
