# amber-json5

Thin wrapper around `json5` that adds diagnostics with source spans for user-facing errors.

## What it provides
- `parse<T>`: deserializes JSON5 and returns `DiagnosticError` with span and path info.
- `spans`: helpers for mapping JSON5 structure to spans (used by `amber-manifest`).
- Re-exports of `json5` serializer/deserializer types for direct use.

## Intended use
This crate exists to keep parse/deserialize errors precise and consistent across the project.
