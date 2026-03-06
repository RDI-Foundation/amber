<!-- amber-docs
summary: Mount config and secrets into container files with `program.mounts`.
-->

# Mounts

This example shows how `program.mounts` materializes config and secret values as files inside a
container.

## Files

- `scenario.json5`: single-component manifest with structured config, a secret, and three file
  mounts under `/run`.
