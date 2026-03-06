<!-- amber-docs
summary: Re-export a child's HTTP capability through an intermediate parent manifest.
-->

# Reexport

This is the smallest multi-file example: the root manifest re-exports a child's HTTP capability
through an intermediate parent manifest.

## Files

- `scenario.json`: root manifest that points at `parent.json`.
- `parent.json`: intermediate manifest that points at `child.json` and re-exports its capability.
- `child.json`: leaf component that serves HTTP from a BusyBox container.
