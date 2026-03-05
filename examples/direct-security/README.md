<!-- amber-docs
summary: Demonstrate the direct native runner and its sandboxing security model.
-->

# Direct backend security demo (TCP-only)

This example is designed to demonstrate Amber’s capability model in **direct** mode:

- A component can only talk to other components if it is given a **slot** and that slot is **bound**
  to an exported capability.
- Capabilities that are **not exported** at the scenario boundary are not reachable from the host.
- On **Linux**, component program ports are not reachable from the host at all. The only way in is
  `amber proxy` exporting an explicit capability.

On macOS, the direct backend is best-effort. The “no direct host access to component ports” guarantee
is Linux-only today.

## Prereqs

- Linux: `bwrap` (bubblewrap), `nsenter` (util-linux), `slirp4netns`
- macOS: `/usr/bin/sandbox-exec`

## Run

In one terminal:

```sh
cd examples/direct-security
OUT=/tmp/amber-direct-security
rm -r "$OUT" 2>/dev/null || true
amber compile --direct "$OUT" scenario.json5
amber run "$OUT"
```

In another terminal, expose the scenario exports:

```sh
amber proxy "$OUT" \
  --export allowed=127.0.0.1:18080 \
  --export denied=127.0.0.1:18081
```

Now:

```sh
curl -sS http://127.0.0.1:18080
curl -sS http://127.0.0.1:18081
```

Expected behavior:

- `allowed` returns the secret (it has a `secret` slot bound to `#secret.secret`).
- `denied` cannot reach the secret even though it guesses the TCP port (Linux: blocked by netns
  isolation; macOS: may succeed due to weaker isolation).

## Security checks

1. Secret is not exportable from the host.

The secret component exports `secret` to its parent (so other components can bind to it), but the
scenario does not export it to the host. This should fail:

```sh
amber proxy "$OUT" --export secret=127.0.0.1:18082
```

2. Linux only: host cannot connect directly to component program ports.

These ports are the programs’ loopback listeners inside their sandboxes:

```sh
curl -v http://127.0.0.1:8101
curl -v http://127.0.0.1:8102
curl -v http://127.0.0.1:8103
```

On Linux, they should fail. The only working host entrypoint is through `amber proxy` exports.
