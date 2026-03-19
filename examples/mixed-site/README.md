<!-- amber-docs
summary: Run one scenario across a direct process, a Compose container, and a VM with a placement file, inspect the startup waves, and verify one host-visible request path that crosses every site.
-->

# Mixed-site execution

This example is the smallest useful mixed-site walkthrough in the repo.

It shows three things at once:

- the manifest still describes one scenario graph rather than three separate deployments
- the placement file decides where each runnable component goes
- `amber run` starts the sites in dependency waves and then stitches them into one routed system

The graph is deliberately simple:

- `console`: a direct/native host process
- `queue`: a Docker Compose container
- `vault`: a VM

`console` calls `queue`, and `queue` calls `vault`, so the startup waves should be:

```json
[["vm_local"], ["compose_local"], ["direct_local"]]
```

That means the host-visible request you make to `console` proves the whole direct -> Compose -> VM
path, without forcing you to proxy three different exports just to see the example work.

## Files

- `scenario.json5`: the root graph
- `local-placement.json5`: the explicit site assignment
- `console.json5`: the direct/native component
- `console.py`: the direct/native HTTP program
- `queue.json5`: the Compose component
- `queue.py`: the Compose HTTP program
- `vault.json5`: the VM component
- `vault.cloud-init.yaml`: the VM guest bootstrap

## Prereqs

- `amber` on `PATH`
- `python3` on the host
- Docker Compose v2
- a local sandbox backend for direct execution:
  - Linux: `bwrap` and `slirp4netns`
  - macOS: `/usr/bin/sandbox-exec`
- QEMU for the VM site:
  - macOS: `qemu`, plus AArch64 firmware such as Homebrew's `edk2-aarch64-code.fd`
  - Linux: `qemu-system-*`, `qemu-img`, and `xorriso`
- a matching Ubuntu 24.04 minimal cloud image available locally and exported through
  `AMBER_CONFIG_BASE_IMAGE`

Examples:

```sh
# Apple Silicon / AArch64 hosts:
export AMBER_CONFIG_BASE_IMAGE="$PWD/ubuntu-24.04-minimal-cloudimg-arm64.img"

# Typical x86_64 Linux hosts:
export AMBER_CONFIG_BASE_IMAGE="$PWD/ubuntu-24.04-minimal-cloudimg-amd64.img"
```

If your Linux host does not expose `/dev/kvm`, force software emulation:

```sh
export AMBER_VM_FORCE_TCG=1
```

## 1) Inspect the run plan

Compile the scenario into a mixed-site run plan first. This is the easiest way to see what Amber
will actually launch before you start anything heavy.

```sh
OUT=/tmp/amber-mixed-site
STATE=/tmp/amber-mixed-site-state
rm -rf "$OUT" "$STATE"
mkdir -p "$OUT"

amber compile examples/mixed-site/scenario.json5 \
  --placement examples/mixed-site/local-placement.json5 \
  --run-plan "$OUT/run-plan.json"

jq '.startup_waves' "$OUT/run-plan.json"
```

Expected output:

```json
[["vm_local"], ["compose_local"], ["direct_local"]]
```

That output is the whole point of the example: the VM must exist before the container can route to
it, and the container must exist before the direct host process can route to it.

## 2) Start the mixed-site run

Run the manifest directly, use the same placement file, and keep the state in one explicit
directory so the follow-up commands are easy to reason about:

```sh
RUN_ID="$(
  amber run examples/mixed-site/scenario.json5 \
    --placement examples/mixed-site/local-placement.json5 \
    --storage-root "$STATE" \
    --observability local \
    --detach |
    sed -n 's/^run_id=//p'
)"

echo "$RUN_ID"
```

Amber stores everything for that run under:

```sh
echo "$STATE/runs/$RUN_ID"
```

## 3) Proxy the direct export

The outside world connects to one site at a time. For this example, expose only the direct
component. Its `/chain` endpoint is the user-friendly proof that the request crosses all three
sites.

```sh
amber proxy "$STATE/runs/$RUN_ID/sites/direct_local/artifact" \
  --export console_http=127.0.0.1:18080
```

In another terminal:

```sh
curl -fsS http://127.0.0.1:18080/id | jq .
curl -fsS http://127.0.0.1:18080/chain | jq .
```

Expected shape:

```json
{
  "site": "direct",
  "queue": {
    "site": "compose",
    "vault": "vm-vault"
  }
}
```

That one response confirms:

- the host reached the direct site through `amber proxy`
- the direct site reached the Compose site through Amber routing
- the Compose site reached the VM site through Amber routing

## 4) Inspect local observability

This example uses `--observability local`, which writes the raw OTLP HTTP requests Amber emitted
during the run to a simple local log:

```sh
sed -n '1,40p' "$STATE/runs/$RUN_ID/observability/requests.log"
```

You should see `/v1/logs` and `/v1/traces` entries after the system starts and after you hit
`/chain`.

## 5) Stop the run

```sh
amber stop "$RUN_ID" --storage-root "$STATE"
```

That tears down the direct process, the Compose site, and the VM site, and it also stops the local
observability sink for this run.
