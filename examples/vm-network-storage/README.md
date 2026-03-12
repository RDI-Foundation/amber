<!-- amber-docs
summary: boot three Ubuntu VMs, observe bound and unbound communication, and verify persistent storage across reruns and a structure-changing migration.
-->

# VM network and storage demo

This example shows how Amber's VM backend handles networking and storage in a small multi-VM
scenario. It is written for developers who are comfortable with VMs but still new to Amber.

It covers:

- how the root scenario owns shared inputs and durable resources
- how child manifests ask for what they need and expose what they offer
- how one VM can call another only when the parent wires that connection in
- why `amber run` and `amber proxy` are separate steps
- why mounted Amber storage survives both reruns and a graph change

The scenario has three VMs:

- `api`: a VM that mounts persistent storage at `/var/lib/app` and exports HTTP
- `bound`: a VM that receives an Amber HTTP slot bound to `api`
- `unbound`: a VM that guesses the same guest-visible URL shape as `bound`, but has no Amber
  binding and therefore cannot reach `api`

The `v2/` variant keeps the same root-owned storage resource but inserts a new `stack` component
between the root and the original VMs. This makes it possible to check what depends on resource
ownership and what depends on graph structure.

## Amber mental model for this example

- `slots` are named inputs that a component expects its parent to supply. In this example, `api`
  needs a storage slot and `bound` needs an HTTP slot.
- `provides` describes interfaces a component makes available from inside the manifest.
- `exports` chooses which of those interfaces are visible to the parent. The root scenario then
  exports them again so you can proxy them on the host.
- `bindings` are the parent-owned connections between those pieces. Here the root connects its
  `app_state` storage resource to `api`, and connects `api`'s HTTP interface to `bound`.
- `amber run` starts the compiled VM runtime and its private Amber network. It does not
  automatically publish anything on localhost.
- `amber proxy` is the host-side bridge. It takes selected scenario exports from the running system
  and exposes them on `127.0.0.1:...` so you can inspect them with normal tools like `curl`.

## Read this example in this order

1. `scenario.json5`
   This is the root graph. It owns the user-supplied `base_image` input, owns the durable storage
   resource, creates the three child components, and wires them together.
2. `api.json5`
   This is the reusable API VM. Focus first on `slots.state`, `program.vm.mounts`,
   `program.vm.network`, `provides`, and `exports`.
3. `probes/bound.json5` and `probes/unbound.json5`
   These show the VM declarations for the two probes. The important difference is that
   `bound.json5` declares an `api` slot and `unbound.json5` does not.
4. `probes/bound.cloud-init.yaml` and `probes/unbound.cloud-init.yaml`
   This is where the network lesson becomes concrete inside the guest. In the bound probe, Amber
   fills in `${slots.api.url}` before boot, so the guest gets a real URL for the API. In the
   unbound probe, the script hardcodes a guessed backend-specific URL instead of receiving one from
   Amber.
5. `v2/scenario.json5` and `v2/stack.json5`
   These show the migration. The storage resource still lives at the root, but the direct
   parent-child structure changes.

The `*.cloud-init.yaml` files matter in this example. They are guest bootstrap files, and they
also show how Amber values become usable inside a VM.

## Layout

- `scenario.json5`: v1 root graph
- `api.json5`: v1 API VM manifest
- `api.cloud-init.yaml`: v1 guest bootstrap for `api`
- `probes/bound.json5`: bound probe VM manifest
- `probes/bound.cloud-init.yaml`: guest bootstrap for `bound`
- `probes/unbound.json5`: unbound probe VM manifest
- `probes/unbound.cloud-init.yaml`: guest bootstrap for `unbound`
- `v2/scenario.json5`: v2 root graph
- `v2/stack.json5`: migration-only wrapper component
- `v2/api.json5`: migrated API VM manifest
- `v2/api.cloud-init.yaml`: v2 guest bootstrap for `api`

## Prereqs

- QEMU installed on the host:
  - macOS: `qemu`, plus AArch64 firmware such as Homebrew's `edk2-aarch64-code.fd`
  - Linux: `qemu-system-*`, `qemu-img`, and `xorriso`; AArch64 hosts also need AArch64 firmware
- A matching Ubuntu 24.04 minimal cloud image available locally and pointed to by
  `AMBER_CONFIG_BASE_IMAGE`:

```sh
# Apple Silicon / AArch64 hosts:
export AMBER_CONFIG_BASE_IMAGE="$PWD/ubuntu-24.04-minimal-cloudimg-arm64.img"

# x86_64 Linux hosts:
export AMBER_CONFIG_BASE_IMAGE="$PWD/ubuntu-24.04-minimal-cloudimg-amd64.img"
```

- Amber runtime binaries built from this checkout:

```sh
cargo build -q -p amber-cli -p amber-router
export AMBER_RUNTIME_BIN_DIR="$PWD/target/debug"
```

If the host does not expose `/dev/kvm`, force software emulation:

```sh
export AMBER_VM_FORCE_TCG=1
```

## Walk through v1

Compile the v1 scenario into a VM artifact directory:

```sh
OUT=/tmp/amber-vm-network-storage
STATE=/tmp/amber-vm-network-storage-state
rm -rf "$OUT" "$STATE"
amber compile --vm "$OUT" examples/vm-network-storage/scenario.json5
```

Start the private Amber VM runtime:

```sh
amber run --storage-root "$STATE" "$OUT"
```

In another terminal, bridge the exported HTTP endpoints onto localhost:

```sh
amber proxy "$OUT" \
  --export api=127.0.0.1:18080 \
  --export bound=127.0.0.1:18081 \
  --export unbound=127.0.0.1:18082
```

The first boot can take a little while because cloud-init has to write the service files and start
the Python servers inside each guest. Wait until the API responds before checking the rest:

```sh
until curl -fsS http://127.0.0.1:18080/version; do sleep 2; done; echo
```

Then inspect the three exports:

```sh
curl -fsS http://127.0.0.1:18080/version; echo
curl -fsS http://127.0.0.1:18080/storage; echo
curl -fsS http://127.0.0.1:18081/reachability; echo
curl -fsS http://127.0.0.1:18082/reachability; echo
curl -fsS http://127.0.0.1:18081/ephemeral; echo
curl -fsS http://127.0.0.1:18082/ephemeral; echo
```

Expected results:

- `api/version` returns `v1`
- `api/storage` returns the seeded durable state from the mounted storage disk
- `bound/reachability` returns `reachable:api`
- `unbound/reachability` returns `blocked:...`
- both probes report `api_visible=false` for `/ephemeral`, showing that guest-local files are not
  shared just because the VMs can communicate

Two details matter here:

- both probes set `program.vm.network.egress` to `"none"`, so this is not a story about general VM
  egress being open
- `bound` can still reach `api` because the parent gave it a specific Amber HTTP capability;
  `unbound` was not given that capability, so guessing an address does not help

The guessed address in `unbound.cloud-init.yaml` is intentionally a backend-specific implementation
detail, not something applications should depend on. It is only there to show that guessing a VM
network address is not the same thing as Amber granting access.

Write one durable value and one run-local value:

```sh
curl -fsS -X PUT --data-binary 'remembered across runs' http://127.0.0.1:18080/storage; echo
curl -fsS -X PUT --data-binary 'discarded after teardown' http://127.0.0.1:18080/ephemeral; echo
```

Then stop `amber proxy`, and stop `amber run`.

## Verify persistence across a rerun

Restart the same compiled output with the same storage root:

```sh
amber run --storage-root "$STATE" "$OUT"
amber proxy "$OUT" \
  --export api=127.0.0.1:18080 \
  --export bound=127.0.0.1:18081 \
  --export unbound=127.0.0.1:18082
```

Check the durable and ephemeral paths again:

```sh
curl -fsS http://127.0.0.1:18080/storage; echo
curl -fsS http://127.0.0.1:18080/ephemeral; echo
```

Expected results:

- `/storage` still returns `remembered across runs`
- `/ephemeral` is back at the boot default for this run

This shows the storage behavior directly: the mounted Amber storage resource persists, and the VM's
own local filesystem state does not.

## Verify persistence across a graph change

Now switch to the v2 root graph:

```sh
amber compile --vm "$OUT" examples/vm-network-storage/v2/scenario.json5
amber run --storage-root "$STATE" "$OUT"
amber proxy "$OUT" \
  --export api=127.0.0.1:18080 \
  --export bound=127.0.0.1:18081 \
  --export unbound=127.0.0.1:18082
```

What changed in v2:

- the root no longer points directly at `api`, `bound`, and `unbound`
- instead, the root instantiates `stack`
- `stack` owns the child VMs and re-exports their HTTP interfaces
- the durable storage resource is still owned by the root and still bound into the API path

Run the same checks:

```sh
curl -fsS http://127.0.0.1:18080/version; echo
curl -fsS http://127.0.0.1:18080/storage; echo
curl -fsS http://127.0.0.1:18081/reachability; echo
curl -fsS http://127.0.0.1:18082/reachability; echo
```

Expected results:

- `api/version` now returns `v2`
- `api/storage` still returns `remembered across runs`
- network behavior is unchanged: `bound` reaches `api`, `unbound` stays blocked

This shows the migration behavior directly: the storage survives because the resource identity
stayed rooted in the same place, even though the component graph above the API changed.
