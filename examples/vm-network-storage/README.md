<!-- amber-docs
summary: Boot three Ubuntu VMs, prove bound and unbound network behavior, and verify persistent storage across reruns and a structure-changing migration.
-->

# VM network and storage demo

This example exercises the VM backend end to end:

- `api` is a VM with a bound storage slot mounted at `/var/lib/app`
- `bound` is a VM that can reach `api` through an Amber binding
- `unbound` is a VM that guesses the same guest-visible route URL but cannot reach `api`

The migration variant under `v2/` preserves the same root-owned storage resource while inserting
an extra `stack` component. That lets you verify storage reuse across a structure-changing
migration.

Layout:

- `scenario.json5`: default scenario
- `api.json5`: default API VM
- `probes/`: bound and unbound probe VMs
- `v2/scenario.json5`: migration scenario
- `v2/api.json5`: migrated API VM
- `v2/stack.json5`: migration-only wrapper component

## Prereqs

- QEMU installed on the host:
  - macOS: `qemu`, plus AArch64 firmware such as Homebrew's `edk2-aarch64-code.fd`
  - Linux: `qemu-system-*`, `qemu-img`, and `xorriso`; AArch64 hosts also need AArch64 firmware
- A host-arch Ubuntu minimal cloud image available locally:

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

## Run v1

Compile the first scenario:

```sh
OUT=/tmp/amber-vm-network-storage
STATE=/tmp/amber-vm-network-storage-state
rm -rf "$OUT" "$STATE"
amber compile --vm "$OUT" examples/vm-network-storage/scenario.json5
```

Start the VMs:

```sh
amber run --storage-root "$STATE" "$OUT"
```

In another terminal, expose the scenario exports:

```sh
amber proxy "$OUT" \
  --export api=127.0.0.1:18080 \
  --export bound=127.0.0.1:18081 \
  --export unbound=127.0.0.1:18082
```

Once boot completes, these checks should pass:

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
- `bound/reachability` returns `reachable:api`
- `unbound/reachability` returns `blocked:...`
- both probe VMs report `api_visible=false` for `/ephemeral`

Write durable and ephemeral state:

```sh
curl -fsS -X PUT --data-binary 'remembered across runs' http://127.0.0.1:18080/storage; echo
curl -fsS -X PUT --data-binary 'discarded after teardown' http://127.0.0.1:18080/ephemeral; echo
```

Stop `amber proxy`, then stop `amber run`.

## Verify reuse on rerun

Restart the same compiled output with the same storage root:

```sh
amber run --storage-root "$STATE" "$OUT"
amber proxy "$OUT" \
  --export api=127.0.0.1:18080 \
  --export bound=127.0.0.1:18081 \
  --export unbound=127.0.0.1:18082
```

Now:

```sh
curl -fsS http://127.0.0.1:18080/storage; echo
curl -fsS http://127.0.0.1:18080/ephemeral; echo
```

Expected results:

- `/storage` still returns `remembered across runs`
- `/ephemeral` is reset to the boot default for the new run

## Verify migration reuse

Recompile the migrated structure into the same output dir and reuse the same storage root:

```sh
amber compile --vm "$OUT" examples/vm-network-storage/v2/scenario.json5
amber run --storage-root "$STATE" "$OUT"
amber proxy "$OUT" \
  --export api=127.0.0.1:18080 \
  --export bound=127.0.0.1:18081 \
  --export unbound=127.0.0.1:18082
```

Final checks:

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

## Automated smoke

Run the live smoke test with:

```sh
cargo test -p amber-cli --test vm_smoke -- --ignored --nocapture
```
