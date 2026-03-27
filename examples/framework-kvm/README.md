<!-- amber-docs
summary: Use experimental `framework.kvm` to access /dev/kvm in Docker Compose.
-->

# framework.kvm Example (Docker Compose)

This example shows how to use the experimental `framework.kvm` capability to give a container
access to the host's KVM device for hardware-accelerated virtualization (QEMU/KVM).

The `checker` component mounts `/dev/kvm` via `framework.kvm` and runs `qemu-system-x86_64` with
`-accel kvm` to verify KVM acceleration works.

## Files

- `scenario.json5`: root manifest enabling `experimental_features: ["kvm"]`
- `checker.json5`: component that mounts `framework.kvm` and runs a QEMU smoke test
- `Dockerfile`: builds the checker image with `qemu-system-x86` pre-installed

## Requirements

The host must have `/dev/kvm` available. On Linux:

```sh
ls -la /dev/kvm
```

## Run

Build the checker image:

```sh
docker build -t amber-example-kvm-checker examples/framework-kvm/
```

Compile:

```sh
OUT=examples/framework-kvm/compose-out
amber compile examples/framework-kvm/scenario.json5 --docker-compose "$OUT"
```

Run, passing `AMBER_KVM_GID` (the GID of `/dev/kvm` on your host):

```sh
AMBER_KVM_GID=$(stat -c %g /dev/kvm) docker compose -f "$OUT/compose.yaml" up
```

QEMU will boot, fail to find a bootable disk, and exit. SeaBIOS output in the logs confirms KVM
acceleration was used. The container exits 0 on success.

Tear down:

```sh
docker compose -f "$OUT/compose.yaml" down -v
```
