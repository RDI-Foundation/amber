# Amber

Amber is a compiler for shareable AI agent components. You write component manifests
that describe programs, capabilities, and wiring. Amber resolves and validates the manifest
graph, then emits runnable, reproducible artifacts you can execute or inspect.

Amber is useful for benchmarking, RL rollouts, reproducible research experiments, and quick
multi-agent prototyping.

## What Amber does

- **Inputs:** a root component manifest (plus any referenced child manifests).
- **Outputs:** a linked scenario plus artifacts like Scenario IR JSON, Graphviz DOT, Docker
  Compose runtime directories, Kubernetes directories, direct/native runtime directories,
  VM runtime directories, metadata JSON, and offline bundles.
- **Behavior:** resolves manifests from local files and `http(s)://` URLs, validates structure
  and wiring, and produces deterministic, inspectable outputs.

Amber can run direct/native and VM artifacts locally (`amber run <output-dir>`), and can also
compile artifacts for environments like Docker Compose and Kubernetes.

## Core concepts

- **Component manifest:** JSON5 file that describes one component: an optional program
  (container image, native path, or VM), optional network endpoints, and how it connects to
  others.
- **Slots / provides:** what a component needs (slots) and what it offers (provides).
- **Bindings / exports:** wiring between components, and what gets exposed to the parent.
- **Scenario:** the fully linked, validated graph produced by the compiler.

If you want the full manifest schema, run `amber docs manifest`. To dump this README from the
binary, run `amber docs readme`. To list embedded examples or dump one example's files, run
`amber docs examples` or `amber docs examples <example>`.

## Getting started

Amber is distributed as a prebuilt CLI binary or as a Docker image.

### Option A: Download the prebuilt CLI

Download the latest artifact from the `amber-publish` workflow:

```
https://github.com/RDI-Foundation/amber/actions/workflows/publish.yaml?query=branch%3Amain
```

Pick the `amber-cli-<platform>.tar.gz` artifact, extract it, and run:

```sh
tar -xzf amber-cli-linux-amd64.tar.gz
./amber --help
```

If you want `amber` on your PATH, move it into a directory that’s already on PATH.

### Option B: Use the Dockerized CLI

```sh
docker run --rm -v "$PWD":/work -w /work ghcr.io/rdi-foundation/amber-cli:v0.3 --help
```

This is most convenient for `amber check`, `amber compile`, and `amber docs`. The host-side
runtime commands below (`amber proxy`, `amber run`, and `amber dashboard`) are simplest with the
native CLI.

## Tutorial

Amber compiles manifests. The fastest way to learn is to compile a tiny manifest pair and
inspect the outputs.

### 1) Create a minimal two-file manifest

```sh
mkdir -p amber-demo
cat > amber-demo/child.json <<'JSON'
{
  "manifest_version": "0.3.0",
  "program": {
    "image": "python:3.11-alpine",
    "entrypoint": ["python", "-m", "http.server", "8080"],
    "network": { "endpoints": [{ "name": "http", "port": 8080 }] }
  },
  "provides": { "api": { "kind": "http", "endpoint": "http" } },
  "exports": { "api": "api" }
}
JSON

cat > amber-demo/parent.json <<'JSON'
{
  "manifest_version": "0.3.0",
  "components": { "child": "./child.json" },
  "exports": { "api": "#child.api" }
}
JSON
```

This is a small end-to-end example: a child component with a single HTTP capability and a parent
that re-exports it.

### 2) Compile and inspect

```sh
amber check amber-demo/parent.json
amber compile amber-demo/parent.json --output amber-demo/out/scenario.json
amber compile amber-demo/parent.json --dot -
```

These output paths stay under `amber-demo/`, so the same `check` and `compile` commands also work
with the Dockerized CLI. Replace `amber` with:

```sh
docker run --rm -v "$PWD":/work -w /work ghcr.io/rdi-foundation/amber-cli:v0.3
```

### 3) Generate Docker Compose and run

```sh
amber compile amber-demo/parent.json \
  --docker-compose amber-demo/out/compose
cd amber-demo/out/compose
docker compose up -d
amber proxy . --export api=127.0.0.1:18080
curl http://127.0.0.1:18080
```

Amber writes `compose.yaml`, `env.example`, and a generated `README.md` into that output
directory.

### 3b) Generate direct/native output and run

```sh
amber compile examples/direct-security/scenario.json5 --direct /tmp/amber-direct
amber run /tmp/amber-direct
```

Direct output only supports components that use `program.path`.

`amber run` for direct output requires a local sandbox backend:
- Linux: `bwrap`, `slirp4netns`, and a Landlock-enabled kernel
- macOS: `/usr/bin/sandbox-exec`

Current enforcement notes:
- Direct/native on Linux has the strongest capability mediation today: Amber runs each component behind a sidecar/router, isolates sidecar networking, joins the component into that namespace, shapes the filesystem with curated read-only mounts plus explicit writable storage, launches component programs through `amber-helper`, applies fixed seccomp and Landlock hardening inside that shaped view, and drops all Linux capabilities for Amber-owned sidecars.
- Docker Compose and Kubernetes now default generated containers to non-escalating privilege settings, run Amber-owned internal routers/provisioners non-root where their images already guarantee it, make those internal root filesystems read-only where possible, and reject external slot targets that resolve to loopback or link-local IPs.
- Docker Compose and Kubernetes do not yet transparently redirect all arbitrary container egress through the router. Amber strongly mediates declared capability paths, but shared pod/service networking still means generic outbound traffic is not yet fully non-bypassable on those backends.

### 3c) Generate VM output and run

```sh
amber compile examples/vm-network-storage/scenario.json5 --vm /tmp/amber-vm
amber run /tmp/amber-vm
```

Depending on the scenario and backend, generated runtime outputs may reference Amber's internal
images:

- `ghcr.io/rdi-foundation/amber-router:v0.1`
- `ghcr.io/rdi-foundation/amber-provisioner:v0.1`
- `ghcr.io/rdi-foundation/amber-helper:v0.2`
- `ghcr.io/rdi-foundation/amber-docker-gateway:v0.1` when using `framework.docker`

Amber writes those references only when needed. Docker Compose and Kubernetes will pull them
automatically; if you're in a restricted environment, pre-pull them ahead of time.

Amber also publishes `ghcr.io/rdi-foundation/amber-manager:v0.1` for running the scenario
manager daemon in a container. Unlike the runtime images above, Amber does not inject that image
into generated outputs; you run it explicitly when you want the manager service.

`amber-manager` reads operator policy from the JSON file passed via `--config`. For example,
operators can register static bindable services, operator-provided bindable root-config values,
and restrict scenario create/upgrade requests to an explicit `scenario_source_allowlist`:

```json
{
  "bindable_services": {
    "manager": {
      "protocol": "http",
      "provider": {
        "kind": "loopback_upstream",
        "upstream": "127.0.0.1:4100"
      }
    }
  },
  "bindable_configs": {
    "openai_prod_api_key": "sk-live-xxxxx",
    "shared_otel_endpoint": "http://otel.internal:4318/v1/traces"
  },
  "scenario_source_allowlist": [
    "file:///opt/amber/scenarios/controller.json5",
    "https://artifacts.example.com/amber/provider.json5"
  ]
}
```

If `scenario_source_allowlist` is omitted, the manager accepts any scenario source URL. If it is
present, any manager request that fetches a scenario from a `source_url` must use one of the
listed URLs. Today that includes create requests, upgrades, and `source_url`-based config schema
lookups. An empty allowlist rejects all such requests.

At runtime, the manager API can remove individual entries from `scenario_source_allowlist` after
bootstrap. That update is in-memory only: it affects subsequent create, upgrade, and
`source_url`-based schema lookups immediately, but it does not rewrite the manager config file, so
the original configured allowlist is restored on manager restart unless you also update `--config`.

Bindable configs are enumerated through the manager API as opaque ids such as
`cfg_openai_prod_api_key`; the raw values are not returned by the API. Create and upgrade
requests can then map root-config paths to those ids with `external_root_config`, for example:

```json
{
  "source_url": "https://artifacts.example.com/amber/provider.json5",
  "root_config": {},
  "external_root_config": {
    "api_key": "cfg_openai_prod_api_key",
    "telemetry.endpoint": "cfg_shared_otel_endpoint"
  }
}
```

The manager resolves `external_root_config` into the effective root config before compilation, so
the caller never needs the underlying secret value.

If you're working in this repo, the published image list and tags live in
`docker/images.json`; CI publishes and verifies those tags on `main`.
Image publishing is fully manifest-driven. Git tags are not used to publish images.

Tag behavior is defined per image in `docker/images.json`:

- `version`: either an immutable semver tag (for example `v1.2.3` or `v1.2.3-alpha.1`)
  or a patch placeholder template (for example `v1.2.x` or `v1.2.3-alpha.x`).
  On `main`, CI resolves `x` to the next available sequence number for that image, then
  publishes that concrete tag. Amber-generated configs and tests use a semver-derived
  runtime compatibility tag.

Every push to `main` publishes `:main` and `:<git-sha>` for each image, creates any missing
resolved `version`, and derives floating semver tags from it.
- Stable example: `v1.2.3` also updates `v1.2` and `v1`.
- Prerelease example: `v1.2.3-alpha.1` also updates `v1.2-alpha.1`, `v1-alpha.1`, and `v1-alpha`.
- Runtime tag example: `version: v1.2.3` bakes `v1`; `version: v0.3.7` bakes `v0.3`; `version:
  v1.2.3-alpha.1` bakes `v1-alpha`.

## Common workflows

### Compile to Scenario IR

```sh
amber compile path/to/root.json5 --output /tmp/scenario.json
```

You can also use an existing Scenario IR as input for `amber compile` to produce other outputs
(for example, Docker Compose, Kubernetes, direct/native runtime artifacts, or VM runtime
artifacts). Scenario IR input is graph-only, so `--bundle` still requires a manifest or bundle
input with manifest source bytes.

### Check-only (linting + diagnostics)

```sh
amber check path/to/root.json5
```

### Compile + run direct/native

```sh
amber compile path/to/root.json5 --direct /tmp/direct-out
amber run /tmp/direct-out
```

Direct output requires `program.path` with an explicit absolute path or a manifest-relative path
like `./bin/server`; it does not search `PATH`. By default, direct mode preserves the same ambient
read-only access to the component's local source tree that it historically exposed. Add
`program.reads` to replace that legacy source-tree read access with explicit manifest-relative or
absolute read-only paths instead. Amber still keeps the executable support path and platform
runtime defaults readable so the process can start.

### Compile + run VM

```sh
amber compile path/to/root.json5 --vm /tmp/vm-out
amber run /tmp/vm-out
```

### Create a bundle for offline, reproducible builds

```sh
amber compile path/to/root.json5 --bundle /tmp/amber-bundle
```

## CLI reference

Every command has its own help page:

```sh
amber --help
amber compile --help
amber docs --help
amber docs examples --help
```

Use these commands when you want the repo docs from the binary itself:

- `amber docs readme`: project overview, common workflows, and this CLI reference.
- `amber docs manifest`: full manifest schema and authoring details.
- `amber docs examples`: list embedded examples.
- `amber docs examples <example>`: dump one embedded example's files.

Top-level command guide:

- `amber check <manifest-or-bundle>`: resolve manifests, run validation and linting, and print diagnostics without writing any artifacts.
- `amber compile <input> [output flags]`: compile a manifest, bundle, or Scenario IR and emit one or more outputs such as Scenario IR, Graphviz DOT, Docker Compose runtime directories, Kubernetes manifests, direct/native artifacts, VM artifacts, metadata, or an offline bundle.
- `amber run <output>`: start a direct/native artifact produced by `amber compile --direct` or a VM artifact produced by `amber compile --vm`. You can pass the output directory, its `direct-plan.json`, or its `vm-plan.json`.
- `amber proxy <output> --export name=127.0.0.1:PORT`: expose a scenario export on localhost. Add `--slot name=127.0.0.1:PORT` to connect a scenario slot to a local upstream at the same time.
- `amber dashboard [--detach]`: start the local Aspire dashboard that Amber examples use for observability and tracing workflows.

Output-specific pointers:

- Docker Compose output is the easiest way to get a runnable multi-container scenario quickly. The generated directory contains `compose.yaml`, `env.example`, and `README.md`.
- Direct output is the easiest way to run local host binaries that use `program.path`.
- VM output packages a local VM runtime for `amber run`.
- Kubernetes output is for cluster deployment; when you proxy against it locally, you usually also need explicit router port-forwards and `amber proxy --mesh-addr`.
- Bundle output is for offline or reproducible recompilation later.

## More information

If you're working in this repo, these docs go deeper:

- Manifest format and examples: `compiler/manifest/README.md` (or `amber docs manifest`)
- Project overview: `README.md` (or `amber docs readme`)
- CLI behavior and outputs: `cli/README.md`
- Compiler pipeline and reporters: `compiler/README.md`
- Docker gateway component: `runtime/docker-gateway/README.md`
- Framework docker example: `examples/framework-docker/README.md`
- Scenario data model: `compiler/scenario/README.md`
- Manifest resolution (file/http) details: `compiler/resolver/README.md`
- Examples: `examples/` (or `amber docs examples`)

---

If you're building new components or integrating Amber into a larger system, start with the
minimal example above, run `amber check`, then iterate
until the compiler output matches the scenario you want to run.
