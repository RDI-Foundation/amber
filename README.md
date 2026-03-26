# Amber

Amber is a compiler for shareable AI agent components. You write component manifests
that describe programs, capabilities, and wiring. Amber resolves and validates the manifest
graph, then emits runnable, reproducible artifacts you can execute or inspect.

Amber is useful for benchmarking, RL rollouts, reproducible research experiments, and quick
multi-agent prototyping.

## What Amber does

- **Inputs:** a root component manifest (plus any referenced child manifests).
- **Outputs:** a linked scenario plus artifacts like Scenario IR JSON, mixed-site run plans,
  Graphviz DOT, Docker Compose runtime directories, Kubernetes directories, direct/native runtime
  directories, VM runtime directories, metadata JSON, and offline bundles.
- **Behavior:** resolves manifests from local files and `http(s)://` URLs, validates structure
  and wiring, produces deterministic, inspectable outputs, and can coordinate mixed-site runs
  across direct/native, VM, Docker Compose, and Kubernetes sites.

Amber can run manifests directly with `amber run <manifest>`, can start compiled mixed-site run
plans, and can still emit raw backend artifacts when you want to inspect or operate a site
without the Amber coordinator.

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

## Fastest first run

If you want the shortest path to a real mixed-site run, use the example in this repo.

In one terminal:

```sh
cd examples/mixed-site
python3 mock-catalog.py
```

In another terminal:

```sh
cd examples/mixed-site
amber run .
```

Amber will compile the manifest in memory, prompt for any missing root config and outside-service
values, start the direct and Compose sites, auto-start the outside-world proxy, print localhost
URLs for the exported entrypoints, and stay attached. Call the printed app URL with `curl`, then
press Ctrl-C in the `amber run` terminal to tear the whole scenario down.

The detailed walkthrough for that flow lives in `examples/mixed-site/README.md`.

## Compiler walkthrough

Amber is still a compiler. When you want inspectable outputs, generated artifacts, or explicit
control over placement, start with a tiny manifest pair and compile it.

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
- Linux: `bwrap` and `slirp4netns`
- macOS: `/usr/bin/sandbox-exec`

### 3c) Generate VM output and run

```sh
amber compile examples/vm-network-storage/scenario.json5 --vm /tmp/amber-vm
amber run /tmp/amber-vm
```

### 3d) Run a mixed-site manifest directly

```sh
cd examples/mixed-site
python3 mock-catalog.py
```

In another terminal:

```sh
cd examples/mixed-site
amber run .
```

This is the friendly mixed-site local-dev path: Amber compiles the manifest, prompts for missing
config, auto-starts the outside-world proxy, publishes exports on localhost, and stays attached.
The `examples/mixed-site/README.md` walkthrough shows the full direct + Compose flow and the
explicit control path if you want to inspect or override placement.

Depending on the scenario and backend, generated runtime outputs may reference Amber's internal
images:

- `ghcr.io/rdi-foundation/amber-router:v0.1`
- `ghcr.io/rdi-foundation/amber-provisioner:v0.1`
- `ghcr.io/rdi-foundation/amber-helper:v0.2`
- `ghcr.io/rdi-foundation/amber-docker-gateway:v0.1` when using `framework.docker`

Amber writes those references only when needed. Docker Compose and Kubernetes will pull them
automatically; if you're in a restricted environment, pre-pull them ahead of time.

If you're working in this repo, the internal image list and tags live in
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

### Compile to a mixed-site run plan

```sh
amber compile path/to/root.json5 --placement path/to/sites.json5 --run-plan /tmp/run-plan.json
```

Run plans are the primary lowered execution artifact for `amber run`. They capture site
assignment, cross-site links, and startup waves without freezing machine-local launch details.

### Run a manifest directly

```sh
amber run path/to/root.json5
amber run path/to/root.json5 --placement path/to/sites.json5 --detach
```

This is the default mixed-site workflow. In an interactive terminal, `amber run` can prompt for
missing config, auto-start the outside-world proxy, print localhost export URLs, and stay
attached as the foreground session owner. Use `--detach` when you want a background run instead.

### Run a compiled mixed-site plan

```sh
amber compile path/to/root.json5 --run-plan /tmp/run-plan.json
amber run /tmp/run-plan.json --detach
```

Use this when you want an inspectable execution plan in version control, CI artifacts, or a
debugging workflow before launch.

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
like `./bin/server`; it does not search `PATH`.

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
- `amber compile <input> [output flags]`: compile a manifest, bundle, or Scenario IR and emit one or more outputs such as Scenario IR, mixed-site run plans, Graphviz DOT, Docker Compose runtime directories, Kubernetes manifests, direct/native artifacts, VM artifacts, metadata, or an offline bundle.
- `amber run <input>`: start a manifest, bundle, mixed-site run plan, direct/native artifact, or VM artifact. Use `--placement` when you want an explicit site layout, `--env-file` when you want an explicit config source, and `--observability` when you want Amber-managed OTLP export for a mixed-site run.
- `amber proxy <output> --export name=127.0.0.1:PORT`: expose a scenario export on localhost. Add `--slot name=127.0.0.1:PORT` to connect a scenario slot to a local upstream at the same time. When the target is a mixed-site run id, Amber can proxy the whole running scenario without making you discover internal artifact paths.
- `amber dashboard [--detach]`: start the local Aspire dashboard that Amber examples use for observability and tracing workflows.

Output-specific pointers:

- Run-plan output is the main lowered execution artifact for mixed-site runs. Inspect it when you
  want to understand placement, cross-site links, and startup ordering before launch.
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
