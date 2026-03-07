# Amber

Amber is a compiler for shareable AI agent components. You write component manifests
that describe containers, inputs, outputs, and wiring. Amber resolves and validates the manifest
graph, then emits a runnable, reproducible scenario plus artifacts you can execute or inspect.

Amber is useful for benchmarking, RL rollouts, reproducible research experiments, and quick
multi-agent prototyping.

## What Amber does

- **Inputs:** a root component manifest (plus any referenced child manifests).
- **Outputs:** a linked scenario plus artifacts like Scenario IR JSON, Graphviz DOT, Docker
  Compose YAML, Kubernetes directories, direct/native run directories, and offline bundles.
- **Behavior:** resolves manifests from local files and `https://` URLs, validates structure
  and wiring, and produces deterministic, inspectable outputs.

Amber can run direct/native artifacts locally (`amber run <direct-output-dir>`), and can also
compile artifacts for environments like Docker Compose and Kubernetes.

## Core concepts

- **Component manifest:** JSON5 file that describes one component: optional program container,
  optional network endpoints, and how it connects to others.
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
docker run --rm -v "$PWD":/work -w /work ghcr.io/rdi-foundation/amber-cli:v0.2 --help
```

## Tutorial

Amber compiles manifests. The fastest way to learn is to compile a tiny manifest pair and
inspect the outputs.

### 1) Create a minimal two-file manifest

```sh
mkdir -p amber-demo
cat > amber-demo/child.json <<'JSON'
{
  "manifest_version": "0.1.0",
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
  "manifest_version": "0.1.0",
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
amber compile amber-demo/parent.json --output /tmp/amber.scenario.json
amber compile amber-demo/parent.json --dot -
```

If you're using the Dockerized CLI, replace `amber` with:

```sh
docker run --rm -v "$PWD":/work -w /work ghcr.io/rdi-foundation/amber-cli:v0.2
```

### 3) Generate Docker Compose and run

```sh
amber compile amber-demo/parent.json \
  --docker-compose /tmp/amber-compose.yaml
docker compose -f /tmp/amber-compose.yaml up
```

### 3b) Generate direct/native output and run

```sh
amber compile examples/direct-security/scenario.json5 --direct /tmp/amber-direct
amber run /tmp/amber-direct
```

Direct output only supports components that use `program.path`.

`amber run` for direct output requires a local sandbox backend:
- Linux: `bwrap` and `slirp4netns`
- macOS: `/usr/bin/sandbox-exec`

The Docker Compose output references the router, provisioner, and helper images used to
enforce the wiring and provision mesh identities: `ghcr.io/rdi-foundation/amber-router:v1`,
`ghcr.io/rdi-foundation/amber-provisioner:v1`, and `ghcr.io/rdi-foundation/amber-helper:v1`.
Docker Compose will pull them automatically;
if you're in a restricted environment, pre-pull them ahead of time.

Some scenarios also use the Docker gateway component to scope Docker Engine API access
per component. In that case, the compose output will reference
`ghcr.io/rdi-foundation/amber-docker-gateway:v1`.

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
- Runtime tag example: `version: v1.2.3` bakes `v1`; `version: v1.2.3-alpha.1` bakes `v1-alpha`.

## Common workflows

### Compile to Scenario IR

```sh
amber compile path/to/root.json5 --output /tmp/scenario.json
```

You can also use an existing Scenario IR as input for `amber compile` to produce other outputs
(for example, Docker Compose or Kubernetes manifests).

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
- `amber compile <manifest-or-bundle> [output flags]`: compile once and emit one or more outputs such as Scenario IR, Graphviz DOT, Docker Compose, Kubernetes manifests, direct/native artifacts, metadata, or an offline bundle.
- `amber run <direct-output>`: start a direct/native artifact produced by `amber compile --direct`. You can pass either the output directory or its `direct-plan.json`.
- `amber proxy <output> --export name=127.0.0.1:PORT`: expose a scenario export on localhost. Add `--slot name=127.0.0.1:PORT` to connect a scenario slot to a local upstream at the same time.
- `amber dashboard [--detach]`: start the local Aspire dashboard that Amber examples use for observability and tracing workflows.

Output-specific pointers:

- Docker Compose output is the easiest way to get a runnable multi-container scenario quickly.
- Direct output is the easiest way to run local host binaries that use `program.path`.
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
