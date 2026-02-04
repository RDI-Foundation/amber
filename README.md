# Amber

Amber is a compiler for shareable AI agent components. You write component manifests
that describe containers, inputs, outputs, and wiring. Amber resolves and validates the manifest
graph, then emits a runnable, reproducible scenario plus artifacts you can execute or inspect.

Amber is useful for benchmarking, RL rollouts, reproducible research experiments, and quick
multi-agent prototyping.

## What Amber does

- **Inputs:** a root component manifest (plus any referenced child manifests).
- **Outputs:** a linked scenario plus artifacts like Scenario IR JSON, Graphviz DOT, Docker
  Compose YAML, and offline bundles.
- **Behavior:** resolves manifests from local files and `https://` URLs, validates structure
  and wiring, and produces deterministic, inspectable outputs.

Amber does **not** run your agents by itself. It compiles to artifacts that you can run in other
environments like Docker Compose and Kubernetes.

## Core concepts

- **Component manifest:** JSON5 file that describes one component: optional program container,
  optional network endpoints, and how it connects to others.
- **Slots / provides:** what a component needs (slots) and what it offers (provides).
- **Bindings / exports:** wiring between components, and what gets exposed to the parent.
- **Scenario:** the fully linked, validated graph produced by the compiler.

If you want the full schema and examples, run `amber docs manifest`. If you have the repo checked
out, the same content lives in `manifest/README.md`.

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
docker run --rm -v "$PWD":/work -w /work ghcr.io/rdi-foundation/amber-cli:main --help
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
docker run --rm -v "$PWD":/work -w /work ghcr.io/rdi-foundation/amber-cli:main
```

### 3) Generate Docker Compose and run

```sh
amber compile amber-demo/parent.json \
  --docker-compose /tmp/amber-compose.yaml
docker compose -f /tmp/amber-compose.yaml up
```

The Docker Compose output references the router and helper images used to
enforce the wiring: `ghcr.io/rdi-foundation/amber-router:v1` and
`ghcr.io/rdi-foundation/amber-helper:v1`. Docker Compose will pull them automatically;
if you're in a restricted environment, pre-pull them ahead of time.

If you're working in this repo, the internal image list and tags live in
`docker/images.json`; CI publishes and verifies those tags on `main`.

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

### Create a bundle for offline, reproducible builds

```sh
amber compile path/to/root.json5 --bundle /tmp/amber-bundle
```

## More information

If you're working in this repo, these docs go deeper:

- Manifest format and examples: `manifest/README.md` (or `amber docs manifest`)
- CLI behavior and outputs: `cli/README.md`
- Compiler pipeline and reporters: `compiler/README.md`
- Scenario data model: `scenario/README.md`
- Manifest resolution (file/http) details: `resolver/README.md`
- Examples: `examples/`

---

If you're building new components or integrating Amber into a larger system, start with the
minimal example above, run `amber check`, then iterate
until the compiler output matches the scenario you want to run.
