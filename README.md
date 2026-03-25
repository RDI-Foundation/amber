# Amber

Amber is a compiler for shareable AI agent components. You describe components,
capabilities, and wiring in JSON5 manifests. Amber resolves the graph,
validates it, and emits runnable, inspectable artifacts.

Amber is a good fit for reproducible experiments, evals, RL rollouts, and
quick multi-agent prototyping.

## What Amber does

- Takes a root component manifest plus any referenced child manifests.
- Resolves manifests from local files and `http(s)://` URLs.
- Validates slots, provides, bindings, and exports.
- Emits outputs such as Scenario IR JSON, Graphviz DOT, Docker Compose
  directories, Kubernetes manifests, direct/native runtime directories, VM
  runtime directories, metadata JSON, and offline bundles.
- Runs direct/native and VM artifacts locally with `amber run`.

## Core concepts

- **Component manifest:** one JSON5 document that describes a component, its
  program, its capabilities, and any child components. Programs can be
  container images, native paths, or VMs.
- **Slots / provides:** what a component needs and what it offers.
- **Bindings / exports:** how components are wired together and what gets
  exposed to the parent.
- **Scenario:** the fully linked, validated graph produced by the compiler.

For the full schema, run `amber docs manifest`. To list embedded examples, run
`amber docs examples`. To print this README from the CLI, run
`amber docs readme`.

## Getting started

Amber is easiest to try with Docker. If you want a local `amber` command,
install the npm package. If you are developing Amber itself, build from source
in this repo.

### Option A: Use the Dockerized CLI (preferred)

```sh
docker run --rm -v "$PWD":/work -w /work ghcr.io/rdi-foundation/amber-cli:v0.3 --help
```

This is the simplest way to use `amber check`, `amber compile`, and
`amber docs` without installing anything else.

The examples below use `amber ...` as a local command. With Docker, replace
that prefix with:

```sh
docker run --rm -v "$PWD":/work -w /work ghcr.io/rdi-foundation/amber-cli:v0.3
```

For host-side runtime commands such as `amber proxy`, `amber run`, and
`amber dashboard`, the npm install is usually more convenient.

### Option B: Install from npm

```sh
npm install -g @rdif/amber@^0.3
amber --help
```

The npm package installs the CLI as a normal local command and downloads the
matching platform runtime package needed by `amber run`.

Current published platform packages cover Linux x64, Linux arm64, and macOS
arm64.

Direct/native execution with `amber run` has a few host requirements:

- Linux: `bwrap` and `slirp4netns`
- macOS: `/usr/bin/sandbox-exec`

VM execution also depends on local QEMU tooling.

### Option C: Build from source

If you are working in this repository:

```sh
cargo build -q -p amber-cli
./target/debug/amber --help
```

## Tutorial

Amber is easiest to understand by compiling a tiny manifest pair and inspecting
the outputs.

Amber also ships embedded examples. Run `amber docs examples` to list them, or
look in `examples/` in this repository.

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

This defines one child component that serves HTTP on port 8080 and a parent
that re-exports that capability.

### 2) Check and compile

```sh
amber check amber-demo/parent.json
amber compile amber-demo/parent.json --output amber-demo/out/scenario.json
amber compile amber-demo/parent.json --dot -
```

`amber check` validates the manifest graph without writing artifacts.
`amber compile` emits the outputs you ask for. Unlike `amber check`, it always
needs at least one output flag.

### 3) Generate Docker Compose and run

```sh
amber compile amber-demo/parent.json \
  --docker-compose amber-demo/out/compose
cd amber-demo/out/compose
docker compose up -d
amber proxy . --export api=127.0.0.1:18080
curl http://127.0.0.1:18080
```

Amber writes a self-contained Compose directory with `compose.yaml`,
`env.example`, and a generated `README.md`.

If you only want to compile with Docker, use the Dockerized CLI for the
`amber compile` step and then run `docker compose up` on the generated output.
Install via npm when you want the local `amber proxy` command. The generated
Compose README includes the exact proxy template for that scenario.

### 3b) Generate direct/native output and run

```sh
amber compile examples/direct-security/scenario.json5 --direct /tmp/amber-direct
amber run /tmp/amber-direct
```

Direct output is for components that use `program.path`. Amber does not search
`PATH`; use an explicit absolute or manifest-relative path.

### 3c) Generate VM output and run

```sh
amber compile examples/vm-network-storage/scenario.json5 --vm /tmp/amber-vm
amber run /tmp/amber-vm
```

VM output packages a local VM runtime. Some generated outputs may reference
Amber runtime images, which Docker Compose and Kubernetes pull automatically
when needed. Running VM outputs locally also requires QEMU tooling on the host.

## Common workflows

### Compile to Scenario IR

```sh
amber compile path/to/root.json5 --output /tmp/scenario.json
```

You can also use existing Scenario IR as input for other compile outputs,
except bundles.

### Check-only

```sh
amber check path/to/root.json5
```

### Compile + run direct/native

```sh
amber compile path/to/root.json5 --direct /tmp/direct-out
amber run /tmp/direct-out
```

### Compile + run VM

```sh
amber compile path/to/root.json5 --vm /tmp/vm-out
amber run /tmp/vm-out
```

### Create an offline bundle

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

Useful built-in docs:

- `amber docs readme`: this overview.
- `amber docs manifest`: manifest schema and authoring details.
- `amber docs examples`: list embedded examples.
- `amber docs examples <example>`: dump one embedded example's files.

Top-level commands:

- `amber check <manifest-or-bundle>`: resolve manifests and print diagnostics
  without writing artifacts.
- `amber compile <input> [output flags]`: compile a manifest, bundle, or
  Scenario IR and emit one or more outputs. `amber compile` requires at least
  one output flag.
- `amber run <output>`: run direct/native or VM artifacts produced by
  `amber compile`. You can pass the output directory, `direct-plan.json`, or
  `vm-plan.json`.
- `amber proxy <output> --export name=127.0.0.1:PORT`: expose a scenario
  export on localhost. The output can be a Docker Compose, Kubernetes, direct,
  or VM artifact. Use `--slot` to connect a local upstream at the same time.
- `amber dashboard [--detach]`: start the Aspire dashboard used by the
  observability examples.

## More information

If you want deeper details after the quick start:

- `compiler/manifest/README.md` or `amber docs manifest`: manifest format and
  authoring.
- `cli/README.md`: CLI behavior and outputs.
- `compiler/README.md`: compiler pipeline and diagnostics.
- `compiler/scenario/README.md`: Scenario IR data model.
- `compiler/resolver/README.md`: manifest resolution from files and URLs.
- `runtime/docker-gateway/README.md`: Docker gateway component.
- `examples/`: end-to-end examples.

---

Start with the minimal example above, run `amber check`, and then add
components and bindings until the compiled outputs match the system you want to
run.
