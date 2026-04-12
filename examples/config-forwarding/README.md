<!-- amber-docs
summary: Show how root config_schema becomes backend runtime inputs and forwarded child config.
-->

# Config forwarding and defaults

This example shows how a root `config_schema` turns into runtime config that you pass in from
outside the compiled scenario.

In this example, the root `api_key` is supplied at runtime and forwarded into the child
component's `config`, while `system_prompt` comes from a `config_schema` default unless you
override it.

## Files

- `scenario.json5`: root manifest. Declares the root `config_schema`, including a defaulted
  `system_prompt`, and forwards both config values into `api_client`.
- `api-client.json5`: child manifest. Declares the child's own `config_schema` and prints the
  rendered `${config}` object on startup.

## What gets rendered

The root manifest says "this scenario needs an `api_key`, has a defaulted `system_prompt`, and
both values should become `api_client.config.*`":

```json5
config_schema: {
  type: "object",
  properties: {
    api_key: { type: "string" },
    system_prompt: {
      type: "string",
      default: "You are an agent.",
    },
  },
  required: ["api_key", "system_prompt"],
  additionalProperties: false,
},

components: {
  api_client: {
    manifest: "./api-client.json5",
    config: {
      api_key: "${config.api_key}",
      system_prompt: "${config.system_prompt}",
    },
  },
},
```

The child manifest says "I expect `api_key` and `system_prompt`, and I will print the final config
object when I start":

```json5
config_schema: {
  type: "object",
  properties: {
    api_key: { type: "string" },
    system_prompt: { type: "string" },
  },
  required: ["api_key", "system_prompt"],
  additionalProperties: false,
},

program: {
  entrypoint: [
    "sh",
    "-c",
    "echo \"api-client starting; config=${config}\"; exec httpd -f -p 8080",
  ],
},
```

If you supply only:

```text
AMBER_CONFIG_API_KEY=demo-key
```

Amber reconstructs the root config as:

```json
{
  "api_key": "demo-key",
  "system_prompt": "You are an agent."
}
```

and renders the child config as:

```json
{
  "api_key": "demo-key",
  "system_prompt": "You are an agent."
}
```

That is the object you will see in the child log line. Only leaf paths become env vars, so nested
paths use `__`: for example, `config.api.key` would become `AMBER_CONFIG_API__KEY`.

## `amber run`

If you want Amber to generate the input file it expects for `amber run`, ask it to emit the
template first:

```sh
amber run . --emit-env-file .env.example
```

You can then point one root config value at a file instead of copying the file contents into the
env file:

```sh
printf 'demo-key\n' > api-key.txt
cat > .env.example <<'EOF'
AMBER_CONFIG_FILE_API_KEY=./api-key.txt
EOF

amber run . --env-file .env.example
```

On an interactive `amber run`, the same prompt also accepts `@./api-key.txt`, shows matching paths
as you type, and completes them with `Tab`. Use `@@...` if you need a literal value that starts
with `@`.

## Docker Compose

Compile to a compose output directory:

```sh
OUT=/tmp/amber-config-forwarding-compose
rm -rf "$OUT"
amber compile examples/config-forwarding/scenario.json5 --docker-compose "$OUT"
```

Amber renders the root input as an env file entry:

```text
# $OUT/env.example
AMBER_CONFIG_API_KEY=
```

The generated service then reads that value:

```yaml
# excerpt from $OUT/compose.yaml
services:
  c1-api-client:
    environment:
      - AMBER_CONFIG_API_KEY=${AMBER_CONFIG_API_KEY?missing config.api_key}
      - AMBER_CONFIG_SYSTEM_PROMPT=${AMBER_CONFIG_SYSTEM_PROMPT}
```

Fill in the required root config and start the stack:

```sh
cat > "$OUT/.env" <<'EOF'
AMBER_CONFIG_API_KEY=demo-key
EOF

cd "$OUT"
docker compose up -d
docker compose logs c1-api-client
```

The startup log will include the rendered child config, so you should see the externally supplied
`api_key` and the defaulted `system_prompt`. If you also set `AMBER_CONFIG_SYSTEM_PROMPT`, that
runtime value overrides the schema default.

## Kubernetes

Compile to a Kubernetes output directory:

```sh
OUT=/tmp/amber-config-forwarding-k8s
rm -rf "$OUT"
amber compile examples/config-forwarding/scenario.json5 --kubernetes "$OUT"
```

Amber renders the root input as a generated env file. Defaulted string values are written as
JSON string literals so they round-trip through Amber's env parser:

```text
# $OUT/root-config.env
AMBER_CONFIG_API_KEY=
AMBER_CONFIG_SYSTEM_PROMPT="You are an agent."
```

and includes that file from `kustomization.yaml`:

```yaml
configMapGenerator:
- name: amber-root-config
  envs:
  - root-config.env
```

Fill in the required root config and apply the manifests:

```sh
printf 'AMBER_CONFIG_API_KEY=demo-key\n' > "$OUT/root-config.env"

NS=$(awk '/^namespace:/{print $2; exit}' "$OUT/kustomization.yaml")
kubectl get namespace "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS"
kubectl apply -k "$OUT"
kubectl -n "$NS" rollout status deploy/c1-api-client
kubectl -n "$NS" logs deploy/c1-api-client -c main
```

The pod log shows the same rendered child config object as the Compose example. If you also want
to proxy the export to localhost, the generated output directory also includes backend-specific
run instructions.
