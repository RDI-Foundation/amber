<!-- amber-docs
summary: Feed repeated slot fan-in into repeated flags, repeated args, and CSV env values.
-->

# Interpolation

This example shows how to pass repeated slot fan-in into an unmodified Unix-style program
interface.

`cli-probe.json5` declares an optional repeated `upstream` slot and writes its argv plus selected
env vars into a tiny HTTP page. The root manifest instantiates that component twice:

- `with_upstreams` gets the same slot bound three times, in declaration order.
- `without_upstreams` gets no bindings, so the repeated expansions disappear cleanly.

What it demonstrates:

- `{ each, argv }` for repeated flag pairs like `--upstream URL`.
- `{ each, arg }` for repeated positional args.
- `{ each, value, join: "," }` for CSV env values.
- `when: "slots.upstream"` as a non-empty fan-in check.
- Binding declaration order flowing through to repeated program args and env values.

## Files

- `scenario.json5`: root manifest that binds `with_upstreams.upstream` three times and leaves
  `without_upstreams.upstream` empty.
- `cli-probe.json5`: child component that turns repeated slot values into repeated flags,
  repeated positional args, and one CSV env var.
- `upstream.json5`: simple HTTP provider used as the fan-in source.

## Docker Compose loop

```sh
OUT=/tmp/amber-interpolation
rm -rf "$OUT"
amber compile examples/interpolation/scenario.json5 \
  --docker-compose "$OUT"
docker compose -f "$OUT/compose.yaml" up -d
amber proxy "$OUT" \
  --export with_upstreams=127.0.0.1:18080 \
  --export without_upstreams=127.0.0.1:18081
curl http://127.0.0.1:18080
curl http://127.0.0.1:18081
```

`with_upstreams` shows three `--upstream` flags, three positional target URLs after `--targets`,
and a comma-separated `upstreams_csv` env value in binding order.

`without_upstreams` shows the same base command without `--has-upstreams`, without `--targets`,
and with `upstreams_csv=unset`.
