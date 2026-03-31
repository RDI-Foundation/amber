use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use amber_compiler::reporter::{
    direct::{DIRECT_CONTROL_SOCKET_RELATIVE_PATH, DIRECT_PLAN_VERSION},
    vm::{VM_PLAN_FILENAME, VM_PLAN_VERSION},
};
use amber_images::AMBER_ROUTER;
use amber_manifest::ManifestDigest;
use amber_template::{
    ProgramArgTemplate, ProgramEnvTemplate, RepeatedProgramArgTemplate, RepeatedProgramEnvTemplate,
    RepeatedTemplateSource, TemplatePart, TemplateSpec,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use serde_yaml::Value as YamlValue;

fn env_value(service: &YamlValue, key: &str) -> Option<String> {
    let env = service.get("environment")?;
    match env {
        YamlValue::Mapping(map) => map
            .get(YamlValue::String(key.to_string()))
            .and_then(YamlValue::as_str)
            .map(str::to_string),
        YamlValue::Sequence(seq) => seq.iter().find_map(|entry| {
            let entry = entry.as_str()?;
            let (k, v) = entry.split_once('=')?;
            if k == key { Some(v.to_string()) } else { None }
        }),
        _ => None,
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root")
        .to_path_buf()
}

fn cli_test_outputs_dir(prefix: &str) -> tempfile::TempDir {
    let outputs_root = workspace_root().join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory")
}

fn write_fixture(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap_or_else(|err| {
        panic!("failed to write fixture {}: {err}", path.display());
    });
}

fn write_json_fixture(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("fixture should serialize"),
    )
    .unwrap_or_else(|err| panic!("failed to write fixture {}: {err}", path.display()));
}

fn parse_json_file(path: &Path) -> Value {
    serde_json::from_str(
        &fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display())),
    )
    .unwrap_or_else(|err| panic!("failed to parse {} as json: {err}", path.display()))
}

fn decode_json_b64(raw: &str) -> Value {
    let bytes = STANDARD
        .decode(raw)
        .unwrap_or_else(|err| panic!("base64 payload should decode: {err}"));
    serde_json::from_slice(&bytes).expect("payload should contain valid JSON")
}

fn decode_template_spec(raw: &str) -> TemplateSpec {
    let bytes = STANDARD
        .decode(raw)
        .unwrap_or_else(|err| panic!("template spec should decode: {err}"));
    serde_json::from_slice(&bytes).expect("template spec should contain valid JSON")
}

fn find_component<'a>(plan: &'a Value, moniker: &str) -> &'a Value {
    plan["components"]
        .as_array()
        .expect("components should be an array")
        .iter()
        .find(|component| component["moniker"].as_str() == Some(moniker))
        .unwrap_or_else(|| panic!("expected component {moniker} in plan: {plan:#}"))
}

struct PlacedFixture {
    manifest: PathBuf,
    placement: PathBuf,
}

fn write_single_image_fixture(root: &Path, site_id: &str, site_kind: &str) -> PlacedFixture {
    write_json_fixture(
        &root.join("svc.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "program": {
                "image": "python:3.13-alpine",
                "entrypoint": ["python3", "-u", "-c", "print('ready')"],
                "network": {
                    "endpoints": [
                        { "name": "http", "port": 8080, "protocol": "http" }
                    ]
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );

    let manifest = root.join("root.json5");
    write_json_fixture(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "svc": "./svc.json5"
            },
            "exports": {
                "svc_http": "#svc.http"
            }
        }),
    );

    let site = if site_kind == "kubernetes" {
        json!({ "kind": site_kind, "context": "kind-amber-test" })
    } else {
        json!({ "kind": site_kind })
    };
    let placement = root.join("placement.json5");
    write_json_fixture(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                site_id: site
            },
            "defaults": {
                "image": site_id
            }
        }),
    );

    PlacedFixture {
        manifest,
        placement,
    }
}

fn write_mixed_site_fixture(root: &Path) -> PlacedFixture {
    write_json_fixture(
        &root.join("a.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "b": { "kind": "http" }
            },
            "program": {
                "path": "/usr/bin/env",
                "args": ["python3", "-u", "-c", "print('ready')"],
                "network": {
                    "endpoints": [
                        { "name": "http", "port": 18080, "protocol": "http" }
                    ]
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );
    write_json_fixture(
        &root.join("b.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "program": {
                "image": "python:3.13-alpine",
                "entrypoint": ["python3", "-u", "-c", "print('ready')"],
                "network": {
                    "endpoints": [
                        { "name": "http", "port": 8080, "protocol": "http" }
                    ]
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );

    let manifest = root.join("root.json5");
    write_json_fixture(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "a": "./a.json5",
                "b": "./b.json5"
            },
            "bindings": [
                { "to": "#a.b", "from": "#b.http" }
            ],
            "exports": {
                "a_http": "#a.http",
                "b_http": "#b.http"
            }
        }),
    );

    let placement = root.join("placement.json5");
    write_json_fixture(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "direct_local": { "kind": "direct" },
                "compose_local": { "kind": "compose" }
            },
            "defaults": {
                "path": "direct_local",
                "image": "compose_local"
            }
        }),
    );

    PlacedFixture {
        manifest,
        placement,
    }
}

mod artifact_outputs;
mod config_each;
mod forwarded_defaults;
mod runtime_conditionals;
mod scenario_ir;
