use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use amber_compiler::{
    CompileOptions, Compiler, DigestStore,
    bundle::BundleBuilder,
    mesh::ProxyMetadata,
    reporter::{
        CompiledScenario, DockerComposeReporter, Reporter as _,
        scenario_ir::scenario_ir_from_compile_output,
    },
};
use amber_config::{apply_schema_defaults, collect_leaf_paths, env_var_for_path, get_by_path_opt};
use amber_manifest::ManifestRef;
use amber_resolver::Resolver;
use amber_scenario::ScenarioIr;
use jsonschema::validator_for;
use serde_json::{Map, Value, json};
use thiserror::Error;
use url::Url;

use crate::{
    domain::{
        CreateScenarioRequest, ExportRequest, ExternalSlotBindingRequest, ScenarioTelemetryRequest,
    },
    json::merge_json,
    runtime::ProxyPlan,
};

pub const ENV_FILE_NAME: &str = ".env";

#[derive(Clone, Debug)]
pub struct CompiledMaterialization {
    pub scenario_ir: ScenarioIr,
    pub scenario_ir_json: String,
    pub root_schema: Option<Value>,
    pub non_secret_root_config: Value,
    pub secret_root_config: Value,
    pub compose_files: BTreeMap<PathBuf, String>,
    pub proxy_metadata: ProxyMetadata,
    pub bundle_root: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct RuntimeInput {
    pub env_contents: String,
    pub proxy_plan: ProxyPlan,
}

#[derive(Clone, Debug)]
pub struct ExportRuntimeBinding {
    pub export_name: String,
    pub internal_listen: std::net::SocketAddr,
    pub published_listen: Option<std::net::SocketAddr>,
}

#[derive(Clone, Debug)]
pub struct SlotRuntimeBinding {
    pub slot_name: String,
    pub upstream: std::net::SocketAddr,
}

#[derive(Debug, Error)]
pub enum CompileError {
    #[error("invalid source URL `{0}`")]
    InvalidSourceUrl(String),

    #[error("compile failed: {0}")]
    Compile(String),

    #[error("bundle generation failed: {0}")]
    Bundle(String),

    #[error("invalid root config: {0}")]
    InvalidRootConfig(String),

    #[error("external slot `{0}` is not declared by the compiled scenario")]
    UnknownExternalSlot(String),

    #[error("missing required external slot binding for `{0}`")]
    MissingRequiredExternalSlot(String),

    #[error("export `{0}` is not declared by the compiled scenario")]
    UnknownExport(String),

    #[error("compiled compose output is missing proxy metadata")]
    MissingProxyMetadata,

    #[error("stored scenario IR is invalid: {0}")]
    InvalidStoredIr(String),

    #[error("failed to write runtime output: {0}")]
    WriteOutput(String),
}

pub async fn compile_create(
    request: &CreateScenarioRequest,
    bundle_dir: Option<&Path>,
) -> Result<CompiledMaterialization, CompileError> {
    compile_and_materialize(
        &request.source_url,
        &request.root_config,
        &request.external_slots,
        &request.exports,
        request.store_bundle,
        bundle_dir,
    )
    .await
}

pub async fn compile_upgrade(
    source_url: &str,
    root_config: &Value,
    external_slots: &BTreeMap<String, ExternalSlotBindingRequest>,
    exports: &BTreeMap<String, ExportRequest>,
    store_bundle: bool,
    bundle_dir: Option<&Path>,
) -> Result<CompiledMaterialization, CompileError> {
    compile_and_materialize(
        source_url,
        root_config,
        external_slots,
        exports,
        store_bundle,
        bundle_dir,
    )
    .await
}

pub fn inspect_stored_ir(scenario_ir_json: &str) -> Result<CompiledMaterialization, CompileError> {
    compiled_materialization_from_stored_ir(
        scenario_ir_json,
        Value::Object(Map::new()),
        Value::Object(Map::new()),
    )
}

pub fn materialize_runtime_from_stored_ir(
    scenario_ir_json: &str,
    non_secret_root_config: Value,
    secret_root_config: Value,
) -> Result<CompiledMaterialization, CompileError> {
    compiled_materialization_from_stored_ir(
        scenario_ir_json,
        non_secret_root_config,
        secret_root_config,
    )
}

pub fn build_runtime_input(
    materialization: &CompiledMaterialization,
    telemetry: &ScenarioTelemetryRequest,
    direct_slot_urls: &BTreeMap<String, String>,
    slot_proxy_bindings: &[SlotRuntimeBinding],
    export_bindings: &[ExportRuntimeBinding],
) -> Result<RuntimeInput, CompileError> {
    let mut env_vars = BTreeMap::new();
    if let Some(root_schema) = materialization.root_schema.as_ref() {
        let merged_root = merge_json(
            materialization.non_secret_root_config.clone(),
            materialization.secret_root_config.clone(),
        );
        for leaf in collect_leaf_paths(root_schema)
            .map_err(|err| CompileError::InvalidRootConfig(err.to_string()))?
        {
            let value = get_by_path_opt(&merged_root, &leaf.path)
                .map_err(|err| CompileError::InvalidRootConfig(err.to_string()))?
                .cloned();
            if let Some(value) = value {
                let env_var = env_var_for_path(&leaf.path)
                    .map_err(|err| CompileError::InvalidRootConfig(err.to_string()))?;
                let encoded = amber_config::encode_env_value(&value)
                    .map_err(|err| CompileError::InvalidRootConfig(err.to_string()))?;
                env_vars.insert(env_var, encoded);
            }
        }
    }

    for (slot, url) in direct_slot_urls {
        env_vars.insert(
            amber_compiler::mesh::external_slot_env_var(slot),
            url.to_string(),
        );
    }

    if let Some(endpoint) = telemetry.upstream_otlp_http_endpoint.as_ref() {
        env_vars.insert(
            "AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT".to_string(),
            endpoint.clone(),
        );
    }

    let mut proxy_plan = ProxyPlan::default();
    for binding in slot_proxy_bindings {
        proxy_plan.slot_bindings.push(crate::runtime::SlotBinding {
            slot: binding.slot_name.clone(),
            upstream: binding.upstream,
        });
    }
    for binding in export_bindings {
        // Prefer the published address for abstract URL rewriting while still
        // keeping the internal loopback listener available for scenario-to-scenario
        // bindings.
        if let Some(published) = binding.published_listen {
            proxy_plan.published_listeners.push(published);
            proxy_plan
                .export_bindings
                .push(crate::runtime::ExportBinding {
                    export: binding.export_name.clone(),
                    listen: published,
                });
        }
        proxy_plan
            .export_bindings
            .push(crate::runtime::ExportBinding {
                export: binding.export_name.clone(),
                listen: binding.internal_listen,
            });
    }

    let mut env_contents = String::new();
    for (key, value) in env_vars {
        env_contents.push_str(&key);
        env_contents.push('=');
        env_contents.push_str(&escape_env_value(&value));
        env_contents.push('\n');
    }

    Ok(RuntimeInput {
        env_contents,
        proxy_plan,
    })
}

pub fn write_runtime_output(
    compose_dir: &Path,
    files: &BTreeMap<PathBuf, String>,
    env_contents: &str,
) -> Result<(), CompileError> {
    if compose_dir.exists() {
        std::fs::remove_dir_all(compose_dir)
            .map_err(|err| CompileError::WriteOutput(err.to_string()))?;
    }
    std::fs::create_dir_all(compose_dir)
        .map_err(|err| CompileError::WriteOutput(err.to_string()))?;
    for (rel_path, content) in files {
        let full_path = compose_dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| CompileError::WriteOutput(err.to_string()))?;
        }
        std::fs::write(&full_path, content)
            .map_err(|err| CompileError::WriteOutput(err.to_string()))?;
    }
    std::fs::write(compose_dir.join(ENV_FILE_NAME), env_contents)
        .map_err(|err| CompileError::WriteOutput(err.to_string()))?;
    Ok(())
}

pub fn root_schema_from_ir(ir: &ScenarioIr) -> Option<Value> {
    root_component(ir).config_schema.clone()
}

async fn compile_and_materialize(
    source_url: &str,
    root_config: &Value,
    external_slots: &BTreeMap<String, crate::domain::ExternalSlotBindingRequest>,
    exports: &BTreeMap<String, ExportRequest>,
    store_bundle: bool,
    bundle_dir: Option<&Path>,
) -> Result<CompiledMaterialization, CompileError> {
    let url = Url::parse(source_url)
        .map_err(|_| CompileError::InvalidSourceUrl(source_url.to_string()))?;
    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let output = if store_bundle {
        let tree = compiler
            .resolve_tree(
                ManifestRef::from_url(url.clone()),
                CompileOptions::default().resolve,
            )
            .await
            .map_err(|err| CompileError::Compile(err.to_string()))?;
        if let Some(bundle_dir) = bundle_dir {
            BundleBuilder::build(&tree, compiler.store(), bundle_dir)
                .map_err(|err| CompileError::Bundle(err.to_string()))?;
        }
        compiler
            .compile_from_tree(tree, CompileOptions::default().optimize)
            .map_err(|err| CompileError::Compile(err.to_string()))?
    } else {
        compiler
            .compile(ManifestRef::from_url(url), CompileOptions::default())
            .await
            .map_err(|err| CompileError::Compile(err.to_string()))?
    };

    let compiled = CompiledScenario::from_compile_output(&output)
        .map_err(|err| CompileError::Compile(err.to_string()))?;
    let scenario_ir = scenario_ir_from_compile_output(&output);
    let scenario_ir_json = serde_json::to_string_pretty(&scenario_ir)
        .map_err(|err| CompileError::Compile(err.to_string()))?;
    let compose = DockerComposeReporter
        .emit(&compiled)
        .map_err(|err| CompileError::Compile(err.to_string()))?;
    let proxy_metadata = extract_proxy_metadata(&compose.files)?;
    validate_slot_request(&proxy_metadata, external_slots)?;
    validate_export_request(&proxy_metadata, exports)?;
    let root_schema = root_schema_from_ir(&scenario_ir);
    let (non_secret_root_config, secret_root_config) =
        validate_and_split_root_config(root_schema.as_ref(), root_config)?;

    Ok(CompiledMaterialization {
        scenario_ir,
        scenario_ir_json,
        root_schema,
        non_secret_root_config,
        secret_root_config,
        compose_files: compose.files,
        proxy_metadata,
        bundle_root: bundle_dir.map(Path::to_path_buf).filter(|_| store_bundle),
    })
}

fn validate_slot_request(
    metadata: &ProxyMetadata,
    requested: &BTreeMap<String, crate::domain::ExternalSlotBindingRequest>,
) -> Result<(), CompileError> {
    for slot in requested.keys() {
        if !metadata.external_slots.contains_key(slot) {
            return Err(CompileError::UnknownExternalSlot(slot.clone()));
        }
    }
    for (slot, meta) in &metadata.external_slots {
        if meta.required && !requested.contains_key(slot) {
            return Err(CompileError::MissingRequiredExternalSlot(slot.clone()));
        }
    }
    Ok(())
}

fn validate_export_request(
    metadata: &ProxyMetadata,
    requested: &BTreeMap<String, ExportRequest>,
) -> Result<(), CompileError> {
    for export in requested.keys() {
        if !metadata.exports.contains_key(export) {
            return Err(CompileError::UnknownExport(export.clone()));
        }
    }
    Ok(())
}

fn validate_and_split_root_config(
    root_schema: Option<&Value>,
    root_config: &Value,
) -> Result<(Value, Value), CompileError> {
    let Some(schema) = root_schema else {
        if root_config.is_null() || root_config == &json!({}) {
            return Ok((json!({}), json!({})));
        }
        return Err(CompileError::InvalidRootConfig(
            "scenario does not declare root config".to_string(),
        ));
    };

    let mut effective = if root_config.is_null() {
        json!({})
    } else {
        root_config.clone()
    };
    apply_schema_defaults(schema, &mut effective)
        .map_err(|err| CompileError::InvalidRootConfig(err.to_string()))?;
    let validator =
        validator_for(schema).map_err(|err| CompileError::InvalidRootConfig(err.to_string()))?;
    if let Err(err) = validator.validate(&effective) {
        return Err(CompileError::InvalidRootConfig(err.to_string()));
    }

    let (mut non_secret, mut secret) = split_secret_paths(schema, &effective)?;
    normalize_json_object(&mut non_secret);
    normalize_json_object(&mut secret);
    Ok((non_secret, secret))
}

fn compiled_materialization_from_stored_ir(
    scenario_ir_json: &str,
    non_secret_root_config: Value,
    secret_root_config: Value,
) -> Result<CompiledMaterialization, CompileError> {
    let scenario_ir: ScenarioIr = serde_json::from_str(scenario_ir_json)
        .map_err(|err| CompileError::InvalidStoredIr(err.to_string()))?;
    let compiled = CompiledScenario::from_ir(scenario_ir.clone())
        .map_err(|err| CompileError::InvalidStoredIr(err.to_string()))?;
    let compose = DockerComposeReporter
        .emit(&compiled)
        .map_err(|err| CompileError::InvalidStoredIr(err.to_string()))?;
    let proxy_metadata = extract_proxy_metadata(&compose.files)?;
    let root_schema = root_schema_from_ir(&scenario_ir);

    Ok(CompiledMaterialization {
        scenario_ir,
        scenario_ir_json: scenario_ir_json.to_string(),
        root_schema: root_schema.clone(),
        non_secret_root_config,
        secret_root_config,
        compose_files: compose.files,
        proxy_metadata,
        bundle_root: None,
    })
}

fn extract_proxy_metadata(
    files: &BTreeMap<PathBuf, String>,
) -> Result<ProxyMetadata, CompileError> {
    let compose = files
        .get(Path::new("compose.yaml"))
        .ok_or(CompileError::MissingProxyMetadata)?;
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(compose).map_err(|err| CompileError::Compile(err.to_string()))?;
    let mapping = yaml
        .as_mapping()
        .ok_or(CompileError::MissingProxyMetadata)?;
    let key = serde_yaml::Value::String("x-amber".to_string());
    let raw = mapping
        .get(&key)
        .ok_or(CompileError::MissingProxyMetadata)?;
    serde_yaml::from_value(raw.clone()).map_err(|err| CompileError::Compile(err.to_string()))
}

fn root_component(ir: &ScenarioIr) -> &amber_scenario::ir::ComponentIr {
    ir.components
        .iter()
        .find(|component| component.id == ir.root)
        .expect("scenario root component should exist")
}

fn split_secret_paths(schema: &Value, effective: &Value) -> Result<(Value, Value), CompileError> {
    let leaves = collect_leaf_paths(schema)
        .map_err(|err| CompileError::InvalidRootConfig(err.to_string()))?;
    let mut non_secret = Value::Object(Map::new());
    let mut secret = Value::Object(Map::new());
    for leaf in leaves {
        let Some(value) = get_by_path_opt(effective, &leaf.path)
            .map_err(|err| CompileError::InvalidRootConfig(err.to_string()))?
            .cloned()
        else {
            continue;
        };
        if leaf.secret {
            insert_json_path(&mut secret, &leaf.path, value);
        } else {
            insert_json_path(&mut non_secret, &leaf.path, value);
        }
    }
    Ok((non_secret, secret))
}

fn normalize_json_object(value: &mut Value) {
    if value.is_null() {
        *value = Value::Object(Map::new());
    }
}

fn insert_json_path(root: &mut Value, path: &str, value: Value) {
    let mut current = root;
    let mut parts = path.split('.').peekable();
    while let Some(part) = parts.next() {
        let is_last = parts.peek().is_none();
        if is_last {
            if let Some(map) = current.as_object_mut() {
                map.insert(part.to_string(), value);
            }
            return;
        }
        if !current.is_object() {
            *current = Value::Object(Map::new());
        }
        let map = current.as_object_mut().expect("object just created");
        current = map
            .entry(part.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
}

fn escape_env_value(value: &str) -> String {
    if value.contains('\n') || value.contains(' ') || value.contains('"') || value.contains('\'') {
        format!("{value:?}")
    } else {
        value.to_string()
    }
}
