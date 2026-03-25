use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use amber_mesh::{MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME, MeshProvisionOutput};
use amber_scenario::{ComponentId, ProgramMount, Scenario};
use amber_template::{ProgramArgTemplate, TemplatePart, TemplateSpec};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    reporter::{
        CompiledScenario, Reporter, ReporterError,
        execution_guide::{
            GENERATED_ENV_SAMPLE_FILENAME, GENERATED_README_FILENAME, build_execution_guide,
        },
    },
    targets::{
        common::{TargetError as MeshError, component_label},
        mesh::{
            addressing::{
                DockerFrameworkBindingPolicy, LocalAddressing, LocalAddressingOptions,
                build_address_plan,
            },
            mesh_config::{
                MeshAddressing, MeshConfigBuildInput, MeshConfigBuildOptions, RouterPorts,
                build_mesh_config_plan,
            },
            plan::{MeshOptions, MeshPlan, build_mesh_plan, map_program_components},
            ports::placeholder_local_route_ports,
            provision::build_mesh_provision_plan,
            proxy_metadata::{
                DEFAULT_EXTERNAL_ENV_FILE, PROXY_METADATA_FILENAME, RouterMetadata,
                build_proxy_metadata,
            },
        },
        program_config::{
            ComponentExecutionPlan, EndpointPlan, ProgramSupport, RuntimeConfigPayload,
            build_component_runtime_plan, build_config_plan,
        },
        storage::{StorageIdentity, StoragePlan, build_storage_plan},
    },
};

pub const DIRECT_PLAN_VERSION: &str = "4";
pub const DIRECT_PLAN_FILENAME: &str = "direct-plan.json";
pub const RUN_SCRIPT_FILENAME: &str = "run.sh";
pub const MESH_PROVISION_PLAN_FILENAME: &str = "mesh-provision-plan.json";
pub const ROUTER_IDENTITY_ID: &str = "/router/direct";
pub const DIRECT_CONTROL_SOCKET_RELATIVE_PATH: &str = ".amber/control/router-control.sock";

const ROUTER_MESH_DIR: &str = "mesh/router";

#[derive(Clone, Copy, Debug, Default)]
pub struct DirectReporter;

#[derive(Clone, Debug)]
pub struct DirectArtifact {
    pub files: BTreeMap<PathBuf, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectPlan {
    pub version: String,
    pub mesh_provision_plan: String,
    pub startup_order: Vec<usize>,
    pub components: Vec<DirectComponentPlan>,
    #[serde(default, skip_serializing_if = "DirectRuntimeAddressPlan::is_empty")]
    pub runtime_addresses: DirectRuntimeAddressPlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router: Option<DirectRouterPlan>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DirectRuntimeAddressPlan {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub slots_by_scope: BTreeMap<usize, BTreeMap<String, DirectRuntimeUrlSource>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub slot_items_by_scope: BTreeMap<usize, BTreeMap<String, Vec<DirectRuntimeUrlSource>>>,
}

impl DirectRuntimeAddressPlan {
    fn is_empty(&self) -> bool {
        self.slots_by_scope.is_empty() && self.slot_items_by_scope.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DirectRuntimeUrlSource {
    Slot {
        component_id: usize,
        slot: String,
        scheme: String,
    },
    SlotItem {
        component_id: usize,
        slot: String,
        item_index: usize,
        scheme: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectComponentPlan {
    pub id: usize,
    pub moniker: String,
    pub log_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<usize>,
    pub sidecar: DirectSidecarPlan,
    pub program: DirectProgramPlan,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectSidecarPlan {
    pub log_name: String,
    pub mesh_port: u16,
    pub mesh_config_path: String,
    pub mesh_identity_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectProgramPlan {
    pub log_name: String,
    pub work_dir: String,
    #[serde(default)]
    pub read_only_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_mounts: Vec<DirectStorageMount>,
    pub execution: DirectProgramExecutionPlan,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectStorageMount {
    pub mount_path: String,
    pub state_subdir: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DirectProgramExecutionPlan {
    Direct {
        entrypoint: Vec<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env: BTreeMap<String, String>,
    },
    HelperRunner {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entrypoint_b64: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env_b64: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        template_spec_b64: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        runtime_config: Option<DirectRuntimeConfigPayload>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mount_spec_b64: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectRuntimeConfigPayload {
    pub root_schema_b64: String,
    pub component_cfg_template_b64: String,
    pub component_schema_b64: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_root_leaf_paths: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectRouterPlan {
    pub identity_id: String,
    pub mesh_port: u16,
    pub control_port: u16,
    pub control_socket_path: String,
    pub mesh_config_path: String,
    pub mesh_identity_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_passthrough: Vec<String>,
}

#[derive(Clone, Debug)]
struct DirectComponentNames {
    base: String,
    mesh_dir: String,
    work_dir: String,
}

impl Reporter for DirectReporter {
    type Artifact = DirectArtifact;

    fn emit(&self, compiled: &CompiledScenario) -> Result<Self::Artifact, ReporterError> {
        render_direct(compiled)
    }
}

fn render_direct(compiled: &CompiledScenario) -> Result<DirectArtifact, ReporterError> {
    render_direct_inner(compiled).map_err(|err| ReporterError::new(err.to_string()))
}

fn render_direct_inner(compiled: &CompiledScenario) -> Result<DirectArtifact, MeshError> {
    let scenario = compiled.scenario();
    let endpoint_plan = crate::targets::program_config::build_endpoint_plan(scenario)?;
    let mesh_plan = build_mesh_plan(
        scenario,
        &endpoint_plan,
        MeshOptions {
            backend_label: "direct reporter",
        },
    )?;
    let program_components = mesh_plan.program_components();
    ensure_direct_mount_sources_supported(scenario, program_components)?;
    ensure_no_endpoint_port_conflicts(&endpoint_plan, scenario, program_components)?;

    let component_names: HashMap<ComponentId, DirectComponentNames> =
        map_program_components(scenario, program_components, |id, local_name| {
            let base = direct_base_name(id, local_name);
            DirectComponentNames {
                mesh_dir: format!("mesh/components/{base}"),
                work_dir: format!("work/components/{base}"),
                base,
            }
        });

    let route_ports = placeholder_local_route_ports(scenario, &endpoint_plan, &mesh_plan);
    let mesh_ports_by_component = placeholder_mesh_ports(program_components);

    let needs_router = mesh_plan.needs_router();
    let router_ports = needs_router.then_some(RouterPorts {
        mesh: 0,
        control: 0,
    });

    let addressing = LocalAddressing::new(
        scenario,
        &route_ports,
        LocalAddressingOptions {
            backend_label: "direct reporter",
            docker_binding: DockerFrameworkBindingPolicy::Unsupported {
                reason: "does not support framework.docker bindings",
            },
        },
    );
    let address_plan = build_address_plan(&mesh_plan, addressing)?;
    let config_plan = build_config_plan(
        scenario,
        compiled.config_analysis(),
        program_components,
        ProgramSupport::Path {
            backend_label: "direct output",
        },
        crate::targets::program_config::RuntimeAddressResolution::Deferred,
        &address_plan.slot_values_by_component,
    )?;
    let storage_plan = build_storage_plan(scenario, program_components);
    let runtime_addresses =
        build_runtime_address_plan(scenario, &address_plan.slot_values_by_component)?;

    let router_mesh_port = router_ports.map_or(0, |ports| ports.mesh);
    let mesh_addressing = LoopbackMeshAddressing {
        mesh_ports_by_component: &mesh_ports_by_component,
        router_mesh_port,
    };
    let mesh_config_plan = build_mesh_config_plan(MeshConfigBuildInput {
        scenario,
        mesh_plan: &mesh_plan,
        route_ports: &route_ports,
        mesh_ports_by_component: &mesh_ports_by_component,
        router_ports,
        addressing: &mesh_addressing,
        options: MeshConfigBuildOptions {
            router_identity_id: ROUTER_IDENTITY_ID,
            component_mesh_listen_addr: "127.0.0.1",
            router_mesh_listen_addr: "127.0.0.1",
            router_control_listen_addr: "127.0.0.1",
        },
    })?;

    let mesh_provision_plan = build_mesh_provision_plan(
        &mesh_config_plan,
        program_components,
        &component_names,
        |name: &DirectComponentNames| MeshProvisionOutput::Filesystem {
            dir: name.mesh_dir.clone(),
        },
        || MeshProvisionOutput::Filesystem {
            dir: ROUTER_MESH_DIR.to_string(),
        },
        |_router_config| {},
    )?;

    let router_metadata = router_ports.map(|ports| RouterMetadata {
        mesh_port: ports.mesh,
        control_port: 0,
        control_socket: Some(DIRECT_CONTROL_SOCKET_RELATIVE_PATH.to_string()),
        control_socket_volume: None,
    });
    let proxy_metadata =
        needs_router.then_some(build_proxy_metadata(scenario, &mesh_plan, router_metadata));

    let startup_order = topological_startup_order(program_components, &mesh_plan)?;
    let startup_order_ids = startup_order.iter().map(|id| id.0).collect::<Vec<_>>();
    let components = build_component_plans(DirectComponentPlanInputs {
        scenario,
        mesh_plan: &mesh_plan,
        config_plan: &config_plan,
        storage_plan: &storage_plan,
        component_names: &component_names,
        mesh_ports_by_component: &mesh_ports_by_component,
        compiled,
        program_components,
    })?;

    let router_plan = router_ports.map(|ports| DirectRouterPlan {
        identity_id: ROUTER_IDENTITY_ID.to_string(),
        mesh_port: ports.mesh,
        control_port: 0,
        control_socket_path: DIRECT_CONTROL_SOCKET_RELATIVE_PATH.to_string(),
        mesh_config_path: mesh_config_relative_path(ROUTER_MESH_DIR),
        mesh_identity_path: mesh_identity_relative_path(ROUTER_MESH_DIR),
        env_passthrough: mesh_config_plan.router_env_passthrough.clone(),
    });

    let direct_plan = DirectPlan {
        version: DIRECT_PLAN_VERSION.to_string(),
        mesh_provision_plan: MESH_PROVISION_PLAN_FILENAME.to_string(),
        startup_order: startup_order_ids,
        components,
        runtime_addresses,
        router: router_plan,
    };

    let mut files = BTreeMap::new();
    files.insert(PathBuf::from(RUN_SCRIPT_FILENAME), render_run_script());
    files.insert(
        PathBuf::from(DIRECT_PLAN_FILENAME),
        serde_json::to_string_pretty(&direct_plan)
            .map_err(|err| MeshError::new(format!("failed to serialize direct plan: {err}")))?,
    );
    files.insert(
        PathBuf::from(MESH_PROVISION_PLAN_FILENAME),
        serde_json::to_string_pretty(&mesh_provision_plan).map_err(|err| {
            MeshError::new(format!("failed to serialize mesh provision plan: {err}"))
        })?,
    );

    if let Some(proxy_metadata) = proxy_metadata {
        files.insert(
            PathBuf::from(PROXY_METADATA_FILENAME),
            serde_json::to_string_pretty(&proxy_metadata).map_err(|err| {
                MeshError::new(format!("failed to serialize proxy metadata: {err}"))
            })?,
        );
    }

    if needs_router && !mesh_config_plan.router_env_passthrough.is_empty() {
        let mut env_content = String::new();
        env_content.push_str("# Router external slot URLs - fill in values before running\n");
        for env_var in mesh_config_plan.router_env_passthrough {
            env_content.push_str(&format!("{env_var}=\n"));
        }
        files.insert(PathBuf::from(DEFAULT_EXTERNAL_ENV_FILE), env_content);
    }

    let execution_guide =
        build_execution_guide(scenario, &mesh_plan, &config_plan, !storage_plan.is_empty())
            .map_err(|err: ReporterError| MeshError::new(err.to_string()))?;
    files.insert(
        PathBuf::from(GENERATED_ENV_SAMPLE_FILENAME),
        execution_guide.render_env_sample(false, "direct"),
    );
    files.insert(
        PathBuf::from(GENERATED_README_FILENAME),
        execution_guide
            .render_direct_readme(files.contains_key(&PathBuf::from(DEFAULT_EXTERNAL_ENV_FILE))),
    );

    Ok(DirectArtifact { files })
}

struct DirectComponentPlanInputs<'a> {
    scenario: &'a Scenario,
    mesh_plan: &'a MeshPlan,
    config_plan: &'a crate::targets::program_config::ConfigPlan,
    storage_plan: &'a StoragePlan,
    component_names: &'a HashMap<ComponentId, DirectComponentNames>,
    mesh_ports_by_component: &'a HashMap<ComponentId, u16>,
    compiled: &'a CompiledScenario,
    program_components: &'a [ComponentId],
}

fn build_component_plans(
    inputs: DirectComponentPlanInputs<'_>,
) -> Result<Vec<DirectComponentPlan>, MeshError> {
    let DirectComponentPlanInputs {
        scenario,
        mesh_plan,
        config_plan,
        storage_plan,
        component_names,
        mesh_ports_by_component,
        compiled,
        program_components,
    } = inputs;
    let mut out = Vec::with_capacity(program_components.len());
    for id in program_components {
        let component = scenario.component(*id);
        let program_plan = config_plan.program_plans.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing program plan for {}",
                component_label(scenario, *id)
            ))
        })?;
        let runtime_plan = build_component_runtime_plan(
            component.moniker.as_str(),
            program_plan,
            config_plan.mount_specs.get(id).map(Vec::as_slice),
            config_plan.runtime_views.get(id),
            false,
            false,
        )?;
        let names = component_names.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing direct component names for {}",
                component.moniker.as_str()
            ))
        })?;
        let mesh_port = *mesh_ports_by_component.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing sidecar mesh port for {}",
                component.moniker.as_str()
            ))
        })?;
        let depends_on = mesh_plan
            .strong_deps()
            .get(id)
            .map(|deps| deps.iter().map(|dep| dep.0).collect::<Vec<_>>())
            .unwrap_or_default();
        let source_dir = component_source_dir(compiled, *id, component.moniker.as_str())?;
        let execution = resolve_direct_execution_plan(
            direct_execution_plan(runtime_plan.execution),
            source_dir.as_deref(),
            component.moniker.as_str(),
        )?;
        let read_only_paths =
            direct_program_read_only_paths(component.program.as_ref(), source_dir.as_deref())?;

        out.push(DirectComponentPlan {
            id: id.0,
            moniker: component.moniker.as_str().to_string(),
            log_name: names.base.clone(),
            source_dir: source_dir
                .as_ref()
                .map(|source_dir| source_dir.display().to_string()),
            depends_on,
            sidecar: DirectSidecarPlan {
                log_name: format!("{}-sidecar", names.base),
                mesh_port,
                mesh_config_path: mesh_config_relative_path(&names.mesh_dir),
                mesh_identity_path: mesh_identity_relative_path(&names.mesh_dir),
            },
            program: DirectProgramPlan {
                log_name: format!("{}-program", names.base),
                work_dir: names.work_dir.clone(),
                read_only_paths,
                storage_mounts: direct_storage_mounts(
                    storage_plan.mounts_by_component.get(id).map(Vec::as_slice),
                ),
                execution,
            },
        });
    }
    Ok(out)
}

fn direct_storage_mounts(
    mounts: Option<&[crate::targets::storage::StorageMount]>,
) -> Vec<DirectStorageMount> {
    let mut out = Vec::new();
    for mount in mounts.into_iter().flatten() {
        out.push(DirectStorageMount {
            mount_path: mount.mount_path.clone(),
            state_subdir: direct_storage_state_subdir(&mount.identity),
        });
    }
    out
}

fn direct_program_read_only_paths(
    program: Option<&amber_scenario::Program>,
    source_dir: Option<&Path>,
) -> Result<Vec<String>, MeshError> {
    let Some(amber_scenario::Program::Path(program)) = program else {
        return Ok(Vec::new());
    };

    let Some(reads) = program.reads.as_ref() else {
        return Ok(source_dir
            .into_iter()
            .map(|path| path.display().to_string())
            .collect());
    };

    let mut paths = BTreeSet::new();
    for read in reads {
        paths.insert(resolve_direct_read_path(read, source_dir)?);
    }
    Ok(paths.into_iter().collect())
}

fn resolve_direct_read_path(path: &str, source_dir: Option<&Path>) -> Result<String, MeshError> {
    let read_path = Path::new(path);
    if read_path.is_absolute() {
        return Ok(path.to_string());
    }

    let source_dir = source_dir.ok_or_else(|| {
        MeshError::new(format!(
            "direct program read path `{path}` is relative, but Amber can only resolve relative \
             reads for components compiled from local file manifests"
        ))
    })?;
    if !source_dir.is_absolute() {
        return Err(MeshError::new(format!(
            "component source directory {} is not absolute; cannot resolve direct read path \
             `{path}`",
            source_dir.display()
        )));
    }

    Ok(source_dir.join(read_path).display().to_string())
}

fn direct_storage_state_subdir(identity: &StorageIdentity) -> String {
    format!(
        "{}/{}-{}",
        direct_storage_component_slug(identity.owner_moniker.as_str()),
        sanitize_storage_segment(identity.resource.as_str()),
        identity.hash_suffix()
    )
}

fn direct_storage_component_slug(component_moniker: &str) -> String {
    let trimmed = component_moniker.trim_matches('/');
    if trimmed.is_empty() {
        return "root".to_string();
    }
    trimmed
        .split('/')
        .map(sanitize_storage_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn sanitize_storage_segment(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    let out = out.trim_matches('-');
    if out.is_empty() {
        "storage".to_string()
    } else {
        out.to_string()
    }
}

fn direct_execution_plan(execution: ComponentExecutionPlan<'_>) -> DirectProgramExecutionPlan {
    match execution {
        ComponentExecutionPlan::Resolved { entrypoint, env } => {
            DirectProgramExecutionPlan::Direct {
                entrypoint: entrypoint.to_vec(),
                env: env.clone(),
            }
        }
        ComponentExecutionPlan::HelperRunner {
            entrypoint_b64,
            env_b64,
            template_spec_b64,
            runtime_config,
            mount_spec_b64,
        } => DirectProgramExecutionPlan::HelperRunner {
            entrypoint_b64,
            env_b64,
            template_spec_b64,
            runtime_config: runtime_config.map(direct_runtime_config_payload),
            mount_spec_b64,
        },
    }
}

fn direct_runtime_config_payload(payload: RuntimeConfigPayload<'_>) -> DirectRuntimeConfigPayload {
    DirectRuntimeConfigPayload {
        root_schema_b64: payload.root_schema_b64,
        component_cfg_template_b64: payload.component_cfg_template_b64,
        component_schema_b64: payload.component_schema_b64,
        allowed_root_leaf_paths: payload.allowed_root_leaf_paths.iter().cloned().collect(),
    }
}

fn component_source_dir(
    compiled: &CompiledScenario,
    id: ComponentId,
    component_moniker: &str,
) -> Result<Option<PathBuf>, MeshError> {
    let Some(resolved_url) = compiled.resolved_url_for_component(id) else {
        return Ok(None);
    };
    if resolved_url.scheme() != "file" {
        return Ok(None);
    }

    let manifest_path = resolved_url.to_file_path().map_err(|_| {
        MeshError::new(format!(
            "failed to convert resolved_url {} to a local path for component {}",
            resolved_url, component_moniker
        ))
    })?;
    let source_dir = manifest_path.parent().ok_or_else(|| {
        MeshError::new(format!(
            "manifest path {} has no parent directory for component {}",
            manifest_path.display(),
            component_moniker
        ))
    })?;
    Ok(Some(source_dir.to_path_buf()))
}

fn resolve_direct_execution_plan(
    execution: DirectProgramExecutionPlan,
    source_dir: Option<&Path>,
    component_moniker: &str,
) -> Result<DirectProgramExecutionPlan, MeshError> {
    match execution {
        DirectProgramExecutionPlan::Direct {
            mut entrypoint,
            env,
        } => {
            let Some(program) = entrypoint.first_mut() else {
                return Err(MeshError::new(format!(
                    "component {component_moniker} program entrypoint must not be empty"
                )));
            };
            *program = resolve_direct_program_path(program, source_dir, component_moniker)?;
            Ok(DirectProgramExecutionPlan::Direct { entrypoint, env })
        }
        DirectProgramExecutionPlan::HelperRunner {
            entrypoint_b64,
            env_b64,
            template_spec_b64,
            runtime_config,
            mount_spec_b64,
        } => Ok(DirectProgramExecutionPlan::HelperRunner {
            entrypoint_b64: entrypoint_b64
                .as_deref()
                .map(|raw| resolve_helper_entrypoint_payload(raw, source_dir, component_moniker))
                .transpose()?,
            env_b64,
            template_spec_b64: template_spec_b64
                .as_deref()
                .map(|raw| resolve_helper_template_spec_payload(raw, source_dir, component_moniker))
                .transpose()?,
            runtime_config,
            mount_spec_b64,
        }),
    }
}

fn resolve_helper_entrypoint_payload(
    raw_b64: &str,
    source_dir: Option<&Path>,
    component_moniker: &str,
) -> Result<String, MeshError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw_b64.as_bytes())
        .map_err(|err| MeshError::new(format!("invalid entrypoint payload: {err}")))?;
    let mut entrypoint: Vec<String> = serde_json::from_slice(&decoded)
        .map_err(|err| MeshError::new(format!("invalid entrypoint payload: {err}")))?;
    let Some(program) = entrypoint.first_mut() else {
        return Err(MeshError::new("entrypoint payload is empty"));
    };
    *program = resolve_direct_program_path(program, source_dir, component_moniker)?;

    let encoded = serde_json::to_vec(&entrypoint)
        .map_err(|err| MeshError::new(format!("failed to encode entrypoint payload: {err}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(encoded))
}

fn resolve_helper_template_spec_payload(
    raw_b64: &str,
    source_dir: Option<&Path>,
    component_moniker: &str,
) -> Result<String, MeshError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw_b64.as_bytes())
        .map_err(|err| MeshError::new(format!("invalid template spec payload: {err}")))?;
    let mut spec: TemplateSpec = serde_json::from_slice(&decoded)
        .map_err(|err| MeshError::new(format!("invalid template spec payload: {err}")))?;
    let program = decode_template_spec_program(raw_b64)?;
    let resolved = resolve_direct_program_path(&program, source_dir, component_moniker)?;
    let Some(path_template) = spec.program.entrypoint.first_mut() else {
        return Err(MeshError::new("template spec program entrypoint is empty"));
    };
    *path_template = ProgramArgTemplate::Arg(vec![TemplatePart::lit(resolved)]);

    let encoded = serde_json::to_vec(&spec)
        .map_err(|err| MeshError::new(format!("failed to encode template spec payload: {err}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(encoded))
}

fn decode_template_spec_program(raw_b64: &str) -> Result<String, MeshError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw_b64.as_bytes())
        .map_err(|err| MeshError::new(format!("invalid template spec payload: {err}")))?;
    let spec: TemplateSpec = serde_json::from_slice(&decoded)
        .map_err(|err| MeshError::new(format!("invalid template spec payload: {err}")))?;
    let path_template = spec
        .program
        .entrypoint
        .first()
        .ok_or_else(|| MeshError::new("template spec program entrypoint is empty"))?;
    render_program_arg_template_literal(path_template)
}

fn render_program_arg_template_literal(arg: &ProgramArgTemplate) -> Result<String, MeshError> {
    let ProgramArgTemplate::Arg(parts) = arg else {
        return Err(MeshError::new(
            "internal error: template spec program entrypoint starts with a conditional arg item",
        ));
    };
    render_template_string_literal(parts)
}

fn render_template_string_literal(parts: &[TemplatePart]) -> Result<String, MeshError> {
    let mut out = String::new();
    for part in parts {
        match part {
            TemplatePart::Lit { lit } => out.push_str(lit),
            TemplatePart::Config { config } => {
                return Err(MeshError::new(format!(
                    "internal error: unresolved runtime config interpolation `{config}` in direct \
                     program path"
                )));
            }
            TemplatePart::Slot { slot, .. } => {
                return Err(MeshError::new(format!(
                    "internal error: unresolved slot interpolation `{slot}` in direct program path"
                )));
            }
            TemplatePart::Item { item, .. } => {
                return Err(MeshError::new(format!(
                    "internal error: unresolved repeated item interpolation `{item}` in direct \
                     program path"
                )));
            }
            TemplatePart::CurrentItem { item } => {
                return Err(MeshError::new(format!(
                    "internal error: unresolved repeated item interpolation `{item}` in direct \
                     program path"
                )));
            }
        }
    }
    if out.is_empty() {
        return Err(MeshError::new(
            "internal error: template spec program entrypoint is empty",
        ));
    }
    Ok(out)
}

fn resolve_direct_program_path(
    program: &str,
    source_dir: Option<&Path>,
    component_moniker: &str,
) -> Result<String, MeshError> {
    let program_path = Path::new(program);
    if program_path.is_absolute() {
        return Ok(program.to_string());
    }

    let has_separator = program.contains('/') || program.contains('\\');
    if !has_separator {
        return Err(MeshError::new(format!(
            "component {component_moniker} uses program path `{program}` without a path \
             separator; direct execution does not search PATH, so use an absolute path or a \
             manifest-relative path like `./bin/server`"
        )));
    }

    let source_dir = source_dir.ok_or_else(|| {
        MeshError::new(format!(
            "component {component_moniker} uses relative program path `{program}`, but direct \
             output can only resolve relative executables for components with a local file \
             `resolved_url`"
        ))
    })?;
    if !source_dir.is_absolute() {
        return Err(MeshError::new(format!(
            "component {component_moniker} has non-absolute source directory {}; cannot resolve \
             relative program path `{program}`",
            source_dir.display()
        )));
    }

    Ok(source_dir.join(program_path).display().to_string())
}

fn mesh_config_relative_path(dir: &str) -> String {
    format!("{dir}/{MESH_CONFIG_FILENAME}")
}

fn mesh_identity_relative_path(dir: &str) -> String {
    format!("{dir}/{MESH_IDENTITY_FILENAME}")
}

fn render_run_script() -> String {
    r#"#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec amber run "$SCRIPT_DIR" "$@"
"#
    .to_string()
}

fn direct_base_name(id: ComponentId, local_name: &str) -> String {
    let mut out = format!("c{}-", id.0);
    for ch in local_name.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.ends_with(':') {
        out.pop();
    }
    if out == format!("c{}-", id.0) {
        out.push_str("component");
    }
    out
}

fn ensure_direct_mount_sources_supported(
    scenario: &Scenario,
    program_components: &[ComponentId],
) -> Result<(), MeshError> {
    for id in program_components {
        let component = scenario.component(*id);
        let Some(program) = component.program.as_ref() else {
            continue;
        };
        for mount in program.mounts() {
            if let ProgramMount::Framework { capability, .. } = mount {
                return Err(MeshError::new(format!(
                    "component {} uses framework mount source `framework.{}`, which is not \
                     supported by direct output",
                    component.moniker.as_str(),
                    capability.as_str(),
                )));
            }
        }
    }
    Ok(())
}

fn ensure_no_endpoint_port_conflicts(
    endpoint_plan: &EndpointPlan,
    scenario: &Scenario,
    program_components: &[ComponentId],
) -> Result<(), MeshError> {
    let mut by_port: BTreeMap<u16, Vec<String>> = BTreeMap::new();
    for id in program_components {
        let component = scenario.component(*id);
        for endpoint in endpoint_plan.component_endpoints(*id) {
            by_port.entry(endpoint.port).or_default().push(format!(
                "{}:{}",
                component.moniker.as_str(),
                endpoint.name
            ));
        }
    }

    let mut conflicts = Vec::new();
    for (port, uses) in by_port {
        if uses.len() > 1 {
            conflicts.push(format!("port {port}: {}", uses.join(", ")));
        }
    }
    if conflicts.is_empty() {
        return Ok(());
    }

    Err(MeshError::new(format!(
        "direct output requires unique program endpoint ports across all components; found \
         conflicts:\n{}",
        conflicts.join("\n")
    )))
}
fn placeholder_mesh_ports(program_components: &[ComponentId]) -> HashMap<ComponentId, u16> {
    let mut out = HashMap::new();
    for id in program_components {
        out.insert(*id, 0);
    }
    out
}

fn build_runtime_address_plan(
    scenario: &Scenario,
    slot_values_by_component: &HashMap<ComponentId, BTreeMap<String, crate::slots::SlotValue>>,
) -> Result<DirectRuntimeAddressPlan, MeshError> {
    let mut slots_by_scope = BTreeMap::new();
    let mut slot_items_by_scope = BTreeMap::new();
    for (scope, slots) in slot_values_by_component {
        let mut singular_entries = BTreeMap::new();
        let mut repeated_entries = BTreeMap::new();
        for (slot, value) in slots {
            let slot_decl = scenario
                .component(*scope)
                .slots
                .get(slot.as_str())
                .ok_or_else(|| {
                    MeshError::new(format!(
                        "missing slot declaration for {}.{} while building direct runtime \
                         addresses",
                        component_label(scenario, *scope),
                        slot
                    ))
                })?;
            match (slot_decl.multiple, value) {
                (true, crate::slots::SlotValue::One(value)) => {
                    repeated_entries.insert(
                        slot.clone(),
                        vec![DirectRuntimeUrlSource::SlotItem {
                            component_id: scope.0,
                            slot: slot.clone(),
                            item_index: 0,
                            scheme: url_scheme(&value.url)?,
                        }],
                    );
                }
                (false, crate::slots::SlotValue::One(value)) => {
                    singular_entries.insert(
                        slot.clone(),
                        DirectRuntimeUrlSource::Slot {
                            component_id: scope.0,
                            slot: slot.clone(),
                            scheme: url_scheme(&value.url)?,
                        },
                    );
                }
                (_, crate::slots::SlotValue::Many(values)) => {
                    let mut sources = Vec::with_capacity(values.len());
                    for (item_index, value) in values.iter().enumerate() {
                        sources.push(DirectRuntimeUrlSource::SlotItem {
                            component_id: scope.0,
                            slot: slot.clone(),
                            item_index,
                            scheme: url_scheme(&value.url)?,
                        });
                    }
                    repeated_entries.insert(slot.clone(), sources);
                }
            }
        }
        if !singular_entries.is_empty() {
            slots_by_scope.insert(scope.0, singular_entries);
        }
        if !repeated_entries.is_empty() {
            slot_items_by_scope.insert(scope.0, repeated_entries);
        }
    }

    Ok(DirectRuntimeAddressPlan {
        slots_by_scope,
        slot_items_by_scope,
    })
}

fn url_scheme(raw: &str) -> Result<String, MeshError> {
    Url::parse(raw)
        .map_err(|err| MeshError::new(format!("invalid direct runtime URL {raw}: {err}")))
        .map(|url| url.scheme().to_string())
}

fn topological_startup_order(
    program_components: &[ComponentId],
    mesh_plan: &MeshPlan,
) -> Result<Vec<ComponentId>, MeshError> {
    let mut indegree: HashMap<ComponentId, usize> = HashMap::new();
    let mut dependents: HashMap<ComponentId, BTreeSet<ComponentId>> = HashMap::new();
    for id in program_components {
        indegree.insert(*id, 0);
    }

    for (consumer, deps) in mesh_plan.strong_deps() {
        if !indegree.contains_key(consumer) {
            continue;
        }
        for dep in deps {
            if !indegree.contains_key(dep) {
                continue;
            }
            *indegree.get_mut(consumer).expect("consumer should exist") += 1;
            dependents.entry(*dep).or_default().insert(*consumer);
        }
    }

    let mut ready: BTreeSet<ComponentId> = indegree
        .iter()
        .filter_map(|(id, &count)| (count == 0).then_some(*id))
        .collect();
    let mut order = Vec::with_capacity(indegree.len());

    while let Some(next) = ready.pop_first() {
        order.push(next);
        if let Some(consumers) = dependents.get(&next) {
            for consumer in consumers {
                let degree = indegree
                    .get_mut(consumer)
                    .expect("consumer indegree should exist");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(*consumer);
                }
            }
        }
    }

    if order.len() != indegree.len() {
        return Err(MeshError::new(
            "internal error: component dependency graph contains a cycle",
        ));
    }
    Ok(order)
}

struct LoopbackMeshAddressing<'a> {
    mesh_ports_by_component: &'a HashMap<ComponentId, u16>,
    router_mesh_port: u16,
}

impl MeshAddressing for LoopbackMeshAddressing<'_> {
    fn mesh_addr_for_component(&self, id: ComponentId) -> Result<String, MeshError> {
        let port = self
            .mesh_ports_by_component
            .get(&id)
            .ok_or_else(|| MeshError::new(format!("missing mesh port for component {id:?}")))?;
        Ok(format!("127.0.0.1:{port}"))
    }

    fn mesh_addr_for_router(&self) -> Result<String, MeshError> {
        Ok(format!("127.0.0.1:{}", self.router_mesh_port))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        path::Path,
        sync::Arc,
    };

    use amber_manifest::{Manifest, ProgramEntrypoint};
    use amber_scenario::{
        BindingEdge, Component, Moniker, Program, ProgramCommon, ProgramPath, Scenario,
    };

    use super::*;
    use crate::{
        slots::{SlotObject, SlotValue},
        targets::storage::{StorageIdentity, StorageMount},
    };

    fn test_scenario() -> Scenario {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              slots: {
                api: { kind: "http", optional: true },
                upstream: { kind: "http", optional: true, multiple: true },
              },
            }
        "#
        .parse()
        .expect("manifest");

        Scenario {
            root: ComponentId(0),
            components: vec![Some(Component {
                id: ComponentId(0),
                parent: None,
                moniker: Moniker::from(Arc::<str>::from("/")),
                digest: amber_manifest::ManifestDigest::new([0; 32]),
                config: None,
                config_schema: None,
                program: None,
                slots: manifest
                    .slots()
                    .iter()
                    .map(|(name, decl)| (name.to_string(), decl.clone()))
                    .collect(),
                provides: BTreeMap::new(),
                resources: BTreeMap::new(),
                metadata: None,
                children: Vec::new(),
            })],
            bindings: Vec::<BindingEdge>::new(),
            exports: Vec::new(),
        }
    }

    #[test]
    fn resolve_helper_entrypoint_payload_rewrites_relative_program() {
        let payload = base64::engine::general_purpose::STANDARD.encode(
            serde_json::to_vec(&vec!["./bin/server", "--port", "8080"])
                .expect("entrypoint should serialize"),
        );

        let resolved =
            resolve_helper_entrypoint_payload(&payload, Some(Path::new("/workspace/app")), "app")
                .expect("payload should resolve");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(resolved.as_bytes())
            .expect("payload should decode");
        let entrypoint: Vec<String> =
            serde_json::from_slice(&decoded).expect("payload should parse");

        assert_eq!(entrypoint[0], "/workspace/app/./bin/server");
        assert_eq!(entrypoint[1], "--port");
        assert_eq!(entrypoint[2], "8080");
    }

    #[test]
    fn resolve_helper_template_spec_payload_rewrites_relative_program() {
        let spec = TemplateSpec {
            program: amber_template::ProgramTemplateSpec {
                entrypoint: vec![
                    ProgramArgTemplate::Arg(vec![TemplatePart::lit("./bin/server")]),
                    ProgramArgTemplate::Arg(vec![TemplatePart::lit("--port")]),
                    ProgramArgTemplate::Arg(vec![TemplatePart::lit("8080")]),
                ],
                env: BTreeMap::new(),
            },
        };
        let payload = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&spec).expect("template spec should serialize"));

        let resolved = resolve_helper_template_spec_payload(
            &payload,
            Some(Path::new("/workspace/app")),
            "app",
        )
        .expect("payload should resolve");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(resolved.as_bytes())
            .expect("payload should decode");
        let spec: TemplateSpec = serde_json::from_slice(&decoded).expect("payload should parse");

        assert_eq!(
            spec.program.entrypoint[0],
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("/workspace/app/./bin/server")])
        );
    }

    #[test]
    fn direct_program_read_only_paths_preserve_legacy_source_dir_when_reads_are_omitted() {
        let paths = direct_program_read_only_paths(
            Some(&Program::Path(ProgramPath {
                path: "./bin/server".to_string(),
                args: ProgramEntrypoint::default(),
                reads: None,
                common: ProgramCommon::default(),
            })),
            Some(Path::new("/workspace/app")),
        )
        .expect("legacy read-only paths should resolve");

        assert_eq!(paths, vec!["/workspace/app".to_string()]);
    }

    #[test]
    fn direct_program_read_only_paths_use_explicit_reads_exactly() {
        let paths = direct_program_read_only_paths(
            Some(&Program::Path(ProgramPath {
                path: "./bin/server".to_string(),
                args: ProgramEntrypoint::default(),
                reads: Some(vec!["./templates".to_string(), "/srv/shared".to_string()]),
                common: ProgramCommon::default(),
            })),
            Some(Path::new("/workspace/app")),
        )
        .expect("explicit read-only paths should resolve");

        assert_eq!(
            paths,
            vec![
                "/srv/shared".to_string(),
                "/workspace/app/./templates".to_string(),
            ]
        );
    }

    #[test]
    fn resolve_direct_program_path_requires_local_file_provenance_for_relative_paths() {
        let err = resolve_direct_program_path("./bin/server", None, "app")
            .expect_err("relative path without source dir should fail");
        assert!(
            err.to_string().contains("local file `resolved_url`"),
            "{}",
            err
        );
    }

    #[test]
    fn direct_storage_state_subdir_includes_identity_hash() {
        let mounts = vec![
            StorageMount {
                identity: StorageIdentity {
                    owner: ComponentId(0),
                    owner_moniker: "/Db".to_string(),
                    resource: "state".to_string(),
                },
                slot: "state".to_string(),
                mount_path: "/var/lib/db".to_string(),
            },
            StorageMount {
                identity: StorageIdentity {
                    owner: ComponentId(1),
                    owner_moniker: "/db".to_string(),
                    resource: "state".to_string(),
                },
                slot: "state".to_string(),
                mount_path: "/var/lib/db".to_string(),
            },
        ];

        let mounts = direct_storage_mounts(Some(&mounts));
        assert_ne!(mounts[0].state_subdir, mounts[1].state_subdir);
        assert!(mounts[0].state_subdir.starts_with("db/state-"));
        assert!(mounts[1].state_subdir.starts_with("db/state-"));
    }

    #[test]
    fn build_runtime_address_plan_preserves_slot_item_order() {
        let slot_values_by_component = HashMap::from([(
            ComponentId(0),
            BTreeMap::from([
                (
                    "api".to_string(),
                    SlotValue::One(SlotObject {
                        url: "http://127.0.0.1:31001".to_string(),
                    }),
                ),
                (
                    "upstream".to_string(),
                    SlotValue::Many(vec![
                        SlotObject {
                            url: "http://127.0.0.1:32001".to_string(),
                        },
                        SlotObject {
                            url: "http://127.0.0.1:32002".to_string(),
                        },
                    ]),
                ),
            ]),
        )]);
        let plan = build_runtime_address_plan(&test_scenario(), &slot_values_by_component)
            .expect("runtime address plan");

        assert!(matches!(
            plan.slots_by_scope.get(&0).and_then(|slots| slots.get("api")),
            Some(DirectRuntimeUrlSource::Slot {
                component_id: 0,
                slot,
                scheme
            }) if slot == "api" && scheme == "http"
        ));
        let slot_items = plan
            .slot_items_by_scope
            .get(&0)
            .and_then(|slots| slots.get("upstream"))
            .expect("slot items");
        assert_eq!(slot_items.len(), 2);
        assert!(matches!(
            &slot_items[0],
            DirectRuntimeUrlSource::SlotItem {
                component_id: 0,
                slot,
                item_index: 0,
                scheme,
            } if slot == "upstream" && scheme == "http"
        ));
        assert!(matches!(
            &slot_items[1],
            DirectRuntimeUrlSource::SlotItem {
                component_id: 0,
                slot,
                item_index: 1,
                scheme,
            } if slot == "upstream" && scheme == "http"
        ));
    }

    #[test]
    fn build_runtime_address_plan_emits_slot_items_for_repeated_slot_with_one_binding() {
        let slot_values_by_component = HashMap::from([(
            ComponentId(0),
            BTreeMap::from([(
                "api".to_string(),
                SlotValue::One(SlotObject {
                    url: "http://127.0.0.1:31001".to_string(),
                }),
            )]),
        )]);
        let mut scenario = test_scenario();
        let manifest: amber_manifest::Manifest = r#"
            {
              manifest_version: "0.3.0",
              slots: {
                api: { kind: "http", optional: true, multiple: true },
              },
            }
        "#
        .parse()
        .expect("manifest");
        scenario.components[0]
            .as_mut()
            .expect("root component should exist")
            .slots
            .insert(
                "api".to_string(),
                manifest
                    .slots()
                    .get("api")
                    .expect("slot decl should exist")
                    .clone(),
            );

        let plan =
            build_runtime_address_plan(&scenario, &slot_values_by_component).expect("runtime plan");

        assert!(
            !plan.slots_by_scope.contains_key(&0),
            "repeated slots should not be exposed as singular runtime slots"
        );
        let slot_items = plan
            .slot_items_by_scope
            .get(&0)
            .and_then(|slots| slots.get("api"))
            .expect("slot items");
        assert_eq!(slot_items.len(), 1);
        assert!(matches!(
            &slot_items[0],
            DirectRuntimeUrlSource::SlotItem {
                component_id: 0,
                slot,
                item_index: 0,
                scheme,
            } if slot == "api" && scheme == "http"
        ));
    }
}
