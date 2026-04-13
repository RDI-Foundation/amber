use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use amber_manifest::{InterpolatedPart, VmEgress};
use amber_mesh::{MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME, MeshProvisionOutput};
use amber_scenario::{ComponentId, Program, ProgramMount, ProgramVm, Scenario};
use amber_template::{TemplatePart, TemplateString};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    config::analysis::ComponentConfigAnalysis,
    reporter::{
        CompiledScenario, Reporter, ReporterError,
        execution_guide::{
            GENERATED_ENV_SAMPLE_FILENAME, GENERATED_README_FILENAME, build_execution_guide,
        },
    },
    targets::{
        common::{TargetError as MeshError, component_label},
        direct::{
            DIRECT_CONTROL_SOCKET_RELATIVE_PATH, DirectRuntimeAddressPlan,
            DirectRuntimeConfigPayload, DirectRuntimeUrlSource,
        },
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
            ComponentExecutionPlan, ProgramSupport, RuntimeAddressResolution, RuntimeConfigPayload,
            VmScalarResolutionU32, build_component_runtime_plan, build_config_plan,
            build_vm_cloud_init_template_string, resolve_slot_interpolation, resolve_vm_scalar_u32,
        },
        storage::{StorageIdentity, StorageMount, StoragePlan, build_storage_plan},
    },
};

pub const VM_PLAN_VERSION: &str = "1";
pub const VM_PLAN_FILENAME: &str = "vm-plan.json";
pub const VM_RUN_SCRIPT_FILENAME: &str = "run.sh";
pub const MESH_PROVISION_PLAN_FILENAME: &str = "mesh-provision-plan.json";
pub const ROUTER_IDENTITY_ID: &str = "/router/vm";
pub const VM_RUNTIME_SLOT_HOST: &str = "10.0.2.100";

const ROUTER_MESH_DIR: &str = "mesh/router";
const DEFAULT_STORAGE_SIZE: &str = "1G";

#[derive(Clone, Copy, Debug, Default)]
pub struct VmReporter;

#[derive(Clone, Debug)]
pub struct VmArtifact {
    pub files: BTreeMap<PathBuf, String>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct VmArtifactBuildOptions<'a> {
    pub(crate) force_router: bool,
    pub(crate) router_identity_id: &'a str,
    pub(crate) mesh_scope: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmPlan {
    pub version: String,
    pub mesh_provision_plan: String,
    pub startup_order: Vec<usize>,
    #[serde(default, skip_serializing_if = "vm_runtime_addresses_is_empty")]
    pub runtime_addresses: DirectRuntimeAddressPlan,
    pub components: Vec<VmComponentPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router: Option<VmRouterPlan>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmComponentPlan {
    pub id: usize,
    pub moniker: String,
    pub log_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<usize>,
    pub mesh_config_path: String,
    pub mesh_identity_path: String,
    pub cpus: VmScalarPlanU32,
    pub memory_mib: VmScalarPlanU32,
    pub base_image: VmHostPathPlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_init_user_data: Option<VmTemplateStringPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_init_vendor_data: Option<VmTemplateStringPlan>,
    pub egress: VmEgressPlan,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_mounts: Vec<VmStorageMount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_config: Option<DirectRuntimeConfigPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_spec_b64: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmStorageMount {
    pub mount_path: String,
    pub state_subdir: String,
    pub serial: String,
    pub size: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmRouterPlan {
    pub identity_id: String,
    pub mesh_port: u16,
    pub control_port: u16,
    pub control_socket_path: String,
    pub mesh_config_path: String,
    pub mesh_identity_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_passthrough: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum VmScalarPlanU32 {
    Literal { value: u32 },
    RuntimeConfig { query: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum VmHostPathPlan {
    Static {
        path: String,
    },
    RuntimeConfig {
        query: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_dir: Option<String>,
    },
    RuntimeTemplate {
        parts: Vec<VmHostPathPart>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_dir: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum VmHostPathPart {
    Literal { value: String },
    RuntimeConfig { query: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum VmTemplateStringPlan {
    Static { value: String },
    RuntimeTemplate { parts: TemplateString },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmEgressPlan {
    None,
    Optional,
}

#[derive(Clone, Debug)]
struct VmComponentNames {
    base: String,
    mesh_dir: String,
}

#[derive(Clone, Debug)]
struct VmComponentPlanInputs<'a> {
    scenario: &'a Scenario,
    mesh_plan: &'a MeshPlan,
    config_plan: &'a crate::targets::program_config::ConfigPlan,
    storage_plan: &'a StoragePlan,
    component_names: &'a HashMap<ComponentId, VmComponentNames>,
    mesh_ports_by_component: &'a HashMap<ComponentId, u16>,
    compiled: &'a CompiledScenario,
    program_components: &'a [ComponentId],
    slot_values_by_component: &'a HashMap<ComponentId, BTreeMap<String, crate::slots::SlotValue>>,
}

impl Reporter for VmReporter {
    type Artifact = VmArtifact;

    fn emit(&self, compiled: &CompiledScenario) -> Result<Self::Artifact, ReporterError> {
        emit_vm_artifact(compiled, false).map_err(|err| ReporterError::new(err.to_string()))
    }
}

pub(crate) fn emit_vm_artifact(
    compiled: &CompiledScenario,
    force_router: bool,
) -> Result<VmArtifact, MeshError> {
    emit_vm_artifact_with_options(
        compiled,
        VmArtifactBuildOptions {
            force_router,
            router_identity_id: ROUTER_IDENTITY_ID,
            mesh_scope: None,
        },
    )
}

pub(crate) fn emit_vm_artifact_with_options(
    compiled: &CompiledScenario,
    options: VmArtifactBuildOptions<'_>,
) -> Result<VmArtifact, MeshError> {
    let scenario = compiled.scenario();
    let endpoint_plan = crate::targets::program_config::build_endpoint_plan(scenario)?;
    let mesh_plan = build_mesh_plan(
        scenario,
        &endpoint_plan,
        MeshOptions {
            backend_label: "vm reporter",
        },
    )?;
    let program_components = mesh_plan.program_components();

    for &component_id in program_components {
        let component = scenario.component(component_id);
        let Some(program) = component.program.as_ref() else {
            continue;
        };
        for mount in program.mounts() {
            if let ProgramMount::Framework { capability, .. } = mount {
                match capability.as_str() {
                    "docker" => {
                        return Err(MeshError::new(
                            "vm reporter does not yet support `framework.docker` mounts",
                        ));
                    }
                    "kvm" => {
                        return Err(MeshError::new(
                            "vm reporter does not yet support `framework.kvm` mounts",
                        ));
                    }
                    _ => {}
                }
            }
        }
    }

    let component_names: HashMap<ComponentId, VmComponentNames> =
        map_program_components(scenario, program_components, |id, local_name| {
            let base = vm_base_name(id, local_name);
            VmComponentNames {
                mesh_dir: format!("mesh/components/{base}"),
                base,
            }
        });

    let route_ports = placeholder_local_route_ports(scenario, &endpoint_plan, &mesh_plan);
    let mesh_ports_by_component = placeholder_mesh_ports(program_components);
    let needs_router = mesh_plan.needs_router() || options.force_router;
    let router_ports = needs_router.then_some(RouterPorts {
        mesh: 0,
        control: 0,
    });

    let addressing = LocalAddressing::new(
        scenario,
        &route_ports,
        LocalAddressingOptions {
            backend_label: "vm reporter",
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
        ProgramSupport::Vm {
            backend_label: "vm output",
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
            router_identity_id: options.router_identity_id,
            mesh_scope: options.mesh_scope,
            component_mesh_listen_addr: "127.0.0.1",
            router_mesh_listen_addr: "127.0.0.1",
            router_control_listen_addr: "127.0.0.1",
            force_router: options.force_router,
        },
    })?;

    let mesh_provision_plan = build_mesh_provision_plan(
        &mesh_config_plan,
        program_components,
        &component_names,
        |name: &VmComponentNames| MeshProvisionOutput::Filesystem {
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
        compose_project: None,
        control_socket: Some(DIRECT_CONTROL_SOCKET_RELATIVE_PATH.to_string()),
        control_socket_volume: None,
    });
    let proxy_metadata =
        needs_router.then_some(build_proxy_metadata(scenario, &mesh_plan, router_metadata));

    let startup_order = topological_startup_order(program_components, &mesh_plan)?;
    let startup_order_ids = startup_order.iter().map(|id| id.0).collect::<Vec<_>>();
    let components = build_component_plans(VmComponentPlanInputs {
        scenario,
        mesh_plan: &mesh_plan,
        config_plan: &config_plan,
        storage_plan: &storage_plan,
        component_names: &component_names,
        mesh_ports_by_component: &mesh_ports_by_component,
        compiled,
        program_components,
        slot_values_by_component: &address_plan.slot_values_by_component,
    })?;

    let router_plan = router_ports.map(|ports| VmRouterPlan {
        identity_id: options.router_identity_id.to_string(),
        mesh_port: ports.mesh,
        control_port: 0,
        control_socket_path: DIRECT_CONTROL_SOCKET_RELATIVE_PATH.to_string(),
        mesh_config_path: mesh_config_relative_path(ROUTER_MESH_DIR),
        mesh_identity_path: mesh_identity_relative_path(ROUTER_MESH_DIR),
        env_passthrough: mesh_config_plan.router_env_passthrough.clone(),
    });

    let vm_plan = VmPlan {
        version: VM_PLAN_VERSION.to_string(),
        mesh_provision_plan: MESH_PROVISION_PLAN_FILENAME.to_string(),
        startup_order: startup_order_ids,
        runtime_addresses,
        components,
        router: router_plan,
    };

    let mut files = BTreeMap::new();
    files.insert(PathBuf::from(VM_RUN_SCRIPT_FILENAME), render_run_script());
    files.insert(
        PathBuf::from(VM_PLAN_FILENAME),
        serde_json::to_string_pretty(&vm_plan)
            .map_err(|err| MeshError::new(format!("failed to serialize vm plan: {err}")))?,
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

    let execution_guide = build_execution_guide(
        scenario,
        &mesh_plan,
        &config_plan,
        !storage_plan.is_empty(),
        false,
    )
    .map_err(|err: ReporterError| MeshError::new(err.to_string()))?;
    files.insert(
        PathBuf::from(GENERATED_ENV_SAMPLE_FILENAME),
        execution_guide.render_env_sample(false, "vm"),
    );
    files.insert(
        PathBuf::from(GENERATED_README_FILENAME),
        render_vm_readme(files.contains_key(&PathBuf::from(DEFAULT_EXTERNAL_ENV_FILE))),
    );

    Ok(VmArtifact { files })
}

fn render_vm_readme(has_router_env_file: bool) -> String {
    let mut out = String::from(
        "# Amber VM Output\n\nThis directory contains VM runtime artifacts produced by `amber \
         compile --vm`.\n\nRun the scenario with:\n\n```sh\namber run .\n```\n\nPersistent \
         storage defaults to a hidden directory next to this artifact. Override it with `amber \
         run --storage-root DIR .` when you need a long-lived shared storage root.\n",
    );
    if has_router_env_file {
        out.push_str(
            "\nIf this scenario has external slots, fill in `.env.router.external` before \
             running.\n",
        );
    }
    out
}

fn build_component_plans(
    inputs: VmComponentPlanInputs<'_>,
) -> Result<Vec<VmComponentPlan>, MeshError> {
    let VmComponentPlanInputs {
        scenario,
        mesh_plan,
        config_plan,
        storage_plan,
        component_names,
        mesh_ports_by_component,
        compiled,
        program_components,
        slot_values_by_component,
    } = inputs;
    let config_analysis = compiled.config_analysis();

    let mut out = Vec::with_capacity(program_components.len());
    for id in program_components {
        let component = scenario.component(*id);
        let Program::Vm(program) = component.program.as_ref().ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing program for {}",
                component.moniker.as_str()
            ))
        })?
        else {
            return Err(MeshError::new(format!(
                "component {} does not use `program.vm`",
                component.moniker.as_str()
            )));
        };

        let program_plan = config_plan.program_plans.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing program plan for {}",
                component_label(scenario, *id)
            ))
        })?;
        let component_config = config_analysis.component(*id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing config analysis for {}",
                component.moniker.as_str()
            ))
        })?;
        let slots = slot_values_by_component.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing slot values for {}",
                component.moniker.as_str()
            ))
        })?;
        let (cloud_init_user_data, user_data_needs_runtime_config) =
            build_vm_template_string_plan(build_vm_cloud_init_template_string(
                scenario,
                *id,
                "program.vm.cloud_init.user_data",
                program.cloud_init.user_data.as_deref(),
                RuntimeAddressResolution::Deferred,
                slots,
                component_config,
            )?);
        let (cloud_init_vendor_data, vendor_data_needs_runtime_config) =
            build_vm_template_string_plan(build_vm_cloud_init_template_string(
                scenario,
                *id,
                "program.vm.cloud_init.vendor_data",
                program.cloud_init.vendor_data.as_deref(),
                RuntimeAddressResolution::Deferred,
                slots,
                component_config,
            )?);
        let cloud_init_needs_runtime_config =
            user_data_needs_runtime_config || vendor_data_needs_runtime_config;
        let vm_runtime_config_required = config_plan.runtime_views.contains_key(id);
        let runtime_plan = build_component_runtime_plan(
            component.moniker.as_str(),
            program_plan,
            config_plan.mount_specs.get(id).map(Vec::as_slice),
            config_plan.runtime_views.get(id),
            cloud_init_needs_runtime_config || vm_runtime_config_required,
            cloud_init_needs_runtime_config || vm_runtime_config_required,
        )?;
        let names = component_names.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing vm component names for {}",
                component.moniker.as_str()
            ))
        })?;
        let _mesh_port = *mesh_ports_by_component.get(id).ok_or_else(|| {
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
        let resource_sizes = storage_sizes_for_component_mounts(scenario, storage_plan, *id)?;

        let (runtime_config, mount_spec_b64) = vm_runtime_mount_inputs(runtime_plan.execution)?;

        out.push(VmComponentPlan {
            id: id.0,
            moniker: component.moniker.as_str().to_string(),
            log_name: names.base.clone(),
            depends_on,
            mesh_config_path: mesh_config_relative_path(&names.mesh_dir),
            mesh_identity_path: mesh_identity_relative_path(&names.mesh_dir),
            cpus: build_vm_scalar_plan(resolve_vm_scalar_u32(
                component_config,
                &program.cpus,
                component.moniker.as_str(),
                "program.vm.cpus",
            )?),
            memory_mib: build_vm_scalar_plan(resolve_vm_scalar_u32(
                component_config,
                &program.memory_mib,
                component.moniker.as_str(),
                "program.vm.memory_mib",
            )?),
            base_image: build_vm_base_image_plan(
                scenario,
                *id,
                program,
                slots,
                component_config,
                source_dir.as_deref(),
                component.moniker.as_str(),
            )?,
            cloud_init_user_data,
            cloud_init_vendor_data,
            egress: match program.egress {
                VmEgress::None => VmEgressPlan::None,
                VmEgress::Optional => VmEgressPlan::Optional,
                _ => VmEgressPlan::None,
            },
            storage_mounts: vm_storage_mounts(
                storage_plan.mounts_by_component.get(id).map(Vec::as_slice),
                &resource_sizes,
            ),
            runtime_config,
            mount_spec_b64,
        });
    }
    Ok(out)
}

fn vm_runtime_mount_inputs(
    execution: ComponentExecutionPlan<'_>,
) -> Result<(Option<DirectRuntimeConfigPayload>, Option<String>), MeshError> {
    match execution {
        ComponentExecutionPlan::Resolved { entrypoint, env } => {
            if !entrypoint.is_empty() || !env.is_empty() {
                return Err(MeshError::new(
                    "internal error: VM programs should not carry guest execution payloads",
                ));
            }
            Ok((None, None))
        }
        ComponentExecutionPlan::HelperRunner {
            template_spec_b64,
            runtime_config,
            mount_spec_b64,
            ..
        } => {
            if template_spec_b64.is_some() {
                return Err(MeshError::new(
                    "internal error: VM programs should not require helper-rendered entrypoints",
                ));
            }
            Ok((
                runtime_config.map(vm_runtime_config_payload),
                mount_spec_b64,
            ))
        }
    }
}

fn vm_runtime_config_payload(payload: RuntimeConfigPayload<'_>) -> DirectRuntimeConfigPayload {
    DirectRuntimeConfigPayload {
        root_schema_b64: payload.root_schema_b64,
        component_cfg_template_b64: payload.component_cfg_template_b64,
        component_schema_b64: payload.component_schema_b64,
        allowed_root_leaf_paths: payload.allowed_root_leaf_paths.iter().cloned().collect(),
    }
}

fn build_vm_template_string_plan(
    template: Option<TemplateString>,
) -> (Option<VmTemplateStringPlan>, bool) {
    let Some(parts) = template else {
        return (None, false);
    };
    let needs_runtime_config = parts
        .iter()
        .any(|part| matches!(part, TemplatePart::Config { .. }));
    let is_static = parts
        .iter()
        .all(|part| matches!(part, TemplatePart::Lit { .. }));
    if is_static {
        let mut value = String::new();
        for part in parts {
            let TemplatePart::Lit { lit } = part else {
                unreachable!("static template should contain only literals");
            };
            value.push_str(&lit);
        }
        (Some(VmTemplateStringPlan::Static { value }), false)
    } else {
        (
            Some(VmTemplateStringPlan::RuntimeTemplate { parts }),
            needs_runtime_config,
        )
    }
}

fn build_vm_scalar_plan(resolution: VmScalarResolutionU32) -> VmScalarPlanU32 {
    match resolution {
        VmScalarResolutionU32::Static(value) => VmScalarPlanU32::Literal { value },
        VmScalarResolutionU32::RuntimeConfig(query) => VmScalarPlanU32::RuntimeConfig { query },
    }
}

fn build_vm_base_image_plan(
    scenario: &Scenario,
    id: ComponentId,
    program: &ProgramVm,
    slots: &BTreeMap<String, crate::slots::SlotValue>,
    component_config: &ComponentConfigAnalysis,
    source_dir: Option<&Path>,
    component_moniker: &str,
) -> Result<VmHostPathPlan, MeshError> {
    let image = program
        .image
        .parse::<amber_manifest::InterpolatedString>()
        .map_err(|err| {
            MeshError::new(format!(
                "failed to parse program.vm.image interpolation in {}: {err}",
                component_label(scenario, id)
            ))
        })?;

    let mut parts = Vec::new();
    for part in &image.parts {
        match part {
            InterpolatedPart::Literal(lit) => push_vm_host_path_literal(&mut parts, lit.clone()),
            InterpolatedPart::Interpolation { source, query } => {
                if let Some(value) = resolve_slot_interpolation(
                    scenario,
                    id,
                    "program.vm.image",
                    source,
                    query,
                    slots,
                )? {
                    push_vm_host_path_literal(&mut parts, value);
                    continue;
                }

                match component_config
                    .resolve_static_string_query(query)
                    .map_err(MeshError::new)?
                {
                    Some(value) => push_vm_host_path_literal(&mut parts, value),
                    None => parts.push(VmHostPathPart::RuntimeConfig {
                        query: query.clone(),
                    }),
                }
            }
            _ => {
                return Err(MeshError::new(format!(
                    "unsupported interpolation part in {} program.vm.image",
                    component_label(scenario, id)
                )));
            }
        }
    }

    if parts.is_empty() {
        return Err(MeshError::new(format!(
            "internal error: produced empty image template for {} program.vm.image",
            component_label(scenario, id)
        )));
    }

    let runtime_source_dir = source_dir.map(|path| path.display().to_string());
    match parts.as_slice() {
        [VmHostPathPart::Literal { value }] => Ok(VmHostPathPlan::Static {
            path: resolve_vm_host_path(value, source_dir, component_moniker)?,
        }),
        [VmHostPathPart::RuntimeConfig { query }] => Ok(VmHostPathPlan::RuntimeConfig {
            query: query.clone(),
            source_dir: runtime_source_dir,
        }),
        _ => Ok(VmHostPathPlan::RuntimeTemplate {
            parts,
            source_dir: runtime_source_dir,
        }),
    }
}

fn push_vm_host_path_literal(parts: &mut Vec<VmHostPathPart>, lit: String) {
    if lit.is_empty() {
        return;
    }

    match parts.last_mut() {
        Some(VmHostPathPart::Literal { value }) => value.push_str(&lit),
        _ => parts.push(VmHostPathPart::Literal { value: lit }),
    }
}

fn resolve_vm_host_path(
    raw: &str,
    source_dir: Option<&Path>,
    component_moniker: &str,
) -> Result<String, MeshError> {
    let path = Path::new(raw);
    if path.is_absolute() {
        return Ok(path.display().to_string());
    }
    let source_dir = source_dir.ok_or_else(|| {
        MeshError::new(format!(
            "component {component_moniker} uses relative host path `{raw}`, but the compiled \
             artifact has no local file `resolved_url`"
        ))
    })?;
    if !source_dir.is_absolute() {
        return Err(MeshError::new(format!(
            "component {component_moniker} has non-absolute source_dir {}",
            source_dir.display()
        )));
    }
    Ok(source_dir.join(path).display().to_string())
}

fn storage_sizes_for_component_mounts(
    scenario: &Scenario,
    storage_plan: &StoragePlan,
    component_id: ComponentId,
) -> Result<HashMap<StorageIdentity, String>, MeshError> {
    let mut sizes = HashMap::new();
    for mount in storage_plan
        .mounts_by_component
        .get(&component_id)
        .into_iter()
        .flatten()
    {
        let owner = scenario.component(mount.identity.owner);
        let resource = owner
            .resources
            .get(mount.identity.resource.as_str())
            .ok_or_else(|| {
                MeshError::new(format!(
                    "missing storage resource {}.resources.{}",
                    owner.moniker.as_str(),
                    mount.identity.resource
                ))
            })?;
        let size = resource
            .params
            .size
            .clone()
            .unwrap_or_else(|| DEFAULT_STORAGE_SIZE.to_string());
        sizes.insert(mount.identity.clone(), size);
    }
    Ok(sizes)
}

fn vm_storage_mounts(
    mounts: Option<&[StorageMount]>,
    sizes: &HashMap<StorageIdentity, String>,
) -> Vec<VmStorageMount> {
    let mut out = Vec::new();
    for mount in mounts.into_iter().flatten() {
        let state_subdir = vm_storage_state_subdir(&mount.identity);
        out.push(VmStorageMount {
            mount_path: mount.mount_path.clone(),
            serial: vm_storage_serial(&mount.identity),
            size: sizes
                .get(&mount.identity)
                .cloned()
                .unwrap_or_else(|| DEFAULT_STORAGE_SIZE.to_string()),
            state_subdir,
        });
    }
    out
}

fn vm_storage_state_subdir(identity: &StorageIdentity) -> String {
    format!(
        "{}/{}-{}",
        vm_storage_component_slug(identity.owner_moniker.as_str()),
        vm_sanitize_storage_segment(identity.resource.as_str()),
        identity.hash_suffix()
    )
}

fn vm_storage_component_slug(component_moniker: &str) -> String {
    let trimmed = component_moniker.trim_matches('/');
    if trimmed.is_empty() {
        return "root".to_string();
    }
    trimmed
        .split('/')
        .map(vm_sanitize_storage_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn vm_sanitize_storage_segment(input: &str) -> String {
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

fn vm_storage_serial(identity: &StorageIdentity) -> String {
    format!("amber-{}", identity.hash_suffix())
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

fn vm_base_name(id: ComponentId, local_name: &str) -> String {
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
                        "missing slot declaration for {}.{} while building vm runtime addresses",
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
        .map_err(|err| MeshError::new(format!("invalid vm runtime URL {raw}: {err}")))
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

fn vm_runtime_addresses_is_empty(plan: &DirectRuntimeAddressPlan) -> bool {
    plan.slots_by_scope.is_empty() && plan.slot_items_by_scope.is_empty()
}
