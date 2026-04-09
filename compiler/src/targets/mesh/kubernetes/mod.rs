mod helpers;
mod resources;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
};

use amber_config as rc;
use amber_manifest::span_for_json_pointer;
use amber_mesh::{
    DYNAMIC_CAPS_API_URL_ENV, MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME, MeshProtocol,
    MeshProvisionOutput, router_export_route_id,
};
use amber_scenario::{ComponentId, ProgramMount, Scenario};
use base64::Engine as _;
use jsonptr::PointerBuf;
use miette::{LabeledSpan, NamedSource, SourceSpan};
pub use resources::*;
use serde::Serialize;

use self::helpers::*;
use crate::{
    CompileOutput,
    reporter::{
        CompiledScenario, Reporter, ReporterError,
        execution_guide::{GENERATED_README_FILENAME, build_execution_guide},
    },
    runtime_interface::{RootInputDescriptor, build_runtime_interface},
    targets::{
        mesh::{
            addressing::{
                DockerFrameworkBindingPolicy, LocalAddressing, LocalAddressingOptions, WorkloadId,
                build_address_plan, build_allow_plan, build_component_egress_allow,
            },
            internal_images::resolve_internal_images,
            mesh_config::{
                MeshConfigBuildInput, MeshConfigBuildOptions, MeshServiceName, RouterPorts,
                ServiceMeshAddressing, build_mesh_config_plan, default_mesh_config_build_options,
                scenario_ir_digest,
            },
            plan::{MeshOptions, component_label, map_program_components},
            ports::{allocate_local_route_ports, allocate_mesh_ports},
            provision::build_mesh_provision_plan,
            proxy_metadata::{
                DEFAULT_EXTERNAL_ENV_FILE, ExportMetadata, ExternalSlotMetadata,
                PROXY_METADATA_FILENAME, PROXY_METADATA_VERSION, ProxyMetadata, RouterMetadata,
            },
        },
        program_config::{
            ComponentExecutionPlan, ProgramImageOrigin, ProgramImagePart, ProgramImagePlan,
            ProgramSupport, build_component_runtime_plan, build_config_plan,
        },
        storage::build_storage_plan,
    },
};

// Helper injection system: When a component requires runtime config interpolation
// or mounts, an init container installs the amber-helper binary into a shared
// volume, then the main container uses the helper as its entrypoint to resolve
// config/templates, materialize mounts, and exec the actual program.
const HELPER_VOLUME_NAME: &str = "amber-helper";
const HELPER_BIN_DIR: &str = "/amber/bin";
const HELPER_BIN_PATH: &str = "/amber/bin/amber-helper";
const MESH_CONFIG_DIR: &str = "/amber/mesh";
const MESH_SECRET_VOLUME_NAME: &str = "amber-mesh";
const ROUTER_NAME: &str = "amber-router";
const PROVISIONER_NAME: &str = "amber-provisioner";
const PROVISIONER_CONFIGMAP_NAME: &str = "amber-mesh-provision";
const PROVISIONER_SERVICE_ACCOUNT: &str = "amber-provisioner";
const PROVISIONER_ROLE_NAME: &str = "amber-provisioner";
const PROVISIONER_ROLE_BINDING_NAME: &str = "amber-provisioner";
const PROVISIONER_PLAN_KEY: &str = "mesh-plan.json";
const PROVISIONER_JOB_BACKOFF_LIMIT: u32 = 6;
const ROUTER_EXTERNAL_SECRET_NAME: &str = "amber-router-external";
const COMPONENT_SIDECAR_ENV_SECRET_NAME: &str = "amber-component-sidecar-env";
const COMPONENT_SIDECAR_ENV_FILE: &str = "component-sidecar.env";
const COMPONENT_MESH_PORT_BASE: u16 = 23000;
const ROUTER_MESH_PORT_BASE: u16 = 24000;
const ROUTER_CONTROL_PORT_BASE: u16 = 24100;
const SCENARIO_RUN_ID_ENV: &str = "AMBER_SCENARIO_RUN_ID";
const OTELCOL_NAME: &str = "amber-otelcol";
const OTELCOL_CONFIGMAP_NAME: &str = "amber-otelcol-config";
const OTELCOL_CONFIG_KEY: &str = "config.yaml";
const OTELCOL_CONFIG_DIR: &str = "/etc/otelcol";
const OTELCOL_CONFIG_PATH: &str = "/etc/otelcol/config.yaml";
const OTELCOL_SERVICE_PORT_GRPC: u16 = 4317;
const OTELCOL_SERVICE_PORT_HTTP: u16 = 4318;
const OTELCOL_UPSTREAM_ENV: &str = "AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT";
const OTELCOL_DEFAULT_UPSTREAM_ENDPOINT: &str = "http://host.docker.internal:18890";
const DEFAULT_OTELCOL_IMAGE: &str = "otel/opentelemetry-collector-contrib:0.143.0";
const ROUTER_OTLP_ENDPOINT: &str = "http://amber-otelcol:4318";
const DEFAULT_STORAGE_REQUEST: &str = "1Gi";
const OTELCOL_SERVICE_ACCOUNT: &str = "amber-otelcol";
const OTELCOL_ROLE_NAME: &str = "amber-otelcol";
const OTELCOL_ROLE_BINDING_NAME: &str = "amber-otelcol";
const MESH_CONFIG_WAIT_TIMEOUT_SECS: u64 = 180;
const INTERNAL_RUNTIME_UID: u32 = 65532;

const ROOT_CONFIG_SECRET_NAME: &str = "amber-root-config-secret";
const ROOT_CONFIG_CONFIGMAP_NAME: &str = "amber-root-config";

/// Reporter that outputs Kubernetes manifests as a directory structure.
#[derive(Clone, Debug, Default)]
pub struct KubernetesReporter;

/// Output artifact containing all generated Kubernetes YAML files.
#[derive(Clone, Debug)]
pub struct KubernetesArtifact {
    /// Map of relative path -> YAML content.
    pub files: BTreeMap<PathBuf, String>,
}

impl Reporter for KubernetesReporter {
    type Artifact = KubernetesArtifact;

    fn emit(&self, compiled: &CompiledScenario) -> Result<Self::Artifact, ReporterError> {
        emit_kubernetes_artifact(compiled, false)
    }
}

// ---- Internal types ----

#[derive(Clone, Debug)]
struct ComponentNames {
    /// Service/deployment name (RFC 1123 subdomain).
    service: String,
    /// NetworkPolicy name.
    netpol: String,
}

impl MeshServiceName for ComponentNames {
    fn mesh_service_name(&self) -> &str {
        &self.service
    }
}

/// Metadata about a config input for the amber-metadata ConfigMap.
#[derive(Clone, Debug, Serialize)]
struct InputMetadata {
    required: bool,
    secret: bool,
}

#[derive(Clone, Debug)]
struct ProgramImageSource {
    src: NamedSource<std::sync::Arc<str>>,
    span: SourceSpan,
    label: String,
}
/// Full scenario metadata stored in amber-metadata ConfigMap.
#[derive(Clone, Debug, Serialize)]
struct ScenarioMetadata {
    version: &'static str,
    digest: String,
    exports: BTreeMap<String, ExportMetadata>,
    inputs: BTreeMap<String, InputMetadata>,
    external_slots: BTreeMap<String, ExternalSlotMetadata>,
}

type KubernetesResult<T> = Result<T, ReporterError>;

pub fn render_kubernetes_with_output(
    output: &CompileOutput,
) -> KubernetesResult<KubernetesArtifact> {
    let compiled = CompiledScenario::from_compile_output(output)
        .map_err(|err| ReporterError::new(err.to_string()))?;
    emit_kubernetes_artifact(&compiled, false)
}

pub(crate) fn emit_kubernetes_artifact(
    compiled: &CompiledScenario,
    force_router: bool,
) -> KubernetesResult<KubernetesArtifact> {
    let s = compiled.scenario();
    let scenario_digest =
        scenario_ir_digest(s).map_err(|err| ReporterError::new(err.to_string()))?;
    let endpoint_plan = crate::targets::program_config::build_endpoint_plan(s)
        .map_err(|e| ReporterError::new(e.to_string()))?;
    let mesh_plan = crate::targets::mesh::plan::build_mesh_plan(
        s,
        &endpoint_plan,
        MeshOptions {
            backend_label: "kubernetes reporter",
        },
    )
    .map_err(|e| ReporterError::new(e.to_string()))?;
    for &component_id in mesh_plan.program_components() {
        let component = s.component(component_id);
        let Some(program) = component.program.as_ref() else {
            continue;
        };
        for mount in program.mounts() {
            if let ProgramMount::Framework { capability, .. } = mount {
                match capability.as_str() {
                    "docker" => {
                        return Err(ReporterError::new(
                            "kubernetes reporter does not yet support runtime injection for \
                             `framework.docker` mounts (missing docker-gateway wiring)",
                        ));
                    }
                    "kvm" => {
                        return Err(ReporterError::new(
                            "kubernetes reporter does not yet support `framework.kvm` mounts",
                        ));
                    }
                    _ => {}
                }
            }
        }
    }
    let images = resolve_internal_images().map_err(ReporterError::new)?;

    let program_components = mesh_plan.program_components();
    let namespace = generate_namespace_name(s, &scenario_digest);

    let names: HashMap<ComponentId, ComponentNames> =
        map_program_components(s, program_components, |id, local_name| {
            let base = service_name(id, local_name);
            ComponentNames {
                service: base.clone(),
                netpol: format!("{base}-netpol"),
            }
        });
    let provisioner_job_name = provisioner_job_name(&scenario_digest);
    let needs_router = mesh_plan.needs_router() || force_router;

    let route_ports = allocate_local_route_ports(s, &endpoint_plan, &mesh_plan)
        .map_err(|e| ReporterError::new(e.to_string()))?;
    let mesh_ports_by_component = allocate_mesh_ports(
        s,
        &endpoint_plan,
        program_components,
        COMPONENT_MESH_PORT_BASE,
        &route_ports,
    )
    .map_err(|e| ReporterError::new(e.to_string()))?;
    let router_ports = needs_router.then_some(RouterPorts {
        mesh: ROUTER_MESH_PORT_BASE,
        control: ROUTER_CONTROL_PORT_BASE,
    });
    let router_mesh_port_opt = router_ports.map(|ports| ports.mesh);

    let addressing = LocalAddressing::new(
        s,
        &route_ports,
        LocalAddressingOptions {
            backend_label: "kubernetes reporter",
            docker_binding: DockerFrameworkBindingPolicy::Unsupported {
                reason: "does not yet support runtime injection for `framework.docker` (missing \
                         docker-gateway wiring)",
            },
        },
    );
    let address_plan = build_address_plan(&mesh_plan, addressing)
        .map_err(|e| ReporterError::new(e.to_string()))?;

    let router_mesh_port = router_ports
        .as_ref()
        .map(|ports| ports.mesh)
        .unwrap_or(ROUTER_MESH_PORT_BASE);
    let mesh_addressing = ServiceMeshAddressing::new(
        &names,
        None,
        &mesh_ports_by_component,
        ROUTER_NAME,
        router_mesh_port,
    );
    let mesh_config_plan = build_mesh_config_plan(MeshConfigBuildInput {
        scenario: s,
        mesh_plan: &mesh_plan,
        route_ports: &route_ports,
        mesh_ports_by_component: &mesh_ports_by_component,
        router_ports,
        addressing: &mesh_addressing,
        options: MeshConfigBuildOptions {
            force_router,
            ..default_mesh_config_build_options()
        },
    })
    .map_err(|e| ReporterError::new(e.to_string()))?;
    let mesh_provision_plan = build_mesh_provision_plan(
        &mesh_config_plan,
        program_components,
        &names,
        |cnames: &ComponentNames| MeshProvisionOutput::KubernetesSecret {
            name: mesh_secret_name(&cnames.service),
            namespace: None,
        },
        || MeshProvisionOutput::KubernetesSecret {
            name: mesh_secret_name(ROUTER_NAME),
            namespace: None,
        },
        |router_config| {
            if let Some(control_listen) = router_config.control_listen {
                router_config.control_listen = Some(
                    format!("127.0.0.1:{}", control_listen.port())
                        .parse()
                        .expect("control listen"),
                );
            }
            router_config.control_allow = Some(vec!["127.0.0.1".to_string(), "::1".to_string()]);
        },
    )
    .map_err(|err| ReporterError::new(err.to_string()))?;

    let allow_plan = build_allow_plan(&mesh_plan, &mesh_ports_by_component, router_mesh_port_opt)
        .map_err(|e| ReporterError::new(e.to_string()))?;

    let (egress_allow, egress_router_allow) = build_component_egress_allow(&allow_plan);

    let config_plan = build_config_plan(
        s,
        compiled.config_analysis(),
        program_components,
        ProgramSupport::Image {
            backend_label: "kubernetes output",
        },
        crate::targets::program_config::RuntimeAddressResolution::Static,
        &address_plan.slot_values_by_component,
    )
    .map_err(|e| ReporterError::new(e.to_string()))?;
    let runtime_interface = build_runtime_interface(s, &mesh_plan, &config_plan)
        .map_err(|err| ReporterError::new(err.to_string()))?;
    let root_inputs = runtime_interface.root_inputs;
    let export_descriptors = runtime_interface.exports;
    let external_slot_descriptors = runtime_interface.external_slots;
    let storage_plan = build_storage_plan(s, program_components);
    let scenario_digest_label = encode_scenario_digest(&scenario_digest);
    let scenario_labels = |extra: &[(&str, &str)]| -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "amber".to_string(),
        );
        labels.insert(
            "amber.io/revision".to_string(),
            sanitize_label_value(&scenario_digest_label),
        );
        for (k, v) in extra {
            labels.insert(k.to_string(), v.to_string());
        }
        labels
    };

    let component_labels = |id: ComponentId, svc_name: &str| -> BTreeMap<String, String> {
        let mut labels = scenario_labels(&[]);
        labels.insert("amber.io/component".to_string(), svc_name.to_string());
        labels.insert("amber.io/component-id".to_string(), format!("c{}", id.0));
        labels
    };
    let router_labels = scenario_labels(&[
        ("amber.io/type", "router"),
        ("amber.io/component", ROUTER_NAME),
    ]);
    let router_selector = {
        let mut m = BTreeMap::new();
        m.insert("amber.io/component".to_string(), ROUTER_NAME.to_string());
        m
    };
    let otelcol_labels = scenario_labels(&[
        ("amber.io/type", "collector"),
        ("amber.io/component", OTELCOL_NAME),
    ]);
    let otelcol_selector = {
        let mut m = BTreeMap::new();
        m.insert("amber.io/component".to_string(), OTELCOL_NAME.to_string());
        m
    };

    // ---- Generate resources ----

    let mut files: BTreeMap<PathBuf, String> = BTreeMap::new();

    let otelcol_config = ConfigMap::new(
        OTELCOL_CONFIGMAP_NAME,
        &namespace,
        otelcol_labels.clone(),
        BTreeMap::from([(OTELCOL_CONFIG_KEY.to_string(), otelcol_config_content())]),
    );
    files.insert(
        PathBuf::from("01-configmaps/amber-otelcol-config.yaml"),
        to_yaml(&otelcol_config)?,
    );
    let otelcol_service_account =
        ServiceAccount::new(OTELCOL_SERVICE_ACCOUNT, &namespace, otelcol_labels.clone());
    files.insert(
        PathBuf::from("02-rbac/amber-otelcol-sa.yaml"),
        to_yaml(&otelcol_service_account)?,
    );

    let otelcol_role = Role::new(
        OTELCOL_ROLE_NAME,
        &namespace,
        otelcol_labels.clone(),
        vec![PolicyRule {
            api_groups: vec!["".to_string()],
            resources: vec!["pods".to_string()],
            verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
            resource_names: None,
        }],
    );
    files.insert(
        PathBuf::from("02-rbac/amber-otelcol-role.yaml"),
        to_yaml(&otelcol_role)?,
    );

    let otelcol_role_binding = RoleBinding::new(
        OTELCOL_ROLE_BINDING_NAME,
        &namespace,
        otelcol_labels.clone(),
        Subject {
            kind: "ServiceAccount".to_string(),
            name: OTELCOL_SERVICE_ACCOUNT.to_string(),
            namespace: None,
        },
        RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "Role".to_string(),
            name: OTELCOL_ROLE_NAME.to_string(),
        },
    );
    files.insert(
        PathBuf::from("02-rbac/amber-otelcol-rolebinding.yaml"),
        to_yaml(&otelcol_role_binding)?,
    );

    let otelcol_container = harden_container(Container {
        name: "otelcol".to_string(),
        image: DEFAULT_OTELCOL_IMAGE.to_string(),
        command: Vec::new(),
        args: vec![format!("--config={OTELCOL_CONFIG_PATH}")],
        env: vec![
            EnvVar::from_field_ref(SCENARIO_RUN_ID_ENV, "metadata.namespace"),
            EnvVar::literal(OTELCOL_UPSTREAM_ENV, OTELCOL_DEFAULT_UPSTREAM_ENDPOINT),
        ],
        env_from: Vec::new(),
        ports: vec![
            ContainerPort {
                name: "otlp-grpc".to_string(),
                container_port: OTELCOL_SERVICE_PORT_GRPC,
                protocol: "TCP",
            },
            ContainerPort {
                name: "otlp-http".to_string(),
                container_port: OTELCOL_SERVICE_PORT_HTTP,
                protocol: "TCP",
            },
        ],
        readiness_probe: None,
        security_context: None,
        volume_mounts: vec![
            VolumeMount {
                name: "otelcol-config".to_string(),
                mount_path: OTELCOL_CONFIG_DIR.to_string(),
                read_only: Some(true),
            },
            VolumeMount {
                name: "otelcol-host-containers".to_string(),
                mount_path: "/var/log/containers".to_string(),
                read_only: Some(true),
            },
            VolumeMount {
                name: "otelcol-host-pods".to_string(),
                mount_path: "/var/log/pods".to_string(),
                read_only: Some(true),
            },
        ],
    });

    let otelcol_daemonset = DaemonSet {
        api_version: "apps/v1",
        kind: "DaemonSet",
        metadata: ObjectMeta {
            name: OTELCOL_NAME.to_string(),
            labels: otelcol_labels.clone(),
            ..Default::default()
        },
        spec: DaemonSetSpec {
            selector: LabelSelector {
                match_labels: otelcol_selector.clone(),
            },
            template: PodTemplateSpec {
                metadata: ObjectMeta {
                    labels: otelcol_labels.clone(),
                    ..Default::default()
                },
                spec: PodSpec {
                    init_containers: Vec::new(),
                    containers: vec![otelcol_container],
                    volumes: vec![
                        Volume::config_map("otelcol-config", OTELCOL_CONFIGMAP_NAME),
                        Volume::host_path("otelcol-host-containers", "/var/log/containers"),
                        Volume::host_path("otelcol-host-pods", "/var/log/pods"),
                    ],
                    service_account_name: Some(OTELCOL_SERVICE_ACCOUNT.to_string()),
                    automount_service_account_token: Some(true),
                    restart_policy: None,
                },
            },
        },
    };
    files.insert(
        PathBuf::from("03-daemonsets/amber-otelcol.yaml"),
        to_yaml(&otelcol_daemonset)?,
    );

    let otelcol_service = Service::new(
        OTELCOL_NAME,
        &namespace,
        otelcol_labels.clone(),
        otelcol_selector.clone(),
        vec![
            ServicePort {
                name: "otlp-grpc".to_string(),
                port: OTELCOL_SERVICE_PORT_GRPC,
                target_port: OTELCOL_SERVICE_PORT_GRPC,
                protocol: "TCP",
            },
            ServicePort {
                name: "otlp-http".to_string(),
                port: OTELCOL_SERVICE_PORT_HTTP,
                target_port: OTELCOL_SERVICE_PORT_HTTP,
                protocol: "TCP",
            },
        ],
    );
    files.insert(
        PathBuf::from("04-services/amber-otelcol.yaml"),
        to_yaml(&otelcol_service)?,
    );
    let root_leaves = &config_plan.root_leaves;
    let root_leaf_by_path: BTreeMap<&str, &rc::SchemaLeaf> = root_leaves
        .iter()
        .map(|leaf| (leaf.path.as_str(), leaf))
        .collect();
    let program_plans = &config_plan.program_plans;

    let router_env_passthrough = &mesh_config_plan.router_env_passthrough;
    let component_sidecar_env_passthrough = mesh_config_plan
        .component_sidecar_env_passthrough
        .iter()
        .filter(|env_var| env_var.as_str() != SCENARIO_RUN_ID_ENV)
        .cloned()
        .collect::<Vec<_>>();
    let mut router_container_ports: Vec<ContainerPort> = Vec::new();
    let mut router_service_ports: Vec<ServicePort> = Vec::new();

    if needs_router {
        router_container_ports.push(ContainerPort {
            name: "mesh".to_string(),
            container_port: router_mesh_port,
            protocol: "TCP",
        });
        router_service_ports.push(ServicePort {
            name: "mesh".to_string(),
            port: router_mesh_port,
            target_port: router_mesh_port,
            protocol: "TCP",
        });
        if let Some(ports) = router_ports {
            router_container_ports.push(ContainerPort {
                name: "control".to_string(),
                container_port: ports.control,
                protocol: "TCP",
            });
        }
    }

    // Build kustomization (resource list and generators/replacements are finalized at the end).
    let mut kustomization = Kustomization::new();
    kustomization.namespace = Some(namespace.clone());

    // If runtime config is needed, generate root config Secret/ConfigMap and .env templates.
    if config_plan.needs_runtime_config {
        // Separate root inputs into secret and non-secret.
        let (secret_leaves, config_leaves): (Vec<_>, Vec<_>) =
            root_inputs.iter().partition(|(_, input)| input.secret);

        if !secret_leaves.is_empty() {
            kustomization.secret_generator.push(SecretGenerator {
                name: ROOT_CONFIG_SECRET_NAME.to_string(),
                namespace: None,
                env_files: vec!["root-config-secret.env".to_string()],
                literals: Vec::new(),
                options: Some(GeneratorOptions {
                    disable_name_suffix_hash: Some(true),
                }),
            });

            files.insert(
                PathBuf::from("root-config-secret.env"),
                render_root_config_env_content(
                    &secret_leaves,
                    "# Root config secrets - fill in values before deploying",
                )?,
            );
        }

        if !config_leaves.is_empty() {
            kustomization.config_map_generator.push(ConfigMapGenerator {
                name: ROOT_CONFIG_CONFIGMAP_NAME.to_string(),
                namespace: None,
                env_files: vec!["root-config.env".to_string()],
                literals: Vec::new(),
                options: Some(GeneratorOptions {
                    disable_name_suffix_hash: Some(true),
                }),
            });

            files.insert(
                PathBuf::from("root-config.env"),
                render_root_config_env_content(
                    &config_leaves,
                    "# Root config values - fill in values before deploying",
                )?,
            );
        }

        // Don't insert kustomization yet - we'll do it at the end after collecting all resource paths
    }

    if needs_router && !router_env_passthrough.is_empty() {
        kustomization.secret_generator.push(SecretGenerator {
            name: ROUTER_EXTERNAL_SECRET_NAME.to_string(),
            namespace: None,
            env_files: vec![DEFAULT_EXTERNAL_ENV_FILE.to_string()],
            literals: Vec::new(),
            options: Some(GeneratorOptions {
                disable_name_suffix_hash: Some(true),
            }),
        });

        let mut env_content = String::new();
        env_content.push_str("# Router external slot URLs - fill in values before deploying\n");
        for env_var in router_env_passthrough {
            env_content.push_str(&format!("{env_var}=\n"));
        }
        files.insert(PathBuf::from(DEFAULT_EXTERNAL_ENV_FILE), env_content);
    }
    if !component_sidecar_env_passthrough.is_empty() {
        kustomization.secret_generator.push(SecretGenerator {
            name: COMPONENT_SIDECAR_ENV_SECRET_NAME.to_string(),
            namespace: None,
            env_files: vec![COMPONENT_SIDECAR_ENV_FILE.to_string()],
            literals: Vec::new(),
            options: Some(GeneratorOptions {
                disable_name_suffix_hash: Some(true),
            }),
        });

        let mut env_content = String::new();
        env_content
            .push_str("# Component sidecar control env - filled by `amber run` when available\n");
        for env_var in &component_sidecar_env_passthrough {
            env_content.push_str(&format!("{env_var}=\n"));
        }
        files.insert(PathBuf::from(COMPONENT_SIDECAR_ENV_FILE), env_content);
    }

    // Note: Per-component ConfigMaps/Secrets are not generated because:
    // - Helper-free execution: all config must already be fully static.
    //   Static values are rendered to strings and inlined directly into the
    //   Deployment YAML as literal env vars. This includes secret config values,
    //   which will be visible in the generated YAML.
    // - Helper execution: config with runtime interpolation uses the helper
    //   binary. The helper reads config values from the root config
    //   Secret/ConfigMap at runtime and resolves templates, so secret values are
    //   not inlined.
    // The only ConfigMaps generated are amber-metadata and the Kustomize-generated
    // root config (when runtime config is needed). Pods only reference explicitly
    // granted keys, so unassigned config never becomes visible inside containers.

    let mut storage_claims = BTreeMap::new();
    for mounts in storage_plan.mounts_by_component.values() {
        for mount in mounts {
            let claim_name = storage_claim_name(&mount.identity);
            storage_claims
                .entry(claim_name.clone())
                .or_insert_with(|| PersistentVolumeClaim {
                    api_version: "v1",
                    kind: "PersistentVolumeClaim",
                    metadata: ObjectMeta {
                        name: claim_name.clone(),
                        ..Default::default()
                    },
                    spec: PersistentVolumeClaimSpec {
                        access_modes: vec!["ReadWriteOnce".to_string()],
                        resources: VolumeResourceRequirements {
                            requests: BTreeMap::from([(
                                "storage".to_string(),
                                storage_request_for(s, &mount.identity),
                            )]),
                        },
                    },
                });
        }
    }
    for (claim_name, claim) in &storage_claims {
        files.insert(
            PathBuf::from(format!("03-persistentvolumeclaims/{claim_name}.yaml")),
            to_yaml(claim)?,
        );
    }

    // Deployments
    for id in program_components {
        let cnames = names.get(id).unwrap();
        let labels = component_labels(*id, &cnames.service);
        let storage_mounts = storage_plan
            .mounts_by_component
            .get(id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let workload_kind = "Deployment";
        let program_plan = program_plans.get(id).unwrap();
        let mesh_port = *mesh_ports_by_component.get(id).expect("mesh port missing");
        let label = component_label(s, *id);
        let pod_annotations = component_pod_annotations(&label);
        let image_origin = program_plan.image_origin().ok_or_else(|| {
            ReporterError::new(format!(
                "internal error: {} is missing a container image origin",
                component_label(s, *id)
            ))
        })?;
        let image_plan = program_plan.image().ok_or_else(|| {
            ReporterError::new(format!(
                "internal error: {} is missing a container image plan",
                component_label(s, *id)
            ))
        })?;
        let image_source = program_image_source(compiled, s, *id, image_origin);
        let (program_image, image_source_env_var) = render_kubernetes_image(
            image_plan,
            &root_leaf_by_path,
            &cnames.service,
            &label,
            image_source.as_ref(),
        )?;
        let mount_specs = config_plan.mount_specs.get(id).map(Vec::as_slice);
        let runtime_plan = build_component_runtime_plan(
            &label,
            program_plan,
            mount_specs,
            config_plan.runtime_views.get(id),
            false,
            false,
        )
        .map_err(|e| ReporterError::new(e.to_string()))?;
        let needs_helper_for_component = runtime_plan.needs_helper;
        let dynamic_caps_api_url = mesh_config_plan
            .component_configs
            .get(id)
            .and_then(|cfg| cfg.dynamic_caps_listen)
            .map(|listen| format!("http://127.0.0.1:{}", listen.port()));

        let mut ports: Vec<ContainerPort> = Vec::new();
        for endpoint in endpoint_plan.component_endpoints(*id) {
            ports.push(ContainerPort {
                name: sanitize_port_name(&endpoint.name),
                container_port: endpoint.port,
                protocol: "TCP",
            });
        }

        let (container, mut volumes) = match runtime_plan.execution {
            ComponentExecutionPlan::Resolved { entrypoint, env } => {
                // Helper-free execution: entrypoint and env are already fully resolved,
                // so we don't need AMBER_CONFIG_* env vars here.
                let container_env: Vec<EnvVar> =
                    env.iter().map(|(k, v)| EnvVar::literal(k, v)).collect();
                let mut container_env = container_env;
                if let Some(url) = dynamic_caps_api_url.as_deref() {
                    container_env.push(EnvVar::literal(DYNAMIC_CAPS_API_URL_ENV, url));
                }
                let scenario_scope = mesh_config_plan
                    .component_configs
                    .get(id)
                    .and_then(|cfg| cfg.identity.mesh_scope.as_deref());
                push_program_observability_env(&mut container_env, &label, scenario_scope);

                let container = Container {
                    name: "main".to_string(),
                    image: program_image.clone(),
                    command: entrypoint.to_vec(),
                    args: Vec::new(),
                    env: container_env,
                    env_from: Vec::new(),
                    ports,
                    readiness_probe: None,
                    security_context: None,
                    volume_mounts: Vec::new(),
                };

                (container, Vec::new())
            }
            ComponentExecutionPlan::HelperRunner {
                entrypoint_b64,
                env_b64,
                template_spec_b64,
                runtime_config,
                mount_spec_b64,
            } => {
                let mut container_env = Vec::new();
                if let Some(entrypoint_b64) = entrypoint_b64 {
                    container_env.push(EnvVar::literal(
                        "AMBER_RESOLVED_ENTRYPOINT_B64",
                        entrypoint_b64,
                    ));
                }
                if let Some(env_b64) = env_b64 {
                    container_env.push(EnvVar::literal("AMBER_RESOLVED_ENV_B64", env_b64));
                }
                if let Some(runtime_config) = runtime_config {
                    let mut config_env = build_component_config_env(
                        &root_inputs,
                        runtime_config.allowed_root_leaf_paths,
                    )?;
                    container_env.append(&mut config_env);
                    container_env.push(EnvVar::literal(
                        "AMBER_ROOT_CONFIG_SCHEMA_B64",
                        runtime_config.root_schema_b64,
                    ));
                    container_env.push(EnvVar::literal(
                        "AMBER_COMPONENT_CONFIG_SCHEMA_B64",
                        runtime_config.component_schema_b64,
                    ));
                    container_env.push(EnvVar::literal(
                        "AMBER_COMPONENT_CONFIG_TEMPLATE_B64",
                        runtime_config.component_cfg_template_b64,
                    ));
                }
                if let Some(template_spec_b64) = template_spec_b64 {
                    container_env.push(EnvVar::literal(
                        "AMBER_TEMPLATE_SPEC_B64",
                        template_spec_b64,
                    ));
                }
                if let Some(mount_spec_b64) = mount_spec_b64 {
                    container_env.push(EnvVar::literal("AMBER_MOUNT_SPEC_B64", mount_spec_b64));
                }
                if let Some(url) = dynamic_caps_api_url.as_deref() {
                    container_env.push(EnvVar::literal(DYNAMIC_CAPS_API_URL_ENV, url));
                }
                let scenario_scope = mesh_config_plan
                    .component_configs
                    .get(id)
                    .and_then(|cfg| cfg.identity.mesh_scope.as_deref());
                push_program_observability_env(&mut container_env, &label, scenario_scope);
                build_helper_runner_container(program_image.clone(), ports, container_env)
            }
        };
        let mut container = harden_container(container);
        let mut storage_volume_names = BTreeSet::new();
        for storage_mount in storage_mounts {
            let claim_name = storage_claim_name(&storage_mount.identity);
            if storage_volume_names.insert(claim_name.clone()) {
                volumes.push(Volume::persistent_volume_claim(
                    claim_name.clone(),
                    claim_name.clone(),
                ));
            }
            container.volume_mounts.push(VolumeMount {
                name: claim_name,
                mount_path: storage_mount.mount_path.clone(),
                read_only: None,
            });
        }
        let mesh_secret = mesh_secret_name(&cnames.service);
        volumes.push(Volume::secret(
            MESH_SECRET_VOLUME_NAME.to_string(),
            mesh_secret,
        ));

        let mut sidecar_env = vec![
            EnvVar::literal(
                "AMBER_ROUTER_CONFIG_PATH",
                format!("{MESH_CONFIG_DIR}/{MESH_CONFIG_FILENAME}"),
            ),
            EnvVar::literal(
                "AMBER_ROUTER_IDENTITY_PATH",
                format!("{MESH_CONFIG_DIR}/{MESH_IDENTITY_FILENAME}"),
            ),
            EnvVar::from_field_ref(SCENARIO_RUN_ID_ENV, "metadata.namespace"),
            EnvVar::literal("OTEL_TRACES_SAMPLER", "always_on"),
            EnvVar::literal("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"),
            EnvVar::literal("OTEL_EXPORTER_OTLP_ENDPOINT", ROUTER_OTLP_ENDPOINT),
        ];
        if let Some(scope) = mesh_config_plan
            .component_configs
            .get(id)
            .and_then(|cfg| cfg.identity.mesh_scope.as_deref())
        {
            sidecar_env.push(EnvVar::literal("AMBER_SCENARIO_SCOPE", scope));
        }
        let mut sidecar_env_from = Vec::new();
        if !component_sidecar_env_passthrough.is_empty() {
            sidecar_env_from.push(EnvFromSource {
                config_map_ref: None,
                secret_ref: Some(LocalObjectReference {
                    name: COMPONENT_SIDECAR_ENV_SECRET_NAME.to_string(),
                    optional: Some(true),
                }),
            });
        }

        let sidecar = harden_non_root_internal_container(Container {
            name: "sidecar".to_string(),
            image: images.router.clone(),
            command: Vec::new(),
            args: Vec::new(),
            env: sidecar_env,
            env_from: sidecar_env_from,
            ports: vec![ContainerPort {
                name: "mesh".to_string(),
                container_port: mesh_port,
                protocol: "TCP",
            }],
            readiness_probe: None,
            security_context: None,
            volume_mounts: vec![VolumeMount {
                name: MESH_SECRET_VOLUME_NAME.to_string(),
                mount_path: MESH_CONFIG_DIR.to_string(),
                read_only: Some(true),
            }],
        });

        if let Some(env_var) = image_source_env_var {
            kustomization.replacements.push(Replacement {
                source: ReplacementSource {
                    kind: "ConfigMap".to_string(),
                    name: ROOT_CONFIG_CONFIGMAP_NAME.to_string(),
                    field_path: format!("data.{env_var}"),
                },
                targets: vec![ReplacementTarget {
                    select: ReplacementSelect {
                        kind: workload_kind.to_string(),
                        name: cnames.service.clone(),
                    },
                    field_paths: vec![
                        "spec.template.spec.containers.[name=main].image".to_string(),
                    ],
                }],
            });
        }

        let mut init_containers = Vec::new();

        if let Some(scope) = mesh_config_plan
            .component_configs
            .get(id)
            .and_then(|cfg| cfg.identity.mesh_scope.as_deref())
        {
            init_containers.push(build_mesh_config_wait_init_container(&images.helper, scope));
        }

        if needs_helper_for_component {
            init_containers.push(harden_read_only_container(Container {
                name: "install-helper".to_string(),
                image: images.helper.clone(),
                command: vec![
                    "/amber-helper".to_string(),
                    "install".to_string(),
                    format!("{}/amber-helper", HELPER_BIN_DIR),
                ],
                args: Vec::new(),
                env: Vec::new(),
                env_from: Vec::new(),
                ports: Vec::new(),
                readiness_probe: None,
                security_context: None,
                volume_mounts: vec![VolumeMount {
                    name: HELPER_VOLUME_NAME.to_string(),
                    mount_path: HELPER_BIN_DIR.to_string(),
                    read_only: None,
                }],
            }));
        }

        let pod_spec = PodSpec {
            init_containers,
            containers: vec![sidecar, container],
            volumes,
            service_account_name: None,
            automount_service_account_token: Some(false),
            restart_policy: None,
        };

        let selector = {
            let mut m = BTreeMap::new();
            m.insert("amber.io/component".to_string(), cnames.service.clone());
            m
        };

        let deployment = Deployment {
            api_version: "apps/v1",
            kind: "Deployment",
            metadata: ObjectMeta {
                name: cnames.service.clone(),
                labels: labels.clone(),
                ..Default::default()
            },
            spec: DeploymentSpec {
                replicas: 1,
                selector: LabelSelector {
                    match_labels: selector,
                },
                strategy: (!storage_mounts.is_empty()).then(|| DeploymentStrategy {
                    strategy_type: "Recreate".to_string(),
                }),
                template: PodTemplateSpec {
                    metadata: ObjectMeta {
                        labels: labels.clone(),
                        annotations: pod_annotations,
                        ..Default::default()
                    },
                    spec: pod_spec,
                },
            },
        };

        files.insert(
            PathBuf::from(format!("03-deployments/{}.yaml", cnames.service)),
            to_yaml(&deployment)?,
        );
    }

    if needs_router {
        let mut env = Vec::new();
        env.push(EnvVar::literal(
            "AMBER_ROUTER_CONFIG_PATH",
            format!("{MESH_CONFIG_DIR}/{MESH_CONFIG_FILENAME}"),
        ));
        env.push(EnvVar::literal(
            "AMBER_ROUTER_IDENTITY_PATH",
            format!("{MESH_CONFIG_DIR}/{MESH_IDENTITY_FILENAME}"),
        ));
        env.push(EnvVar::from_field_ref(
            SCENARIO_RUN_ID_ENV,
            "metadata.namespace",
        ));
        env.push(EnvVar::literal("OTEL_TRACES_SAMPLER", "always_on"));
        env.push(EnvVar::literal(
            "OTEL_EXPORTER_OTLP_PROTOCOL",
            "http/protobuf",
        ));
        env.push(EnvVar::literal(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            ROUTER_OTLP_ENDPOINT,
        ));
        if let Some(scope) = mesh_config_plan
            .router_config
            .as_ref()
            .and_then(|cfg| cfg.identity.mesh_scope.as_deref())
        {
            env.push(EnvVar::literal("AMBER_SCENARIO_SCOPE", scope));
        }

        let mut env_from = Vec::new();
        if !router_env_passthrough.is_empty() {
            env_from.push(EnvFromSource {
                config_map_ref: None,
                secret_ref: Some(LocalObjectReference {
                    name: ROUTER_EXTERNAL_SECRET_NAME.to_string(),
                    optional: Some(true),
                }),
            });
        }

        let container = harden_non_root_internal_container(Container {
            name: "router".to_string(),
            image: images.router.clone(),
            command: Vec::new(),
            args: Vec::new(),
            env,
            env_from,
            ports: router_container_ports.clone(),
            readiness_probe: None,
            security_context: None,
            volume_mounts: vec![VolumeMount {
                name: MESH_SECRET_VOLUME_NAME.to_string(),
                mount_path: MESH_CONFIG_DIR.to_string(),
                read_only: Some(true),
            }],
        });
        let router_secret = mesh_secret_name(ROUTER_NAME);

        let init_containers = mesh_config_plan
            .router_config
            .as_ref()
            .and_then(|cfg| cfg.identity.mesh_scope.as_deref())
            .map(|scope| vec![build_mesh_config_wait_init_container(&images.helper, scope)])
            .unwrap_or_default();

        let deployment = Deployment {
            api_version: "apps/v1",
            kind: "Deployment",
            metadata: ObjectMeta {
                name: ROUTER_NAME.to_string(),
                labels: router_labels.clone(),
                ..Default::default()
            },
            spec: DeploymentSpec {
                replicas: 1,
                selector: LabelSelector {
                    match_labels: router_selector.clone(),
                },
                strategy: None,
                template: PodTemplateSpec {
                    metadata: ObjectMeta {
                        labels: router_labels.clone(),
                        ..Default::default()
                    },
                    spec: PodSpec {
                        init_containers,
                        containers: vec![container],
                        volumes: vec![Volume::secret(
                            MESH_SECRET_VOLUME_NAME.to_string(),
                            router_secret,
                        )],
                        service_account_name: None,
                        automount_service_account_token: Some(false),
                        restart_policy: None,
                    },
                },
            },
        };

        files.insert(
            PathBuf::from("03-deployments/amber-router.yaml"),
            to_yaml(&deployment)?,
        );

        if !router_service_ports.is_empty() {
            let service = Service::new(
                ROUTER_NAME,
                &namespace,
                router_labels.clone(),
                router_selector.clone(),
                router_service_ports.clone(),
            );
            files.insert(
                PathBuf::from("04-services/amber-router.yaml"),
                to_yaml(&service)?,
            );
        }
    }

    // Services (only for components with provides)
    for id in program_components {
        let cnames = names.get(id).unwrap();
        let labels = component_labels(*id, &cnames.service);
        let mesh_port = *mesh_ports_by_component.get(id).expect("mesh port missing");

        let selector = {
            let mut m = BTreeMap::new();
            m.insert("amber.io/component".to_string(), cnames.service.clone());
            m
        };

        let service_ports = vec![ServicePort {
            name: "mesh".to_string(),
            port: mesh_port,
            target_port: mesh_port,
            protocol: "TCP",
        }];

        let svc = Service::new(&cnames.service, &namespace, labels, selector, service_ports);

        files.insert(
            PathBuf::from(format!("04-services/{}.yaml", cnames.service)),
            to_yaml(&svc)?,
        );
    }

    // NetworkPolicies
    for id in program_components {
        let cnames = names.get(id).unwrap();
        let labels = component_labels(*id, &cnames.service);

        let pod_selector = {
            let mut m = BTreeMap::new();
            m.insert("amber.io/component".to_string(), cnames.service.clone());
            m
        };

        let mut netpol = NetworkPolicy::new(&cnames.netpol, &namespace, labels, pod_selector);

        if let Some(allowed) = allow_plan.for_component(*id) {
            for (port, consumers) in allowed {
                let from: Vec<NetworkPolicyPeer> = consumers
                    .iter()
                    .map(|consumer| match consumer {
                        WorkloadId::Component(cid) => {
                            let consumer_names = names.get(cid).unwrap();
                            NetworkPolicyPeer {
                                pod_selector: Some(LabelSelector {
                                    match_labels: {
                                        let mut m = BTreeMap::new();
                                        m.insert(
                                            "amber.io/component".to_string(),
                                            consumer_names.service.clone(),
                                        );
                                        m
                                    },
                                }),
                                namespace_selector: None,
                                ip_block: None,
                            }
                        }
                        WorkloadId::Router => NetworkPolicyPeer {
                            pod_selector: Some(LabelSelector {
                                match_labels: router_selector.clone(),
                            }),
                            namespace_selector: None,
                            ip_block: None,
                        },
                    })
                    .collect();

                if from.is_empty() {
                    continue;
                }

                netpol.add_ingress_rule(NetworkPolicyIngressRule {
                    from,
                    ports: vec![NetworkPolicyPort {
                        protocol: "TCP",
                        port: *port,
                    }],
                });
            }
        }

        let egress_from_consumers = egress_allow.get(id);
        let egress_to_router = egress_router_allow.get(id);
        if egress_from_consumers.is_some() || egress_to_router.is_some() {
            netpol.add_egress_rule(NetworkPolicyEgressRule {
                to: vec![NetworkPolicyPeer {
                    pod_selector: None,
                    namespace_selector: None,
                    ip_block: Some(IpBlock {
                        cidr: "0.0.0.0/0".to_string(),
                        except: Vec::new(),
                    }),
                }],
                ports: vec![
                    NetworkPolicyPort {
                        protocol: "UDP",
                        port: 53,
                    },
                    NetworkPolicyPort {
                        protocol: "TCP",
                        port: 53,
                    },
                ],
            });
            netpol.add_egress_rule(NetworkPolicyEgressRule {
                to: vec![NetworkPolicyPeer {
                    pod_selector: Some(LabelSelector {
                        match_labels: otelcol_selector.clone(),
                    }),
                    namespace_selector: None,
                    ip_block: None,
                }],
                ports: vec![NetworkPolicyPort {
                    protocol: "TCP",
                    port: OTELCOL_SERVICE_PORT_HTTP,
                }],
            });

            if let Some(by_provider) = egress_from_consumers {
                for (provider, ports) in by_provider {
                    let provider_names = names.get(provider).unwrap();
                    let mut selector = BTreeMap::new();
                    selector.insert(
                        "amber.io/component".to_string(),
                        provider_names.service.clone(),
                    );
                    netpol.add_egress_rule(NetworkPolicyEgressRule {
                        to: vec![NetworkPolicyPeer {
                            pod_selector: Some(LabelSelector {
                                match_labels: selector,
                            }),
                            namespace_selector: None,
                            ip_block: None,
                        }],
                        ports: ports
                            .iter()
                            .map(|port| NetworkPolicyPort {
                                protocol: "TCP",
                                port: *port,
                            })
                            .collect(),
                    });
                }
            }

            if let Some(ports) = egress_to_router {
                netpol.add_egress_rule(NetworkPolicyEgressRule {
                    to: vec![NetworkPolicyPeer {
                        pod_selector: Some(LabelSelector {
                            match_labels: router_selector.clone(),
                        }),
                        namespace_selector: None,
                        ip_block: None,
                    }],
                    ports: ports
                        .iter()
                        .map(|port| NetworkPolicyPort {
                            protocol: "TCP",
                            port: *port,
                        })
                        .collect(),
                });
            }
        }

        files.insert(
            PathBuf::from(format!("05-networkpolicies/{}.yaml", cnames.netpol)),
            to_yaml(&netpol)?,
        );
    }

    if needs_router {
        let mut netpol = NetworkPolicy::new(
            format!("{ROUTER_NAME}-netpol"),
            &namespace,
            router_labels.clone(),
            router_selector.clone(),
        );

        if let Some(allowed) = allow_plan.for_router() {
            for (port, consumers) in allowed {
                let from: Vec<NetworkPolicyPeer> = consumers
                    .iter()
                    .filter_map(|consumer| match consumer {
                        WorkloadId::Component(cid) => {
                            let consumer_names = names
                                .get(cid)
                                .expect("router consumer should be a runnable component");
                            Some(NetworkPolicyPeer {
                                pod_selector: Some(LabelSelector {
                                    match_labels: {
                                        let mut m = BTreeMap::new();
                                        m.insert(
                                            "amber.io/component".to_string(),
                                            consumer_names.service.clone(),
                                        );
                                        m
                                    },
                                }),
                                namespace_selector: None,
                                ip_block: None,
                            })
                        }
                        WorkloadId::Router => None,
                    })
                    .collect();

                if from.is_empty() {
                    continue;
                }

                netpol.add_ingress_rule(NetworkPolicyIngressRule {
                    from,
                    ports: vec![NetworkPolicyPort {
                        protocol: "TCP",
                        port: *port,
                    }],
                });
            }
        }

        if !mesh_plan.exports().is_empty() {
            netpol.add_ingress_rule(NetworkPolicyIngressRule {
                from: vec![NetworkPolicyPeer {
                    pod_selector: None,
                    namespace_selector: None,
                    ip_block: Some(IpBlock {
                        cidr: "0.0.0.0/0".to_string(),
                        except: Vec::new(),
                    }),
                }],
                ports: vec![NetworkPolicyPort {
                    protocol: "TCP",
                    port: router_mesh_port,
                }],
            });
        }

        files.insert(
            PathBuf::from("05-networkpolicies/amber-router-netpol.yaml"),
            to_yaml(&netpol)?,
        );
    }

    let export_metadata: BTreeMap<String, ExportMetadata> = export_descriptors
        .into_iter()
        .map(|(name, export)| {
            let route_protocol = match export.protocol {
                amber_manifest::NetworkProtocol::Http | amber_manifest::NetworkProtocol::Https => {
                    MeshProtocol::Http
                }
                amber_manifest::NetworkProtocol::Tcp => MeshProtocol::Tcp,
                other => panic!("unsupported kubernetes export protocol: {other}"),
            };
            let route_id = router_export_route_id(&name, route_protocol);
            (
                name,
                ExportMetadata {
                    component: export.component,
                    provide: export.provide,
                    protocol: export.protocol.to_string(),
                    router_mesh_port,
                    route_id: Some(route_id),
                },
            )
        })
        .collect();

    let mut input_metadata: BTreeMap<String, InputMetadata> = BTreeMap::new();
    for (path, input) in root_inputs {
        input_metadata.insert(
            path.clone(),
            InputMetadata {
                required: input.required,
                secret: input.secret,
            },
        );
    }

    let external_slot_metadata: BTreeMap<String, ExternalSlotMetadata> = external_slot_descriptors
        .into_iter()
        .map(|(name, slot)| {
            (
                name,
                ExternalSlotMetadata {
                    required: slot.required,
                    kind: slot.decl.kind,
                    url_env: slot.url_env,
                },
            )
        })
        .collect();

    let scenario_metadata = ScenarioMetadata {
        version: "1",
        digest: encode_scenario_digest(&scenario_digest),
        exports: export_metadata.clone(),
        inputs: input_metadata,
        external_slots: external_slot_metadata.clone(),
    };

    let metadata_json = serde_json::to_string_pretty(&scenario_metadata)
        .map_err(|e| ReporterError::new(format!("failed to serialize scenario metadata: {e}")))?;

    let mut metadata_data = BTreeMap::new();
    metadata_data.insert("scenario.json".to_string(), metadata_json);

    let metadata_cm = ConfigMap::new(
        "amber-metadata",
        &namespace,
        scenario_labels(&[("amber.io/type", "metadata")]),
        metadata_data,
    );
    files.insert(
        PathBuf::from("01-configmaps/amber-metadata.yaml"),
        to_yaml(&metadata_cm)?,
    );

    if !mesh_provision_plan.targets.is_empty() {
        let mut secret_names = BTreeSet::new();
        for target in &mesh_provision_plan.targets {
            if let MeshProvisionOutput::KubernetesSecret { name, .. } = &target.output {
                secret_names.insert(name.clone());
            }
        }
        let secret_names: Vec<String> = secret_names.into_iter().collect();

        let plan_json = serde_json::to_string_pretty(&mesh_provision_plan)
            .map_err(|e| ReporterError::new(format!("failed to serialize mesh plan: {e}")))?;
        let mut plan_data = BTreeMap::new();
        plan_data.insert(PROVISIONER_PLAN_KEY.to_string(), plan_json);
        let plan_cm = ConfigMap::new(
            PROVISIONER_CONFIGMAP_NAME,
            &namespace,
            scenario_labels(&[("amber.io/type", "mesh-provision")]),
            plan_data,
        );
        files.insert(
            PathBuf::from("01-configmaps/amber-mesh-provision.yaml"),
            to_yaml(&plan_cm)?,
        );

        let provisioner_labels = scenario_labels(&[("amber.io/type", "provisioner")]);
        let service_account = ServiceAccount::new(
            PROVISIONER_SERVICE_ACCOUNT,
            &namespace,
            provisioner_labels.clone(),
        );
        files.insert(
            PathBuf::from("02-rbac/amber-provisioner-sa.yaml"),
            to_yaml(&service_account)?,
        );

        let role = Role::new(
            PROVISIONER_ROLE_NAME,
            &namespace,
            provisioner_labels.clone(),
            vec![
                PolicyRule {
                    api_groups: vec!["".to_string()],
                    resources: vec!["secrets".to_string()],
                    verbs: vec!["create".to_string()],
                    resource_names: None,
                },
                PolicyRule {
                    api_groups: vec!["".to_string()],
                    resources: vec!["secrets".to_string()],
                    verbs: vec!["get".to_string(), "update".to_string()],
                    resource_names: Some(secret_names),
                },
            ],
        );
        files.insert(
            PathBuf::from("02-rbac/amber-provisioner-role.yaml"),
            to_yaml(&role)?,
        );

        let role_binding = RoleBinding::new(
            PROVISIONER_ROLE_BINDING_NAME,
            &namespace,
            provisioner_labels,
            Subject {
                kind: "ServiceAccount".to_string(),
                name: PROVISIONER_SERVICE_ACCOUNT.to_string(),
                namespace: None,
            },
            RoleRef {
                api_group: "rbac.authorization.k8s.io".to_string(),
                kind: "Role".to_string(),
                name: PROVISIONER_ROLE_NAME.to_string(),
            },
        );
        files.insert(
            PathBuf::from("02-rbac/amber-provisioner-rolebinding.yaml"),
            to_yaml(&role_binding)?,
        );

        let plan_mount_name = "mesh-plan";
        let plan_mount_dir = "/etc/amber";
        let container = harden_non_root_internal_container(Container {
            name: PROVISIONER_NAME.to_string(),
            image: images.provisioner.clone(),
            command: Vec::new(),
            args: Vec::new(),
            env: vec![EnvVar::literal(
                "AMBER_MESH_PROVISION_PLAN_PATH",
                format!("{plan_mount_dir}/{PROVISIONER_PLAN_KEY}"),
            )],
            env_from: Vec::new(),
            ports: Vec::new(),
            readiness_probe: None,
            security_context: None,
            volume_mounts: vec![VolumeMount {
                name: plan_mount_name.to_string(),
                mount_path: plan_mount_dir.to_string(),
                read_only: Some(true),
            }],
        });

        let job = Job::new_with_backoff_limit(
            &provisioner_job_name,
            &namespace,
            scenario_labels(&[("amber.io/type", "provisioner")]),
            PodTemplateSpec {
                metadata: ObjectMeta {
                    labels: scenario_labels(&[("amber.io/type", "provisioner")]),
                    ..Default::default()
                },
                spec: PodSpec {
                    init_containers: Vec::new(),
                    containers: vec![container],
                    volumes: vec![Volume::config_map(
                        plan_mount_name.to_string(),
                        PROVISIONER_CONFIGMAP_NAME,
                    )],
                    service_account_name: Some(PROVISIONER_SERVICE_ACCOUNT.to_string()),
                    automount_service_account_token: None,
                    restart_policy: Some("Never"),
                },
            },
            Some(PROVISIONER_JOB_BACKOFF_LIMIT),
        );
        let mut job = job;
        job.spec.ttl_seconds_after_finished = Some(300);
        files.insert(
            PathBuf::from("02-rbac/amber-provisioner-job.yaml"),
            to_yaml(&job)?,
        );
    }

    if needs_router {
        let router_metadata = RouterMetadata {
            mesh_port: router_mesh_port,
            control_port: router_ports.as_ref().expect("router ports missing").control,
            compose_project: None,
            control_socket: None,
            control_socket_volume: None,
        };
        let proxy_metadata = ProxyMetadata {
            version: PROXY_METADATA_VERSION.to_string(),
            router: Some(router_metadata),
            exports: export_metadata.clone(),
            external_slots: external_slot_metadata.clone(),
        };
        let proxy_json = serde_json::to_string_pretty(&proxy_metadata)
            .map_err(|e| ReporterError::new(format!("failed to serialize proxy metadata: {e}")))?;
        files.insert(PathBuf::from(PROXY_METADATA_FILENAME), proxy_json);
    }

    let execution_guide =
        build_execution_guide(s, &mesh_plan, &config_plan, !storage_plan.is_empty(), false)?;
    let mut rollout_commands: Vec<String> = program_components
        .iter()
        .map(|id| {
            let service = &names.get(id).expect("component names").service;
            format!("kubectl -n {namespace} rollout status deploy/{service}")
        })
        .collect();
    if needs_router {
        rollout_commands.push(format!(
            "kubectl -n {namespace} rollout status deploy/{ROUTER_NAME}"
        ));
    }
    rollout_commands.sort();
    files.insert(
        PathBuf::from(GENERATED_README_FILENAME),
        execution_guide.render_kubernetes_readme(&namespace, &rollout_commands, needs_router),
    );

    // Always generate kustomization.yaml for consistency, even if not using helper mode.
    let mut kust_resources = Vec::new();

    for path in files.keys() {
        if path == &PathBuf::from("root-config.env")
            || path == &PathBuf::from("root-config-secret.env")
            || path == &PathBuf::from(DEFAULT_EXTERNAL_ENV_FILE)
            || path == &PathBuf::from(COMPONENT_SIDECAR_ENV_FILE)
            || path == &PathBuf::from(PROXY_METADATA_FILENAME)
            || path == &PathBuf::from(GENERATED_README_FILENAME)
        {
            continue; // Skip non-resource files.
        }
        kust_resources.push(path.to_string_lossy().to_string());
    }
    kust_resources.sort();

    kustomization.resources = kust_resources;
    files.insert(
        PathBuf::from("kustomization.yaml"),
        to_yaml(&kustomization)?,
    );

    Ok(KubernetesArtifact { files })
}

#[cfg(test)]
mod tests;
