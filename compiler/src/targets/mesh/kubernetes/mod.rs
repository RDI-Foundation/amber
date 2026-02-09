mod resources;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
};

use amber_config as rc;
use amber_mesh::{
    MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME, MESH_PROVISION_PLAN_VERSION, MeshProvisionOutput,
    MeshProvisionPlan, MeshProvisionTarget, MeshProvisionTargetKind,
};
use amber_scenario::{ComponentId, Scenario};
pub use resources::*;
use serde::Serialize;

use crate::{
    CompileOutput,
    reporter::{Reporter, ReporterError},
    targets::mesh::{
        addressing::{Addressing, WorkloadId, build_address_plan, build_allow_plan},
        config::{ProgramPlan, encode_helper_payload, encode_schema_b64},
        internal_images::resolve_internal_images,
        mesh_config::{MeshAddressing, RouterPorts, build_mesh_config_plan},
        plan::{MeshError, MeshOptions, component_label},
        ports::{allocate_mesh_ports, allocate_slot_ports},
        proxy_metadata::{
            DEFAULT_EXTERNAL_ENV_FILE, ExportMetadata, ExternalSlotMetadata,
            PROXY_METADATA_FILENAME, PROXY_METADATA_VERSION, ProxyMetadata, RouterMetadata,
            collect_exports_metadata, collect_external_slot_metadata,
        },
    },
};

// Helper injection system: When a component requires runtime config interpolation,
// an init container installs the amber-helper binary into a shared volume, then the
// main container uses the helper as its entrypoint to resolve config templates and
// exec the actual program.
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
const COMPONENT_MESH_PORT_BASE: u16 = 23000;
const ROUTER_MESH_PORT_BASE: u16 = 24000;
const ROUTER_CONTROL_PORT_BASE: u16 = 24100;

// Root config Secret/ConfigMap names.
const ROOT_CONFIG_SECRET_NAME: &str = "amber-root-config-secret";
const ROOT_CONFIG_CONFIGMAP_NAME: &str = "amber-root-config";

/// Kubernetes reporter configuration.
#[derive(Clone, Debug, Default)]
pub struct KubernetesReporterConfig {
    /// Disable generation of NetworkPolicy enforcement check resources.
    pub disable_networkpolicy_check: bool,
}

/// Reporter that outputs Kubernetes manifests as a directory structure.
#[derive(Clone, Debug, Default)]
pub struct KubernetesReporter {
    pub config: KubernetesReporterConfig,
}

/// Output artifact containing all generated Kubernetes YAML files.
#[derive(Clone, Debug)]
pub struct KubernetesArtifact {
    /// Map of relative path -> YAML content.
    pub files: BTreeMap<PathBuf, String>,
}

impl Reporter for KubernetesReporter {
    type Artifact = KubernetesArtifact;

    fn emit(&self, output: &CompileOutput) -> Result<Self::Artifact, ReporterError> {
        render_kubernetes(output, &self.config)
    }
}

struct KubernetesAddressing<'a> {
    scenario: &'a Scenario,
    slot_ports_by_component: &'a HashMap<ComponentId, BTreeMap<String, u16>>,
}

impl Addressing for KubernetesAddressing<'_> {
    type Error = crate::targets::mesh::plan::MeshError;

    fn resolve_binding_url(
        &mut self,
        binding: &crate::targets::mesh::plan::ResolvedBinding,
    ) -> Result<String, Self::Error> {
        let local_port = self.local_slot_port(binding.consumer, &binding.slot)?;
        Ok(format!("http://127.0.0.1:{local_port}"))
    }

    fn resolve_external_binding_url(
        &mut self,
        binding: &crate::targets::mesh::plan::ResolvedExternalBinding,
    ) -> Result<String, Self::Error> {
        let local_port = self.local_slot_port(binding.consumer, &binding.slot)?;
        Ok(format!("http://127.0.0.1:{local_port}"))
    }
}

impl KubernetesAddressing<'_> {
    fn local_slot_port(&self, component: ComponentId, slot: &str) -> Result<u16, MeshError> {
        self.slot_ports_by_component
            .get(&component)
            .and_then(|ports| ports.get(slot))
            .copied()
            .ok_or_else(|| {
                MeshError::new(format!(
                    "internal error: missing local port allocation for {}.{}",
                    component_label(self.scenario, component),
                    slot
                ))
            })
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

/// Metadata about a config input for the amber-metadata ConfigMap.
#[derive(Clone, Debug, Serialize)]
struct InputMetadata {
    required: bool,
    secret: bool,
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

fn render_kubernetes(
    output: &CompileOutput,
    config: &KubernetesReporterConfig,
) -> KubernetesResult<KubernetesArtifact> {
    let s = &output.scenario;

    let mesh_plan = crate::targets::mesh::plan::build_mesh_plan(
        s,
        &output.store,
        MeshOptions {
            backend_label: "kubernetes reporter",
        },
    )
    .map_err(|e| ReporterError::new(e.to_string()))?;
    let images = resolve_internal_images().map_err(ReporterError::new)?;

    let program_components = mesh_plan.program_components.as_slice();
    let manifests = &mesh_plan.manifests;

    // Generate namespace name.
    let namespace = generate_namespace_name(s);

    // Generate component names.
    let mut names: HashMap<ComponentId, ComponentNames> = HashMap::new();
    for id in program_components {
        let c = s.component(*id);
        let base = service_name(*id, c.moniker.local_name().unwrap_or("component"));
        names.insert(
            *id,
            ComponentNames {
                service: base.clone(),
                netpol: format!("{base}-netpol"),
            },
        );
    }
    let root_manifest = manifests[s.root.0]
        .as_ref()
        .expect("root manifest should exist");

    let needs_router = !mesh_plan.external_bindings.is_empty() || !mesh_plan.exports.is_empty();

    let slot_ports_by_component = allocate_slot_ports(s, program_components)
        .map_err(|e| ReporterError::new(e.to_string()))?;
    let mesh_ports_by_component = allocate_mesh_ports(
        s,
        program_components,
        COMPONENT_MESH_PORT_BASE,
        &slot_ports_by_component,
    )
    .map_err(|e| ReporterError::new(e.to_string()))?;
    let router_ports = needs_router.then_some(RouterPorts {
        mesh: ROUTER_MESH_PORT_BASE,
        control: ROUTER_CONTROL_PORT_BASE,
    });
    let router_mesh_port_opt = router_ports.map(|ports| ports.mesh);

    let addressing = KubernetesAddressing {
        scenario: s,
        slot_ports_by_component: &slot_ports_by_component,
    };
    let address_plan = build_address_plan(&mesh_plan, addressing)
        .map_err(|e| ReporterError::new(e.to_string()))?;

    struct KubernetesMeshAddressing<'a> {
        names: &'a HashMap<ComponentId, ComponentNames>,
        namespace: &'a str,
        mesh_ports_by_component: &'a HashMap<ComponentId, u16>,
        router_mesh_port: u16,
    }

    impl MeshAddressing for KubernetesMeshAddressing<'_> {
        fn mesh_addr_for_component(&self, id: ComponentId) -> Result<String, MeshError> {
            let svc = self.names.get(&id).ok_or_else(|| {
                MeshError::new(format!("missing service name for component {id:?}"))
            })?;
            let port = *self
                .mesh_ports_by_component
                .get(&id)
                .ok_or_else(|| MeshError::new(format!("missing mesh port for component {id:?}")))?;
            Ok(format!(
                "{}.{}.svc.cluster.local:{}",
                svc.service, self.namespace, port
            ))
        }

        fn mesh_addr_for_router(&self) -> Result<String, MeshError> {
            Ok(format!(
                "{}.{}.svc.cluster.local:{}",
                ROUTER_NAME, self.namespace, self.router_mesh_port
            ))
        }
    }

    let router_mesh_port = router_ports
        .as_ref()
        .map(|ports| ports.mesh)
        .unwrap_or(ROUTER_MESH_PORT_BASE);
    let mesh_addressing = KubernetesMeshAddressing {
        names: &names,
        namespace: &namespace,
        mesh_ports_by_component: &mesh_ports_by_component,
        router_mesh_port,
    };
    let mesh_config_plan = build_mesh_config_plan(
        s,
        &mesh_plan,
        root_manifest,
        &slot_ports_by_component,
        &mesh_ports_by_component,
        router_ports,
        &mesh_addressing,
    )
    .map_err(|e| ReporterError::new(e.to_string()))?;
    let mesh_provision_plan =
        build_provision_plan(&mesh_config_plan, program_components, &names, &namespace)
            .map_err(|err| ReporterError::new(err.to_string()))?;

    let allow_plan = build_allow_plan(&mesh_plan, &mesh_ports_by_component, router_mesh_port_opt)
        .map_err(|e| ReporterError::new(e.to_string()))?;

    let mut egress_allow: HashMap<ComponentId, BTreeMap<ComponentId, BTreeSet<u16>>> =
        HashMap::new();
    let mut egress_router_allow: HashMap<ComponentId, BTreeSet<u16>> = HashMap::new();

    for (provider, by_port) in &allow_plan.by_provider {
        match provider {
            WorkloadId::Component(provider_id) => {
                for (port, consumers) in by_port {
                    for consumer in consumers {
                        if let WorkloadId::Component(consumer_id) = consumer {
                            egress_allow
                                .entry(*consumer_id)
                                .or_default()
                                .entry(*provider_id)
                                .or_default()
                                .insert(*port);
                        }
                    }
                }
            }
            WorkloadId::Router => {
                for (port, consumers) in by_port {
                    for consumer in consumers {
                        if let WorkloadId::Component(consumer_id) = consumer {
                            egress_router_allow
                                .entry(*consumer_id)
                                .or_default()
                                .insert(*port);
                        }
                    }
                }
            }
        }
    }

    let config_plan = crate::targets::mesh::config::build_config_plan(
        s,
        program_components,
        &address_plan.slot_values_by_component,
        &address_plan.binding_values_by_component,
    )
    .map_err(|e| ReporterError::new(e.to_string()))?;
    let root_schema = config_plan.root_schema.as_ref();

    // Standard labels for all resources.
    let scenario_labels = |extra: &[(&str, &str)]| -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "amber".to_string(),
        );
        labels.insert(
            "amber.io/scenario".to_string(),
            sanitize_label_value(&namespace),
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

    // ---- Generate resources ----

    let mut files: BTreeMap<PathBuf, String> = BTreeMap::new();

    // Namespace
    let ns = Namespace::new(&namespace, scenario_labels(&[]));
    files.insert(PathBuf::from("00-namespace.yaml"), to_yaml(&ns)?);

    let root_leaves = &config_plan.root_leaves;
    let program_plans = &config_plan.program_plans;
    let any_helper = config_plan.uses_helper;

    let router_env_passthrough = &mesh_config_plan.router_env_passthrough;
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

    // Build kustomization (will be populated at the end if helper mode is used).
    let mut kustomization = Kustomization::new();
    kustomization.namespace = Some(namespace.clone());

    // If any component needs helper, generate root config Secret/ConfigMap and .env templates.
    if any_helper {
        // Separate root leaves into secret and non-secret.
        let (secret_leaves, config_leaves): (Vec<_>, Vec<_>) =
            root_leaves.iter().partition(|l| l.secret);

        // Add secretGenerator for secret config values.
        if !secret_leaves.is_empty() {
            kustomization.secret_generator.push(SecretGenerator {
                name: ROOT_CONFIG_SECRET_NAME.to_string(),
                namespace: Some(namespace.clone()),
                env_files: vec!["root-config-secret.env".to_string()],
                literals: Vec::new(),
                options: Some(GeneratorOptions {
                    disable_name_suffix_hash: Some(true),
                }),
            });

            // Generate template .env file for secrets.
            let mut env_content = String::new();
            env_content.push_str("# Root config secrets - fill in values before deploying\n");
            for leaf in &secret_leaves {
                let env_var = rc::env_var_for_path(&leaf.path)
                    .map_err(|e| ReporterError::new(format!("failed to map config path: {e}")))?;
                env_content.push_str(&format!("{}=\n", env_var));
            }
            files.insert(PathBuf::from("root-config-secret.env"), env_content);
        }

        // Add configMapGenerator for non-secret config values.
        if !config_leaves.is_empty() {
            kustomization.config_map_generator.push(ConfigMapGenerator {
                name: ROOT_CONFIG_CONFIGMAP_NAME.to_string(),
                namespace: Some(namespace.clone()),
                env_files: vec!["root-config.env".to_string()],
                literals: Vec::new(),
                options: Some(GeneratorOptions {
                    disable_name_suffix_hash: Some(true),
                }),
            });

            // Generate template .env file for config.
            let mut env_content = String::new();
            env_content.push_str("# Root config values - fill in values before deploying\n");
            for leaf in &config_leaves {
                let env_var = rc::env_var_for_path(&leaf.path)
                    .map_err(|e| ReporterError::new(format!("failed to map config path: {e}")))?;
                env_content.push_str(&format!("{}=\n", env_var));
            }
            files.insert(PathBuf::from("root-config.env"), env_content);
        }

        // Don't insert kustomization yet - we'll do it at the end after collecting all resource paths
    }

    if needs_router && !router_env_passthrough.is_empty() {
        kustomization.secret_generator.push(SecretGenerator {
            name: ROUTER_EXTERNAL_SECRET_NAME.to_string(),
            namespace: Some(namespace.clone()),
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

    // Note: Per-component ConfigMaps/Secrets are not generated because:
    // - Direct mode: all config must be fully static (no runtime interpolation).
    //   Static values are rendered to strings and inlined directly into the
    //   Deployment YAML as literal env vars. This includes secret config values,
    //   which will be visible in the generated YAML.
    // - Helper mode: config with runtime interpolation uses the helper binary.
    //   The helper reads config values from the root config Secret/ConfigMap at
    //   runtime and resolves templates, so secret values are not inlined.
    // The only ConfigMaps generated are amber-metadata and the Kustomize-generated
    // root config (when helper mode is used).

    // Encode root schema for helper (needed for all helper components).
    let root_schema_b64 = if any_helper {
        let root_schema = root_schema.ok_or_else(|| {
            ReporterError::new(
                "root component must declare `config_schema` when runtime config interpolation is \
                 required"
                    .to_string(),
            )
        })?;
        Some(
            encode_schema_b64("root config definition", root_schema)
                .map_err(|e| ReporterError::new(e.to_string()))?,
        )
    } else {
        None
    };

    // Deployments
    for id in program_components {
        let c = s.component(*id);
        let cnames = names.get(id).unwrap();
        let labels = component_labels(*id, &cnames.service);
        let program = c.program.as_ref().unwrap();
        let program_plan = program_plans.get(id).unwrap();
        let mesh_port = *mesh_ports_by_component.get(id).expect("mesh port missing");

        // Container ports.
        let mut ports: Vec<ContainerPort> = Vec::new();
        if let Some(network) = &program.network {
            for ep in &network.endpoints {
                ports.push(ContainerPort {
                    name: sanitize_port_name(&ep.name),
                    container_port: ep.port,
                    protocol: "TCP",
                });
            }
        }

        // Build container based on program mode.
        let (container, mut volumes) = match program_plan {
            ProgramPlan::Direct { entrypoint, env } => {
                // Direct mode: use resolved entrypoint and env directly.
                // Config values are already baked into the entrypoint/env strings,
                // so we don't need AMBER_CONFIG_* env vars here.
                let container_env: Vec<EnvVar> =
                    env.iter().map(|(k, v)| EnvVar::literal(k, v)).collect();

                let container = Container {
                    name: "main".to_string(),
                    image: program.image.clone(),
                    command: entrypoint.clone(),
                    args: Vec::new(),
                    env: container_env,
                    env_from: Vec::new(),
                    ports,
                    readiness_probe: None,
                    volume_mounts: Vec::new(),
                };

                (container, Vec::new())
            }
            ProgramPlan::Helper {
                template_spec,
                component_template,
                component_schema,
            } => {
                let label = component_label(s, *id);
                let payload = encode_helper_payload(
                    &label,
                    template_spec,
                    component_template,
                    component_schema,
                )
                .map_err(|e| ReporterError::new(e.to_string()))?;

                // Helper mode: use helper binary as entrypoint, mount shared volume.
                let mut container_env: Vec<EnvVar> = Vec::new();

                // Collect config paths referenced by this component's template.
                let referenced_paths = collect_config_refs(component_template);

                // Add only the root config env vars that are actually referenced by this component.
                // If referenced_paths is None, it means the component template is Root and needs all config.
                for leaf in root_leaves {
                    // Check if this leaf path is referenced by the component template.
                    let should_include = match &referenced_paths {
                        Some(paths) => paths.contains(&leaf.path),
                        None => true, // Root template needs all config
                    };

                    if !should_include {
                        continue;
                    }

                    let env_var = rc::env_var_for_path(&leaf.path).map_err(|e| {
                        ReporterError::new(format!("failed to map config path: {e}"))
                    })?;

                    if leaf.secret {
                        container_env.push(EnvVar::from_secret(
                            &env_var,
                            ROOT_CONFIG_SECRET_NAME,
                            &env_var,
                        ));
                    } else {
                        container_env.push(EnvVar::from_config_map(
                            &env_var,
                            ROOT_CONFIG_CONFIGMAP_NAME,
                            &env_var,
                        ));
                    }
                }

                // Add helper-specific env vars.
                let root_schema_b64 = root_schema_b64
                    .as_ref()
                    .expect("helper mode requires root schema");
                container_env.push(EnvVar::literal(
                    "AMBER_ROOT_CONFIG_SCHEMA_B64",
                    root_schema_b64,
                ));
                container_env.push(EnvVar::literal(
                    "AMBER_COMPONENT_CONFIG_SCHEMA_B64",
                    &payload.component_schema_b64,
                ));
                container_env.push(EnvVar::literal(
                    "AMBER_COMPONENT_CONFIG_TEMPLATE_B64",
                    &payload.component_cfg_template_b64,
                ));
                container_env.push(EnvVar::literal(
                    "AMBER_TEMPLATE_SPEC_B64",
                    &payload.template_spec_b64,
                ));

                let container = Container {
                    name: "main".to_string(),
                    image: program.image.clone(),
                    command: vec![HELPER_BIN_PATH.to_string(), "run".to_string()],
                    args: Vec::new(),
                    env: container_env,
                    env_from: Vec::new(),
                    ports,
                    readiness_probe: None,
                    volume_mounts: vec![VolumeMount {
                        name: HELPER_VOLUME_NAME.to_string(),
                        mount_path: HELPER_BIN_DIR.to_string(),
                        read_only: Some(true),
                    }],
                };

                let volumes = vec![Volume::empty_dir(HELPER_VOLUME_NAME)];

                (container, volumes)
            }
        };
        let mesh_secret = mesh_secret_name(&cnames.service);
        volumes.push(Volume::secret(
            MESH_SECRET_VOLUME_NAME.to_string(),
            mesh_secret,
        ));

        let sidecar = Container {
            name: "sidecar".to_string(),
            image: images.router.clone(),
            command: Vec::new(),
            args: Vec::new(),
            env: vec![
                EnvVar::literal(
                    "AMBER_ROUTER_CONFIG_PATH",
                    format!("{MESH_CONFIG_DIR}/{MESH_CONFIG_FILENAME}"),
                ),
                EnvVar::literal(
                    "AMBER_ROUTER_IDENTITY_PATH",
                    format!("{MESH_CONFIG_DIR}/{MESH_IDENTITY_FILENAME}"),
                ),
            ],
            env_from: Vec::new(),
            ports: vec![ContainerPort {
                name: "mesh".to_string(),
                container_port: mesh_port,
                protocol: "TCP",
            }],
            readiness_probe: None,
            volume_mounts: vec![VolumeMount {
                name: MESH_SECRET_VOLUME_NAME.to_string(),
                mount_path: MESH_CONFIG_DIR.to_string(),
                read_only: Some(true),
            }],
        };

        // Add init containers.
        let mut init_containers = Vec::new();

        // For helper mode, add init container to install the helper binary.
        if matches!(program_plan, ProgramPlan::Helper { .. }) {
            init_containers.push(Container {
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
                volume_mounts: vec![VolumeMount {
                    name: HELPER_VOLUME_NAME.to_string(),
                    mount_path: HELPER_BIN_DIR.to_string(),
                    read_only: None,
                }],
            });
        }

        // Add init container to wait for NetworkPolicy enforcement check.
        if !config.disable_networkpolicy_check {
            init_containers.push(Container {
                name: "wait-for-netpol-check".to_string(),
                image: "busybox:1.36".to_string(),
                command: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    format!(
                        "RESPONSE=$(nc amber-netpol-client.{} 8080 </dev/null 2>/dev/null); [ \
                         \"$RESPONSE\" = \"ready\" ] && echo 'NetworkPolicy enforcement verified'",
                        namespace
                    ),
                ],
                args: Vec::new(),
                env: Vec::new(),
                env_from: Vec::new(),
                ports: Vec::new(),
                readiness_probe: None,
                volume_mounts: Vec::new(),
            });
        }

        let pod_spec = PodSpec {
            init_containers,
            containers: vec![sidecar, container],
            volumes,
            service_account_name: None,
            automount_service_account_token: Some(false),
            restart_policy: None,
        };

        let deployment = Deployment {
            api_version: "apps/v1",
            kind: "Deployment",
            metadata: ObjectMeta {
                name: cnames.service.clone(),
                namespace: Some(namespace.clone()),
                labels: labels.clone(),
                ..Default::default()
            },
            spec: DeploymentSpec {
                replicas: 1,
                selector: LabelSelector {
                    match_labels: {
                        let mut m = BTreeMap::new();
                        m.insert("amber.io/component".to_string(), cnames.service.clone());
                        m
                    },
                },
                template: PodTemplateSpec {
                    metadata: ObjectMeta {
                        labels: labels.clone(),
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

        let container = Container {
            name: "router".to_string(),
            image: images.router.clone(),
            command: Vec::new(),
            args: Vec::new(),
            env,
            env_from,
            ports: router_container_ports.clone(),
            readiness_probe: None,
            volume_mounts: vec![VolumeMount {
                name: MESH_SECRET_VOLUME_NAME.to_string(),
                mount_path: MESH_CONFIG_DIR.to_string(),
                read_only: Some(true),
            }],
        };
        let router_secret = mesh_secret_name(ROUTER_NAME);

        let deployment = Deployment {
            api_version: "apps/v1",
            kind: "Deployment",
            metadata: ObjectMeta {
                name: ROUTER_NAME.to_string(),
                namespace: Some(namespace.clone()),
                labels: router_labels.clone(),
                ..Default::default()
            },
            spec: DeploymentSpec {
                replicas: 1,
                selector: LabelSelector {
                    match_labels: router_selector.clone(),
                },
                template: PodTemplateSpec {
                    metadata: ObjectMeta {
                        labels: router_labels.clone(),
                        ..Default::default()
                    },
                    spec: PodSpec {
                        init_containers: Vec::new(),
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

        // Add ingress rules for bound consumers + router exports.
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

        if !mesh_plan.exports.is_empty() {
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

    // NetworkPolicy enforcement check (unless disabled).
    if !config.disable_networkpolicy_check {
        let enforcement_resources =
            generate_netpol_enforcement_check(&namespace, &scenario_labels(&[]));
        for (filename, resource_yaml) in enforcement_resources {
            files.insert(
                PathBuf::from(format!("06-enforcement/{filename}")),
                resource_yaml?,
            );
        }
    }

    // Metadata ConfigMap
    let export_metadata = collect_exports_metadata(s, &mesh_plan, router_mesh_port);

    let mut input_metadata: BTreeMap<String, InputMetadata> = BTreeMap::new();
    for leaf in root_leaves {
        input_metadata.insert(
            leaf.path.clone(),
            InputMetadata {
                required: leaf.required,
                secret: leaf.secret,
            },
        );
    }

    let external_slot_metadata = collect_external_slot_metadata(root_manifest, &mesh_plan);

    let scenario_metadata = ScenarioMetadata {
        version: "1",
        digest: s.component(s.root).digest.to_string(),
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

        let service_account = ServiceAccount::new(PROVISIONER_SERVICE_ACCOUNT, &namespace);
        files.insert(
            PathBuf::from("02-rbac/amber-provisioner-sa.yaml"),
            to_yaml(&service_account)?,
        );

        let role = Role::new(
            PROVISIONER_ROLE_NAME,
            &namespace,
            vec![PolicyRule {
                api_groups: vec!["".to_string()],
                resources: vec!["secrets".to_string()],
                verbs: vec![
                    "get".to_string(),
                    "create".to_string(),
                    "update".to_string(),
                ],
                resource_names: Some(secret_names),
            }],
        );
        files.insert(
            PathBuf::from("02-rbac/amber-provisioner-role.yaml"),
            to_yaml(&role)?,
        );

        let role_binding = RoleBinding::new(
            PROVISIONER_ROLE_BINDING_NAME,
            &namespace,
            Subject {
                kind: "ServiceAccount".to_string(),
                name: PROVISIONER_SERVICE_ACCOUNT.to_string(),
                namespace: Some(namespace.clone()),
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
        let container = Container {
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
            volume_mounts: vec![VolumeMount {
                name: plan_mount_name.to_string(),
                mount_path: plan_mount_dir.to_string(),
                read_only: Some(true),
            }],
        };

        let job = Job::new_with_backoff_limit(
            PROVISIONER_NAME,
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
        files.insert(
            PathBuf::from("02-rbac/amber-provisioner-job.yaml"),
            to_yaml(&job)?,
        );
    }

    if needs_router {
        let router_metadata = RouterMetadata {
            mesh_port: router_mesh_port,
            control_port: router_ports.as_ref().expect("router ports missing").control,
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

    // Build and insert kustomization with actual file paths.
    // Always generate kustomization.yaml for consistency, even if not using helper mode.
    let mut kust_resources = Vec::new();

    // Collect all YAML files, excluding non-resource files
    for path in files.keys() {
        if path == &PathBuf::from("root-config.env")
            || path == &PathBuf::from("root-config-secret.env")
            || path == &PathBuf::from(DEFAULT_EXTERNAL_ENV_FILE)
            || path == &PathBuf::from(PROXY_METADATA_FILENAME)
        {
            continue; // Skip non-resource files.
        }
        kust_resources.push(path.to_string_lossy().to_string());
    }
    kust_resources.sort();

    // Set the resources list and insert the kustomization
    kustomization.resources = kust_resources;
    files.insert(
        PathBuf::from("kustomization.yaml"),
        to_yaml(&kustomization)?,
    );

    Ok(KubernetesArtifact { files })
}

// ---- Helper functions ----

fn build_provision_plan(
    mesh_config_plan: &crate::targets::mesh::mesh_config::MeshConfigPlan,
    program_components: &[ComponentId],
    names: &HashMap<ComponentId, ComponentNames>,
    namespace: &str,
) -> Result<MeshProvisionPlan, String> {
    let mut targets = Vec::new();
    for id in program_components {
        let cnames = names
            .get(id)
            .ok_or_else(|| format!("missing service name for component {id:?}"))?;
        let template = mesh_config_plan
            .component_configs
            .get(id)
            .ok_or_else(|| format!("missing config template for component {id:?}"))?
            .clone();
        targets.push(MeshProvisionTarget {
            kind: MeshProvisionTargetKind::Component,
            config: template,
            output: MeshProvisionOutput::KubernetesSecret {
                name: mesh_secret_name(&cnames.service),
                namespace: Some(namespace.to_string()),
            },
        });
    }
    if let Some(router_template) = mesh_config_plan.router_config.as_ref() {
        let mut router_template = router_template.clone();
        if let Some(control_listen) = router_template.control_listen {
            router_template.control_listen = Some(
                format!("127.0.0.1:{}", control_listen.port())
                    .parse()
                    .expect("control listen"),
            );
        }
        router_template.control_allow = Some(vec!["127.0.0.1".to_string(), "::1".to_string()]);
        targets.push(MeshProvisionTarget {
            kind: MeshProvisionTargetKind::Router,
            config: router_template,
            output: MeshProvisionOutput::KubernetesSecret {
                name: mesh_secret_name(ROUTER_NAME),
                namespace: Some(namespace.to_string()),
            },
        });
    }
    Ok(MeshProvisionPlan {
        version: MESH_PROVISION_PLAN_VERSION.to_string(),
        targets,
    })
}

fn mesh_secret_name(service: &str) -> String {
    format!("{service}-mesh")
}

fn generate_namespace_name(s: &Scenario) -> String {
    let root = s.component(s.root);
    let short_name = root
        .moniker
        .local_name()
        .unwrap_or("scenario")
        .to_lowercase();
    // Get digest bytes and encode as hex (DNS-safe)
    let digest_bytes = root.digest.bytes();
    let digest_hex: String = digest_bytes[..4]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let base = format!("{}-{}", sanitize_dns_name(&short_name), digest_hex);
    truncate_dns_name(&base, 63)
}

fn service_name(id: ComponentId, local_name: &str) -> String {
    let slug = sanitize_dns_name(local_name);
    let name = format!("c{}-{}", id.0, slug);
    truncate_dns_name(&name, 63)
}

fn sanitize_dns_name(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    // Remove leading/trailing hyphens and collapse multiple hyphens.
    let out = out.trim_matches('-');
    let mut result = String::new();
    let mut last_hyphen = false;
    for ch in out.chars() {
        if ch == '-' {
            if !last_hyphen {
                result.push(ch);
                last_hyphen = true;
            }
        } else {
            result.push(ch);
            last_hyphen = false;
        }
    }
    if result.is_empty() {
        "component".to_string()
    } else {
        result
    }
}

fn truncate_dns_name(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        s[..max_len].trim_end_matches('-').to_string()
    }
}

fn sanitize_label_value(s: &str) -> String {
    // Kubernetes label values: max 63 chars, alphanumeric, -, _, .
    let mut out = String::new();
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        }
    }
    truncate_dns_name(&out, 63)
}

fn sanitize_port_name(s: &str) -> String {
    // Port names: max 15 chars, lowercase alphanumeric and hyphens.
    let sanitized = sanitize_dns_name(s);
    truncate_dns_name(&sanitized, 15)
}

// ---- Runtime config / helper mode support ----

/// Collect all config paths referenced in a RootConfigTemplate.
/// Returns None if the template is Root (indicating all config should be provided).
/// Returns Some(paths) with the specific paths referenced in the template.
fn collect_config_refs(
    template: &rc::RootConfigTemplate,
) -> Option<std::collections::BTreeSet<String>> {
    use std::collections::BTreeSet;

    fn collect_from_node(node: &rc::ConfigNode, acc: &mut BTreeSet<String>) {
        match node {
            rc::ConfigNode::ConfigRef(path) => {
                acc.insert(path.clone());
            }
            rc::ConfigNode::StringTemplate(parts) => {
                for part in parts {
                    if let amber_template::TemplatePart::Config { config } = part {
                        acc.insert(config.clone());
                    }
                }
            }
            rc::ConfigNode::Array(items) => {
                for item in items {
                    collect_from_node(item, acc);
                }
            }
            rc::ConfigNode::Object(map) => {
                for value in map.values() {
                    collect_from_node(value, acc);
                }
            }
            _ => {}
        }
    }

    match template {
        rc::RootConfigTemplate::Root => {
            // Root template means the component IS the root and receives the entire root config.
            // Return None to indicate all config paths should be provided.
            None
        }
        rc::RootConfigTemplate::Node(node) => {
            let mut paths = BTreeSet::new();
            collect_from_node(node, &mut paths);
            Some(paths)
        }
    }
}

/// Generates NetworkPolicy enforcement check resources.
///
/// This creates a two-phase test within the namespace:
/// 1. An "allowed" server that the client CAN connect to (proves networking works)
/// 2. A "blocked" server that the client should NOT be able to connect to
/// 3. A NetworkPolicy that blocks ingress to the "blocked" server only
/// 4. A client that verifies both conditions
///
/// The client uses a "poison pill" pattern:
/// - Phase 1: Try to connect to allowed server. If this fails, networking is broken - exit with error.
/// - Phase 2: Try to connect to blocked server. If this succeeds, NetworkPolicy isn't enforced - exit with error.
/// - Success: Both checks pass, stay alive.
fn generate_netpol_enforcement_check(
    namespace: &str,
    labels: &BTreeMap<String, String>,
) -> Vec<(&'static str, KubernetesResult<String>)> {
    let mut check_labels = labels.clone();
    check_labels.insert("amber.io/type".to_string(), "netpol-check".to_string());

    let server_labels = {
        let mut l = check_labels.clone();
        l.insert(
            "amber.io/netpol-check-role".to_string(),
            "server".to_string(),
        );
        l
    };

    let client_labels = {
        let mut l = check_labels.clone();
        l.insert(
            "amber.io/netpol-check-role".to_string(),
            "client".to_string(),
        );
        l
    };

    // Create a single server deployment that listens on two ports
    let server_deployment = Deployment {
        api_version: "apps/v1",
        kind: "Deployment",
        metadata: ObjectMeta {
            name: "amber-netpol-server".to_string(),
            namespace: Some(namespace.to_string()),
            labels: server_labels.clone(),
            ..Default::default()
        },
        spec: DeploymentSpec {
            replicas: 1,
            selector: LabelSelector {
                match_labels: {
                    let mut m = BTreeMap::new();
                    m.insert(
                        "amber.io/netpol-check-role".to_string(),
                        "server".to_string(),
                    );
                    m
                },
            },
            template: PodTemplateSpec {
                metadata: ObjectMeta {
                    labels: server_labels.clone(),
                    ..Default::default()
                },
                spec: PodSpec {
                    init_containers: Vec::new(),
                    containers: vec![Container {
                        name: "server".to_string(),
                        image: "busybox:1.36".to_string(),
                        command: vec![
                            "/bin/sh".to_string(),
                            "-c".to_string(),
                            // Run two servers - one on port 8080 (allowed), one on 8081 (will be blocked)
                            "while true; do echo 'ready' | nc -l -p 8080 >/dev/null; done & while \
                             true; do echo 'ready' | nc -l -p 8081 >/dev/null; done & wait"
                                .to_string(),
                        ],
                        ports: vec![
                            ContainerPort {
                                name: "allowed".to_string(),
                                container_port: 8080,
                                protocol: "TCP",
                            },
                            ContainerPort {
                                name: "blocked".to_string(),
                                container_port: 8081,
                                protocol: "TCP",
                            },
                        ],
                        ..Default::default()
                    }],
                    volumes: Vec::new(),
                    service_account_name: None,
                    automount_service_account_token: Some(false),
                    restart_policy: None,
                },
            },
        },
    };

    // Service for allowed port (8080) - no NetworkPolicy blocks this
    let allowed_service = Service::new(
        "amber-netpol-allowed",
        namespace,
        check_labels.clone(),
        {
            let mut m = BTreeMap::new();
            m.insert(
                "amber.io/netpol-check-role".to_string(),
                "server".to_string(),
            );
            m
        },
        vec![ServicePort {
            name: "tcp".to_string(),
            port: 8080,
            target_port: 8080,
            protocol: "TCP",
        }],
    );

    // Service for blocked port (8081) - NetworkPolicy will block this
    let blocked_service = Service::new(
        "amber-netpol-blocked",
        namespace,
        check_labels.clone(),
        {
            let mut m = BTreeMap::new();
            m.insert(
                "amber.io/netpol-check-role".to_string(),
                "server".to_string(),
            );
            m
        },
        vec![ServicePort {
            name: "tcp".to_string(),
            port: 8080,
            target_port: 8081,
            protocol: "TCP",
        }],
    );

    // NetworkPolicy - deny ingress to port 8081 only
    let deny_policy = NetworkPolicy {
        api_version: "networking.k8s.io/v1",
        kind: "NetworkPolicy",
        metadata: ObjectMeta {
            name: "amber-netpol-deny-blocked".to_string(),
            namespace: Some(namespace.to_string()),
            labels: check_labels.clone(),
            ..Default::default()
        },
        spec: NetworkPolicySpec {
            pod_selector: LabelSelector {
                match_labels: {
                    let mut m = BTreeMap::new();
                    m.insert(
                        "amber.io/netpol-check-role".to_string(),
                        "server".to_string(),
                    );
                    m
                },
            },
            policy_types: vec!["Ingress"],
            ingress: vec![
                // Allow ingress on port 8080 only
                NetworkPolicyIngressRule {
                    ports: vec![NetworkPolicyPort {
                        port: 8080,
                        protocol: "TCP",
                    }],
                    from: Vec::new(), // from anywhere
                },
            ],
            egress: Vec::new(),
        },
    };

    // Client check script - simple and fast, relies on Kubernetes restart policy
    let client_script = r#"
echo "=========================================="
echo "Amber NetworkPolicy Enforcement Check"
echo "=========================================="
echo ""

# Phase 1: Verify we CAN connect to the allowed server
# Kubernetes will restart this pod if it fails, so no retry loop needed
echo "Phase 1: Testing basic connectivity..."
RESPONSE=$(nc amber-netpol-allowed 8080 </dev/null 2>/dev/null)
if [ "$RESPONSE" != "ready" ]; then
    echo "FATAL: Cannot connect to amber-netpol-allowed:8080"
    echo "Basic networking is not working. Pod will restart."
    exit 1
fi
echo "  SUCCESS: Connected to allowed server and received: $RESPONSE"

# Phase 2: Verify we CANNOT connect to the blocked server
echo ""
echo "Phase 2: Testing NetworkPolicy enforcement..."
RESPONSE=$(nc -w 2 amber-netpol-blocked 8080 </dev/null 2>/dev/null || true)
if [ -n "$RESPONSE" ]; then
    echo ""
    echo "=========================================="
    echo "FATAL: NetworkPolicy is NOT enforced!"
    echo "=========================================="
    echo ""
    echo "Your Kubernetes cluster's CNI does not support NetworkPolicy."
    echo "Amber scenarios require NetworkPolicy for security isolation."
    echo ""
    echo "To fix this, either:"
    echo "  1. Install a CNI that supports NetworkPolicy:"
    echo "     - Calico, Cilium, Weave Net, etc."
    echo "  2. Re-generate with --disable-networkpolicy-check"
    echo ""
    exit 1
fi
echo "  SUCCESS: Connection was correctly blocked"

echo ""
echo "=========================================="
echo "NetworkPolicy enforcement VERIFIED"
echo "=========================================="
echo ""

# Start server to signal readiness to other pods
echo "Starting readiness server on port 8080..."
while true; do echo "ready" | nc -l -p 8080 >/dev/null; done
"#;

    let client_deployment = Deployment {
        api_version: "apps/v1",
        kind: "Deployment",
        metadata: ObjectMeta {
            name: "amber-netpol-client".to_string(),
            namespace: Some(namespace.to_string()),
            labels: client_labels.clone(),
            ..Default::default()
        },
        spec: DeploymentSpec {
            replicas: 1,
            selector: LabelSelector {
                match_labels: {
                    let mut m = BTreeMap::new();
                    m.insert(
                        "amber.io/netpol-check-role".to_string(),
                        "client".to_string(),
                    );
                    m
                },
            },
            template: PodTemplateSpec {
                metadata: ObjectMeta {
                    labels: client_labels.clone(),
                    ..Default::default()
                },
                spec: PodSpec {
                    init_containers: Vec::new(),
                    containers: vec![Container {
                        name: "client".to_string(),
                        image: "busybox:1.36".to_string(),
                        command: vec![
                            "/bin/sh".to_string(),
                            "-c".to_string(),
                            client_script.to_string(),
                        ],
                        ports: vec![ContainerPort {
                            name: "ready".to_string(),
                            container_port: 8080,
                            protocol: "TCP",
                        }],
                        readiness_probe: Some(Probe {
                            exec: None,
                            http_get: None,
                            tcp_socket: Some(TcpSocketAction { port: 8080 }),
                            initial_delay_seconds: Some(1),
                            period_seconds: Some(2),
                            timeout_seconds: Some(1),
                            failure_threshold: Some(30),
                        }),
                        ..Default::default()
                    }],
                    volumes: Vec::new(),
                    service_account_name: None,
                    automount_service_account_token: Some(false),
                    restart_policy: None,
                },
            },
        },
    };

    // Client service - allows scenario pods to check if enforcement check passed
    let client_service = Service::new(
        "amber-netpol-client",
        namespace,
        client_labels.clone(),
        {
            let mut m = BTreeMap::new();
            m.insert(
                "amber.io/netpol-check-role".to_string(),
                "client".to_string(),
            );
            m
        },
        vec![ServicePort {
            name: "http".to_string(),
            port: 8080,
            target_port: 8080,
            protocol: "TCP",
        }],
    );

    vec![
        ("server-deployment.yaml", to_yaml(&server_deployment)),
        ("allowed-service.yaml", to_yaml(&allowed_service)),
        ("blocked-service.yaml", to_yaml(&blocked_service)),
        ("deny-policy.yaml", to_yaml(&deny_policy)),
        ("client-deployment.yaml", to_yaml(&client_deployment)),
        ("client-service.yaml", to_yaml(&client_service)),
    ]
}

fn to_yaml<T: Serialize>(value: &T) -> Result<String, ReporterError> {
    serde_yaml::to_string(value)
        .map_err(|e| ReporterError::new(format!("failed to serialize YAML: {e}")))
}

#[cfg(test)]
mod tests;
