mod resources;

use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::Arc,
};

use amber_config as rc;
use amber_manifest::{BindingTarget, InterpolatedPart, InterpolationSource, Manifest};
use amber_scenario::{ComponentId, Scenario};
use amber_template::{ProgramTemplateSpec, TemplatePart, TemplateSpec};
use base64::Engine as _;
pub use resources::*;
use serde::Serialize;
use serde_json::Value;

use super::{Reporter, ReporterError};
use crate::{
    CompileOutput,
    binding_query::{BindingObject, resolve_binding_query},
    config_template,
    slot_query::{SlotObject, resolve_slot_query},
};

/// Helper image for runtime config interpolation.
const HELPER_IMAGE: &str = "ghcr.io/rdi-foundation/amber-helper:v1";
/// Volume name for sharing helper binary between init container and main container.
const HELPER_VOLUME_NAME: &str = "amber-helper";
/// Path where helper binary is installed in the shared volume.
const HELPER_BIN_DIR: &str = "/amber/bin";
/// Full path to helper binary.
const HELPER_BIN_PATH: &str = "/amber/bin/amber-helper";

/// Root config Secret/ConfigMap names.
const ROOT_CONFIG_SECRET_NAME: &str = "amber-root-config-secret";
const ROOT_CONFIG_CONFIGMAP_NAME: &str = "amber-root-config";

type TemplateString = Vec<TemplatePart>;

/// Kubernetes reporter configuration.
#[derive(Clone, Debug, Default)]
pub struct KubernetesReporterConfig {
    /// Allow deployment without NetworkPolicy enforcement check.
    pub allow_no_networkpolicy: bool,
}

/// Reporter that outputs Kubernetes manifests as a directory structure.
#[derive(Clone, Debug, Default)]
pub struct KubernetesReporter {
    pub config: KubernetesReporterConfig,
}

/// Output artifact containing all generated K8s YAML files.
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

// ---- Internal types ----

#[derive(Clone, Debug)]
struct ComponentNames {
    /// Service/deployment name (DNS-1123 compliant)
    service: String,
    /// NetworkPolicy name
    netpol: String,
}

#[derive(Clone, Debug)]
struct Endpoint {
    #[allow(dead_code)]
    name: String,
    port: u16,
}

/// Metadata about a scenario export for the amber-metadata ConfigMap.
#[derive(Clone, Debug, Serialize)]
struct ExportMetadata {
    component: String,
    provide: String,
    service: String,
    port: u16,
    kind: String,
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
}

/// How a program component will be run.
#[derive(Clone, Debug)]
enum ProgramMode {
    /// Direct execution - all config is statically resolved at compile time.
    Direct {
        entrypoint: Vec<String>,
        env: BTreeMap<String, String>,
    },
    /// Helper-mediated execution - needs runtime config interpolation.
    Helper {
        /// Base64-encoded TemplateSpec (program entrypoint + env with config refs).
        template_spec_b64: String,
        /// Base64-encoded component config template (for resolving against root config).
        component_cfg_template_b64: String,
        /// Base64-encoded component config schema (for validation).
        component_schema_b64: String,
    },
}

type K8sResult<T> = Result<T, ReporterError>;

fn render_kubernetes(
    output: &CompileOutput,
    config: &KubernetesReporterConfig,
) -> K8sResult<KubernetesArtifact> {
    let s = &output.scenario;

    let manifests = crate::manifest_table::build_manifest_table(&s.components, &output.store)
        .map_err(|e| {
            ReporterError::new(format!(
                "internal error: missing manifest content for {} (digest {})",
                component_label(s, e.component),
                e.digest
            ))
        })?;

    // Backend prerequisite: strong dependency graph must be acyclic.
    if let Err(cycle) = amber_scenario::graph::topo_order(s) {
        let cycle_str = cycle
            .cycle
            .iter()
            .map(|id| format!("c{}", id.0))
            .collect::<Vec<_>>()
            .join(" -> ");
        return Err(ReporterError::new(format!(
            "kubernetes reporter requires an acyclic dependency graph (ignoring weak bindings). \
             Found a cycle: {cycle_str}"
        )));
    }

    // Collect program components (these become deployments).
    let program_components: Vec<ComponentId> = s
        .components_iter()
        .filter_map(|(id, c)| c.program.as_ref().map(|_| id))
        .collect();

    // Generate namespace name.
    let namespace = generate_namespace_name(s);

    // Generate component names.
    let mut names: HashMap<ComponentId, ComponentNames> = HashMap::new();
    for id in &program_components {
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

    // Validate: every binding endpoint is between program components.
    for b in &s.bindings {
        if s.component(b.from.component).program.is_none() {
            return Err(ReporterError::new(format!(
                "binding source {}.{} is not runnable (component has no program)",
                component_label(s, b.from.component),
                b.from.name
            )));
        }
        if s.component(b.to.component).program.is_none() {
            return Err(ReporterError::new(format!(
                "binding target {}.{} is not runnable (component has no program)",
                component_label(s, b.to.component),
                b.to.name
            )));
        }
    }
    for ex in &s.exports {
        if s.component(ex.from.component).program.is_none() {
            return Err(ReporterError::new(format!(
                "scenario export '{}' points at {}.{} which is not runnable (component has no \
                 program)",
                ex.name,
                component_label(s, ex.from.component),
                ex.from.name
            )));
        }
    }

    // Build slot values and binding values for each component (resolved URLs to services).
    let mut slot_values: HashMap<ComponentId, BTreeMap<String, SlotObject>> = HashMap::new();
    let mut binding_values: HashMap<ComponentId, BTreeMap<String, BindingObject>> = HashMap::new();
    for id in &program_components {
        slot_values.insert(*id, BTreeMap::new());
        binding_values.insert(*id, BTreeMap::new());
    }

    // Track inbound allowlist: provider -> set of (consumer_component, port)
    let mut inbound_allow: HashMap<ComponentId, Vec<(ComponentId, u16)>> = HashMap::new();

    for b in &s.bindings {
        let provider = b.from.component;
        let consumer = b.to.component;

        let endpoint = resolve_provide_endpoint(s, provider, &b.from.name)?;
        let provider_names = names.get(&provider).ok_or_else(|| {
            ReporterError::new(format!(
                "internal error: missing names for provider {}",
                component_label(s, provider)
            ))
        })?;

        // Slot resolves to K8s service DNS.
        let url = if provider == consumer {
            // Self-reference: use localhost
            format!("http://127.0.0.1:{}", endpoint.port)
        } else {
            format!(
                "http://{}.{}.svc.cluster.local:{}",
                provider_names.service, namespace, endpoint.port
            )
        };

        slot_values
            .entry(consumer)
            .or_default()
            .insert(b.to.name.clone(), SlotObject { url: url.clone() });

        if let Some(name) = b.name.as_ref() {
            binding_values
                .entry(consumer)
                .or_default()
                .insert(name.clone(), BindingObject { url });
        }

        // Track for NetworkPolicy
        if provider != consumer {
            inbound_allow
                .entry(provider)
                .or_default()
                .push((consumer, endpoint.port));
        }
    }

    // Compose config templates for all components.
    let root_id = s.root;
    let root_schema = manifests[root_id.0]
        .as_ref()
        .and_then(|m| m.config_schema())
        .map(|s| &s.0);

    let root_template = if root_schema.is_some() {
        rc::RootConfigTemplate::Root
    } else {
        rc::RootConfigTemplate::Node(rc::ConfigNode::empty_object())
    };

    let mut composed_templates: HashMap<ComponentId, rc::RootConfigTemplate> = HashMap::new();
    compose_templates_dfs(
        s,
        s.root,
        &manifests,
        root_schema,
        &root_template,
        &mut composed_templates,
    )
    .map_err(|e| {
        ReporterError::new(format!("failed to compose component config templates: {e}"))
    })?;

    let binding_urls_by_scope =
        binding_urls_by_scope(s, &manifests, &slot_values).map_err(ReporterError::new)?;

    let resolved_templates =
        resolve_binding_templates(composed_templates, &binding_urls_by_scope, s)
            .map_err(ReporterError::new)?;

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

    // ---- Generate resources ----

    let mut files: BTreeMap<PathBuf, String> = BTreeMap::new();

    // Namespace
    let ns = Namespace::new(&namespace, scenario_labels(&[]));
    files.insert(PathBuf::from("00-namespace.yaml"), to_yaml(&ns)?);

    // Collect root config leaf paths for metadata.
    let root_leaves = if let Some(schema) = root_schema {
        rc::collect_leaf_paths(schema).map_err(|e| {
            ReporterError::new(format!("failed to enumerate root config paths: {e}"))
        })?
    } else {
        Vec::new()
    };

    // Build ProgramMode for each component (determines if helper is needed).
    let mut program_modes: HashMap<ComponentId, ProgramMode> = HashMap::new();
    let mut any_helper = false;

    for id in &program_components {
        let c = s.component(*id);
        let program = c.program.as_ref().unwrap();
        let slots = slot_values.get(id).unwrap();

        let component_template = resolved_templates.get(id).ok_or_else(|| {
            ReporterError::new(format!(
                "no config template for component {}",
                component_label(s, *id)
            ))
        })?;

        // Get the config node for template resolution.
        let template_opt: Option<&rc::ConfigNode> = match component_template {
            rc::RootConfigTemplate::Node(node) => Some(node),
            rc::RootConfigTemplate::Root => None,
        };

        let component_schema = manifests[id.0]
            .as_ref()
            .and_then(|m| m.config_schema())
            .map(|s| &s.0);

        let bindings = binding_values.get(id).unwrap();

        let mode = build_program_mode(
            s,
            *id,
            program,
            slots,
            bindings,
            template_opt,
            component_schema,
            component_template,
        )?;

        if matches!(mode, ProgramMode::Helper { .. }) {
            any_helper = true;
        }

        program_modes.insert(*id, mode);
    }

    // Build kustomization (will be populated at the end if helper mode is used).
    let mut kustomization = Kustomization::new();
    kustomization.namespace = Some(namespace.clone());

    // If any component needs helper, generate kustomization.yaml and root config template.
    if any_helper {
        let root_schema = root_schema.ok_or_else(|| {
            ReporterError::new(
                "root component must declare `config_schema` when runtime config interpolation is \
                 required"
                    .to_string(),
            )
        })?;

        // Separate root leaves into secret and non-secret.
        let secret_leaves: Vec<_> = root_leaves.iter().filter(|l| l.secret).collect();
        let config_leaves: Vec<_> = root_leaves.iter().filter(|l| !l.secret).collect();

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

        // Encode root schema for helper.
        let b64 = base64::engine::general_purpose::STANDARD;
        let root_schema_json =
            serde_json::to_vec(&rc::canonical_json(root_schema)).map_err(|e| {
                ReporterError::new(format!("failed to serialize root config definition: {e}"))
            })?;
        let _root_schema_b64 = b64.encode(root_schema_json);
    }

    // Note: Per-component ConfigMaps/Secrets are not generated because:
    // - Direct mode: config values are baked into entrypoint/env at compile time
    // - Helper mode: config comes from root config Secret/ConfigMap at runtime
    // The only ConfigMaps needed are amber-metadata and the Kustomize-generated root config.

    // Encode root schema for helper (needed for all helper components).
    let root_schema_b64 = if any_helper {
        let root_schema = root_schema.ok_or_else(|| {
            ReporterError::new(
                "root component must declare `config_schema` when runtime config interpolation is \
                 required"
                    .to_string(),
            )
        })?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let root_schema_json =
            serde_json::to_vec(&rc::canonical_json(root_schema)).map_err(|e| {
                ReporterError::new(format!("failed to serialize root config definition: {e}"))
            })?;
        Some(b64.encode(root_schema_json))
    } else {
        None
    };

    // Deployments
    for id in &program_components {
        let c = s.component(*id);
        let cnames = names.get(id).unwrap();
        let labels = component_labels(*id, &cnames.service);
        let program = c.program.as_ref().unwrap();
        let mode = program_modes.get(id).unwrap();

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
        let (container, volumes) = match mode {
            ProgramMode::Direct { entrypoint, env } => {
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
                    volume_mounts: Vec::new(),
                };

                (container, Vec::new())
            }
            ProgramMode::Helper {
                template_spec_b64,
                component_cfg_template_b64,
                component_schema_b64,
            } => {
                // Helper mode: use helper binary as entrypoint, mount shared volume.
                let mut container_env: Vec<EnvVar> = Vec::new();

                // Add root config env vars from kustomize-generated Secret/ConfigMap.
                for leaf in &root_leaves {
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
                    component_schema_b64,
                ));
                container_env.push(EnvVar::literal(
                    "AMBER_COMPONENT_CONFIG_TEMPLATE_B64",
                    component_cfg_template_b64,
                ));
                container_env.push(EnvVar::literal(
                    "AMBER_TEMPLATE_SPEC_B64",
                    template_spec_b64,
                ));

                let container = Container {
                    name: "main".to_string(),
                    image: program.image.clone(),
                    command: vec![HELPER_BIN_PATH.to_string(), "run".to_string()],
                    args: Vec::new(),
                    env: container_env,
                    env_from: Vec::new(),
                    ports,
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

        // Add init containers.
        let mut init_containers = Vec::new();

        // For helper mode, add init container to install the helper binary.
        if matches!(mode, ProgramMode::Helper { .. }) {
            init_containers.push(Container {
                name: "install-helper".to_string(),
                image: HELPER_IMAGE.to_string(),
                command: vec![
                    "/amber-helper".to_string(),
                    "install".to_string(),
                    format!("{}/amber-helper", HELPER_BIN_DIR),
                ],
                args: Vec::new(),
                env: Vec::new(),
                env_from: Vec::new(),
                ports: Vec::new(),
                volume_mounts: vec![VolumeMount {
                    name: HELPER_VOLUME_NAME.to_string(),
                    mount_path: HELPER_BIN_DIR.to_string(),
                    read_only: None,
                }],
            });
        }

        // Add init container to wait for NetworkPolicy enforcement check.
        if !config.allow_no_networkpolicy {
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
                volume_mounts: Vec::new(),
            });
        }

        let pod_spec = PodSpec {
            init_containers,
            containers: vec![container],
            volumes,
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

    // Services (only for components with provides)
    for id in &program_components {
        let c = s.component(*id);
        if c.provides.is_empty() {
            continue;
        }

        let cnames = names.get(id).unwrap();
        let labels = component_labels(*id, &cnames.service);
        let program = c.program.as_ref().unwrap();

        let mut service_ports: Vec<ServicePort> = Vec::new();
        if let Some(network) = &program.network {
            for ep in &network.endpoints {
                service_ports.push(ServicePort {
                    name: sanitize_port_name(&ep.name),
                    port: ep.port,
                    target_port: ep.port,
                    protocol: "TCP",
                });
            }
        }

        if service_ports.is_empty() {
            continue;
        }

        let selector = {
            let mut m = BTreeMap::new();
            m.insert("amber.io/component".to_string(), cnames.service.clone());
            m
        };

        let svc = Service::new(&cnames.service, &namespace, labels, selector, service_ports);

        files.insert(
            PathBuf::from(format!("04-services/{}.yaml", cnames.service)),
            to_yaml(&svc)?,
        );
    }

    // NetworkPolicies
    for id in &program_components {
        let cnames = names.get(id).unwrap();
        let labels = component_labels(*id, &cnames.service);

        let pod_selector = {
            let mut m = BTreeMap::new();
            m.insert("amber.io/component".to_string(), cnames.service.clone());
            m
        };

        let mut netpol = NetworkPolicy::new(&cnames.netpol, &namespace, labels, pod_selector);

        // Add ingress rules for bound consumers.
        if let Some(allowed) = inbound_allow.get(id) {
            // Group by port.
            let mut by_port: BTreeMap<u16, Vec<ComponentId>> = BTreeMap::new();
            for (consumer, port) in allowed {
                by_port.entry(*port).or_default().push(*consumer);
            }

            for (port, consumers) in by_port {
                let from: Vec<NetworkPolicyPeer> = consumers
                    .iter()
                    .map(|cid| {
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
                        }
                    })
                    .collect();

                netpol.add_ingress_rule(NetworkPolicyIngressRule {
                    from,
                    ports: vec![NetworkPolicyPort {
                        protocol: "TCP",
                        port,
                    }],
                });
            }
        }

        files.insert(
            PathBuf::from(format!("05-networkpolicies/{}.yaml", cnames.netpol)),
            to_yaml(&netpol)?,
        );
    }

    // NetworkPolicy enforcement check (unless disabled).
    if !config.allow_no_networkpolicy {
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
    let mut export_metadata: BTreeMap<String, ExportMetadata> = BTreeMap::new();
    for ex in &s.exports {
        let provider = ex.from.component;
        let provider_names = names.get(&provider).unwrap();
        let endpoint = resolve_provide_endpoint(s, provider, &ex.from.name)?;

        export_metadata.insert(
            ex.name.clone(),
            ExportMetadata {
                component: s.component(provider).moniker.as_str().to_string(),
                provide: ex.from.name.clone(),
                service: provider_names.service.clone(),
                port: endpoint.port,
                kind: format!("{}", ex.capability.kind),
            },
        );
    }

    let mut input_metadata: BTreeMap<String, InputMetadata> = BTreeMap::new();
    for leaf in &root_leaves {
        input_metadata.insert(
            leaf.path.clone(),
            InputMetadata {
                required: leaf.required,
                secret: leaf.secret,
            },
        );
    }

    let scenario_metadata = ScenarioMetadata {
        version: "1",
        digest: s.component(s.root).digest.to_string(),
        exports: export_metadata,
        inputs: input_metadata,
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

    // Build and insert kustomization with actual file paths.
    // Always generate kustomization.yaml for consistency, even if not using helper mode.
    let mut kust_resources = Vec::new();

    // Collect all YAML files, excluding non-resource files
    for path in files.keys() {
        if path == &PathBuf::from("root-config.env")
            || path == &PathBuf::from("root-config-secret.env")
        {
            continue; // Skip .env template files
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

fn component_label(s: &Scenario, id: ComponentId) -> String {
    s.component(id).moniker.as_str().to_string()
}

fn binding_urls_by_scope(
    s: &Scenario,
    manifests: &[Option<Arc<Manifest>>],
    slot_values_by_component: &HashMap<ComponentId, BTreeMap<String, SlotObject>>,
) -> Result<HashMap<u64, BTreeMap<String, BindingObject>>, String> {
    let mut out: HashMap<u64, BTreeMap<String, BindingObject>> = HashMap::new();

    for (idx, manifest) in manifests.iter().enumerate() {
        let Some(manifest) = manifest else {
            continue;
        };
        let realm = ComponentId(idx);
        let mut by_name = BTreeMap::new();

        for (target, binding) in manifest.bindings() {
            let Some(name) = binding.name.as_ref() else {
                continue;
            };

            let (target_component, slot_name) = match target {
                BindingTarget::SelfSlot(slot) => (realm, slot.as_str()),
                BindingTarget::ChildSlot { child, slot } => {
                    let child_id = child_component_id_for_name(s, realm, child.as_str())?;
                    (child_id, slot.as_str())
                }
                _ => {
                    return Err(format!(
                        "unsupported binding target {:?} in {}",
                        target,
                        component_label(s, realm)
                    ));
                }
            };

            let slot_values = slot_values_by_component
                .get(&target_component)
                .ok_or_else(|| {
                    format!(
                        "internal error: missing slot values for {}",
                        component_label(s, target_component)
                    )
                })?;
            let slot = slot_values.get(slot_name).ok_or_else(|| {
                format!(
                    "internal error: missing slot url for {}.{}",
                    component_label(s, target_component),
                    slot_name
                )
            })?;

            by_name.insert(
                name.to_string(),
                BindingObject {
                    url: slot.url.clone(),
                },
            );
        }

        out.insert(realm.0 as u64, by_name);
    }

    Ok(out)
}

fn resolve_binding_templates(
    templates: HashMap<ComponentId, rc::RootConfigTemplate>,
    bindings_by_scope: &HashMap<u64, BTreeMap<String, BindingObject>>,
    s: &Scenario,
) -> Result<HashMap<ComponentId, rc::RootConfigTemplate>, String> {
    let mut out = HashMap::with_capacity(templates.len());
    for (id, template) in templates {
        let resolved = match template {
            rc::RootConfigTemplate::Root => rc::RootConfigTemplate::Root,
            rc::RootConfigTemplate::Node(node) => {
                let resolved =
                    resolve_binding_parts_in_config(&node, bindings_by_scope).map_err(|err| {
                        format!(
                            "failed to resolve binding interpolation in config for {}: {err}",
                            component_label(s, id)
                        )
                    })?;
                rc::RootConfigTemplate::Node(resolved)
            }
        };
        out.insert(id, resolved);
    }
    Ok(out)
}

fn resolve_binding_parts_in_config(
    node: &rc::ConfigNode,
    bindings_by_scope: &HashMap<u64, BTreeMap<String, BindingObject>>,
) -> Result<rc::ConfigNode, String> {
    match node {
        rc::ConfigNode::StringTemplate(parts) => {
            let mut out = Vec::with_capacity(parts.len());
            for part in parts {
                match part {
                    TemplatePart::Lit { lit } => out.push(TemplatePart::lit(lit)),
                    TemplatePart::Config { config } => out.push(TemplatePart::config(config)),
                    TemplatePart::Binding { binding, scope } => {
                        let bindings = bindings_by_scope
                            .get(scope)
                            .ok_or_else(|| format!("bindings scope {scope} is missing"))?;
                        let url = resolve_binding_query(bindings, binding)?;
                        out.push(TemplatePart::lit(url));
                    }
                }
            }
            Ok(rc::ConfigNode::StringTemplate(out).simplify())
        }
        rc::ConfigNode::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(resolve_binding_parts_in_config(item, bindings_by_scope)?);
            }
            Ok(rc::ConfigNode::Array(out))
        }
        rc::ConfigNode::Object(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                out.insert(
                    k.clone(),
                    resolve_binding_parts_in_config(v, bindings_by_scope)?,
                );
            }
            Ok(rc::ConfigNode::Object(out))
        }
        other => Ok(other.clone()),
    }
}

fn child_component_id_for_name(
    s: &Scenario,
    parent: ComponentId,
    child_name: &str,
) -> Result<ComponentId, String> {
    let parent_component = s.component(parent);
    for child_id in &parent_component.children {
        let child = s.component(*child_id);
        if child.moniker.local_name() == Some(child_name) {
            return Ok(*child_id);
        }
    }
    Err(format!(
        "internal error: missing child {child_name:?} for {}",
        component_label(s, parent)
    ))
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
    // K8s label values: max 63 chars, alphanumeric, -, _, .
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

fn resolve_provide_endpoint(
    s: &Scenario,
    component_id: ComponentId,
    provide_name: &str,
) -> Result<Endpoint, ReporterError> {
    let component = s.component(component_id);

    let provide = component.provides.get(provide_name).ok_or_else(|| {
        ReporterError::new(format!(
            "provide {}.{} not found",
            component_label(s, component_id),
            provide_name
        ))
    })?;

    let program = component.program.as_ref().ok_or_else(|| {
        ReporterError::new(format!(
            "provide {}.{} requires a program, but component has none",
            component_label(s, component_id),
            provide_name
        ))
    })?;

    let network = program.network.as_ref().ok_or_else(|| {
        ReporterError::new(format!(
            "provide {}.{} requires program.network, but none exists",
            component_label(s, component_id),
            provide_name
        ))
    })?;

    let endpoint_name = provide.endpoint.as_deref().ok_or_else(|| {
        ReporterError::new(format!(
            "provide {}.{} is missing an endpoint reference",
            component_label(s, component_id),
            provide_name
        ))
    })?;

    let endpoint = network
        .endpoints
        .iter()
        .find(|e| e.name == endpoint_name)
        .ok_or_else(|| {
            ReporterError::new(format!(
                "provide {}.{} references unknown endpoint {:?}",
                component_label(s, component_id),
                provide_name,
                endpoint_name
            ))
        })?;

    Ok(Endpoint {
        name: endpoint.name.clone(),
        port: endpoint.port,
    })
}

fn compose_templates_dfs(
    s: &Scenario,
    id: ComponentId,
    manifests: &[Option<Arc<Manifest>>],
    parent_schema: Option<&Value>,
    parent_template: &rc::RootConfigTemplate,
    out: &mut HashMap<ComponentId, rc::RootConfigTemplate>,
) -> Result<(), String> {
    let c = s.component(id);
    let m = manifests[id.0].as_ref().expect("manifest should exist");
    let schema = m.config_schema().map(|s| &s.0);

    let this_template = if id == s.root {
        if schema.is_some() {
            rc::RootConfigTemplate::Root
        } else {
            rc::RootConfigTemplate::Node(rc::ConfigNode::empty_object())
        }
    } else if schema.is_none() {
        rc::RootConfigTemplate::Node(rc::ConfigNode::empty_object())
    } else {
        let initial = config_template::parse_instance_config_template(
            c.config.as_ref(),
            parent_schema,
            id.0 as u64,
        )
        .map_err(|e| e.to_string())?;
        let composed = rc::compose_config_template(initial, parent_template)
            .map_err(|e| e.to_string())?
            .simplify();
        rc::RootConfigTemplate::Node(composed)
    };

    out.insert(id, this_template.clone());

    for &child in &c.children {
        compose_templates_dfs(s, child, manifests, schema, &this_template, out)?;
    }
    Ok(())
}

// ---- Runtime config / helper mode support ----

/// Attempt to resolve a config interpolation to a static string; otherwise keep it as runtime.
enum ConfigResolution {
    Static(String),
    Runtime,
}

/// Try to resolve a config query against a composed template.
/// Returns Static if the value is fully resolved, Runtime if it contains config refs.
fn resolve_config_query_for_program(
    template: Option<&rc::ConfigNode>,
    query: &str,
) -> Result<ConfigResolution, String> {
    let Some(template) = template else {
        return Ok(ConfigResolution::Runtime);
    };

    // Empty query means "the whole config".
    if query.is_empty() {
        return if !template.contains_runtime() {
            let v = template.evaluate_static().map_err(|e| e.to_string())?;
            Ok(ConfigResolution::Static(
                rc::stringify_for_interpolation(&v).map_err(|e| e.to_string())?,
            ))
        } else {
            Ok(ConfigResolution::Runtime)
        };
    }

    // Traverse until we either:
    // - reach the node (resolved)
    // - hit a runtime insert (ConfigRef) before path ends (runtime)
    // - find a missing key (error)
    let mut cur = template;
    for seg in query.split('.') {
        if seg.is_empty() {
            return Err(format!("invalid config path {query:?}: empty segment"));
        }
        match cur {
            rc::ConfigNode::Object(map) => {
                let Some(next) = map.get(seg) else {
                    return Err(format!("config.{query} not found (missing key {seg:?})"));
                };
                cur = next;
            }
            rc::ConfigNode::ConfigRef(_) => return Ok(ConfigResolution::Runtime),
            _ => {
                return Err(format!(
                    "config.{query} not found (encountered non-object before segment {seg:?})"
                ));
            }
        }
    }

    if !cur.contains_runtime() {
        let v = cur.evaluate_static().map_err(|e| e.to_string())?;
        Ok(ConfigResolution::Static(
            rc::stringify_for_interpolation(&v).map_err(|e| e.to_string())?,
        ))
    } else {
        Ok(ConfigResolution::Runtime)
    }
}

/// Render a template string that is known to be fully static.
fn render_template_string_static(ts: &TemplateString) -> Result<String, String> {
    if rc::template_string_is_runtime(ts) {
        return Err(
            "internal error: attempted to render a runtime template string statically".to_string(),
        );
    }
    let mut out = String::new();
    for part in ts {
        match part {
            TemplatePart::Lit { lit } => out.push_str(lit),
            TemplatePart::Config { .. } => unreachable!(),
            TemplatePart::Binding { .. } => unreachable!(),
        }
    }
    Ok(out)
}

/// Build ProgramMode for a component by analyzing its entrypoint and env for runtime config refs.
#[allow(clippy::too_many_arguments)]
fn build_program_mode(
    s: &Scenario,
    id: ComponentId,
    program: &amber_manifest::Program,
    slots: &BTreeMap<String, SlotObject>,
    bindings: &BTreeMap<String, BindingObject>,
    template_opt: Option<&rc::ConfigNode>,
    component_schema: Option<&Value>,
    component_template: &rc::RootConfigTemplate,
) -> K8sResult<ProgramMode> {
    let mut entrypoint_ts: Vec<TemplateString> = Vec::new();
    let mut needs_helper = false;

    for (idx, arg) in program.args.0.iter().enumerate() {
        let mut ts: TemplateString = Vec::new();
        for part in &arg.parts {
            match part {
                InterpolatedPart::Literal(lit) => ts.push(TemplatePart::lit(lit)),
                InterpolatedPart::Interpolation { source, query } => match source {
                    InterpolationSource::Slots => {
                        let v = resolve_slot_query(slots, query).map_err(|e| {
                            ReporterError::new(format!(
                                "failed to resolve slot query in {}: {e}",
                                component_label(s, id)
                            ))
                        })?;
                        ts.push(TemplatePart::lit(v));
                    }
                    InterpolationSource::Bindings => {
                        let v = resolve_binding_query(bindings, query).map_err(|e| {
                            ReporterError::new(format!(
                                "failed to resolve binding query in {}: {e}",
                                component_label(s, id)
                            ))
                        })?;
                        ts.push(TemplatePart::lit(v));
                    }
                    InterpolationSource::Config => {
                        match resolve_config_query_for_program(template_opt, query)
                            .map_err(ReporterError::new)?
                        {
                            ConfigResolution::Static(v) => ts.push(TemplatePart::lit(v)),
                            ConfigResolution::Runtime => {
                                ts.push(TemplatePart::config(query.clone()));
                                needs_helper = true;
                            }
                        }
                    }
                    other => {
                        return Err(ReporterError::new(format!(
                            "unsupported interpolation source {other} in {} \
                             program.entrypoint[{idx}]",
                            component_label(s, id)
                        )));
                    }
                },
                _ => {
                    return Err(ReporterError::new(format!(
                        "unsupported interpolation part in {} program.entrypoint[{idx}]",
                        component_label(s, id)
                    )));
                }
            }
        }
        if ts.is_empty() {
            return Err(ReporterError::new(format!(
                "internal error: produced empty template for {} program.entrypoint[{idx}]",
                component_label(s, id)
            )));
        }
        entrypoint_ts.push(ts);
    }

    // program.env
    let mut env_ts: BTreeMap<String, TemplateString> = BTreeMap::new();
    for (k, v) in &program.env {
        let mut ts: TemplateString = Vec::new();
        for part in &v.parts {
            match part {
                InterpolatedPart::Literal(lit) => ts.push(TemplatePart::lit(lit)),
                InterpolatedPart::Interpolation { source, query } => match source {
                    InterpolationSource::Slots => {
                        let vv = resolve_slot_query(slots, query).map_err(|e| {
                            ReporterError::new(format!(
                                "failed to resolve slot query in {}: {e}",
                                component_label(s, id)
                            ))
                        })?;
                        ts.push(TemplatePart::lit(vv));
                    }
                    InterpolationSource::Bindings => {
                        let vv = resolve_binding_query(bindings, query).map_err(|e| {
                            ReporterError::new(format!(
                                "failed to resolve binding query in {}: {e}",
                                component_label(s, id)
                            ))
                        })?;
                        ts.push(TemplatePart::lit(vv));
                    }
                    InterpolationSource::Config => {
                        match resolve_config_query_for_program(template_opt, query)
                            .map_err(ReporterError::new)?
                        {
                            ConfigResolution::Static(vv) => ts.push(TemplatePart::lit(vv)),
                            ConfigResolution::Runtime => {
                                ts.push(TemplatePart::config(query.clone()));
                                needs_helper = true;
                            }
                        }
                    }
                    other => {
                        return Err(ReporterError::new(format!(
                            "unsupported interpolation source {other} in {} program.env.{k}",
                            component_label(s, id)
                        )));
                    }
                },
                _ => {
                    return Err(ReporterError::new(format!(
                        "unsupported interpolation part in {} program.env.{k}",
                        component_label(s, id)
                    )));
                }
            }
        }
        env_ts.insert(k.clone(), ts);
    }

    if needs_helper {
        // Build TemplateSpec for the helper.
        let spec = TemplateSpec {
            program: ProgramTemplateSpec {
                entrypoint: entrypoint_ts,
                env: env_ts,
            },
        };

        let b64 = base64::engine::general_purpose::STANDARD;

        let spec_json = serde_json::to_vec(&spec).map_err(|e| {
            ReporterError::new(format!(
                "failed to serialize template spec for {}: {e}",
                component_label(s, id)
            ))
        })?;
        let spec_b64 = b64.encode(spec_json);

        // Convert component template to payload format.
        let cfg_template_value = component_template.to_json_ir();

        let template_json = serde_json::to_vec(&cfg_template_value).map_err(|e| {
            ReporterError::new(format!(
                "failed to serialize component config template for {}: {e}",
                component_label(s, id)
            ))
        })?;
        let template_b64 = b64.encode(template_json);

        let schema = component_schema.ok_or_else(|| {
            ReporterError::new(format!(
                "component {} requires config_schema when using runtime config interpolation",
                component_label(s, id)
            ))
        })?;

        let schema_json = serde_json::to_vec(&rc::canonical_json(schema)).map_err(|e| {
            ReporterError::new(format!(
                "failed to serialize component config definition for {}: {e}",
                component_label(s, id)
            ))
        })?;
        let schema_b64 = b64.encode(schema_json);

        Ok(ProgramMode::Helper {
            template_spec_b64: spec_b64,
            component_cfg_template_b64: template_b64,
            component_schema_b64: schema_b64,
        })
    } else {
        // Fully resolved: render to concrete entrypoint/env.
        let mut rendered_entrypoint: Vec<String> = Vec::new();
        for ts in entrypoint_ts {
            rendered_entrypoint
                .push(render_template_string_static(&ts).map_err(ReporterError::new)?);
        }

        let mut rendered_env: BTreeMap<String, String> = BTreeMap::new();
        for (k, ts) in env_ts {
            rendered_env.insert(
                k,
                render_template_string_static(&ts).map_err(ReporterError::new)?,
            );
        }

        Ok(ProgramMode::Direct {
            entrypoint: rendered_entrypoint,
            env: rendered_env,
        })
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
) -> Vec<(&'static str, K8sResult<String>)> {
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
    echo "  2. Re-generate with --allow-no-networkpolicy"
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
                        ..Default::default()
                    }],
                    volumes: Vec::new(),
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
