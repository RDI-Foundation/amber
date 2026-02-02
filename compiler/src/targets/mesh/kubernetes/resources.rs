use std::collections::BTreeMap;

use serde::Serialize;

/// Kubernetes object metadata.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

// ---- Namespace ----

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Namespace {
    pub api_version: &'static str,
    pub kind: &'static str,
    pub metadata: ObjectMeta,
}

impl Namespace {
    pub fn new(name: impl Into<String>, labels: BTreeMap<String, String>) -> Self {
        Self {
            api_version: "v1",
            kind: "Namespace",
            metadata: ObjectMeta {
                name: name.into(),
                labels,
                ..Default::default()
            },
        }
    }
}

// ---- ConfigMap ----

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigMap {
    pub api_version: &'static str,
    pub kind: &'static str,
    pub metadata: ObjectMeta,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, String>,
}

impl ConfigMap {
    pub fn new(
        name: impl Into<String>,
        namespace: impl Into<String>,
        labels: BTreeMap<String, String>,
        data: BTreeMap<String, String>,
    ) -> Self {
        Self {
            api_version: "v1",
            kind: "ConfigMap",
            metadata: ObjectMeta {
                name: name.into(),
                namespace: Some(namespace.into()),
                labels,
                ..Default::default()
            },
            data,
        }
    }
}

// ---- Secret ----

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    pub api_version: &'static str,
    pub kind: &'static str,
    pub metadata: ObjectMeta,
    #[serde(rename = "type")]
    pub secret_type: &'static str,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub string_data: BTreeMap<String, String>,
}

impl Secret {
    pub fn new(
        name: impl Into<String>,
        namespace: impl Into<String>,
        labels: BTreeMap<String, String>,
        string_data: BTreeMap<String, String>,
    ) -> Self {
        Self {
            api_version: "v1",
            kind: "Secret",
            metadata: ObjectMeta {
                name: name.into(),
                namespace: Some(namespace.into()),
                labels,
                ..Default::default()
            },
            secret_type: "Opaque",
            string_data,
        }
    }
}

// ---- Service ----

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub api_version: &'static str,
    pub kind: &'static str,
    pub metadata: ObjectMeta,
    pub spec: ServiceSpec,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    pub selector: BTreeMap<String, String>,
    pub ports: Vec<ServicePort>,
    #[serde(rename = "type")]
    pub service_type: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicePort {
    pub name: String,
    pub port: u16,
    pub target_port: u16,
    pub protocol: &'static str,
}

impl Service {
    pub fn new(
        name: impl Into<String>,
        namespace: impl Into<String>,
        labels: BTreeMap<String, String>,
        selector: BTreeMap<String, String>,
        ports: Vec<ServicePort>,
    ) -> Self {
        Self {
            api_version: "v1",
            kind: "Service",
            metadata: ObjectMeta {
                name: name.into(),
                namespace: Some(namespace.into()),
                labels,
                ..Default::default()
            },
            spec: ServiceSpec {
                selector,
                ports,
                service_type: "ClusterIP",
            },
        }
    }
}

// ---- Deployment ----

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    pub api_version: &'static str,
    pub kind: &'static str,
    pub metadata: ObjectMeta,
    pub spec: DeploymentSpec,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentSpec {
    pub replicas: u32,
    pub selector: LabelSelector,
    pub template: PodTemplateSpec,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    pub match_labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PodTemplateSpec {
    pub metadata: ObjectMeta,
    pub spec: PodSpec,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSpec {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub init_containers: Vec<Container>,
    pub containers: Vec<Container>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<Volume>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<&'static str>,
}

// ---- Probes ----

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_get: Option<HttpGetAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_socket: Option<TcpSocketAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_delay_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_threshold: Option<i32>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpGetAction {
    pub path: String,
    pub port: u16,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpSocketAction {
    pub port: u16,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecAction {
    pub command: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Container {
    pub name: String,
    pub image: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env_from: Vec<EnvFromSource>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<ContainerPort>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readiness_probe: Option<Probe>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub volume_mounts: Vec<VolumeMount>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvVar {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_from: Option<EnvVarSource>,
}

impl EnvVar {
    pub fn literal(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Some(value.into()),
            value_from: None,
        }
    }

    pub fn from_config_map(
        name: impl Into<String>,
        config_map_name: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: None,
            value_from: Some(EnvVarSource {
                config_map_key_ref: Some(KeyRef {
                    name: config_map_name.into(),
                    key: key.into(),
                    optional: Some(true),
                }),
                secret_key_ref: None,
            }),
        }
    }

    pub fn from_secret(
        name: impl Into<String>,
        secret_name: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: None,
            value_from: Some(EnvVarSource {
                config_map_key_ref: None,
                secret_key_ref: Some(KeyRef {
                    name: secret_name.into(),
                    key: key.into(),
                    optional: Some(true),
                }),
            }),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvVarSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_map_key_ref: Option<KeyRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key_ref: Option<KeyRef>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRef {
    pub name: String,
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvFromSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_map_ref: Option<LocalObjectReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<LocalObjectReference>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalObjectReference {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerPort {
    pub name: String,
    pub container_port: u16,
    pub protocol: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeMount {
    pub name: String,
    pub mount_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Volume {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_map: Option<ConfigMapVolumeSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretVolumeSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub empty_dir: Option<EmptyDirVolumeSource>,
}

impl Volume {
    pub fn config_map(name: impl Into<String>, config_map_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            config_map: Some(ConfigMapVolumeSource {
                name: config_map_name.into(),
            }),
            secret: None,
            empty_dir: None,
        }
    }

    pub fn secret(name: impl Into<String>, secret_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            config_map: None,
            secret: Some(SecretVolumeSource {
                secret_name: secret_name.into(),
            }),
            empty_dir: None,
        }
    }

    pub fn empty_dir(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            config_map: None,
            secret: None,
            empty_dir: Some(EmptyDirVolumeSource {}),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigMapVolumeSource {
    pub name: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretVolumeSource {
    pub secret_name: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmptyDirVolumeSource {}

// ---- NetworkPolicy ----

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicy {
    pub api_version: &'static str,
    pub kind: &'static str,
    pub metadata: ObjectMeta,
    pub spec: NetworkPolicySpec,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicySpec {
    pub pod_selector: LabelSelector,
    pub policy_types: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<NetworkPolicyIngressRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<NetworkPolicyEgressRule>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicyIngressRule {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub from: Vec<NetworkPolicyPeer>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<NetworkPolicyPort>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicyEgressRule {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<NetworkPolicyPeer>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<NetworkPolicyPort>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicyPeer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_selector: Option<LabelSelector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<LabelSelector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_block: Option<IpBlock>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpBlock {
    pub cidr: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub except: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicyPort {
    pub protocol: &'static str,
    pub port: u16,
}

impl NetworkPolicy {
    pub fn new(
        name: impl Into<String>,
        namespace: impl Into<String>,
        labels: BTreeMap<String, String>,
        pod_selector: BTreeMap<String, String>,
    ) -> Self {
        Self {
            api_version: "networking.k8s.io/v1",
            kind: "NetworkPolicy",
            metadata: ObjectMeta {
                name: name.into(),
                namespace: Some(namespace.into()),
                labels,
                ..Default::default()
            },
            spec: NetworkPolicySpec {
                pod_selector: LabelSelector {
                    match_labels: pod_selector,
                },
                policy_types: vec!["Ingress"],
                ingress: Vec::new(),
                egress: Vec::new(),
            },
        }
    }

    pub fn add_ingress_rule(&mut self, rule: NetworkPolicyIngressRule) {
        self.spec.ingress.push(rule);
    }

    pub fn add_egress_rule(&mut self, rule: NetworkPolicyEgressRule) {
        if !self.spec.policy_types.contains(&"Egress") {
            self.spec.policy_types.push("Egress");
        }
        self.spec.egress.push(rule);
    }
}

// ---- Job (for NetworkPolicy enforcement check) ----

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub api_version: &'static str,
    pub kind: &'static str,
    pub metadata: ObjectMeta,
    pub spec: JobSpec,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backoff_limit: Option<u32>,
    pub template: PodTemplateSpec,
}

impl Job {
    pub fn new(
        name: impl Into<String>,
        namespace: impl Into<String>,
        labels: BTreeMap<String, String>,
        template: PodTemplateSpec,
    ) -> Self {
        Self {
            api_version: "batch/v1",
            kind: "Job",
            metadata: ObjectMeta {
                name: name.into(),
                namespace: Some(namespace.into()),
                labels,
                ..Default::default()
            },
            spec: JobSpec {
                backoff_limit: Some(0),
                template,
            },
        }
    }
}

// ---- Kustomization ----

/// Kustomization configuration for runtime config generation.
/// Used to generate ConfigMaps/Secrets from .env files at deploy time.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kustomization {
    pub api_version: String,
    pub kind: String,
    /// Resources to include (relative paths to YAML files).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    /// ConfigMap generators.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub config_map_generator: Vec<ConfigMapGenerator>,
    /// Secret generators.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secret_generator: Vec<SecretGenerator>,
    /// Namespace to apply to all resources.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

impl Kustomization {
    pub fn new() -> Self {
        Self {
            api_version: "kustomize.config.k8s.io/v1beta1".to_string(),
            kind: "Kustomization".to_string(),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigMapGenerator {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Generate from .env files.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "envs")]
    pub env_files: Vec<String>,
    /// Literal key=value pairs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub literals: Vec<String>,
    /// Disable hash suffix on generated name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<GeneratorOptions>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretGenerator {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Generate from .env files.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "envs")]
    pub env_files: Vec<String>,
    /// Literal key=value pairs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub literals: Vec<String>,
    /// Disable hash suffix on generated name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<GeneratorOptions>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratorOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_name_suffix_hash: Option<bool>,
}
