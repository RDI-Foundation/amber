use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
};

use amber_mesh::{
    MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME, MESH_PROVISION_PLAN_VERSION, MeshConfigPublic,
    MeshIdentity, MeshIdentitySecret, MeshProvisionOutput, MeshProvisionPlan, MeshProvisionTarget,
    MeshProvisionTargetKind,
};
use base64::Engine as _;
use reqwest::{Certificate, Client, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
enum ProvisionerError {
    #[error(
        "missing mesh provision plan (set AMBER_MESH_PROVISION_PLAN_PATH, \
         AMBER_MESH_PROVISION_PLAN_B64, or AMBER_MESH_PROVISION_PLAN_JSON)"
    )]
    MissingPlan,
    #[error("invalid mesh provision plan: {0}")]
    InvalidPlan(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("kubernetes api error: {0}")]
    Kubernetes(String),
    #[error("base64 decode error: {0}")]
    Base64(String),
    #[error("json error: {0}")]
    Json(String),
}

type Result<T> = std::result::Result<T, ProvisionerError>;

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("amber provisioner failed: {err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let plan = load_plan()?;
    if plan.version != MESH_PROVISION_PLAN_VERSION {
        return Err(ProvisionerError::InvalidPlan(format!(
            "unsupported plan version {}",
            plan.version
        )));
    }
    if plan.targets.is_empty() {
        return Err(ProvisionerError::InvalidPlan(
            "plan has no targets".to_string(),
        ));
    }

    let mut seen_ids = HashSet::new();
    for target in &plan.targets {
        let id = &target.config.identity.id;
        if !seen_ids.insert(id.clone()) {
            return Err(ProvisionerError::InvalidPlan(format!(
                "duplicate identity id {id}"
            )));
        }
    }

    let needs_kube = plan
        .targets
        .iter()
        .any(|target| matches!(target.output, MeshProvisionOutput::KubernetesSecret { .. }));
    let kube = if needs_kube {
        Some(KubeClient::from_env()?)
    } else {
        None
    };

    let mut existing_identities: HashMap<String, MeshIdentity> = HashMap::new();
    let mut existing_outputs: HashMap<String, ExistingOutput> = HashMap::new();

    for target in &plan.targets {
        let id = target.config.identity.id.clone();
        let state = match &target.output {
            MeshProvisionOutput::Filesystem { dir } => {
                let dir = PathBuf::from(dir);
                let identity_path = dir.join(MESH_IDENTITY_FILENAME);
                let config_path = dir.join(MESH_CONFIG_FILENAME);
                let identity_exists = identity_path.exists();
                let config_exists = config_path.exists();
                let identity = if identity_exists {
                    Some(read_identity(&identity_path)?)
                } else {
                    None
                };
                let config = if config_exists {
                    Some(read_public_config(&config_path)?)
                } else {
                    None
                };
                ExistingOutput::Filesystem(FilesystemOutput {
                    dir,
                    identity_path,
                    config_path,
                    identity,
                    config,
                })
            }
            MeshProvisionOutput::KubernetesSecret { name, namespace } => {
                let kube = kube.as_ref().ok_or_else(|| {
                    ProvisionerError::Kubernetes(
                        "kubernetes outputs requested but no kube client available".to_string(),
                    )
                })?;
                let namespace = namespace.clone().unwrap_or_else(|| kube.namespace.clone());
                let secret = kube.get_secret(&namespace, name).await?;
                ExistingOutput::Kubernetes {
                    name: name.clone(),
                    namespace,
                    secret,
                }
            }
        };

        if let Some(identity) = state.identity_secret()? {
            let mesh_scope = target.config.identity.mesh_scope.clone();
            let identity = identity_from_secret(&identity, mesh_scope)?;
            existing_identities.insert(id.clone(), identity);
        }
        existing_outputs.insert(id, state);
    }

    let mut identities = existing_identities;
    for target in &plan.targets {
        let id = &target.config.identity.id;
        if identities.contains_key(id) {
            continue;
        }
        let identity =
            MeshIdentity::generate(id.clone(), target.config.identity.mesh_scope.clone());
        identities.insert(id.clone(), identity);
    }

    for target in &plan.targets {
        let id = &target.config.identity.id;
        let identity = identities
            .get(id)
            .ok_or_else(|| {
                ProvisionerError::InvalidPlan(format!("missing identity for target {}", id))
            })?
            .clone();
        let public_config = target
            .config
            .to_public_config(&identities)
            .map_err(|err| ProvisionerError::InvalidPlan(err.to_string()))?;
        let identity_secret = MeshIdentitySecret::from_identity(&identity);
        let output = existing_outputs.get(id).ok_or_else(|| {
            ProvisionerError::InvalidPlan(format!("missing output info for target {}", id))
        })?;

        match output {
            ExistingOutput::Filesystem(output) => {
                write_filesystem(target, output, &public_config, &identity_secret)?;
            }
            ExistingOutput::Kubernetes {
                name,
                namespace,
                secret,
            } => {
                let kube = kube.as_ref().ok_or_else(|| {
                    ProvisionerError::Kubernetes(
                        "kubernetes outputs requested but no kube client available".to_string(),
                    )
                })?;
                write_kubernetes(
                    target,
                    kube,
                    namespace,
                    name,
                    secret.as_ref(),
                    &public_config,
                    &identity_secret,
                )
                .await?;
            }
        }
    }

    Ok(())
}

fn load_plan() -> Result<MeshProvisionPlan> {
    if let Ok(path) = env::var("AMBER_MESH_PROVISION_PLAN_PATH") {
        let raw = fs::read_to_string(&path)?;
        return parse_plan_json(&raw);
    }

    if let Ok(b64) = env::var("AMBER_MESH_PROVISION_PLAN_B64") {
        if b64.trim().is_empty() {
            return Err(ProvisionerError::MissingPlan);
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64.trim().as_bytes())
            .map_err(|err| ProvisionerError::Base64(err.to_string()))?;
        let raw =
            String::from_utf8(decoded).map_err(|err| ProvisionerError::Json(err.to_string()))?;
        return parse_plan_json(&raw);
    }

    if let Ok(raw) = env::var("AMBER_MESH_PROVISION_PLAN_JSON") {
        if raw.trim().is_empty() {
            return Err(ProvisionerError::MissingPlan);
        }
        return parse_plan_json(&raw);
    }

    Err(ProvisionerError::MissingPlan)
}

fn parse_plan_json(raw: &str) -> Result<MeshProvisionPlan> {
    serde_json::from_str(raw).map_err(|err| ProvisionerError::InvalidPlan(err.to_string()))
}

fn read_identity(path: &Path) -> Result<MeshIdentitySecret> {
    let raw = fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(|err| ProvisionerError::Json(err.to_string()))
}

fn read_public_config(path: &Path) -> Result<MeshConfigPublic> {
    let raw = fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(|err| ProvisionerError::Json(err.to_string()))
}

fn identity_from_secret(
    secret: &MeshIdentitySecret,
    mesh_scope: Option<String>,
) -> Result<MeshIdentity> {
    let public_key = secret
        .public_key()
        .map_err(|err| ProvisionerError::InvalidPlan(err.to_string()))?;
    Ok(MeshIdentity {
        id: secret.id.clone(),
        public_key,
        private_key: secret.private_key,
        mesh_scope,
    })
}

fn write_filesystem(
    target: &MeshProvisionTarget,
    output: &FilesystemOutput,
    public_config: &MeshConfigPublic,
    identity_secret: &MeshIdentitySecret,
) -> Result<()> {
    let existing_identity = output.identity.as_ref();
    let existing_config = output.config.as_ref();

    if let Some(existing_identity) = existing_identity {
        if existing_identity.id != identity_secret.id {
            return Err(ProvisionerError::InvalidPlan(format!(
                "identity file for {} does not match plan id",
                identity_label(target)
            )));
        }
        if let Some(existing_config) = existing_config {
            verify_identity_matches_config(existing_identity, existing_config, target)?;
            if config_matches(existing_config, public_config)? {
                return Ok(());
            }
        }
    }

    if existing_identity.is_none() && existing_config.is_some() {
        return Err(ProvisionerError::InvalidPlan(format!(
            "config file exists without identity for {}",
            identity_label(target)
        )));
    }

    fs::create_dir_all(&output.dir)?;

    if existing_identity.is_none() {
        let raw = serde_json::to_string_pretty(identity_secret)
            .map_err(|err| ProvisionerError::Json(err.to_string()))?;
        fs::write(&output.identity_path, raw)?;
    }

    let raw = serde_json::to_string_pretty(public_config)
        .map_err(|err| ProvisionerError::Json(err.to_string()))?;
    fs::write(&output.config_path, raw)?;

    Ok(())
}

async fn write_kubernetes(
    target: &MeshProvisionTarget,
    kube: &KubeClient,
    namespace: &str,
    name: &str,
    existing_secret: Option<&KubeSecret>,
    public_config: &MeshConfigPublic,
    identity_secret: &MeshIdentitySecret,
) -> Result<()> {
    if let Some(existing) = existing_secret {
        verify_identity_matches_config(&existing.identity, &existing.config, target)?;
        if config_matches(&existing.config, public_config)? {
            return Ok(());
        }
        let config_raw = serde_json::to_string_pretty(public_config)
            .map_err(|err| ProvisionerError::Json(err.to_string()))?;
        let identity_raw = serde_json::to_string_pretty(identity_secret)
            .map_err(|err| ProvisionerError::Json(err.to_string()))?;
        let mut string_data = BTreeMap::new();
        string_data.insert(MESH_CONFIG_FILENAME.to_string(), config_raw);
        string_data.insert(MESH_IDENTITY_FILENAME.to_string(), identity_raw);
        kube.update_secret(namespace, name, &existing.resource_version, &string_data)
            .await?;
        return Ok(());
    }

    let config_raw = serde_json::to_string_pretty(public_config)
        .map_err(|err| ProvisionerError::Json(err.to_string()))?;
    let identity_raw = serde_json::to_string_pretty(identity_secret)
        .map_err(|err| ProvisionerError::Json(err.to_string()))?;

    let mut string_data = BTreeMap::new();
    string_data.insert(MESH_CONFIG_FILENAME.to_string(), config_raw);
    string_data.insert(MESH_IDENTITY_FILENAME.to_string(), identity_raw);

    kube.create_secret(namespace, name, &string_data).await
}

fn verify_identity_matches_config(
    identity: &MeshIdentitySecret,
    config: &MeshConfigPublic,
    target: &MeshProvisionTarget,
) -> Result<()> {
    if identity.id != config.identity.id {
        return Err(ProvisionerError::InvalidPlan(format!(
            "identity/config id mismatch for {}",
            identity_label(target)
        )));
    }
    let public_key = identity
        .public_key()
        .map_err(|err| ProvisionerError::InvalidPlan(err.to_string()))?;
    if public_key != config.identity.public_key {
        return Err(ProvisionerError::InvalidPlan(format!(
            "identity/config key mismatch for {}",
            identity_label(target)
        )));
    }
    Ok(())
}

fn config_matches(existing: &MeshConfigPublic, desired: &MeshConfigPublic) -> Result<bool> {
    let existing =
        serde_json::to_value(existing).map_err(|err| ProvisionerError::Json(err.to_string()))?;
    let desired =
        serde_json::to_value(desired).map_err(|err| ProvisionerError::Json(err.to_string()))?;
    Ok(existing == desired)
}

fn identity_label(target: &MeshProvisionTarget) -> String {
    match target.kind {
        MeshProvisionTargetKind::Component => target.config.identity.id.clone(),
        MeshProvisionTargetKind::Router => "router".to_string(),
    }
}

#[derive(Clone, Debug)]
struct FilesystemOutput {
    dir: PathBuf,
    identity_path: PathBuf,
    config_path: PathBuf,
    identity: Option<MeshIdentitySecret>,
    config: Option<MeshConfigPublic>,
}

#[derive(Clone, Debug)]
enum ExistingOutput {
    Filesystem(FilesystemOutput),
    Kubernetes {
        name: String,
        namespace: String,
        secret: Option<KubeSecret>,
    },
}

impl ExistingOutput {
    fn identity_secret(&self) -> Result<Option<MeshIdentitySecret>> {
        match self {
            ExistingOutput::Filesystem(output) => Ok(output.identity.clone()),
            ExistingOutput::Kubernetes { secret, .. } => {
                Ok(secret.as_ref().map(|s| s.identity.clone()))
            }
        }
    }
}

#[derive(Clone)]
struct KubeClient {
    client: Client,
    token: String,
    namespace: String,
    base_url: String,
}

impl KubeClient {
    fn from_env() -> Result<Self> {
        let host = env::var("KUBERNETES_SERVICE_HOST").map_err(|_| {
            ProvisionerError::Kubernetes("missing KUBERNETES_SERVICE_HOST".to_string())
        })?;
        let port = env::var("KUBERNETES_SERVICE_PORT").map_err(|_| {
            ProvisionerError::Kubernetes("missing KUBERNETES_SERVICE_PORT".to_string())
        })?;
        let token = fs::read_to_string(service_account_token_path()).map_err(|err| {
            ProvisionerError::Kubernetes(format!("failed to read service account token: {err}"))
        })?;
        let namespace = fs::read_to_string(service_account_namespace_path()).map_err(|err| {
            ProvisionerError::Kubernetes(format!("failed to read service account namespace: {err}"))
        })?;
        let ca_pem = fs::read(service_account_ca_path()).map_err(|err| {
            ProvisionerError::Kubernetes(format!("failed to read service account CA: {err}"))
        })?;
        let cert = Certificate::from_pem(&ca_pem).map_err(|err| {
            ProvisionerError::Kubernetes(format!("failed to parse service account CA: {err}"))
        })?;
        let client = Client::builder()
            .add_root_certificate(cert)
            .build()
            .map_err(|err| {
                ProvisionerError::Kubernetes(format!("failed to build kube client: {err}"))
            })?;
        Ok(Self {
            client,
            token: token.trim().to_string(),
            namespace: namespace.trim().to_string(),
            base_url: format!("https://{host}:{port}"),
        })
    }

    async fn get_secret(&self, namespace: &str, name: &str) -> Result<Option<KubeSecret>> {
        let url = format!(
            "{}/api/v1/namespaces/{}/secrets/{name}",
            self.base_url, namespace
        );
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|err| ProvisionerError::Kubernetes(format!("failed to get secret: {err}")))?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(ProvisionerError::Kubernetes(format!(
                "failed to get secret {} (status {})",
                name,
                resp.status()
            )));
        }
        let payload: KubeSecretPayload = resp.json().await.map_err(|err| {
            ProvisionerError::Kubernetes(format!("failed to parse secret: {err}"))
        })?;
        let data = payload.data.unwrap_or_default();
        let resource_version = payload.metadata.resource_version;
        let config_raw = decode_secret_value(&data, MESH_CONFIG_FILENAME)?;
        let identity_raw = decode_secret_value(&data, MESH_IDENTITY_FILENAME)?;
        let config: MeshConfigPublic = serde_json::from_str(&config_raw)
            .map_err(|err| ProvisionerError::Json(err.to_string()))?;
        let identity: MeshIdentitySecret = serde_json::from_str(&identity_raw)
            .map_err(|err| ProvisionerError::Json(err.to_string()))?;
        Ok(Some(KubeSecret {
            config,
            identity,
            resource_version,
        }))
    }

    async fn create_secret(
        &self,
        namespace: &str,
        name: &str,
        string_data: &BTreeMap<String, String>,
    ) -> Result<()> {
        let url = format!("{}/api/v1/namespaces/{}/secrets", self.base_url, namespace);
        let body = SecretCreateRequest {
            api_version: "v1",
            kind: "Secret",
            metadata: SecretMetadata { name },
            secret_type: "Opaque",
            string_data,
        };
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|err| {
                ProvisionerError::Kubernetes(format!("failed to create secret: {err}"))
            })?;
        if resp.status() == StatusCode::CONFLICT {
            return Ok(());
        }
        if !resp.status().is_success() {
            return Err(ProvisionerError::Kubernetes(format!(
                "failed to create secret {} (status {})",
                name,
                resp.status()
            )));
        }
        Ok(())
    }

    async fn update_secret(
        &self,
        namespace: &str,
        name: &str,
        resource_version: &str,
        string_data: &BTreeMap<String, String>,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/namespaces/{}/secrets/{name}",
            self.base_url, namespace
        );
        let data = build_secret_data_from_string_data(string_data);
        let body = SecretUpdateRequest {
            api_version: "v1",
            kind: "Secret",
            metadata: SecretMetadataWithNamespace {
                name,
                namespace,
                resource_version,
            },
            secret_type: "Opaque",
            data: &data,
        };
        let resp = self
            .client
            .put(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|err| {
                ProvisionerError::Kubernetes(format!("failed to update secret: {err}"))
            })?;
        if resp.status() == StatusCode::NOT_FOUND {
            return self.create_secret(namespace, name, string_data).await;
        }
        if !resp.status().is_success() {
            return Err(ProvisionerError::Kubernetes(format!(
                "failed to update secret {} (status {})",
                name,
                resp.status()
            )));
        }
        Ok(())
    }
}

fn build_secret_data_from_string_data(
    string_data: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut data = BTreeMap::new();
    for (key, value) in string_data {
        data.insert(
            key.clone(),
            base64::engine::general_purpose::STANDARD.encode(value.as_bytes()),
        );
    }
    data
}

fn decode_secret_value(data: &BTreeMap<String, String>, key: &str) -> Result<String> {
    let raw = data
        .get(key)
        .ok_or_else(|| ProvisionerError::Kubernetes(format!("secret missing key {}", key)))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .map_err(|err| ProvisionerError::Base64(err.to_string()))?;
    String::from_utf8(decoded).map_err(|err| ProvisionerError::Json(err.to_string()))
}

fn service_account_token_path() -> &'static str {
    "/var/run/secrets/kubernetes.io/serviceaccount/token"
}

fn service_account_namespace_path() -> &'static str {
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
}

fn service_account_ca_path() -> &'static str {
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
}

#[derive(Debug, Deserialize)]
struct KubeSecretPayload {
    data: Option<BTreeMap<String, String>>,
    metadata: KubeSecretMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KubeSecretMetadata {
    resource_version: String,
}

#[derive(Clone, Debug)]
struct KubeSecret {
    config: MeshConfigPublic,
    identity: MeshIdentitySecret,
    resource_version: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretCreateRequest<'a> {
    api_version: &'a str,
    kind: &'a str,
    metadata: SecretMetadata<'a>,
    #[serde(rename = "type")]
    secret_type: &'a str,
    string_data: &'a BTreeMap<String, String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretMetadata<'a> {
    name: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretUpdateRequest<'a> {
    api_version: &'a str,
    kind: &'a str,
    metadata: SecretMetadataWithNamespace<'a>,
    #[serde(rename = "type")]
    secret_type: &'a str,
    data: &'a BTreeMap<String, String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretMetadataWithNamespace<'a> {
    name: &'a str,
    namespace: &'a str,
    #[serde(rename = "resourceVersion")]
    resource_version: &'a str,
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[tokio::test]
    async fn provisioner_resets_mismatched_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mesh_dir = dir.path().join("c1");
        fs::create_dir_all(&mesh_dir).expect("create mesh dir");

        let template = amber_mesh::MeshConfigTemplate {
            identity: amber_mesh::MeshIdentityTemplate {
                id: "/c1".to_string(),
                mesh_scope: Some("scope".to_string()),
            },
            mesh_listen: "0.0.0.0:23001".parse::<SocketAddr>().unwrap(),
            control_listen: None,
            control_allow: None,
            peers: Vec::new(),
            inbound: Vec::new(),
            outbound: Vec::new(),
            transport: amber_mesh::TransportConfig::NoiseIk {},
        };

        let plan = MeshProvisionPlan {
            version: MESH_PROVISION_PLAN_VERSION.to_string(),
            targets: vec![MeshProvisionTarget {
                kind: MeshProvisionTargetKind::Component,
                config: template.clone(),
                output: MeshProvisionOutput::Filesystem {
                    dir: mesh_dir.to_string_lossy().to_string(),
                },
            }],
        };

        let identity = MeshIdentity::generate(
            template.identity.id.clone(),
            template.identity.mesh_scope.clone(),
        );
        let mut identities = HashMap::new();
        identities.insert(identity.id.clone(), identity.clone());
        let expected_config = template
            .to_public_config(&identities)
            .expect("public config");
        let mut public_config = template
            .to_public_config(&identities)
            .expect("public config");
        public_config.mesh_listen = "0.0.0.0:23002".parse::<SocketAddr>().unwrap();

        let identity_secret = MeshIdentitySecret::from_identity(&identity);
        fs::write(
            mesh_dir.join(MESH_IDENTITY_FILENAME),
            serde_json::to_string_pretty(&identity_secret).expect("identity json"),
        )
        .expect("write identity");
        fs::write(
            mesh_dir.join(MESH_CONFIG_FILENAME),
            serde_json::to_string_pretty(&public_config).expect("config json"),
        )
        .expect("write config");

        let plan_json = serde_json::to_string(&plan).expect("plan json");
        unsafe {
            env::set_var("AMBER_MESH_PROVISION_PLAN_JSON", plan_json);
        }

        run().await.expect("provisioner should reset config");
        unsafe {
            env::remove_var("AMBER_MESH_PROVISION_PLAN_JSON");
        }

        let updated_raw =
            fs::read_to_string(mesh_dir.join(MESH_CONFIG_FILENAME)).expect("read updated config");
        let updated: MeshConfigPublic =
            serde_json::from_str(&updated_raw).expect("parse updated config");
        let updated_value = serde_json::to_value(&updated).expect("updated json");
        let expected_value = serde_json::to_value(&expected_config).expect("expected json");
        assert_eq!(updated_value, expected_value);
    }
}
