use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use thiserror::Error;

pub mod component_protocol;
pub mod dynamic_caps;
pub mod telemetry;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeshIdentity {
    pub id: String,
    #[serde(with = "key_serde_32")]
    pub public_key: [u8; 32],
    #[serde(with = "key_serde_64")]
    pub private_key: [u8; 64],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_scope: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeshIdentityPublic {
    pub id: String,
    #[serde(with = "key_serde_32")]
    pub public_key: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_scope: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeshIdentitySecret {
    pub id: String,
    #[serde(with = "key_serde_64")]
    pub private_key: [u8; 64],
}

impl MeshIdentity {
    pub fn generate(id: impl Into<String>, mesh_scope: Option<String>) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let keypair = signing_key.to_keypair_bytes();
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            id: id.into(),
            public_key,
            private_key: keypair,
            mesh_scope,
        }
    }

    pub fn derive(id: impl Into<String>, mesh_scope: Option<String>, seed: &str) -> Self {
        let id = id.into();
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"amber.mesh.identity.v1\0");
        hasher.update(seed.as_bytes());
        hasher.update(b"\0");
        hasher.update(id.as_bytes());
        hasher.update(b"\0");
        if let Some(scope) = mesh_scope.as_deref() {
            hasher.update(scope.as_bytes());
        }
        let secret: [u8; 32] = hasher.finalize().into();
        let signing_key = SigningKey::from_bytes(&secret);
        let keypair = signing_key.to_keypair_bytes();
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            id,
            public_key,
            private_key: keypair,
            mesh_scope,
        }
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_keypair_bytes(&self.private_key)
            .expect("mesh identity private key should be valid")
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.public_key)
            .expect("mesh identity public key should be valid")
    }
}

impl MeshIdentityPublic {
    pub fn from_identity(identity: &MeshIdentity) -> Self {
        Self {
            id: identity.id.clone(),
            public_key: identity.public_key,
            mesh_scope: identity.mesh_scope.clone(),
        }
    }
}

impl MeshIdentitySecret {
    pub fn from_identity(identity: &MeshIdentity) -> Self {
        Self {
            id: identity.id.clone(),
            private_key: identity.private_key,
        }
    }

    pub fn signing_key(&self) -> Result<SigningKey, MeshConfigError> {
        SigningKey::from_keypair_bytes(&self.private_key)
            .map_err(|err| MeshConfigError::Invalid(err.to_string()))
    }

    pub fn public_key(&self) -> Result<[u8; 32], MeshConfigError> {
        Ok(self.signing_key()?.verifying_key().to_bytes())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeshPeer {
    pub id: String,
    #[serde(with = "key_serde_32")]
    pub public_key: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MeshProtocol {
    Http,
    Tcp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeshConfig {
    pub identity: MeshIdentity,
    pub mesh_listen: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_listen: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_caps_listen: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_allow: Option<Vec<String>>,
    pub peers: Vec<MeshPeer>,
    pub inbound: Vec<InboundRoute>,
    pub outbound: Vec<OutboundRoute>,
    #[serde(default = "default_transport")]
    pub transport: TransportConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeshConfigPublic {
    pub identity: MeshIdentityPublic,
    pub mesh_listen: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_listen: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_caps_listen: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_allow: Option<Vec<String>>,
    pub peers: Vec<MeshPeer>,
    pub inbound: Vec<InboundRoute>,
    pub outbound: Vec<OutboundRoute>,
    #[serde(default = "default_transport")]
    pub transport: TransportConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeshIdentityTemplate {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_scope: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeshPeerTemplate {
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeshConfigTemplate {
    pub identity: MeshIdentityTemplate,
    pub mesh_listen: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_listen: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_caps_listen: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_allow: Option<Vec<String>>,
    pub peers: Vec<MeshPeerTemplate>,
    pub inbound: Vec<InboundRoute>,
    pub outbound: Vec<OutboundRoute>,
    #[serde(default = "default_transport")]
    pub transport: TransportConfig,
}

pub const MESH_PROVISION_PLAN_VERSION: &str = "2";
pub const MESH_CONFIG_FILENAME: &str = "mesh-config.json";
pub const MESH_IDENTITY_FILENAME: &str = "mesh-identity.json";
pub const FRAMEWORK_COMPONENT_CONTROLLER_URL_ENV: &str = "AMBER_FRAMEWORK_COMPONENT_CONTROLLER_URL";
pub const FRAMEWORK_COMPONENT_CONTROLLER_AUTH_TOKEN_ENV: &str =
    "AMBER_FRAMEWORK_COMPONENT_CONTROLLER_AUTH_TOKEN";
pub const DYNAMIC_CAPS_API_URL_ENV: &str = dynamic_caps::DYNAMIC_CAPS_API_URL_ENV;
pub const DYNAMIC_CAPS_TOKEN_VERIFY_KEY_B64_ENV: &str =
    dynamic_caps::DYNAMIC_CAPS_TOKEN_VERIFY_KEY_B64_ENV;

pub fn stable_temp_socket_path(namespace: &str, kind: &str, path: &Path) -> PathBuf {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"amber.temp_socket_path.v1\0");
    hasher.update(namespace.as_bytes());
    hasher.update(b"\0");
    hasher.update(kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(path.as_os_str().to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let suffix = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    env::temp_dir()
        .join(namespace)
        .join(format!("{kind}-{suffix}.sock"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeshProvisionPlan {
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_seed: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub existing_peer_identities: Vec<MeshIdentityPublic>,
    pub targets: Vec<MeshProvisionTarget>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeshProvisionTarget {
    pub kind: MeshProvisionTargetKind,
    pub config: MeshConfigTemplate,
    pub output: MeshProvisionOutput,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshProvisionTargetKind {
    Component,
    Router,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum MeshProvisionOutput {
    Filesystem {
        dir: String,
    },
    KubernetesSecret {
        name: String,
        namespace: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InboundRoute {
    pub route_id: String,
    pub capability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_profile: Option<String>,
    pub protocol: MeshProtocol,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_plugins: Vec<HttpRoutePlugin>,
    pub target: InboundTarget,
    pub allowed_issuers: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HttpRoutePlugin {
    A2a,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OutboundRoute {
    pub route_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_route_id: Option<String>,
    pub slot: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_profile: Option<String>,
    pub listen_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<String>,
    pub protocol: MeshProtocol,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_plugins: Vec<HttpRoutePlugin>,
    pub peer_addr: String,
    pub peer_id: String,
    pub capability: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum InboundTarget {
    Local {
        port: u16,
    },
    External {
        url_env: String,
        #[serde(default, skip_serializing_if = "is_false")]
        optional: bool,
    },
    MeshForward {
        peer_addr: String,
        peer_id: String,
        route_id: String,
        capability: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TransportConfig {
    NoiseIk {},
}

fn default_transport() -> TransportConfig {
    TransportConfig::NoiseIk {}
}

fn is_false(value: &bool) -> bool {
    !*value
}

pub fn component_route_id(identity_id: &str, capability: &str, protocol: MeshProtocol) -> String {
    format!(
        "component:{identity_id}:{capability}:{}",
        protocol_label(protocol)
    )
}

pub fn public_export_rewrite_route_id(
    component: &str,
    provide: &str,
    protocol: MeshProtocol,
) -> String {
    component_route_id(component, provide, protocol)
}

fn abstract_route_rewrite_enabled(capability_kind: Option<&str>, protocol: MeshProtocol) -> bool {
    matches!(
        (capability_kind, protocol),
        (Some(kind), MeshProtocol::Http)
            if kind == amber_manifest::CapabilityKind::A2a.as_str()
    )
}

pub fn http_route_plugins_for_capability_kind(
    capability_kind: Option<&str>,
    protocol: MeshProtocol,
) -> Vec<HttpRoutePlugin> {
    abstract_route_rewrite_enabled(capability_kind, protocol)
        .then_some(HttpRoutePlugin::A2a)
        .into_iter()
        .collect()
}

pub fn router_external_route_id(slot: &str) -> String {
    format!("router:external:{slot}:http")
}

pub fn router_framework_route_id(
    identity_id: &str,
    slot: &str,
    capability: &str,
    protocol: MeshProtocol,
) -> String {
    format!(
        "router:framework:{identity_id}:{slot}:{capability}:{}",
        protocol_label(protocol)
    )
}

pub fn router_export_route_id(export: &str, protocol: MeshProtocol) -> String {
    format!("router:export:{export}:{}", protocol_label(protocol))
}

pub fn router_dynamic_export_route_id(
    provider_peer_id: &str,
    export: &str,
    protocol: MeshProtocol,
) -> String {
    format!(
        "router:dynamic-export:{provider_peer_id}:{export}:{}",
        protocol_label(protocol)
    )
}

pub fn framework_cap_instance_id(
    authority_realm_moniker: &str,
    consumer_moniker: &str,
    consumer_component_key: &str,
    slot: &str,
    capability: &str,
) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"amber.framework_component.cap_instance.v1\0");
    hasher.update(authority_realm_moniker.as_bytes());
    hasher.update(b"\0");
    hasher.update(consumer_moniker.as_bytes());
    hasher.update(b"\0");
    hasher.update(consumer_component_key.as_bytes());
    hasher.update(b"\0");
    hasher.update(slot.as_bytes());
    hasher.update(b"\0");
    hasher.update(capability.as_bytes());
    format!(
        "cap_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&hasher.finalize()[..12])
    )
}

fn protocol_label(protocol: MeshProtocol) -> &'static str {
    match protocol {
        MeshProtocol::Http => "http",
        MeshProtocol::Tcp => "tcp",
    }
}

pub fn encode_config_b64(config: &MeshConfig) -> Result<String, serde_json::Error> {
    let json = serde_json::to_vec(config)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

pub fn generate_identity_seed() -> String {
    let signing_key = SigningKey::generate(&mut OsRng);
    base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes())
}

#[derive(Debug, Error)]
pub enum MeshConfigError {
    #[error("invalid mesh config: {0}")]
    Invalid(String),
}

pub fn decode_config_b64(raw: &str) -> Result<MeshConfig, MeshConfigError> {
    if raw.trim().is_empty() {
        return Err(MeshConfigError::Invalid("empty mesh config".to_string()));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .map_err(|err| MeshConfigError::Invalid(err.to_string()))?;
    serde_json::from_slice(&decoded).map_err(|err| MeshConfigError::Invalid(err.to_string()))
}

impl MeshConfigPublic {
    pub fn from_config(config: &MeshConfig) -> Self {
        Self {
            identity: MeshIdentityPublic::from_identity(&config.identity),
            mesh_listen: config.mesh_listen,
            control_listen: config.control_listen,
            dynamic_caps_listen: config.dynamic_caps_listen,
            control_allow: config.control_allow.clone(),
            peers: config.peers.clone(),
            inbound: config.inbound.clone(),
            outbound: config.outbound.clone(),
            transport: config.transport.clone(),
        }
    }

    pub fn with_identity_secret(
        self,
        secret: MeshIdentitySecret,
    ) -> Result<MeshConfig, MeshConfigError> {
        if secret.id != self.identity.id {
            return Err(MeshConfigError::Invalid(format!(
                "identity id mismatch (config={}, secret={})",
                self.identity.id, secret.id
            )));
        }
        let public_key = secret.public_key()?;
        if public_key != self.identity.public_key {
            return Err(MeshConfigError::Invalid(
                "identity public key does not match private key".to_string(),
            ));
        }
        Ok(MeshConfig {
            identity: MeshIdentity {
                id: self.identity.id,
                public_key: self.identity.public_key,
                private_key: secret.private_key,
                mesh_scope: self.identity.mesh_scope,
            },
            mesh_listen: self.mesh_listen,
            control_listen: self.control_listen,
            dynamic_caps_listen: self.dynamic_caps_listen,
            control_allow: self.control_allow,
            peers: self.peers,
            inbound: self.inbound,
            outbound: self.outbound,
            transport: self.transport,
        })
    }
}

impl MeshConfigTemplate {
    pub fn to_public_config(
        &self,
        identities: &HashMap<String, MeshIdentity>,
    ) -> Result<MeshConfigPublic, MeshConfigError> {
        let identity = identities.get(&self.identity.id).ok_or_else(|| {
            MeshConfigError::Invalid(format!("missing identity for {}", self.identity.id))
        })?;
        let mut peers = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            let peer_identity = identities.get(&peer.id).ok_or_else(|| {
                MeshConfigError::Invalid(format!("missing peer identity for {}", peer.id))
            })?;
            peers.push(MeshPeer {
                id: peer_identity.id.clone(),
                public_key: peer_identity.public_key,
            });
        }
        Ok(MeshConfigPublic {
            identity: MeshIdentityPublic::from_identity(identity),
            mesh_listen: self.mesh_listen,
            control_listen: self.control_listen,
            dynamic_caps_listen: self.dynamic_caps_listen,
            control_allow: self.control_allow.clone(),
            peers,
            inbound: self.inbound.clone(),
            outbound: self.outbound.clone(),
            transport: self.transport.clone(),
        })
    }
}

mod key_serde_32 {
    use super::*;

    pub fn serialize<S>(key: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(serde::de::Error::custom)?;
        Ok(bytes)
    }
}

mod key_serde_64 {
    use super::*;

    pub fn serialize<S>(key: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        let bytes: [u8; 64] = decoded
            .as_slice()
            .try_into()
            .map_err(serde::de::Error::custom)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_route_plugins_only_enable_a2a_http_rewrites() {
        assert_eq!(
            http_route_plugins_for_capability_kind(
                Some(amber_manifest::CapabilityKind::A2a.as_str()),
                MeshProtocol::Http,
            ),
            vec![HttpRoutePlugin::A2a]
        );
        assert!(
            http_route_plugins_for_capability_kind(
                Some(amber_manifest::CapabilityKind::Http.as_str()),
                MeshProtocol::Http,
            )
            .is_empty()
        );
        assert!(
            http_route_plugins_for_capability_kind(
                Some(amber_manifest::CapabilityKind::A2a.as_str()),
                MeshProtocol::Tcp,
            )
            .is_empty()
        );
    }

    #[test]
    fn stable_temp_socket_path_is_deterministic_for_known_input() {
        let path = stable_temp_socket_path(
            "amber-direct-control",
            "current",
            Path::new("/tmp/amber/example/sites/direct_local/artifact"),
        );
        assert_eq!(
            path,
            env::temp_dir()
                .join("amber-direct-control")
                .join("current-9308da51951bac96.sock",)
        );
    }
}
