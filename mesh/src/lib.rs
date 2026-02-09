use std::{collections::HashMap, net::SocketAddr};

use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    Udp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeshConfig {
    pub identity: MeshIdentity,
    pub mesh_listen: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_listen: Option<SocketAddr>,
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
    pub control_allow: Option<Vec<String>>,
    pub peers: Vec<MeshPeerTemplate>,
    pub inbound: Vec<InboundRoute>,
    pub outbound: Vec<OutboundRoute>,
    #[serde(default = "default_transport")]
    pub transport: TransportConfig,
}

pub const MESH_PROVISION_PLAN_VERSION: &str = "1";
pub const MESH_CONFIG_FILENAME: &str = "mesh-config.json";
pub const MESH_IDENTITY_FILENAME: &str = "mesh-identity.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeshProvisionPlan {
    pub version: String,
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
    pub capability: String,
    pub protocol: MeshProtocol,
    pub target: InboundTarget,
    pub allowed_issuers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OutboundRoute {
    pub slot: String,
    pub listen_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<String>,
    pub protocol: MeshProtocol,
    pub peer_addr: String,
    pub peer_id: String,
    pub capability: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

pub fn encode_config_b64(config: &MeshConfig) -> Result<String, serde_json::Error> {
    let json = serde_json::to_vec(config)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
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
