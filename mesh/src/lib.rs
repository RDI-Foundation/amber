use std::net::SocketAddr;

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
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
    pub peers: Vec<MeshPeer>,
    pub inbound: Vec<InboundRoute>,
    pub outbound: Vec<OutboundRoute>,
    #[serde(default = "default_transport")]
    pub transport: TransportConfig,
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
    pub token_caveats: Vec<Caveat>,
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct Caveat {
    pub key: String,
    pub value: String,
}

impl Caveat {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Token(pub String);

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MacaroonPayload {
    pub issuer_id: String,
    pub caveats: Vec<Caveat>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SignedMacaroon {
    pub payload: MacaroonPayload,
    #[serde(with = "key_serde_64")]
    pub signature: [u8; 64],
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("invalid token encoding")]
    InvalidEncoding,
    #[error("invalid token json: {0}")]
    InvalidJson(String),
    #[error("invalid token signature")]
    InvalidSignature,
    #[error("token missing required caveat {0}")]
    MissingCaveat(String),
}

impl SignedMacaroon {
    pub fn sign(payload: MacaroonPayload, signer: &SigningKey) -> Self {
        let bytes =
            serde_json::to_vec(&payload).expect("macaroon payload serialization should not fail");
        let signature = signer.sign(&bytes).to_bytes();
        Self { payload, signature }
    }

    pub fn verify(&self, verifier: &VerifyingKey) -> Result<MacaroonPayload, TokenError> {
        let bytes = serde_json::to_vec(&self.payload)
            .map_err(|err| TokenError::InvalidJson(err.to_string()))?;
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        verifier
            .verify_strict(&bytes, &signature)
            .map_err(|_| TokenError::InvalidSignature)?;
        Ok(self.payload.clone())
    }

    pub fn encode(&self) -> Result<Token, TokenError> {
        let json =
            serde_json::to_vec(self).map_err(|err| TokenError::InvalidJson(err.to_string()))?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        Ok(Token(encoded))
    }

    pub fn decode(token: &Token) -> Result<Self, TokenError> {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.0.as_bytes())
            .map_err(|_| TokenError::InvalidEncoding)?;
        serde_json::from_slice(&decoded).map_err(|err| TokenError::InvalidJson(err.to_string()))
    }
}

#[derive(Clone, Debug)]
pub struct TokenClaims {
    pub issuer_id: String,
    pub caveats: Vec<Caveat>,
}

pub trait TokenIssuer {
    fn issue(&self, caveats: &[Caveat]) -> Result<Token, TokenError>;
}

pub trait TokenVerifier {
    fn verify(&self, token: &Token, required: &[Caveat]) -> Result<TokenClaims, TokenError>;
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
