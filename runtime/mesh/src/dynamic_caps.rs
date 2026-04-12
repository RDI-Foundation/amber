use std::fmt;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{MeshProtocol, OutboundRoute, router_external_route_id};

pub const DYNAMIC_CAPS_REF_SCHEME: &str = "amber";
pub const DYNAMIC_CAPS_REF_HOST: &str = "ref";
pub const DYNAMIC_CAPS_REF_VERSION: u32 = 1;

pub const DYNAMIC_CAPS_API_URL_ENV: &str = "AMBER_DYNAMIC_CAPS_API_URL";
pub const DYNAMIC_CAPS_CONTROL_URL_ENV: &str = "AMBER_DYNAMIC_CAPS_CONTROL_URL";
pub const DYNAMIC_CAPS_CONTROL_AUTH_TOKEN_ENV: &str = "AMBER_DYNAMIC_CAPS_CONTROL_AUTH_TOKEN";
pub const DYNAMIC_CAPS_TOKEN_VERIFY_KEY_B64_ENV: &str = "AMBER_DYNAMIC_CAPS_TOKEN_VERIFY_KEY_B64";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DescriptorIr {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RootAuthoritySelectorIr {
    SelfProvide {
        component_id: String,
        provide_name: String,
    },
    Binding {
        consumer_component_id: String,
        slot_name: String,
        provider_component_id: String,
        provider_capability_name: String,
    },
    ExternalSlotBinding {
        consumer_component_id: String,
        slot_name: String,
        external_slot_component_id: String,
        external_slot_name: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldEntryKind {
    RootAuthority,
    DelegatedGrant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldEntryState {
    Live,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MaterializedHandleSummary {
    pub handle_id: String,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HeldEntrySummary {
    pub held_id: String,
    pub entry_kind: HeldEntryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_authority_selector: Option<RootAuthoritySelectorIr>,
    pub state: HeldEntryState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_component: Option<String>,
    pub descriptor: DescriptorIr,
    #[serde(default)]
    pub materializations: Vec<MaterializedHandleSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HeldEntryDetail {
    #[serde(flatten)]
    pub summary: HeldEntrySummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sharer_component_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_component_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HeldListResponse {
    pub held: Vec<HeldEntrySummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HeldEvent {
    pub event: String,
    pub held_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<DescriptorIr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ShareRequest {
    pub source: ShareSource,
    pub recipient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub options: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShareSource {
    Handle { value: String },
    HeldId { value: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ShareResponse {
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MaterializeRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MaterializeResponse {
    pub held_id: String,
    pub handle_id: String,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RevokeRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RevokeResponse {
    pub outcome: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InspectRefRequest {
    pub r#ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InspectRefResponse {
    pub state: HeldEntryState,
    pub grant_id: String,
    pub holder_component_id: String,
    pub descriptor: DescriptorIr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InspectHandleRequest {
    pub handle: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InspectHandleResponse {
    pub held_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    pub state: HeldEntryState,
    pub descriptor: DescriptorIr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DynamicCapabilitiesSnapshotIr {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<GrantSnapshotIr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GrantSnapshotIr {
    pub snapshot_grant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_snapshot_grant_id: Option<String>,
    pub root_authority_selector: RootAuthoritySelectorIr,
    pub sharer_component_id: String,
    pub holder_component_id: String,
    pub descriptor: DescriptorIr,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub share_options: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DynamicCapabilityRefClaims {
    pub version: u32,
    pub run_id: String,
    pub grant_id: String,
    pub holder_component_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor_hint: Option<String>,
}

pub fn generate_dynamic_capability_signing_seed() -> [u8; 32] {
    SigningKey::generate(&mut OsRng).to_bytes()
}

pub fn signing_key_from_seed(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

pub fn signing_key_from_seed_b64(raw: &str) -> Result<SigningKey, DynamicCapabilityRefError> {
    let decoded = STANDARD.decode(raw.as_bytes()).map_err(|err| {
        DynamicCapabilityRefError::InvalidToken(format!(
            "failed to decode dynamic capability signing seed: {err}"
        ))
    })?;
    let seed: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        DynamicCapabilityRefError::InvalidToken(
            "dynamic capability signing seed must be exactly 32 bytes".to_string(),
        )
    })?;
    Ok(signing_key_from_seed(seed))
}

pub fn signing_seed_b64(signing_key: &SigningKey) -> String {
    STANDARD.encode(signing_key.to_bytes())
}

pub fn verify_key_b64(signing_key: &SigningKey) -> String {
    STANDARD.encode(signing_key.verifying_key().to_bytes())
}

pub fn verify_key_from_b64(raw: &str) -> Result<VerifyingKey, DynamicCapabilityRefError> {
    let decoded = STANDARD.decode(raw.as_bytes()).map_err(|err| {
        DynamicCapabilityRefError::InvalidToken(format!(
            "failed to decode dynamic capability verify key: {err}"
        ))
    })?;
    let bytes: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        DynamicCapabilityRefError::InvalidToken(
            "dynamic capability verify key must be exactly 32 bytes".to_string(),
        )
    })?;
    VerifyingKey::from_bytes(&bytes).map_err(|err| {
        DynamicCapabilityRefError::InvalidToken(format!(
            "dynamic capability verify key is malformed: {err}"
        ))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExactRootRouteError {
    InvalidLogicalComponentId,
    NotFound,
    Ambiguous,
}

fn provider_moniker_from_logical_component_id(
    logical_component_id: &str,
) -> Result<&str, ExactRootRouteError> {
    logical_component_id
        .strip_prefix("components.")
        .filter(|moniker| moniker.starts_with('/'))
        .ok_or(ExactRootRouteError::InvalidLogicalComponentId)
}

pub fn exact_root_outbound_route<'a>(
    outbound: impl IntoIterator<Item = &'a OutboundRoute>,
    selector: &RootAuthoritySelectorIr,
) -> Result<Option<&'a OutboundRoute>, ExactRootRouteError> {
    match selector {
        RootAuthoritySelectorIr::SelfProvide { .. } => Ok(None),
        RootAuthoritySelectorIr::Binding {
            slot_name,
            provider_component_id,
            provider_capability_name,
            ..
        } => {
            let provider_moniker =
                provider_moniker_from_logical_component_id(provider_component_id)?;
            let matches = outbound
                .into_iter()
                .filter(|route| {
                    route.slot == *slot_name
                        && route.capability == *provider_capability_name
                        && route.peer_id == provider_moniker
                })
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [] => Err(ExactRootRouteError::NotFound),
                [route] => Ok(Some(*route)),
                _ => Err(ExactRootRouteError::Ambiguous),
            }
        }
        RootAuthoritySelectorIr::ExternalSlotBinding {
            slot_name,
            external_slot_name,
            ..
        } => {
            let expected_route_id = router_external_route_id(external_slot_name);
            let matches = outbound
                .into_iter()
                .filter(|route| {
                    route.protocol == MeshProtocol::Http
                        && route.slot == *slot_name
                        && route.capability == *external_slot_name
                        && route.route_id == expected_route_id
                })
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [] => Err(ExactRootRouteError::NotFound),
                [route] => Ok(Some(*route)),
                _ => Err(ExactRootRouteError::Ambiguous),
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DynamicCapabilityRefToken {
    claims: DynamicCapabilityRefClaims,
    signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedDynamicCapabilityRef {
    pub claims: DynamicCapabilityRefClaims,
    pub relative_path: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
    signature: Signature,
}

#[derive(Debug)]
pub enum DynamicCapabilityRefError {
    InvalidUrl(String),
    InvalidToken(String),
    InvalidSignature,
}

impl fmt::Display for DynamicCapabilityRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(message) | Self::InvalidToken(message) => f.write_str(message),
            Self::InvalidSignature => f.write_str("invalid dynamic capability ref signature"),
        }
    }
}

impl std::error::Error for DynamicCapabilityRefError {}

pub fn encode_dynamic_capability_ref(
    claims: DynamicCapabilityRefClaims,
    signing_key: &SigningKey,
) -> Result<String, DynamicCapabilityRefError> {
    let payload = serde_json::to_vec(&claims).map_err(|err| {
        DynamicCapabilityRefError::InvalidToken(format!(
            "failed to encode dynamic capability ref claims: {err}"
        ))
    })?;
    let signature = signing_key.sign(&payload);
    let token = DynamicCapabilityRefToken {
        claims,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    };
    let encoded = serde_json::to_vec(&token).map_err(|err| {
        DynamicCapabilityRefError::InvalidToken(format!(
            "failed to encode dynamic capability ref token: {err}"
        ))
    })?;
    Ok(URL_SAFE_NO_PAD.encode(encoded))
}

pub fn decode_dynamic_capability_ref(
    raw: &str,
    verify_key: &VerifyingKey,
) -> Result<ParsedDynamicCapabilityRef, DynamicCapabilityRefError> {
    let parsed = decode_dynamic_capability_ref_unverified(raw)?;
    verify_dynamic_capability_ref(&parsed, verify_key)?;
    Ok(parsed)
}

pub fn decode_dynamic_capability_ref_unverified(
    raw: &str,
) -> Result<ParsedDynamicCapabilityRef, DynamicCapabilityRefError> {
    let parsed = Url::parse(raw).map_err(|err| {
        DynamicCapabilityRefError::InvalidUrl(format!(
            "failed to parse dynamic capability ref: {err}"
        ))
    })?;
    parse_dynamic_capability_ref_url_unverified(&parsed)
}

pub fn parse_dynamic_capability_ref_url(
    url: &Url,
    verify_key: &VerifyingKey,
) -> Result<ParsedDynamicCapabilityRef, DynamicCapabilityRefError> {
    let parsed = parse_dynamic_capability_ref_url_unverified(url)?;
    verify_dynamic_capability_ref(&parsed, verify_key)?;
    Ok(parsed)
}

pub fn parse_dynamic_capability_ref_url_unverified(
    url: &Url,
) -> Result<ParsedDynamicCapabilityRef, DynamicCapabilityRefError> {
    if url.scheme() != DYNAMIC_CAPS_REF_SCHEME || url.host_str() != Some(DYNAMIC_CAPS_REF_HOST) {
        return Err(DynamicCapabilityRefError::InvalidUrl(
            "dynamic capability ref must use amber://ref/...".to_string(),
        ));
    }
    let raw_path = url.path().strip_prefix('/').ok_or_else(|| {
        DynamicCapabilityRefError::InvalidUrl("dynamic capability ref path is missing".to_string())
    })?;
    if raw_path.is_empty() {
        return Err(DynamicCapabilityRefError::InvalidUrl(
            "dynamic capability ref token is missing".to_string(),
        ));
    }
    let (token_b64, tail) = raw_path.split_once('/').unwrap_or((raw_path, ""));
    let token_raw = URL_SAFE_NO_PAD
        .decode(token_b64.as_bytes())
        .map_err(|err| {
            DynamicCapabilityRefError::InvalidToken(format!(
                "failed to decode dynamic capability ref token: {err}"
            ))
        })?;
    let token: DynamicCapabilityRefToken = serde_json::from_slice(&token_raw).map_err(|err| {
        DynamicCapabilityRefError::InvalidToken(format!(
            "failed to decode dynamic capability ref token JSON: {err}"
        ))
    })?;
    let signature_raw = URL_SAFE_NO_PAD
        .decode(token.signature.as_bytes())
        .map_err(|err| {
            DynamicCapabilityRefError::InvalidToken(format!(
                "failed to decode dynamic capability ref signature: {err}"
            ))
        })?;
    let signature = Signature::from_slice(&signature_raw).map_err(|err| {
        DynamicCapabilityRefError::InvalidToken(format!(
            "dynamic capability ref signature is malformed: {err}"
        ))
    })?;
    let relative_path = if tail.is_empty() {
        "/".to_string()
    } else {
        format!("/{tail}")
    };
    Ok(ParsedDynamicCapabilityRef {
        claims: token.claims,
        relative_path,
        query: url.query().map(ToOwned::to_owned),
        fragment: url.fragment().map(ToOwned::to_owned),
        signature,
    })
}

pub fn verify_dynamic_capability_ref(
    parsed: &ParsedDynamicCapabilityRef,
    verify_key: &VerifyingKey,
) -> Result<(), DynamicCapabilityRefError> {
    let claims_bytes = serde_json::to_vec(&parsed.claims).map_err(|err| {
        DynamicCapabilityRefError::InvalidToken(format!(
            "failed to re-encode dynamic capability ref claims: {err}"
        ))
    })?;
    verify_key
        .verify(&claims_bytes, &parsed.signature)
        .map_err(|_| DynamicCapabilityRefError::InvalidSignature)
}

pub fn build_dynamic_capability_ref_url(
    claims: DynamicCapabilityRefClaims,
    signing_key: &SigningKey,
    relative_path: &str,
    query: Option<&str>,
    fragment: Option<&str>,
) -> Result<String, DynamicCapabilityRefError> {
    let token = encode_dynamic_capability_ref(claims, signing_key)?;
    let normalized_path = if relative_path.is_empty() {
        "/".to_string()
    } else if relative_path.starts_with('/') {
        relative_path.to_string()
    } else {
        format!("/{relative_path}")
    };
    let mut url = Url::parse(&format!(
        "{DYNAMIC_CAPS_REF_SCHEME}://{DYNAMIC_CAPS_REF_HOST}/{token}"
    ))
    .map_err(|err| {
        DynamicCapabilityRefError::InvalidUrl(format!(
            "failed to construct dynamic capability ref url: {err}"
        ))
    })?;
    url.set_path(&format!("/{token}{normalized_path}"));
    url.set_query(query);
    url.set_fragment(fragment);
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HttpRoutePlugin;

    fn outbound_route(
        route_id: &str,
        slot: &str,
        capability: &str,
        peer_id: &str,
    ) -> OutboundRoute {
        OutboundRoute {
            route_id: route_id.to_string(),
            rewrite_route_id: None,
            slot: slot.to_string(),
            capability_kind: Some("http".to_string()),
            capability_profile: None,
            listen_port: 23100,
            listen_addr: None,
            protocol: MeshProtocol::Http,
            http_plugins: Vec::<HttpRoutePlugin>::new(),
            peer_addr: "127.0.0.1:31000".to_string(),
            peer_id: peer_id.to_string(),
            capability: capability.to_string(),
        }
    }

    fn test_claims() -> DynamicCapabilityRefClaims {
        DynamicCapabilityRefClaims {
            version: DYNAMIC_CAPS_REF_VERSION,
            run_id: "run-123".to_string(),
            grant_id: "g_abc".to_string(),
            holder_component_id: "components./worker".to_string(),
            descriptor_hint: Some("worker.http".to_string()),
        }
    }

    #[test]
    fn dynamic_capability_ref_round_trip_preserves_claims_and_suffix() {
        let signing_key = signing_key_from_seed(generate_dynamic_capability_signing_seed());
        let raw = build_dynamic_capability_ref_url(
            test_claims(),
            &signing_key,
            "/v1/items/42",
            Some("expand=true"),
            Some("frag"),
        )
        .expect("dynamic ref should build");

        let parsed = decode_dynamic_capability_ref(&raw, &signing_key.verifying_key())
            .expect("dynamic ref should decode");
        assert_eq!(parsed.claims, test_claims());
        assert_eq!(parsed.relative_path, "/v1/items/42");
        assert_eq!(parsed.query.as_deref(), Some("expand=true"));
        assert_eq!(parsed.fragment.as_deref(), Some("frag"));
    }

    #[test]
    fn dynamic_capability_ref_rejects_signature_tampering() {
        let signing_key = signing_key_from_seed(generate_dynamic_capability_signing_seed());
        let raw = build_dynamic_capability_ref_url(test_claims(), &signing_key, "/", None, None)
            .expect("dynamic ref should build");
        let mut parsed = Url::parse(&raw).expect("dynamic ref url should parse");
        let raw_path = parsed.path().trim_start_matches('/');
        let (token, suffix) = raw_path.split_once('/').unwrap_or((raw_path, ""));
        let token_raw = URL_SAFE_NO_PAD
            .decode(token.as_bytes())
            .expect("token should decode");
        let mut token: DynamicCapabilityRefToken =
            serde_json::from_slice(&token_raw).expect("token json should decode");
        token.claims.grant_id = "g_tampered".to_string();
        let tampered = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&token).expect("tampered token should encode"));
        parsed.set_path(&format!("/{tampered}/{}", suffix));

        let err = decode_dynamic_capability_ref(parsed.as_str(), &signing_key.verifying_key())
            .expect_err("tampered ref should be rejected");
        assert!(matches!(err, DynamicCapabilityRefError::InvalidSignature));
    }

    #[test]
    fn verify_key_b64_round_trip_preserves_key_material() {
        let signing_key = signing_key_from_seed(generate_dynamic_capability_signing_seed());
        let encoded = verify_key_b64(&signing_key);
        let decoded = verify_key_from_b64(&encoded).expect("verify key should decode");
        assert_eq!(decoded.to_bytes(), signing_key.verifying_key().to_bytes());
    }

    #[test]
    fn held_entry_summary_serialization_keeps_empty_materializations() {
        let summary = HeldEntrySummary {
            held_id: "held_grant_g_abc".to_string(),
            entry_kind: HeldEntryKind::DelegatedGrant,
            grant_id: Some("g_abc".to_string()),
            root_authority_selector: None,
            state: HeldEntryState::Live,
            from_component: Some("components./sender".to_string()),
            descriptor: DescriptorIr {
                kind: "http".to_string(),
                label: "provider.api".to_string(),
                profile: None,
            },
            materializations: Vec::new(),
        };

        let value = serde_json::to_value(&summary).expect("held entry should serialize");
        assert!(
            value
                .get("materializations")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|materializations| materializations.is_empty()),
            "held entry summaries must keep an explicit empty materializations array: {value}",
        );
    }

    #[test]
    fn exact_root_outbound_route_matches_binding_provider_exactly() {
        let routes = [
            outbound_route(
                "component:/provider-a:http:http",
                "upstream",
                "http",
                "/provider-a",
            ),
            outbound_route(
                "component:/provider-b:http:http",
                "upstream",
                "http",
                "/provider-b",
            ),
        ];
        let selector = RootAuthoritySelectorIr::Binding {
            consumer_component_id: "components./consumer".to_string(),
            slot_name: "upstream".to_string(),
            provider_component_id: "components./provider-b".to_string(),
            provider_capability_name: "http".to_string(),
        };

        let route = exact_root_outbound_route(routes.iter(), &selector)
            .expect("binding selector should resolve")
            .expect("binding selector should yield a route");
        assert_eq!(route.peer_id, "/provider-b");
        assert_eq!(route.route_id, "component:/provider-b:http:http");
    }

    #[test]
    fn exact_root_outbound_route_rejects_ambiguous_binding_matches() {
        let routes = [
            outbound_route("route-a", "upstream", "http", "/provider"),
            outbound_route("route-b", "upstream", "http", "/provider"),
        ];
        let selector = RootAuthoritySelectorIr::Binding {
            consumer_component_id: "components./consumer".to_string(),
            slot_name: "upstream".to_string(),
            provider_component_id: "components./provider".to_string(),
            provider_capability_name: "http".to_string(),
        };

        let err = exact_root_outbound_route(routes.iter(), &selector)
            .expect_err("ambiguous binding selector must fail");
        assert_eq!(err, ExactRootRouteError::Ambiguous);
    }
}
