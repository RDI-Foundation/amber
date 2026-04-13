use std::collections::{BTreeMap, BTreeSet, VecDeque};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use super::{planner::*, state::*, *};

pub(crate) const DYNAMIC_CAPABILITY_ROOT_HELD_PREFIX: &str = "held_root_";
pub(crate) const DYNAMIC_CAPABILITY_GRANT_HELD_PREFIX: &str = "held_grant_";
pub(crate) const DYNAMIC_CAPABILITY_GRANT_ID_PREFIX: &str = "g_";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DynamicGrantRecord {
    pub(crate) grant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) parent_grant_id: Option<String>,
    pub(crate) root_authority_selector: RootAuthoritySelectorIr,
    pub(crate) sharer_component_id: String,
    pub(crate) holder_component_id: String,
    pub(crate) descriptor: DescriptorIr,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub(crate) share_options: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) idempotency_key: Option<String>,
    #[serde(default = "dynamic_grant_live_default")]
    pub(crate) live: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) revocation_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DynamicCapabilityJournalEntry {
    pub(crate) generation: u64,
    pub(crate) event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) holder_component_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sharer_component_id: Option<String>,
    pub(crate) root_authority_selector: RootAuthoritySelectorIr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DynamicCapabilitySourceKey {
    RootAuthority(RootAuthoritySelectorIr),
    Grant(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HeldEntryKey {
    RootAuthority(RootAuthoritySelectorIr),
    Grant(String),
}

#[derive(Clone, Debug)]
pub(crate) struct DerivedRootAuthorityRecord {
    pub(crate) selector: RootAuthoritySelectorIr,
    pub(crate) holder_component_id: String,
    pub(crate) descriptor: DescriptorIr,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedDynamicCapabilitySource {
    pub(crate) source_key: DynamicCapabilitySourceKey,
    pub(crate) root_authority_selector: RootAuthoritySelectorIr,
    pub(crate) descriptor: DescriptorIr,
}

#[derive(Clone, Debug)]
pub(crate) enum DynamicCapabilityShareOutcome {
    Created { grant_id: String, r#ref: String },
    Deduplicated { grant_id: String, r#ref: String },
    Noop { reason: String },
}

#[derive(Clone, Debug)]
pub(crate) struct DynamicCapabilityRevokeOutcome {
    // Production code only needs to know whether revocation changed anything; tests assert the
    // exact grant set to keep cascade revocation behavior pinned down.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) revoked_grant_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum DynamicCapabilityControlSourceRequest {
    RootAuthority {
        root_authority_selector: RootAuthoritySelectorIr,
    },
    Grant {
        grant_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ControlDynamicHeldListRequest {
    pub(crate) holder_component_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ControlDynamicHeldDetailRequest {
    pub(crate) holder_component_id: String,
    pub(crate) held_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ControlDynamicShareRequest {
    pub(crate) caller_component_id: String,
    #[serde(flatten)]
    pub(crate) source: DynamicCapabilityControlSourceRequest,
    pub(crate) recipient_component_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub(crate) options: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ControlDynamicInspectRefRequest {
    pub(crate) holder_component_id: String,
    pub(crate) r#ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ControlDynamicRevokeRequest {
    pub(crate) caller_component_id: String,
    #[serde(flatten)]
    pub(crate) target: DynamicCapabilityControlSourceRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DynamicCapabilityAllowedPeer {
    pub(crate) peer_id: String,
    pub(crate) peer_key_b64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PublishDynamicCapabilityOriginRequest {
    pub(crate) overlay_id: String,
    pub(crate) route_id: String,
    pub(crate) root_authority_selector: RootAuthoritySelectorIr,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_peers: Vec<DynamicCapabilityAllowedPeer>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PublishDynamicCapabilityOriginResponse {
    pub(crate) route_id: String,
    pub(crate) capability: String,
    pub(crate) protocol: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ControlDynamicResolveOriginRequest {
    pub(crate) holder_component_id: String,
    #[serde(flatten)]
    pub(crate) source: DynamicCapabilityControlSourceRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct InternalDynamicResolveOriginRequest {
    pub(crate) holder_component_id: String,
    #[serde(flatten)]
    pub(crate) source: DynamicCapabilityControlSourceRequest,
    pub(crate) holder_peer_id: String,
    pub(crate) holder_peer_key_b64: String,
    pub(crate) holder_site_kind: SiteKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ControlDynamicResolveOriginResponse {
    pub(crate) held_id: String,
    pub(crate) descriptor: DescriptorIr,
    pub(crate) origin_route_id: String,
    pub(crate) origin_capability: String,
    pub(crate) origin_protocol: String,
    pub(crate) origin_peer_id: String,
    pub(crate) origin_peer_key_b64: String,
    pub(crate) origin_peer_addr: String,
}

fn dynamic_grant_live_default() -> bool {
    true
}

pub(crate) fn dynamic_capability_scope_supported(kind: &amber_manifest::CapabilityKind) -> bool {
    kind.transport() == CapabilityTransport::Http
}

pub(crate) fn logical_component_id(moniker: &str) -> String {
    format!("components.{moniker}")
}

pub(crate) fn moniker_from_logical_component_id(
    logical_component_id: &str,
) -> std::result::Result<&str, ProtocolErrorResponse> {
    logical_component_id
        .strip_prefix("components.")
        .filter(|moniker| moniker.starts_with('/'))
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::UnknownRecipientIdentity,
                &format!(
                    "logical component identity `{logical_component_id}` must use \
                     `components./...`"
                ),
            )
        })
}

pub(crate) fn descriptor_label(moniker: &str, capability_name: &str) -> String {
    let trimmed = moniker.trim_matches('/');
    if trimmed.is_empty() {
        capability_name.to_string()
    } else {
        format!("{}.{}", trimmed.replace('/', "."), capability_name)
    }
}

pub(crate) fn root_authority_key(selector: &RootAuthoritySelectorIr) -> String {
    URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(selector).expect("root authority selector should serialize"))
}

fn origin_overlay_suffix(
    holder_component_id: &str,
    root_authority_selector: &RootAuthoritySelectorIr,
) -> String {
    URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "holder_component_id": holder_component_id,
            "root_authority_selector": root_authority_selector,
        }))
        .expect("dynamic capability origin overlay key should serialize"),
    )
}

pub(crate) fn origin_overlay_id(
    holder_component_id: &str,
    root_authority_selector: &RootAuthoritySelectorIr,
) -> String {
    format!(
        "dynamic-cap-origin-{}",
        origin_overlay_suffix(holder_component_id, root_authority_selector)
    )
}

pub(crate) fn origin_route_id(
    holder_component_id: &str,
    root_authority_selector: &RootAuthoritySelectorIr,
) -> String {
    format!(
        "dynamic-cap-origin-route-{}",
        origin_overlay_suffix(holder_component_id, root_authority_selector)
    )
}

pub(crate) fn held_id_for_root(selector: &RootAuthoritySelectorIr) -> String {
    format!(
        "{DYNAMIC_CAPABILITY_ROOT_HELD_PREFIX}{}",
        root_authority_key(selector)
    )
}

pub(crate) fn held_id_for_grant(grant_id: &str) -> String {
    format!("{DYNAMIC_CAPABILITY_GRANT_HELD_PREFIX}{grant_id}")
}

pub(crate) fn parse_held_entry_key(
    held_id: &str,
) -> std::result::Result<HeldEntryKey, ProtocolErrorResponse> {
    if let Some(encoded_selector) = held_id.strip_prefix(DYNAMIC_CAPABILITY_ROOT_HELD_PREFIX) {
        let raw = URL_SAFE_NO_PAD
            .decode(encoded_selector.as_bytes())
            .map_err(|err| {
                protocol_error(
                    ProtocolErrorCode::UnknownHandle,
                    &format!("root held id is malformed: {err}"),
                )
            })?;
        let selector = serde_json::from_slice(&raw).map_err(|err| {
            protocol_error(
                ProtocolErrorCode::UnknownHandle,
                &format!("root held id payload is malformed: {err}"),
            )
        })?;
        return Ok(HeldEntryKey::RootAuthority(selector));
    }
    if let Some(grant_id) = held_id.strip_prefix(DYNAMIC_CAPABILITY_GRANT_HELD_PREFIX) {
        return Ok(HeldEntryKey::Grant(grant_id.to_string()));
    }
    Err(protocol_error(
        ProtocolErrorCode::UnknownHandle,
        &format!("held id `{held_id}` is not a dynamic capability handle"),
    ))
}

pub(crate) fn next_dynamic_grant_id(state: &mut FrameworkControlState) -> String {
    let grant_id = format!(
        "{DYNAMIC_CAPABILITY_GRANT_ID_PREFIX}{:016x}",
        state.next_dynamic_capability_grant_id
    );
    state.next_dynamic_capability_grant_id += state.id_stride.max(1);
    grant_id
}

pub(crate) fn live_component_ids(
    state: &FrameworkControlState,
) -> std::result::Result<BTreeSet<String>, ProtocolErrorResponse> {
    Ok(decode_live_scenario(state)?
        .components_iter()
        .filter(|(_, component)| component.program.is_some())
        .map(|(_, component)| logical_component_id(component.moniker.as_str()))
        .collect())
}

pub(crate) fn derive_root_authorities(
    state: &FrameworkControlState,
) -> std::result::Result<BTreeMap<String, DerivedRootAuthorityRecord>, ProtocolErrorResponse> {
    let scenario = decode_live_scenario(state)?;
    let cross_site_links = live_cross_site_link_index(state);
    let mut roots = BTreeMap::new();

    for (_, component) in scenario.components_iter() {
        if component.program.is_none() {
            continue;
        }
        let holder_component_id = logical_component_id(component.moniker.as_str());
        for (provide_name, provide) in &component.provides {
            if !dynamic_capability_scope_supported(&provide.decl.kind) {
                continue;
            }
            let selector = RootAuthoritySelectorIr::SelfProvide {
                component_id: holder_component_id.clone(),
                provide_name: provide_name.clone(),
            };
            roots.insert(
                root_authority_key(&selector),
                DerivedRootAuthorityRecord {
                    selector,
                    holder_component_id: holder_component_id.clone(),
                    descriptor: DescriptorIr {
                        kind: provide.decl.kind.to_string(),
                        profile: provide.decl.profile.clone(),
                        label: descriptor_label(component.moniker.as_str(), provide_name),
                    },
                },
            );
        }
    }

    for binding in &scenario.bindings {
        let consumer = scenario.component(binding.to.component);
        if consumer.program.is_none() {
            continue;
        }
        let Some(slot_decl) = consumer.slots.get(binding.to.name.as_str()) else {
            continue;
        };
        if !dynamic_capability_scope_supported(&slot_decl.decl.kind) {
            continue;
        }
        let consumer_component_id = logical_component_id(consumer.moniker.as_str());
        let Some((selector, label)) = derived_binding_root_selector(
            &scenario,
            binding,
            consumer.moniker.as_str(),
            &cross_site_links,
        ) else {
            continue;
        };
        roots.insert(
            root_authority_key(&selector),
            DerivedRootAuthorityRecord {
                selector,
                holder_component_id: consumer_component_id,
                descriptor: DescriptorIr {
                    kind: slot_decl.decl.kind.to_string(),
                    profile: slot_decl.decl.profile.clone(),
                    label,
                },
            },
        );
    }

    Ok(roots)
}

fn derived_binding_root_selector(
    scenario: &Scenario,
    binding: &amber_scenario::BindingEdge,
    consumer_moniker: &str,
    cross_site_links: &BTreeMap<(String, String, String, String), String>,
) -> Option<(RootAuthoritySelectorIr, String)> {
    match &binding.from {
        BindingFrom::Component(ProvideRef {
            component,
            name: provide_name,
        }) => {
            let provider = scenario.component(*component);
            let consumer_component_id = logical_component_id(consumer_moniker);
            let provider_component_id = logical_component_id(provider.moniker.as_str());
            if let Some(external_slot_name) = cross_site_links.get(&(
                consumer_component_id.clone(),
                binding.to.name.clone(),
                provider_component_id.clone(),
                provide_name.clone(),
            )) {
                return Some((
                    RootAuthoritySelectorIr::ExternalSlotBinding {
                        consumer_component_id,
                        slot_name: binding.to.name.clone(),
                        external_slot_component_id: provider_component_id,
                        external_slot_name: external_slot_name.clone(),
                    },
                    descriptor_label(provider.moniker.as_str(), provide_name),
                ));
            }
            Some((
                RootAuthoritySelectorIr::Binding {
                    consumer_component_id,
                    slot_name: binding.to.name.clone(),
                    provider_component_id,
                    provider_capability_name: provide_name.clone(),
                },
                descriptor_label(provider.moniker.as_str(), provide_name),
            ))
        }
        BindingFrom::External(SlotRef {
            component,
            name: external_slot_name,
        }) => {
            let external_component = scenario.component(*component);
            Some((
                RootAuthoritySelectorIr::ExternalSlotBinding {
                    consumer_component_id: logical_component_id(consumer_moniker),
                    slot_name: binding.to.name.clone(),
                    external_slot_component_id: logical_component_id(
                        external_component.moniker.as_str(),
                    ),
                    external_slot_name: external_slot_name.clone(),
                },
                external_slot_name.clone(),
            ))
        }
        _ => None,
    }
}

fn live_cross_site_link_index(
    state: &FrameworkControlState,
) -> BTreeMap<(String, String, String, String), String> {
    let mut links = state
        .run_links
        .iter()
        .map(|link| {
            (
                (
                    logical_component_id(&link.consumer_component),
                    link.slot.clone(),
                    logical_component_id(&link.provider_component),
                    link.provide.clone(),
                ),
                link.external_slot_name.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for child in visible_child_records(state)
        .filter(|child| super::orchestration::child_link_overlays_are_active(child))
    {
        for link in super::orchestration::child_link_records(child) {
            links
                .entry((
                    logical_component_id(&link.consumer_component),
                    link.slot.clone(),
                    logical_component_id(&link.provider_component),
                    link.provide.clone(),
                ))
                .or_insert(link.external_slot_name.clone());
        }
    }

    links
}

pub(crate) fn grant_record<'a>(
    state: &'a FrameworkControlState,
    grant_id: &str,
) -> std::result::Result<&'a DynamicGrantRecord, ProtocolErrorResponse> {
    state
        .dynamic_capability_grants
        .get(grant_id)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::UnknownRef,
                &format!("dynamic grant `{grant_id}` does not exist"),
            )
        })
}

fn live_grant_children_by_parent(state: &FrameworkControlState) -> BTreeMap<String, Vec<String>> {
    let mut children = BTreeMap::<String, Vec<String>>::new();
    for grant in state.dynamic_capability_grants.values() {
        if !grant.live {
            continue;
        }
        let Some(parent_grant_id) = grant.parent_grant_id.as_ref() else {
            continue;
        };
        children
            .entry(parent_grant_id.clone())
            .or_default()
            .push(grant.grant_id.clone());
    }
    for descendants in children.values_mut() {
        descendants.sort();
    }
    children
}

fn apply_grant_revocations(
    state: &mut FrameworkControlState,
    revoked: BTreeMap<String, String>,
) -> Vec<String> {
    let mut revoked_grant_ids = Vec::new();
    for (grant_id, reason) in revoked {
        let Some(grant) = state.dynamic_capability_grants.get_mut(&grant_id) else {
            continue;
        };
        if !grant.live {
            continue;
        }
        grant.live = false;
        grant.revocation_reason = Some(reason.clone());
        state
            .dynamic_capability_journal
            .push(DynamicCapabilityJournalEntry {
                generation: state.generation,
                event: "grant_revoked".to_string(),
                grant_id: Some(grant_id.clone()),
                holder_component_id: Some(grant.holder_component_id.clone()),
                sharer_component_id: Some(grant.sharer_component_id.clone()),
                root_authority_selector: grant.root_authority_selector.clone(),
                reason: Some(reason),
            });
        revoked_grant_ids.push(grant_id);
    }
    revoked_grant_ids
}

fn expand_grant_revocations_to_subtree(
    state: &FrameworkControlState,
    seed_reasons: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let children_by_parent = live_grant_children_by_parent(state);
    let mut revoked = seed_reasons;
    let mut queue = revoked.keys().cloned().collect::<VecDeque<_>>();

    while let Some(parent_grant_id) = queue.pop_front() {
        let Some(children) = children_by_parent.get(&parent_grant_id) else {
            continue;
        };
        for child_grant_id in children {
            if revoked.contains_key(child_grant_id) {
                continue;
            }
            revoked.insert(child_grant_id.clone(), "ancestor_revoked".to_string());
            queue.push_back(child_grant_id.clone());
        }
    }

    revoked
}

fn grant_snapshot_sort_key(grant: &DynamicGrantRecord) -> (String, String, String, String) {
    (
        root_authority_key(&grant.root_authority_selector),
        grant.holder_component_id.clone(),
        grant.sharer_component_id.clone(),
        grant.grant_id.clone(),
    )
}

fn append_snapshot_subtree(
    grant_id: &str,
    grants_by_id: &BTreeMap<String, DynamicGrantRecord>,
    children_by_parent: &BTreeMap<String, Vec<String>>,
    ordered: &mut Vec<DynamicGrantRecord>,
) {
    let Some(grant) = grants_by_id.get(grant_id) else {
        return;
    };
    ordered.push(grant.clone());
    let Some(children) = children_by_parent.get(grant_id) else {
        return;
    };
    let mut sorted_children = children
        .iter()
        .filter_map(|child_grant_id| grants_by_id.get(child_grant_id))
        .cloned()
        .collect::<Vec<_>>();
    sorted_children.sort_by_key(grant_snapshot_sort_key);
    for child in sorted_children {
        append_snapshot_subtree(&child.grant_id, grants_by_id, children_by_parent, ordered);
    }
}

pub(crate) fn reconcile_dynamic_capability_grants(
    state: &mut FrameworkControlState,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let live_components = live_component_ids(state)?;
    let roots = derive_root_authorities(state)?;
    let mut revoked = BTreeMap::new();

    for grant in state.dynamic_capability_grants.values() {
        if !grant.live {
            continue;
        }
        if !live_components.contains(&grant.holder_component_id) {
            revoked.insert(grant.grant_id.clone(), "holder_unavailable".to_string());
            continue;
        }
        if !roots.contains_key(&root_authority_key(&grant.root_authority_selector)) {
            revoked.insert(grant.grant_id.clone(), "origin_unavailable".to_string());
            continue;
        }
        if let Some(parent_grant_id) = grant.parent_grant_id.as_deref() {
            match state.dynamic_capability_grants.get(parent_grant_id) {
                Some(parent) if parent.live => {}
                _ => {
                    revoked.insert(grant.grant_id.clone(), "ancestor_revoked".to_string());
                }
            }
        }
    }

    apply_grant_revocations(state, expand_grant_revocations_to_subtree(state, revoked));

    Ok(())
}

pub(crate) fn restore_dynamic_capabilities_from_snapshot(
    state: &mut FrameworkControlState,
    snapshot: Option<&DynamicCapabilitiesSnapshotIr>,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    let live_components = live_component_ids(state)?;
    let roots = derive_root_authorities(state)?;
    let mut snapshot_to_live = BTreeMap::<String, String>::new();

    let mut pending = snapshot.grants.clone();
    while !pending.is_empty() {
        let mut deferred = Vec::new();
        let mut restored_any = false;
        for grant in pending {
            if !live_components.contains(&grant.holder_component_id)
                || !live_components.contains(&grant.sharer_component_id)
            {
                continue;
            }
            if !roots.contains_key(&root_authority_key(&grant.root_authority_selector)) {
                continue;
            }
            let parent_grant_id = match grant.parent_snapshot_grant_id.as_deref() {
                Some(parent_snapshot_grant_id) => {
                    match snapshot_to_live.get(parent_snapshot_grant_id) {
                        Some(parent_grant_id) => Some(parent_grant_id.clone()),
                        None => {
                            deferred.push(grant);
                            continue;
                        }
                    }
                }
                None => None,
            };
            let grant_id = next_dynamic_grant_id(state);
            snapshot_to_live.insert(grant.snapshot_grant_id.clone(), grant_id.clone());
            state.dynamic_capability_grants.insert(
                grant_id.clone(),
                DynamicGrantRecord {
                    grant_id: grant_id.clone(),
                    parent_grant_id,
                    root_authority_selector: grant.root_authority_selector.clone(),
                    sharer_component_id: grant.sharer_component_id.clone(),
                    holder_component_id: grant.holder_component_id.clone(),
                    descriptor: grant.descriptor.clone(),
                    share_options: grant.share_options.clone(),
                    idempotency_key: None,
                    live: true,
                    revocation_reason: None,
                },
            );
            state
                .dynamic_capability_journal
                .push(DynamicCapabilityJournalEntry {
                    generation: state.generation,
                    event: "grant_replayed".to_string(),
                    grant_id: Some(grant_id),
                    holder_component_id: Some(grant.holder_component_id.clone()),
                    sharer_component_id: Some(grant.sharer_component_id.clone()),
                    root_authority_selector: grant.root_authority_selector.clone(),
                    reason: None,
                });
            restored_any = true;
        }
        if deferred.is_empty() {
            break;
        }
        if !restored_any {
            let unresolved_parents = deferred
                .iter()
                .filter_map(|grant| {
                    grant
                        .parent_snapshot_grant_id
                        .as_ref()
                        .map(|parent| format!("{} -> {parent}", grant.snapshot_grant_id))
                })
                .collect::<Vec<_>>()
                .join(", ");
            return Err(protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!(
                    "dynamic capability snapshot contains unresolved parent links: \
                     {unresolved_parents}"
                ),
            ));
        }
        pending = deferred;
    }

    Ok(())
}

pub(crate) fn dynamic_capability_snapshot(
    state: &FrameworkControlState,
) -> std::result::Result<DynamicCapabilitiesSnapshotIr, ProtocolErrorResponse> {
    let live_components = live_component_ids(state)?;
    let roots = derive_root_authorities(state)?;
    let grants_by_id = state
        .dynamic_capability_grants
        .values()
        .filter(|grant| grant.live)
        .filter(|grant| live_components.contains(&grant.holder_component_id))
        .filter(|grant| live_components.contains(&grant.sharer_component_id))
        .filter(|grant| roots.contains_key(&root_authority_key(&grant.root_authority_selector)))
        .map(|grant| (grant.grant_id.clone(), grant.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut children_by_parent = BTreeMap::<String, Vec<String>>::new();
    for grant in grants_by_id.values() {
        let Some(parent_grant_id) = grant.parent_grant_id.as_ref() else {
            continue;
        };
        children_by_parent
            .entry(parent_grant_id.clone())
            .or_default()
            .push(grant.grant_id.clone());
    }
    let mut root_grants = grants_by_id
        .values()
        .filter(|grant| {
            grant
                .parent_grant_id
                .as_ref()
                .is_none_or(|parent_grant_id| !grants_by_id.contains_key(parent_grant_id))
        })
        .cloned()
        .collect::<Vec<_>>();
    root_grants.sort_by_key(grant_snapshot_sort_key);
    let mut grants = Vec::with_capacity(grants_by_id.len());
    for root_grant in root_grants {
        append_snapshot_subtree(
            &root_grant.grant_id,
            &grants_by_id,
            &children_by_parent,
            &mut grants,
        );
    }

    Ok(DynamicCapabilitiesSnapshotIr {
        version: amber_mesh::dynamic_caps::DYNAMIC_CAPS_REF_VERSION,
        grants: grants
            .into_iter()
            .map(|grant| GrantSnapshotIr {
                snapshot_grant_id: grant.grant_id,
                parent_snapshot_grant_id: grant.parent_grant_id,
                root_authority_selector: grant.root_authority_selector,
                sharer_component_id: grant.sharer_component_id,
                holder_component_id: grant.holder_component_id,
                descriptor: grant.descriptor,
                share_options: grant.share_options,
            })
            .collect(),
    })
}

pub(crate) fn live_held_entries(
    state: &FrameworkControlState,
    holder_component_id: &str,
) -> std::result::Result<Vec<HeldEntrySummary>, ProtocolErrorResponse> {
    let roots = derive_root_authorities(state)?;
    let mut held = roots
        .values()
        .filter(|root| root.holder_component_id == holder_component_id)
        .map(|root| HeldEntrySummary {
            held_id: held_id_for_root(&root.selector),
            entry_kind: HeldEntryKind::RootAuthority,
            grant_id: None,
            root_authority_selector: Some(root.selector.clone()),
            state: HeldEntryState::Live,
            from_component: None,
            descriptor: root.descriptor.clone(),
            materializations: Vec::new(),
        })
        .collect::<Vec<_>>();
    held.extend(
        state
            .dynamic_capability_grants
            .values()
            .filter(|grant| grant.holder_component_id == holder_component_id)
            .filter(|grant| grant.live)
            .map(|grant| HeldEntrySummary {
                held_id: held_id_for_grant(&grant.grant_id),
                entry_kind: HeldEntryKind::DelegatedGrant,
                grant_id: Some(grant.grant_id.clone()),
                root_authority_selector: None,
                state: HeldEntryState::Live,
                from_component: Some(grant.sharer_component_id.clone()),
                descriptor: grant.descriptor.clone(),
                materializations: Vec::new(),
            }),
    );
    held.sort_by(|left, right| left.held_id.cmp(&right.held_id));
    Ok(held)
}

pub(crate) fn held_entry_detail(
    state: &FrameworkControlState,
    holder_component_id: &str,
    held_id: &str,
) -> std::result::Result<HeldEntryDetail, ProtocolErrorResponse> {
    match parse_held_entry_key(held_id)? {
        HeldEntryKey::RootAuthority(selector) => {
            let roots = derive_root_authorities(state)?;
            let root = roots.get(&root_authority_key(&selector)).ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::UnknownHandle,
                    &format!("root held entry `{held_id}` is not live"),
                )
            })?;
            if root.holder_component_id != holder_component_id {
                return Err(protocol_error(
                    ProtocolErrorCode::UnknownHandle,
                    "root held entry does not belong to the caller",
                ));
            }
            Ok(HeldEntryDetail {
                summary: HeldEntrySummary {
                    held_id: held_id.to_string(),
                    entry_kind: HeldEntryKind::RootAuthority,
                    grant_id: None,
                    root_authority_selector: Some(root.selector.clone()),
                    state: HeldEntryState::Live,
                    from_component: None,
                    descriptor: root.descriptor.clone(),
                    materializations: Vec::new(),
                },
                sharer_component_id: None,
                holder_component_id: Some(root.holder_component_id.clone()),
                revocation_reason: None,
            })
        }
        HeldEntryKey::Grant(grant_id) => {
            let grant = grant_record(state, &grant_id)?;
            if grant.holder_component_id != holder_component_id {
                return Err(protocol_error(
                    ProtocolErrorCode::UnknownHandle,
                    "delegated held entry does not belong to the caller",
                ));
            }
            Ok(HeldEntryDetail {
                summary: HeldEntrySummary {
                    held_id: held_id.to_string(),
                    entry_kind: HeldEntryKind::DelegatedGrant,
                    grant_id: Some(grant.grant_id.clone()),
                    root_authority_selector: None,
                    state: if grant.live {
                        HeldEntryState::Live
                    } else {
                        HeldEntryState::Revoked
                    },
                    from_component: Some(grant.sharer_component_id.clone()),
                    descriptor: grant.descriptor.clone(),
                    materializations: Vec::new(),
                },
                sharer_component_id: Some(grant.sharer_component_id.clone()),
                holder_component_id: Some(grant.holder_component_id.clone()),
                revocation_reason: grant.revocation_reason.clone(),
            })
        }
    }
}

#[cfg(test)]
pub(crate) fn source_key_from_held_id(
    state: &FrameworkControlState,
    holder_component_id: &str,
    held_id: &str,
) -> std::result::Result<DynamicCapabilitySourceKey, ProtocolErrorResponse> {
    match parse_held_entry_key(held_id)? {
        HeldEntryKey::RootAuthority(selector) => {
            let roots = derive_root_authorities(state)?;
            let root = roots.get(&root_authority_key(&selector)).ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::UnknownSource,
                    &format!("root source `{held_id}` is not live"),
                )
            })?;
            if root.holder_component_id != holder_component_id {
                return Err(protocol_error(
                    ProtocolErrorCode::UnknownSource,
                    "root source does not belong to the caller",
                ));
            }
            Ok(DynamicCapabilitySourceKey::RootAuthority(selector))
        }
        HeldEntryKey::Grant(grant_id) => {
            let grant = grant_record(state, &grant_id).map_err(|_| {
                protocol_error(
                    ProtocolErrorCode::UnknownSource,
                    &format!("delegated source `{held_id}` does not exist"),
                )
            })?;
            if grant.holder_component_id != holder_component_id {
                return Err(protocol_error(
                    ProtocolErrorCode::UnknownSource,
                    "delegated source does not belong to the caller",
                ));
            }
            if !grant.live {
                return Err(protocol_error(
                    ProtocolErrorCode::RevokedSource,
                    "delegated source has been revoked",
                ));
            }
            Ok(DynamicCapabilitySourceKey::Grant(grant_id))
        }
    }
}

pub(crate) fn source_key_from_control_request(
    source: &DynamicCapabilityControlSourceRequest,
) -> DynamicCapabilitySourceKey {
    match source {
        DynamicCapabilityControlSourceRequest::RootAuthority {
            root_authority_selector,
        } => DynamicCapabilitySourceKey::RootAuthority(root_authority_selector.clone()),
        DynamicCapabilityControlSourceRequest::Grant { grant_id } => {
            DynamicCapabilitySourceKey::Grant(grant_id.clone())
        }
    }
}

pub(crate) fn resolve_dynamic_share_source(
    state: &FrameworkControlState,
    holder_component_id: &str,
    source_key: &DynamicCapabilitySourceKey,
) -> std::result::Result<ResolvedDynamicCapabilitySource, ProtocolErrorResponse> {
    match source_key {
        DynamicCapabilitySourceKey::RootAuthority(selector) => {
            let roots = derive_root_authorities(state)?;
            let root = roots.get(&root_authority_key(selector)).ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::UnknownSource,
                    "root authority source is not live",
                )
            })?;
            if root.holder_component_id != holder_component_id {
                return Err(protocol_error(
                    ProtocolErrorCode::UnknownSource,
                    "root authority source does not belong to the caller",
                ));
            }
            Ok(ResolvedDynamicCapabilitySource {
                source_key: source_key.clone(),
                root_authority_selector: root.selector.clone(),
                descriptor: root.descriptor.clone(),
            })
        }
        DynamicCapabilitySourceKey::Grant(grant_id) => {
            let grant = grant_record(state, grant_id).map_err(|_| {
                protocol_error(
                    ProtocolErrorCode::UnknownSource,
                    "delegated grant source does not exist",
                )
            })?;
            if grant.holder_component_id != holder_component_id {
                return Err(protocol_error(
                    ProtocolErrorCode::UnknownSource,
                    "delegated grant source does not belong to the caller",
                ));
            }
            if !grant.live {
                return Err(protocol_error(
                    ProtocolErrorCode::RevokedSource,
                    "delegated grant source has been revoked",
                ));
            }
            Ok(ResolvedDynamicCapabilitySource {
                source_key: DynamicCapabilitySourceKey::Grant(grant.grant_id.clone()),
                root_authority_selector: grant.root_authority_selector.clone(),
                descriptor: grant.descriptor.clone(),
            })
        }
    }
}

pub(crate) fn resolve_dynamic_materialization_source(
    state: &FrameworkControlState,
    holder_component_id: &str,
    source_key: &DynamicCapabilitySourceKey,
) -> std::result::Result<ResolvedDynamicCapabilitySource, ProtocolErrorResponse> {
    match source_key {
        DynamicCapabilitySourceKey::RootAuthority(selector) => {
            let roots = derive_root_authorities(state)?;
            let root = roots.get(&root_authority_key(selector)).ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::UnknownHandle,
                    "root authority handle is not live",
                )
            })?;
            if root.holder_component_id != holder_component_id {
                return Err(protocol_error(
                    ProtocolErrorCode::UnknownHandle,
                    "root authority handle does not belong to the caller",
                ));
            }
            Ok(ResolvedDynamicCapabilitySource {
                source_key: source_key.clone(),
                root_authority_selector: root.selector.clone(),
                descriptor: root.descriptor.clone(),
            })
        }
        DynamicCapabilitySourceKey::Grant(grant_id) => {
            let grant = grant_record(state, grant_id).map_err(|_| {
                protocol_error(
                    ProtocolErrorCode::UnknownRef,
                    "dynamic capability ref does not exist",
                )
            })?;
            if grant.holder_component_id != holder_component_id {
                return Err(protocol_error(
                    ProtocolErrorCode::RecipientMismatch,
                    "dynamic capability ref is bound to a different holder",
                ));
            }
            if !grant.live {
                return Err(protocol_error(
                    ProtocolErrorCode::RevokedRef,
                    "dynamic capability ref has been revoked",
                ));
            }
            Ok(ResolvedDynamicCapabilitySource {
                source_key: DynamicCapabilitySourceKey::Grant(grant.grant_id.clone()),
                root_authority_selector: grant.root_authority_selector.clone(),
                descriptor: grant.descriptor.clone(),
            })
        }
    }
}

pub(crate) fn mint_dynamic_capability_ref(
    state: &FrameworkControlState,
    grant: &DynamicGrantRecord,
) -> std::result::Result<String, ProtocolErrorResponse> {
    let signing_key = amber_mesh::dynamic_caps::signing_key_from_seed_b64(
        &state.dynamic_capability_signing_seed_b64,
    )
    .map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("dynamic capability signing key is invalid: {err}"),
        )
    })?;
    amber_mesh::dynamic_caps::build_dynamic_capability_ref_url(
        amber_mesh::dynamic_caps::DynamicCapabilityRefClaims {
            version: amber_mesh::dynamic_caps::DYNAMIC_CAPS_REF_VERSION,
            run_id: state.run_id.clone(),
            grant_id: grant.grant_id.clone(),
            holder_component_id: grant.holder_component_id.clone(),
            descriptor_hint: Some(grant.descriptor.label.clone()),
        },
        &signing_key,
        "/",
        None,
        None,
    )
    .map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("failed to mint dynamic capability ref: {err}"),
        )
    })
}

pub(crate) fn inspect_dynamic_ref(
    state: &FrameworkControlState,
    holder_component_id: &str,
    raw_ref: &str,
) -> std::result::Result<amber_mesh::dynamic_caps::InspectRefResponse, ProtocolErrorResponse> {
    let signing_key = amber_mesh::dynamic_caps::signing_key_from_seed_b64(
        &state.dynamic_capability_signing_seed_b64,
    )
    .map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("dynamic capability signing key is invalid: {err}"),
        )
    })?;
    let parsed = amber_mesh::dynamic_caps::decode_dynamic_capability_ref_unverified(raw_ref)
        .map_err(|err| {
            protocol_error(
                ProtocolErrorCode::MalformedRef,
                &format!("dynamic capability ref is malformed: {err}"),
            )
        })?;
    if parsed.claims.version != amber_mesh::dynamic_caps::DYNAMIC_CAPS_REF_VERSION {
        return Err(protocol_error(
            ProtocolErrorCode::MalformedRef,
            &format!(
                "dynamic capability ref version {} is unsupported",
                parsed.claims.version
            ),
        ));
    }
    if parsed.claims.run_id != state.run_id {
        return Err(protocol_error(
            ProtocolErrorCode::MalformedRef,
            "dynamic capability ref belongs to a different run",
        ));
    }
    if parsed.claims.holder_component_id != holder_component_id {
        return Err(protocol_error(
            ProtocolErrorCode::RecipientMismatch,
            "dynamic capability ref is bound to a different holder",
        ));
    }
    amber_mesh::dynamic_caps::verify_dynamic_capability_ref(&parsed, &signing_key.verifying_key())
        .map_err(|err| {
            protocol_error(
                ProtocolErrorCode::MalformedRef,
                &format!("dynamic capability ref is malformed: {err}"),
            )
        })?;
    let grant = grant_record(state, &parsed.claims.grant_id)?;
    if grant.holder_component_id != holder_component_id {
        return Err(protocol_error(
            ProtocolErrorCode::RecipientMismatch,
            "dynamic capability ref is bound to a different holder",
        ));
    }
    if !grant.live {
        return Err(protocol_error(
            ProtocolErrorCode::RevokedRef,
            "dynamic capability ref has been revoked",
        ));
    }
    Ok(amber_mesh::dynamic_caps::InspectRefResponse {
        state: HeldEntryState::Live,
        grant_id: grant.grant_id.clone(),
        holder_component_id: grant.holder_component_id.clone(),
        descriptor: grant.descriptor.clone(),
        held_id: Some(held_id_for_grant(&grant.grant_id)),
    })
}

pub(crate) fn validate_live_recipient(
    state: &FrameworkControlState,
    recipient_component_id: &str,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let _ = moniker_from_logical_component_id(recipient_component_id)?;
    if !live_component_ids(state)?.contains(recipient_component_id) {
        return Err(protocol_error(
            ProtocolErrorCode::RecipientNotLive,
            &format!("recipient `{recipient_component_id}` is not live"),
        ));
    }
    Ok(())
}

fn source_parent_grant_id(source_key: &DynamicCapabilitySourceKey) -> Option<&str> {
    match source_key {
        DynamicCapabilitySourceKey::RootAuthority(_) => None,
        DynamicCapabilitySourceKey::Grant(grant_id) => Some(grant_id.as_str()),
    }
}

fn recipient_has_ancestor_authority(
    state: &FrameworkControlState,
    roots: &BTreeMap<String, DerivedRootAuthorityRecord>,
    recipient_component_id: &str,
    resolved_source: &ResolvedDynamicCapabilitySource,
) -> bool {
    let root = roots.get(&root_authority_key(
        &resolved_source.root_authority_selector,
    ));
    if let Some(root) = root
        && root.holder_component_id == recipient_component_id
    {
        return true;
    }
    let DynamicCapabilitySourceKey::Grant(mut current_grant_id) =
        resolved_source.source_key.clone()
    else {
        return false;
    };
    loop {
        let Some(current) = state.dynamic_capability_grants.get(&current_grant_id) else {
            return false;
        };
        if current.holder_component_id == recipient_component_id {
            return true;
        }
        let Some(parent) = current.parent_grant_id.clone() else {
            return false;
        };
        current_grant_id = parent;
    }
}

fn matching_idempotent_grant<'a>(
    state: &'a FrameworkControlState,
    caller_component_id: &str,
    recipient_component_id: &str,
    resolved_source: &ResolvedDynamicCapabilitySource,
    idempotency_key: &str,
    options: &serde_json::Value,
) -> Option<&'a DynamicGrantRecord> {
    state.dynamic_capability_grants.values().find(|grant| {
        grant.live
            && grant.sharer_component_id == caller_component_id
            && grant.holder_component_id == recipient_component_id
            && grant.root_authority_selector == resolved_source.root_authority_selector
            && grant.parent_grant_id.as_deref()
                == source_parent_grant_id(&resolved_source.source_key)
            && grant.descriptor == resolved_source.descriptor
            && grant.share_options == *options
            && grant.idempotency_key.as_deref() == Some(idempotency_key)
    })
}

fn conflicting_idempotent_grant<'a>(
    state: &'a FrameworkControlState,
    caller_component_id: &str,
    resolved_source: &ResolvedDynamicCapabilitySource,
    idempotency_key: &str,
) -> Option<&'a DynamicGrantRecord> {
    state.dynamic_capability_grants.values().find(|grant| {
        grant.live
            && grant.sharer_component_id == caller_component_id
            && grant.root_authority_selector == resolved_source.root_authority_selector
            && grant.parent_grant_id.as_deref()
                == source_parent_grant_id(&resolved_source.source_key)
            && grant.idempotency_key.as_deref() == Some(idempotency_key)
    })
}

pub(crate) fn share_dynamic_capability(
    state: &mut FrameworkControlState,
    caller_component_id: &str,
    source_key: &DynamicCapabilitySourceKey,
    recipient_component_id: &str,
    idempotency_key: Option<&str>,
    options: &serde_json::Value,
) -> std::result::Result<DynamicCapabilityShareOutcome, ProtocolErrorResponse> {
    let resolved_source = resolve_dynamic_share_source(state, caller_component_id, source_key)?;
    validate_live_recipient(state, recipient_component_id)?;

    if caller_component_id == recipient_component_id {
        return Ok(DynamicCapabilityShareOutcome::Noop {
            reason: "recipient_already_has_authority".to_string(),
        });
    }

    let roots = derive_root_authorities(state)?;
    if recipient_has_ancestor_authority(state, &roots, recipient_component_id, &resolved_source) {
        return Ok(DynamicCapabilityShareOutcome::Noop {
            reason: "recipient_already_has_authority".to_string(),
        });
    }

    if let Some(idempotency_key) = idempotency_key
        && let Some(existing) = matching_idempotent_grant(
            state,
            caller_component_id,
            recipient_component_id,
            &resolved_source,
            idempotency_key,
            options,
        )
    {
        return Ok(DynamicCapabilityShareOutcome::Deduplicated {
            grant_id: existing.grant_id.clone(),
            r#ref: mint_dynamic_capability_ref(state, existing)?,
        });
    }
    if let Some(idempotency_key) = idempotency_key
        && let Some(conflict) = conflicting_idempotent_grant(
            state,
            caller_component_id,
            &resolved_source,
            idempotency_key,
        )
    {
        return Err(protocol_error(
            ProtocolErrorCode::IdempotencyConflict,
            &format!(
                "idempotency key `{idempotency_key}` already names live grant `{}` with different \
                 share semantics",
                conflict.grant_id
            ),
        ));
    }

    let grant_id = next_dynamic_grant_id(state);
    let grant = DynamicGrantRecord {
        grant_id: grant_id.clone(),
        parent_grant_id: source_parent_grant_id(&resolved_source.source_key).map(str::to_string),
        root_authority_selector: resolved_source.root_authority_selector.clone(),
        sharer_component_id: caller_component_id.to_string(),
        holder_component_id: recipient_component_id.to_string(),
        descriptor: resolved_source.descriptor.clone(),
        share_options: options.clone(),
        idempotency_key: idempotency_key.map(str::to_string),
        live: true,
        revocation_reason: None,
    };
    let dynamic_ref = mint_dynamic_capability_ref(state, &grant)?;
    state
        .dynamic_capability_grants
        .insert(grant_id.clone(), grant.clone());
    state
        .dynamic_capability_journal
        .push(DynamicCapabilityJournalEntry {
            generation: state.generation,
            event: "share_committed".to_string(),
            grant_id: Some(grant_id.clone()),
            holder_component_id: Some(recipient_component_id.to_string()),
            sharer_component_id: Some(caller_component_id.to_string()),
            root_authority_selector: grant.root_authority_selector,
            reason: None,
        });
    Ok(DynamicCapabilityShareOutcome::Created {
        grant_id,
        r#ref: dynamic_ref,
    })
}

fn caller_has_revoke_authority(
    state: &FrameworkControlState,
    roots: &BTreeMap<String, DerivedRootAuthorityRecord>,
    caller_component_id: &str,
    grant: &DynamicGrantRecord,
) -> bool {
    if grant.holder_component_id == caller_component_id {
        return true;
    }
    if roots
        .get(&root_authority_key(&grant.root_authority_selector))
        .is_some_and(|root| root.holder_component_id == caller_component_id)
    {
        return true;
    }
    let mut current = grant.parent_grant_id.as_deref();
    while let Some(parent_grant_id) = current {
        let Some(parent) = state.dynamic_capability_grants.get(parent_grant_id) else {
            return false;
        };
        if parent.holder_component_id == caller_component_id {
            return true;
        }
        current = parent.parent_grant_id.as_deref();
    }
    false
}

pub(crate) fn revoke_dynamic_capability(
    state: &mut FrameworkControlState,
    caller_component_id: &str,
    target: &DynamicCapabilitySourceKey,
) -> std::result::Result<DynamicCapabilityRevokeOutcome, ProtocolErrorResponse> {
    let roots = derive_root_authorities(state)?;
    let mut seed_reasons = BTreeMap::new();

    match target {
        DynamicCapabilitySourceKey::RootAuthority(selector) => {
            let root = roots.get(&root_authority_key(selector)).ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::UnknownHandle,
                    "root authority revoke target is not live",
                )
            })?;
            if root.holder_component_id != caller_component_id {
                return Err(protocol_error(
                    ProtocolErrorCode::CallerLacksAuthority,
                    "caller does not hold the root authority it tried to revoke",
                ));
            }
            for grant in state.dynamic_capability_grants.values() {
                if grant.live && grant.root_authority_selector == *selector {
                    seed_reasons.insert(grant.grant_id.clone(), "ancestor_revoked".to_string());
                }
            }
        }
        DynamicCapabilitySourceKey::Grant(grant_id) => {
            let grant = grant_record(state, grant_id)?;
            if !grant.live {
                return Err(protocol_error(
                    ProtocolErrorCode::AlreadyRevoked,
                    "dynamic capability grant has already been revoked",
                ));
            }
            if !caller_has_revoke_authority(state, &roots, caller_component_id, grant) {
                return Err(protocol_error(
                    ProtocolErrorCode::CallerLacksAuthority,
                    "caller does not have authority to revoke that grant",
                ));
            }
            seed_reasons.insert(
                grant_id.clone(),
                if grant.holder_component_id == caller_component_id {
                    "self_revoked".to_string()
                } else {
                    "ancestor_revoked".to_string()
                },
            );
        }
    }

    let revoked_grant_ids = apply_grant_revocations(
        state,
        expand_grant_revocations_to_subtree(state, seed_reasons),
    );
    if revoked_grant_ids.is_empty() {
        return Err(protocol_error(
            ProtocolErrorCode::AlreadyRevoked,
            "dynamic capability revoke target is already fully revoked",
        ));
    }

    Ok(DynamicCapabilityRevokeOutcome { revoked_grant_ids })
}
