use base64::Engine as _;

use super::{
    dynamic_caps,
    orchestration::{
        ProtocolApiError, load_site_manager_state, local_router_identity_for_overlay,
        publish_dynamic_capability_origin,
    },
    planner::{ControlStateApp, live_assignment_map, protocol_error},
    state::{FrameworkControlState, persist_control_state_update},
    *,
};

pub(crate) enum DynamicCapsInspectRequest {
    HeldList(dynamic_caps::ControlDynamicHeldListRequest),
    HeldDetail(dynamic_caps::ControlDynamicHeldDetailRequest),
    InspectRef(dynamic_caps::ControlDynamicInspectRefRequest),
    ResolveOrigin(dynamic_caps::ControlDynamicResolveOriginRequest),
}

pub(crate) enum DynamicCapsInspectResponse {
    HeldList(amber_mesh::dynamic_caps::HeldListResponse),
    HeldDetail(HeldEntryDetail),
    InspectRef(amber_mesh::dynamic_caps::InspectRefResponse),
    ResolveOrigin(dynamic_caps::ControlDynamicResolveOriginResponse),
}

pub(crate) enum DynamicCapsMutateRequest {
    Share(dynamic_caps::ControlDynamicShareRequest),
    Revoke(dynamic_caps::ControlDynamicRevokeRequest),
}

pub(crate) enum DynamicCapsMutateResponse {
    Share(amber_mesh::dynamic_caps::ShareResponse),
    Revoke(amber_mesh::dynamic_caps::RevokeResponse),
}

pub(crate) async fn execute_dynamic_caps_inspect(
    app: &ControlStateApp,
    request: DynamicCapsInspectRequest,
) -> std::result::Result<DynamicCapsInspectResponse, ProtocolApiError> {
    Ok(match request {
        DynamicCapsInspectRequest::HeldList(request) => {
            let held = {
                let state = app.control_state.lock().await;
                dynamic_caps::live_held_entries(&state, &request.holder_component_id)?
            };
            DynamicCapsInspectResponse::HeldList(amber_mesh::dynamic_caps::HeldListResponse {
                held,
            })
        }
        DynamicCapsInspectRequest::HeldDetail(request) => {
            let detail = {
                let state = app.control_state.lock().await;
                dynamic_caps::held_entry_detail(
                    &state,
                    &request.holder_component_id,
                    &request.held_id,
                )?
            };
            DynamicCapsInspectResponse::HeldDetail(detail)
        }
        DynamicCapsInspectRequest::InspectRef(request) => {
            let response = {
                let state = app.control_state.lock().await;
                dynamic_caps::inspect_dynamic_ref(
                    &state,
                    &request.holder_component_id,
                    &request.r#ref,
                )?
            };
            DynamicCapsInspectResponse::InspectRef(response)
        }
        DynamicCapsInspectRequest::ResolveOrigin(request) => {
            DynamicCapsInspectResponse::ResolveOrigin(
                resolve_dynamic_capability_origin(app, request).await?,
            )
        }
    })
}

pub(crate) async fn execute_dynamic_caps_mutate(
    app: &ControlStateApp,
    request: DynamicCapsMutateRequest,
) -> std::result::Result<DynamicCapsMutateResponse, ProtocolApiError> {
    Ok(match request {
        DynamicCapsMutateRequest::Share(request) => {
            let response = {
                let mut state = app.control_state.lock().await;
                persist_control_state_update(
                    &mut state,
                    &app.state_path,
                    "dynamic capability share",
                    |state| {
                        let outcome = dynamic_caps::share_dynamic_capability(
                            state,
                            &request.caller_component_id,
                            &dynamic_caps::source_key_from_control_request(&request.source),
                            &request.recipient_component_id,
                            request.idempotency_key.as_deref(),
                            &request.options,
                        )?;
                        Ok(match outcome {
                            dynamic_caps::DynamicCapabilityShareOutcome::Created {
                                grant_id,
                                r#ref,
                            } => amber_mesh::dynamic_caps::ShareResponse {
                                outcome: "created".to_string(),
                                reason: None,
                                grant_id: Some(grant_id),
                                r#ref: Some(r#ref),
                            },
                            dynamic_caps::DynamicCapabilityShareOutcome::Deduplicated {
                                grant_id,
                                r#ref,
                            } => amber_mesh::dynamic_caps::ShareResponse {
                                outcome: "deduplicated".to_string(),
                                reason: None,
                                grant_id: Some(grant_id),
                                r#ref: Some(r#ref),
                            },
                            dynamic_caps::DynamicCapabilityShareOutcome::Noop { reason } => {
                                amber_mesh::dynamic_caps::ShareResponse {
                                    outcome: "noop".to_string(),
                                    reason: Some(reason),
                                    grant_id: None,
                                    r#ref: None,
                                }
                            }
                        })
                    },
                )?
            };
            DynamicCapsMutateResponse::Share(response)
        }
        DynamicCapsMutateRequest::Revoke(request) => {
            {
                let mut state = app.control_state.lock().await;
                persist_control_state_update(
                    &mut state,
                    &app.state_path,
                    "dynamic capability revoke",
                    |state| {
                        dynamic_caps::revoke_dynamic_capability(
                            state,
                            &request.caller_component_id,
                            &dynamic_caps::source_key_from_control_request(&request.target),
                        )?;
                        Ok(())
                    },
                )?;
            }
            DynamicCapsMutateResponse::Revoke(amber_mesh::dynamic_caps::RevokeResponse {
                outcome: "revoked".to_string(),
            })
        }
    })
}

pub(crate) fn local_component_runtime(
    app: &ControlStateApp,
    state: &FrameworkControlState,
    logical_component_id: &str,
) -> std::result::Result<LiveComponentRuntimeMetadata, ProtocolErrorResponse> {
    let moniker = dynamic_caps::moniker_from_logical_component_id(logical_component_id)?;
    let assignments = live_assignment_map(state);
    let site_id = assignments.get(moniker).ok_or_else(|| {
        protocol_error(
            ProtocolErrorCode::OriginUnavailable,
            &format!("live component `{logical_component_id}` is not assigned to a live site"),
        )
    })?;
    if site_id != &app.controller_plan.site_id {
        return Err(protocol_error(
            ProtocolErrorCode::OriginUnavailable,
            &format!(
                "live component `{logical_component_id}` is assigned to site `{site_id}`, not \
                 local site `{}`",
                app.controller_plan.site_id
            ),
        ));
    }
    let site_plan = site_controller_runtime_plan_from_controller_plan(&app.controller_plan);
    app.runtime
        .collect_live_component_runtime_metadata(&site_plan)
        .map_err(|err| {
            protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "failed to resolve live runtime metadata for component \
                     `{logical_component_id}` on site `{site_id}`: {err}"
                ),
            )
        })?
        .remove(moniker)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "live runtime metadata for component `{logical_component_id}` is unavailable \
                     on site `{site_id}`"
                ),
            )
        })
}

pub(crate) async fn resolve_dynamic_capability_origin_internal(
    app: &ControlStateApp,
    request: dynamic_caps::InternalDynamicResolveOriginRequest,
) -> std::result::Result<dynamic_caps::ControlDynamicResolveOriginResponse, ProtocolApiError> {
    let state = app.control_state.lock().await.clone();
    let source_key = dynamic_caps::source_key_from_control_request(&request.source);
    let resolved_source = dynamic_caps::resolve_dynamic_materialization_source(
        &state,
        &request.holder_component_id,
        &source_key,
    )?;
    let roots = dynamic_caps::derive_root_authorities(&state)?;
    let root = roots
        .get(&dynamic_caps::root_authority_key(
            &resolved_source.root_authority_selector,
        ))
        .ok_or_else(|| {
            ProtocolApiError::from(protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                "dynamic capability root authority is no longer live",
            ))
        })?;
    let _origin_runtime = local_component_runtime(app, &state, &root.holder_component_id)?;
    let origin_manager_state = load_site_manager_state(app, &app.controller_plan.site_id)?;
    let origin_peer = local_router_identity_for_overlay(app).await?;
    let origin_peer_addr = origin_manager_state
        .router_mesh_addr
        .as_deref()
        .ok_or_else(|| {
            ProtocolApiError::from(protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "site `{}` does not expose a live router mesh address for dynamic capability \
                     publication",
                    app.controller_plan.site_id
                ),
            ))
        })
        .and_then(|router_mesh_addr| {
            app.runtime
                .router_mesh_addr_for_consumer(
                    app.controller_plan.kind,
                    request.holder_site_kind,
                    router_mesh_addr,
                )
                .map_err(|err| {
                    ProtocolApiError::from(protocol_error(
                        ProtocolErrorCode::OriginUnavailable,
                        &format!(
                            "site `{}` exposes an invalid live router mesh address for dynamic \
                             capability publication: {err}",
                            app.controller_plan.site_id
                        ),
                    ))
                })
        })?;
    let overlay_id = dynamic_caps::origin_overlay_id(
        &request.holder_component_id,
        &resolved_source.root_authority_selector,
    );
    let route_id = dynamic_caps::origin_route_id(
        &request.holder_component_id,
        &resolved_source.root_authority_selector,
    );
    let publish = publish_dynamic_capability_origin(
        app,
        &app.controller_plan.site_id,
        &dynamic_caps::PublishDynamicCapabilityOriginRequest {
            overlay_id,
            route_id: route_id.clone(),
            root_authority_selector: resolved_source.root_authority_selector.clone(),
            allowed_peers: vec![dynamic_caps::DynamicCapabilityAllowedPeer {
                peer_id: request.holder_peer_id.clone(),
                peer_key_b64: request.holder_peer_key_b64.clone(),
            }],
        },
    )
    .await?;
    let held_id = match &source_key {
        dynamic_caps::DynamicCapabilitySourceKey::RootAuthority(selector) => {
            dynamic_caps::held_id_for_root(selector)
        }
        dynamic_caps::DynamicCapabilitySourceKey::Grant(grant_id) => {
            dynamic_caps::held_id_for_grant(grant_id)
        }
    };
    Ok(dynamic_caps::ControlDynamicResolveOriginResponse {
        held_id,
        descriptor: resolved_source.descriptor,
        origin_route_id: publish.route_id,
        origin_capability: publish.capability,
        origin_protocol: publish.protocol,
        origin_peer_id: origin_peer.id,
        origin_peer_key_b64: base64::engine::general_purpose::STANDARD
            .encode(origin_peer.public_key),
        origin_peer_addr,
    })
}

async fn resolve_dynamic_capability_origin(
    app: &ControlStateApp,
    request: dynamic_caps::ControlDynamicResolveOriginRequest,
) -> std::result::Result<dynamic_caps::ControlDynamicResolveOriginResponse, ProtocolApiError> {
    let holder_runtime = {
        let state = app.control_state.lock().await.clone();
        local_component_runtime(app, &state, &request.holder_component_id)?
    };
    resolve_dynamic_capability_origin_internal(
        app,
        dynamic_caps::InternalDynamicResolveOriginRequest {
            holder_component_id: request.holder_component_id,
            source: request.source,
            holder_peer_id: holder_runtime.mesh_config.identity.id.clone(),
            holder_peer_key_b64: base64::engine::general_purpose::STANDARD
                .encode(holder_runtime.mesh_config.identity.public_key),
            holder_site_kind: app.controller_plan.kind,
        },
    )
    .await
}
