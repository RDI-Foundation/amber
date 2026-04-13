use std::{collections::BTreeMap, sync::Arc};

use amber_mesh::{
    MeshProtocol,
    component_protocol::{ProtocolErrorCode, ProtocolErrorResponse},
    dynamic_caps::{
        self as mesh_dynamic_caps, DescriptorIr, HeldEntryDetail, HeldEntryKind, HeldEntryState,
        HeldEvent, HeldListResponse, InspectHandleRequest, InspectHandleResponse,
        InspectRefRequest, InspectRefResponse, MaterializeRequest, MaterializeResponse,
        MaterializedHandleSummary, RevokeRequest, RevokeResponse, RootAuthoritySelectorIr,
        ShareRequest, ShareResponse, ShareSource,
    },
    telemetry::SCENARIO_RUN_ID_ENV,
};
use base64::Engine as _;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use serde::{Serialize, de::DeserializeOwned};
use tokio::time::{Duration, MissedTickBehavior, interval};

use super::*;

const DYNAMIC_CAPS_CONTROLLER_HELD_LIST_PATH: &str = "/v1/controller/dynamic-caps/held";
const DYNAMIC_CAPS_CONTROLLER_HELD_DETAIL_PATH: &str = "/v1/controller/dynamic-caps/held/detail";
const DYNAMIC_CAPS_CONTROLLER_SHARE_PATH: &str = "/v1/controller/dynamic-caps/share";
const DYNAMIC_CAPS_CONTROLLER_INSPECT_REF_PATH: &str = "/v1/controller/dynamic-caps/inspect-ref";
const DYNAMIC_CAPS_CONTROLLER_REVOKE_PATH: &str = "/v1/controller/dynamic-caps/revoke";
const DYNAMIC_CAPS_CONTROLLER_RESOLVE_ORIGIN_PATH: &str =
    "/v1/controller/dynamic-caps/resolve-origin";
const DYNAMIC_CAPS_HANDLE_PREFIX: &str = "/v1/handles/";
const DYNAMIC_CAPS_HANDLE_ID_PREFIX: &str = "hdl_";
const DYNAMIC_CAPS_WATCH_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug)]
struct DynamicCapsControllerEnv {
    control_url: String,
    control_auth_token: String,
    verify_key_raw: String,
    run_id: String,
}

#[derive(Clone, Debug, Serialize)]
struct ControlDynamicHeldListRequest {
    holder_component_id: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DynamicCapabilityControlSourceRequest {
    RootAuthority {
        root_authority_selector: RootAuthoritySelectorIr,
    },
    Grant {
        grant_id: String,
    },
}

#[derive(Clone, Debug, Serialize)]
struct ControlDynamicHeldDetailRequest {
    holder_component_id: String,
    held_id: String,
}

#[derive(Clone, Debug, Serialize)]
struct ControlDynamicShareRequest {
    caller_component_id: String,
    #[serde(flatten)]
    source: DynamicCapabilityControlSourceRequest,
    recipient_component_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    options: serde_json::Value,
}

#[derive(Clone, Debug, Serialize)]
struct ControlDynamicInspectRefRequest {
    holder_component_id: String,
    r#ref: String,
}

#[derive(Clone, Debug, Serialize)]
struct ControlDynamicRevokeRequest {
    caller_component_id: String,
    #[serde(flatten)]
    target: DynamicCapabilityControlSourceRequest,
}

#[derive(Clone, Debug, Serialize)]
struct ControlDynamicResolveOriginRequest {
    holder_component_id: String,
    #[serde(flatten)]
    source: DynamicCapabilityControlSourceRequest,
}

#[derive(Clone, Debug, Deserialize)]
struct ControlDynamicResolveOriginResponse {
    held_id: String,
    descriptor: DescriptorIr,
    origin_route_id: String,
    origin_capability: String,
    origin_protocol: String,
    origin_peer_id: String,
    origin_peer_key_b64: String,
    origin_peer_addr: String,
}

#[derive(Clone)]
pub(super) struct DynamicCapsRuntime {
    listen_addr: SocketAddr,
    component_id: Arc<str>,
    run_id: Arc<str>,
    control_url: Arc<str>,
    control_auth_token: Arc<str>,
    verify_key: ed25519_dalek::VerifyingKey,
    config: Arc<MeshConfig>,
    client: Arc<HttpClient>,
    a2a_url_rewrite_table: Arc<a2a::UrlRewriteTable>,
    handles: Arc<Mutex<DynamicCapsLocalState>>,
}

#[derive(Default)]
struct DynamicCapsLocalState {
    next_handle_id: u64,
    handles_by_id: BTreeMap<String, DynamicHandleRecord>,
    handle_id_by_held_id: BTreeMap<String, String>,
}

struct DynamicHandleRecord {
    handle_id: String,
    held_id: String,
    descriptor: DescriptorIr,
    upstream: Option<DynamicHandleUpstream>,
}

#[derive(Clone)]
struct DynamicHandleUpstream {
    route_id: Arc<str>,
    sender: Arc<Mutex<client_http1::SendRequest<BoxBody>>>,
    _tasks: Arc<DynamicHandleUpstreamTasks>,
}

struct DynamicHandleUpstreamTasks {
    conn_task: tokio::task::JoinHandle<()>,
    bridge_task: tokio::task::JoinHandle<Result<(), RouterError>>,
}

struct DynamicHandleProxyRoute {
    handle_id: String,
    forwarded_path: String,
}

#[derive(Clone)]
struct StaticRootHandleMatch {
    held_id: String,
    source: DynamicCapabilityControlSourceRequest,
}

#[derive(Default)]
struct HeldWatchSnapshot {
    held: BTreeMap<String, HeldEntryDetail>,
    materializations: BTreeMap<String, Vec<MaterializedHandleSummary>>,
}

impl DynamicHandleUpstream {
    fn is_alive(&self) -> bool {
        !self._tasks.conn_task.is_finished() && !self._tasks.bridge_task.is_finished()
    }
}

impl Drop for DynamicHandleUpstreamTasks {
    fn drop(&mut self) {
        self.conn_task.abort();
        self.bridge_task.abort();
    }
}

impl DynamicCapsRuntime {
    pub(super) fn build(
        config: Arc<MeshConfig>,
        client: Arc<HttpClient>,
        a2a_url_rewrite_table: Arc<a2a::UrlRewriteTable>,
    ) -> Result<Option<Arc<Self>>, RouterError> {
        let Some(listen_addr) = config.dynamic_caps_listen else {
            return Ok(None);
        };
        let Some(control_env) = resolve_dynamic_caps_controller_env()? else {
            tracing::warn!(
                target: "amber.internal",
                component_id = %config.identity.id,
                %listen_addr,
                "dynamic capabilities disabled because control env is not configured"
            );
            return Ok(None);
        };
        let verify_key = mesh_dynamic_caps::verify_key_from_b64(&control_env.verify_key_raw)
            .map_err(|err| RouterError::InvalidConfig(err.to_string()))?;
        Ok(Some(Arc::new(Self {
            listen_addr,
            component_id: Arc::<str>::from(format!("components.{}", config.identity.id)),
            run_id: Arc::<str>::from(control_env.run_id),
            control_url: Arc::<str>::from(control_env.control_url),
            control_auth_token: Arc::<str>::from(control_env.control_auth_token),
            verify_key,
            config,
            client,
            a2a_url_rewrite_table,
            handles: Arc::new(Mutex::new(DynamicCapsLocalState::default())),
        })))
    }

    fn local_api_base_url(&self) -> Result<Url, ProtocolErrorResponse> {
        Url::parse(&format!("http://127.0.0.1:{}", self.listen_addr.port())).map_err(|err| {
            self.protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                format!("dynamic capability listen address is invalid: {err}"),
            )
        })
    }

    fn protocol_error(
        &self,
        code: ProtocolErrorCode,
        message: impl Into<String>,
    ) -> ProtocolErrorResponse {
        ProtocolErrorResponse {
            code,
            message: message.into(),
            details: None,
        }
    }

    async fn control_post_json<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Resp, ProtocolErrorResponse> {
        let url = format!("{}{}", self.control_url.trim_end_matches('/'), path);
        let request_body = serde_json::to_vec(body).map_err(|err| {
            self.protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                format!("failed to serialize dynamic capability control request: {err}"),
            )
        })?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                AMBER_FRAMEWORK_AUTH_HEADER,
                self.control_auth_token.as_ref(),
            )
            .body(
                Full::new(Bytes::from(request_body))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|err| {
                self.protocol_error(
                    ProtocolErrorCode::ControlStateUnavailable,
                    format!("failed to build dynamic capability control request: {err}"),
                )
            })?;
        let response = self.client.request(request).await.map_err(|err| {
            self.protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                format!("failed to reach authoritative dynamic capability control service: {err}"),
            )
        })?;
        let status = response.status();
        let body = response.into_body().collect().await.map_err(|err| {
            self.protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                format!("failed to read dynamic capability control response: {err}"),
            )
        })?;
        let bytes = body.to_bytes();
        if status.is_success() {
            return serde_json::from_slice(&bytes).map_err(|err| {
                self.protocol_error(
                    ProtocolErrorCode::ControlStateUnavailable,
                    format!("dynamic capability control service returned invalid JSON: {err}"),
                )
            });
        }
        if let Ok(protocol_error) = serde_json::from_slice::<ProtocolErrorResponse>(&bytes) {
            return Err(protocol_error);
        }
        Err(self.protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            format!("dynamic capability control service returned {status}"),
        ))
    }

    async fn control_held_list(&self) -> Result<HeldListResponse, ProtocolErrorResponse> {
        self.control_post_json(
            DYNAMIC_CAPS_CONTROLLER_HELD_LIST_PATH,
            &ControlDynamicHeldListRequest {
                holder_component_id: self.component_id.to_string(),
            },
        )
        .await
    }

    async fn control_held_detail(
        &self,
        held_id: &str,
    ) -> Result<HeldEntryDetail, ProtocolErrorResponse> {
        self.control_post_json(
            DYNAMIC_CAPS_CONTROLLER_HELD_DETAIL_PATH,
            &ControlDynamicHeldDetailRequest {
                holder_component_id: self.component_id.to_string(),
                held_id: held_id.to_string(),
            },
        )
        .await
    }

    async fn control_resolve_origin(
        &self,
        source: DynamicCapabilityControlSourceRequest,
    ) -> Result<ControlDynamicResolveOriginResponse, ProtocolErrorResponse> {
        self.control_post_json(
            DYNAMIC_CAPS_CONTROLLER_RESOLVE_ORIGIN_PATH,
            &ControlDynamicResolveOriginRequest {
                holder_component_id: self.component_id.to_string(),
                source,
            },
        )
        .await
    }

    fn next_handle_id(state: &mut DynamicCapsLocalState) -> String {
        let handle_id = format!(
            "{DYNAMIC_CAPS_HANDLE_ID_PREFIX}{:016x}",
            state.next_handle_id
        );
        state.next_handle_id += 1;
        handle_id
    }

    fn materialized_handle_url(
        &self,
        handle_id: &str,
        relative_path: &str,
        query: Option<&str>,
        fragment: Option<&str>,
    ) -> Result<String, ProtocolErrorResponse> {
        let mut url = self.local_api_base_url()?;
        url.set_path(&join_paths(
            &format!("{DYNAMIC_CAPS_HANDLE_PREFIX}{handle_id}"),
            relative_path,
        ));
        url.set_query(query);
        url.set_fragment(fragment);
        Ok(url.to_string())
    }

    fn parse_ref_for_local_holder(
        &self,
        raw_ref: &str,
    ) -> Result<mesh_dynamic_caps::ParsedDynamicCapabilityRef, ProtocolErrorResponse> {
        let parsed = mesh_dynamic_caps::decode_dynamic_capability_ref_unverified(raw_ref)
            .map_err(|err| self.protocol_error(ProtocolErrorCode::MalformedRef, err.to_string()))?;
        if parsed.claims.version != mesh_dynamic_caps::DYNAMIC_CAPS_REF_VERSION {
            return Err(self.protocol_error(
                ProtocolErrorCode::MalformedRef,
                format!(
                    "dynamic capability ref version {} is unsupported",
                    parsed.claims.version
                ),
            ));
        }
        if parsed.claims.run_id != self.run_id.as_ref() {
            return Err(self.protocol_error(
                ProtocolErrorCode::MalformedRef,
                "dynamic capability ref belongs to a different run",
            ));
        }
        if parsed.claims.holder_component_id != self.component_id.as_ref() {
            return Err(self.protocol_error(
                ProtocolErrorCode::RecipientMismatch,
                "dynamic capability ref is bound to a different holder",
            ));
        }
        mesh_dynamic_caps::verify_dynamic_capability_ref(&parsed, &self.verify_key)
            .map_err(|err| self.protocol_error(ProtocolErrorCode::MalformedRef, err.to_string()))?;
        Ok(parsed)
    }

    fn source_from_held_detail(
        &self,
        detail: &HeldEntryDetail,
    ) -> Result<DynamicCapabilityControlSourceRequest, ProtocolErrorResponse> {
        match detail.summary.entry_kind {
            HeldEntryKind::DelegatedGrant => detail
                .summary
                .grant_id
                .as_ref()
                .map(|grant_id| DynamicCapabilityControlSourceRequest::Grant {
                    grant_id: grant_id.clone(),
                })
                .ok_or_else(|| {
                    self.protocol_error(
                        ProtocolErrorCode::UnknownHandle,
                        "delegated grant held entry is missing its grant id",
                    )
                }),
            HeldEntryKind::RootAuthority => detail
                .summary
                .root_authority_selector
                .as_ref()
                .map(
                    |selector| DynamicCapabilityControlSourceRequest::RootAuthority {
                        root_authority_selector: selector.clone(),
                    },
                )
                .ok_or_else(|| {
                    self.protocol_error(
                        ProtocolErrorCode::UnknownHandle,
                        "root held entry is missing its root authority selector",
                    )
                }),
        }
    }

    fn root_static_handle_url(
        &self,
        selector: &RootAuthoritySelectorIr,
    ) -> Result<Option<String>, ProtocolErrorResponse> {
        let route = match mesh_dynamic_caps::exact_root_outbound_route(
            self.config.outbound.iter(),
            selector,
        ) {
            Ok(route) => route,
            Err(mesh_dynamic_caps::ExactRootRouteError::InvalidLogicalComponentId) => {
                return Err(self.protocol_error(
                    ProtocolErrorCode::UnknownHandle,
                    "dynamic capability root selector is malformed",
                ));
            }
            Err(mesh_dynamic_caps::ExactRootRouteError::NotFound) => return Ok(None),
            Err(mesh_dynamic_caps::ExactRootRouteError::Ambiguous) => {
                return Err(self.protocol_error(
                    ProtocolErrorCode::AuthorityPathUnavailable,
                    "dynamic capability root handle is ambiguous",
                ));
            }
        };
        let Some(route) = route else {
            return Ok(None);
        };
        if route.protocol != MeshProtocol::Http {
            return Ok(None);
        }
        Ok(Some(format!("http://127.0.0.1:{}", route.listen_port)))
    }

    async fn static_root_handle_match(
        &self,
        raw_handle: &str,
    ) -> Result<Option<StaticRootHandleMatch>, ProtocolErrorResponse> {
        let parsed = match Url::parse(raw_handle) {
            Ok(parsed) => parsed,
            Err(_) => return Ok(None),
        };
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed
                .host_str()
                .is_some_and(|host| host == "127.0.0.1" || host == "localhost" || host == "::1")
        {
            return Ok(None);
        }
        let Some(port) = parsed.port_or_known_default() else {
            return Ok(None);
        };
        let held = self.control_held_list().await?;
        for entry in held.held {
            if entry.entry_kind != HeldEntryKind::RootAuthority {
                continue;
            }
            let Some(selector) = entry.root_authority_selector.as_ref() else {
                continue;
            };
            let Some(url) = self.root_static_handle_url(selector)? else {
                continue;
            };
            let expected = Url::parse(&url).map_err(|err| {
                self.protocol_error(
                    ProtocolErrorCode::HandleNotDynamic,
                    format!("static dynamic capability handle is invalid: {err}"),
                )
            })?;
            if expected.port_or_known_default() == Some(port) {
                return Ok(Some(StaticRootHandleMatch {
                    held_id: entry.held_id,
                    source: DynamicCapabilityControlSourceRequest::RootAuthority {
                        root_authority_selector: selector.clone(),
                    },
                }));
            }
        }
        Ok(None)
    }

    fn parse_dynamic_handle_proxy_route(path: &str) -> Option<DynamicHandleProxyRoute> {
        let remainder = path.strip_prefix(DYNAMIC_CAPS_HANDLE_PREFIX)?;
        let (handle_id, forwarded_path) = remainder
            .split_once('/')
            .map(|(handle_id, tail)| (handle_id, format!("/{tail}")))
            .unwrap_or((remainder, "/".to_string()));
        (!handle_id.is_empty()).then(|| DynamicHandleProxyRoute {
            handle_id: handle_id.to_string(),
            forwarded_path,
        })
    }

    async fn handle_summary_map(&self) -> BTreeMap<String, Vec<MaterializedHandleSummary>> {
        let state = self.handles.lock().await;
        state
            .handles_by_id
            .values()
            .map(|record| {
                (
                    record.held_id.clone(),
                    MaterializedHandleSummary {
                        handle_id: record.handle_id.clone(),
                        url: self
                            .materialized_handle_url(&record.handle_id, "/", None, None)
                            .unwrap_or_else(|_| String::new()),
                    },
                )
            })
            .fold(
                BTreeMap::<String, Vec<MaterializedHandleSummary>>::new(),
                |mut out, (held_id, summary)| {
                    out.entry(held_id).or_default().push(summary);
                    out
                },
            )
    }

    async fn held_with_materializations(
        &self,
    ) -> Result<Vec<HeldEntryDetail>, ProtocolErrorResponse> {
        let held = self.control_held_list().await?;
        let materializations = self.handle_summary_map().await;
        let mut details = Vec::with_capacity(held.held.len());
        for entry in held.held {
            let mut detail = self.control_held_detail(&entry.held_id).await?;
            detail.summary.materializations = materializations
                .get(&detail.summary.held_id)
                .cloned()
                .unwrap_or_default();
            details.push(detail);
        }
        Ok(details)
    }

    async fn source_from_handle(
        &self,
        raw_handle: &str,
    ) -> Result<DynamicCapabilityControlSourceRequest, ProtocolErrorResponse> {
        if let Some(route) = Self::parse_dynamic_handle_proxy_route(
            Url::parse(raw_handle)
                .ok()
                .map(|url| url.path().to_string())
                .as_deref()
                .unwrap_or(""),
        ) {
            let held_id = {
                let state = self.handles.lock().await;
                state
                    .handles_by_id
                    .get(&route.handle_id)
                    .map(|record| record.held_id.clone())
                    .ok_or_else(|| {
                        self.protocol_error(
                            ProtocolErrorCode::UnknownSource,
                            "dynamic capability handle does not exist",
                        )
                    })?
            };
            let detail = self.control_held_detail(&held_id).await?;
            return self.source_from_held_detail(&detail);
        }
        if let Some(static_match) = self.static_root_handle_match(raw_handle).await? {
            return Ok(static_match.source);
        }
        Err(self.protocol_error(
            ProtocolErrorCode::UnknownSource,
            "handle does not correspond to a dynamic capability source",
        ))
    }

    async fn materialize_static_root(
        &self,
        held_id: &str,
    ) -> Result<Option<MaterializeResponse>, ProtocolErrorResponse> {
        let detail = self.control_held_detail(held_id).await?;
        if detail.summary.entry_kind != HeldEntryKind::RootAuthority {
            return Ok(None);
        }
        let Some(selector) = detail.summary.root_authority_selector.as_ref() else {
            return Err(self.protocol_error(
                ProtocolErrorCode::UnknownHandle,
                "root authority materialization is missing its selector",
            ));
        };
        let Some(url) = self.root_static_handle_url(selector)? else {
            return Ok(None);
        };
        let handle_id = format!("static-{}", held_id.replace('/', "_"));
        Ok(Some(MaterializeResponse {
            held_id: held_id.to_string(),
            handle_id,
            url,
        }))
    }

    async fn ensure_dynamic_handle_materialized(
        &self,
        source: DynamicCapabilityControlSourceRequest,
        descriptor_hint: Option<DescriptorIr>,
    ) -> Result<MaterializeResponse, ProtocolErrorResponse> {
        let resolved = self.control_resolve_origin(source.clone()).await?;
        if resolved.origin_protocol != "http" {
            return Err(self.protocol_error(
                ProtocolErrorCode::PathEstablishmentFailed,
                format!(
                    "dynamic capability protocol `{}` is not supported for local materialization",
                    resolved.origin_protocol
                ),
            ));
        }
        let existing = {
            let state = self.handles.lock().await;
            state
                .handle_id_by_held_id
                .get(&resolved.held_id)
                .cloned()
                .and_then(|handle_id| {
                    state
                        .handles_by_id
                        .get(&handle_id)
                        .map(|record| (handle_id, record))
                })
                .map(|(handle_id, _)| handle_id)
        };
        let handle_id = if let Some(handle_id) = existing {
            handle_id
        } else {
            let mut state = self.handles.lock().await;
            let handle_id = Self::next_handle_id(&mut state);
            state
                .handle_id_by_held_id
                .insert(resolved.held_id.clone(), handle_id.clone());
            state.handles_by_id.insert(
                handle_id.clone(),
                DynamicHandleRecord {
                    handle_id: handle_id.clone(),
                    held_id: resolved.held_id.clone(),
                    descriptor: descriptor_hint.unwrap_or_else(|| resolved.descriptor.clone()),
                    upstream: None,
                },
            );
            handle_id
        };
        self.refresh_dynamic_handle_upstream(&handle_id, &resolved)
            .await?;
        Ok(MaterializeResponse {
            held_id: resolved.held_id,
            handle_id: handle_id.clone(),
            url: self.materialized_handle_url(&handle_id, "/", None, None)?,
        })
    }

    async fn refresh_dynamic_handle_upstream(
        &self,
        handle_id: &str,
        resolved: &ControlDynamicResolveOriginResponse,
    ) -> Result<(), ProtocolErrorResponse> {
        let peer_key = base64::engine::general_purpose::STANDARD
            .decode(resolved.origin_peer_key_b64.as_bytes())
            .map_err(|err| {
                self.protocol_error(
                    ProtocolErrorCode::PathEstablishmentFailed,
                    format!("dynamic capability origin peer key is invalid: {err}"),
                )
            })?;
        let peer_key: [u8; 32] = peer_key.as_slice().try_into().map_err(|_| {
            self.protocol_error(
                ProtocolErrorCode::PathEstablishmentFailed,
                "dynamic capability origin peer key must be exactly 32 bytes",
            )
        })?;
        let mut outbound = connect_noise_with_key(
            &resolved.origin_peer_addr,
            &resolved.origin_peer_id,
            peer_key,
            self.config.as_ref(),
        )
        .await
        .map_err(|err| {
            self.protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                format!("failed to connect to dynamic capability origin: {err}"),
            )
        })?;
        outbound
            .send_open(&OpenFrame {
                route_id: resolved.origin_route_id.clone(),
                capability: resolved.origin_capability.clone(),
                protocol: MeshProtocol::Http,
                slot: None,
                capability_kind: None,
                capability_profile: None,
            })
            .await
            .map_err(|err| {
                self.protocol_error(
                    ProtocolErrorCode::PathEstablishmentFailed,
                    format!("failed to open dynamic capability origin route: {err}"),
                )
            })?;
        let (local, remote) = duplex(64 * 1024);
        let bridge_task =
            tokio::spawn(async move { proxy_noise_to_plain(&mut outbound, remote).await });
        let (sender, conn) = client_http1::handshake(TokioIo::new(local))
            .await
            .map_err(|err| {
                self.protocol_error(
                    ProtocolErrorCode::PathEstablishmentFailed,
                    format!("failed to initialize dynamic capability upstream: {err}"),
                )
            })?;
        let conn_task = tokio::spawn(async move {
            if let Err(err) = conn.await {
                tracing::warn!(
                    target: "amber.internal",
                    "dynamic capability upstream connection failed: {err}"
                );
            }
        });
        let upstream = DynamicHandleUpstream {
            route_id: Arc::<str>::from(resolved.origin_route_id.as_str()),
            sender: Arc::new(Mutex::new(sender)),
            _tasks: Arc::new(DynamicHandleUpstreamTasks {
                conn_task,
                bridge_task,
            }),
        };
        let mut state = self.handles.lock().await;
        let record = state.handles_by_id.get_mut(handle_id).ok_or_else(|| {
            self.protocol_error(
                ProtocolErrorCode::UnknownHandle,
                "dynamic capability handle disappeared during materialization",
            )
        })?;
        record.upstream = Some(upstream);
        Ok(())
    }

    async fn ensure_dynamic_handle_upstream(
        &self,
        handle_id: &str,
    ) -> Result<(DynamicHandleRecordView, DynamicHandleUpstream), ProtocolErrorResponse> {
        let (held_id, descriptor, current_upstream) = {
            let state = self.handles.lock().await;
            let record = state.handles_by_id.get(handle_id).ok_or_else(|| {
                self.protocol_error(
                    ProtocolErrorCode::UnknownHandle,
                    "dynamic capability handle does not exist",
                )
            })?;
            (
                record.held_id.clone(),
                record.descriptor.clone(),
                record.upstream.clone(),
            )
        };
        let detail = self.control_held_detail(&held_id).await?;
        if detail.summary.state != HeldEntryState::Live {
            return Err(self.protocol_error(
                ProtocolErrorCode::RevokedRef,
                "dynamic capability handle has been revoked",
            ));
        }
        if let Some(upstream) = current_upstream
            && upstream.is_alive()
        {
            return Ok((
                DynamicHandleRecordView {
                    held_id,
                    descriptor,
                },
                upstream,
            ));
        }
        let source = self.source_from_held_detail(&detail)?;
        let resolved = self.control_resolve_origin(source).await?;
        self.refresh_dynamic_handle_upstream(handle_id, &resolved)
            .await?;
        let state = self.handles.lock().await;
        let record = state.handles_by_id.get(handle_id).ok_or_else(|| {
            self.protocol_error(
                ProtocolErrorCode::UnknownHandle,
                "dynamic capability handle disappeared during refresh",
            )
        })?;
        Ok((
            DynamicHandleRecordView {
                held_id: record.held_id.clone(),
                descriptor: record.descriptor.clone(),
            },
            record.upstream.clone().ok_or_else(|| {
                self.protocol_error(
                    ProtocolErrorCode::PathEstablishmentFailed,
                    "dynamic capability upstream was not established",
                )
            })?,
        ))
    }

    async fn materialize_request(
        &self,
        request: MaterializeRequest,
    ) -> Result<MaterializeResponse, ProtocolErrorResponse> {
        if let Some(raw_ref) = request.r#ref.as_deref() {
            let parsed = self.parse_ref_for_local_holder(raw_ref)?;
            let materialized = self
                .ensure_dynamic_handle_materialized(
                    DynamicCapabilityControlSourceRequest::Grant {
                        grant_id: parsed.claims.grant_id.clone(),
                    },
                    None,
                )
                .await?;
            return Ok(MaterializeResponse {
                held_id: materialized.held_id,
                handle_id: materialized.handle_id.clone(),
                url: self.materialized_handle_url(
                    &materialized.handle_id,
                    &parsed.relative_path,
                    parsed.query.as_deref(),
                    parsed.fragment.as_deref(),
                )?,
            });
        }
        let held_id = request.held_id.as_deref().ok_or_else(|| {
            self.protocol_error(
                ProtocolErrorCode::UnknownHandle,
                "materialize requires either ref or held_id",
            )
        })?;
        if let Some(static_root) = self.materialize_static_root(held_id).await? {
            return Ok(static_root);
        }
        let detail = self.control_held_detail(held_id).await?;
        self.ensure_dynamic_handle_materialized(self.source_from_held_detail(&detail)?, None)
            .await
    }

    async fn materialize_ref_url(&self, raw_ref: &str) -> Result<String, ProtocolErrorResponse> {
        Ok(self
            .materialize_request(MaterializeRequest {
                r#ref: Some(raw_ref.to_string()),
                held_id: None,
            })
            .await?
            .url)
    }

    pub(super) async fn rewrite_dynamic_refs_in_a2a_body(
        &self,
        raw: &mut Vec<u8>,
    ) -> Result<bool, ProtocolErrorResponse> {
        let refs = a2a::collect_dynamic_capability_refs(raw);
        if refs.is_empty() {
            return Ok(false);
        }
        let mut replacements = BTreeMap::new();
        for raw_ref in refs {
            let materialized = self.materialize_ref_url(&raw_ref).await?;
            replacements.insert(raw_ref, materialized);
        }
        Ok(a2a::rewrite_dynamic_capability_ref_fields(
            raw,
            &replacements,
        ))
    }

    async fn inspect_handle(
        &self,
        request: InspectHandleRequest,
    ) -> Result<InspectHandleResponse, ProtocolErrorResponse> {
        if let Some(route) = Self::parse_dynamic_handle_proxy_route(
            Url::parse(&request.handle)
                .ok()
                .map(|url| url.path().to_string())
                .as_deref()
                .unwrap_or(""),
        ) {
            let held_id = {
                let state = self.handles.lock().await;
                state
                    .handles_by_id
                    .get(&route.handle_id)
                    .map(|record| record.held_id.clone())
                    .ok_or_else(|| {
                        self.protocol_error(
                            ProtocolErrorCode::UnknownHandle,
                            "dynamic capability handle does not exist",
                        )
                    })?
            };
            let detail = self.control_held_detail(&held_id).await?;
            return Ok(InspectHandleResponse {
                held_id: detail.summary.held_id,
                grant_id: detail.summary.grant_id,
                state: detail.summary.state,
                descriptor: detail.summary.descriptor,
            });
        }
        if let Some(static_match) = self.static_root_handle_match(&request.handle).await? {
            let detail = self.control_held_detail(&static_match.held_id).await?;
            return Ok(InspectHandleResponse {
                held_id: detail.summary.held_id,
                grant_id: detail.summary.grant_id,
                state: detail.summary.state,
                descriptor: detail.summary.descriptor,
            });
        }
        Err(self.protocol_error(
            ProtocolErrorCode::HandleNotDynamic,
            "handle is not a dynamic capability handle",
        ))
    }

    async fn watch_chunk(
        &self,
        snapshot: &mut HeldWatchSnapshot,
    ) -> Result<Option<Bytes>, ProtocolErrorResponse> {
        let current = self.held_with_materializations().await?;
        let current_map = current
            .iter()
            .cloned()
            .map(|detail| (detail.summary.held_id.clone(), detail))
            .collect::<BTreeMap<_, _>>();
        let current_materializations = current
            .iter()
            .map(|detail| {
                (
                    detail.summary.held_id.clone(),
                    detail.summary.materializations.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut lines = Vec::new();

        for (held_id, detail) in &current_map {
            if !snapshot.held.contains_key(held_id) {
                lines.push(
                    serde_json::to_vec(&HeldEvent {
                        event: "grant_available".to_string(),
                        held_id: held_id.clone(),
                        grant_id: detail.summary.grant_id.clone(),
                        handle_id: None,
                        url: None,
                        descriptor: Some(detail.summary.descriptor.clone()),
                        reason: None,
                    })
                    .expect("held event should serialize"),
                );
            }
        }

        for held_id in snapshot.held.keys() {
            if current_map.contains_key(held_id) {
                continue;
            }
            let revoked = self.control_held_detail(held_id).await.ok();
            lines.push(
                serde_json::to_vec(&HeldEvent {
                    event: "grant_revoked".to_string(),
                    held_id: held_id.clone(),
                    grant_id: revoked
                        .as_ref()
                        .and_then(|detail| detail.summary.grant_id.clone()),
                    handle_id: None,
                    url: None,
                    descriptor: revoked
                        .as_ref()
                        .map(|detail| detail.summary.descriptor.clone()),
                    reason: revoked.and_then(|detail| detail.revocation_reason),
                })
                .expect("held event should serialize"),
            );
        }

        for (held_id, materializations) in &current_materializations {
            let previous = snapshot.materializations.get(held_id);
            for materialization in materializations {
                if previous.is_some_and(|previous| {
                    previous
                        .iter()
                        .any(|existing| existing.handle_id == materialization.handle_id)
                }) {
                    continue;
                }
                lines.push(
                    serde_json::to_vec(&HeldEvent {
                        event: "grant_materialized".to_string(),
                        held_id: held_id.clone(),
                        grant_id: current_map
                            .get(held_id)
                            .and_then(|detail| detail.summary.grant_id.clone()),
                        handle_id: Some(materialization.handle_id.clone()),
                        url: Some(materialization.url.clone()),
                        descriptor: None,
                        reason: None,
                    })
                    .expect("held event should serialize"),
                );
            }
        }

        snapshot.held = current_map;
        snapshot.materializations = current_materializations;
        if lines.is_empty() {
            return Ok(None);
        }
        let mut chunk = Vec::new();
        for line in lines {
            chunk.extend_from_slice(&line);
            chunk.push(b'\n');
        }
        Ok(Some(Bytes::from(chunk)))
    }

    async fn proxy_dynamic_handle_request(
        &self,
        route: DynamicHandleProxyRoute,
        req: Request<Incoming>,
    ) -> Response<BoxBody> {
        let Ok((record, upstream)) = self.ensure_dynamic_handle_upstream(&route.handle_id).await
        else {
            return error_response(
                StatusCode::GONE,
                "dynamic capability handle has been revoked",
            );
        };
        let mut parts = req.into_parts();
        let query = parts
            .0
            .uri
            .query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default();
        let path_and_query = format!("{}{}", route.forwarded_path, query);
        match path_and_query.parse::<Uri>() {
            Ok(uri) => parts.0.uri = uri,
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "dynamic capability handle request path is invalid",
                );
            }
        }
        let req = Request::from_parts(parts.0, parts.1);
        proxy_outbound_http_request(
            OutboundHttpProxyState {
                upstream: upstream.sender.clone(),
                plugins: if record.descriptor.kind == "a2a" {
                    Arc::from([Arc::new(a2a::A2aUrlRewritePlugin::new(
                        self.a2a_url_rewrite_table.clone(),
                    )) as Arc<dyn HttpExchangePlugin>])
                } else {
                    Arc::from(Vec::<Arc<dyn HttpExchangePlugin>>::new())
                },
                route_id: upstream.route_id.clone(),
                peer_id: Arc::<str>::from(self.config.identity.id.as_str()),
                labels: HttpExchangeLabels {
                    kind: HttpEdgeKind::Binding,
                    emit_telemetry: true,
                    slot: None,
                    capability: Arc::<str>::from(record.descriptor.label.as_str()),
                    capability_kind: Some(Arc::<str>::from(record.descriptor.kind.as_str())),
                    capability_profile: record.descriptor.profile.as_deref().map(Arc::<str>::from),
                    source_component: Some(Arc::<str>::from(self.config.identity.id.as_str())),
                    source_endpoint: Arc::<str>::from(record.held_id.as_str()),
                    destination_component: None,
                    destination_endpoint: Arc::<str>::from(record.descriptor.label.as_str()),
                },
                dynamic_caps: Some(Arc::new(self.clone())),
            },
            req,
        )
        .await
    }
}

fn nonempty_env_var(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn required_dynamic_caps_env_var(
    name: &'static str,
    value: Option<String>,
) -> Result<String, RouterError> {
    value.ok_or_else(|| {
        RouterError::InvalidConfig(format!(
            "{name} must be set when dynamic_caps_listen is configured"
        ))
    })
}

fn resolve_dynamic_caps_controller_env() -> Result<Option<DynamicCapsControllerEnv>, RouterError> {
    let control_url = nonempty_env_var(amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_URL_ENV);
    let control_auth_token =
        nonempty_env_var(amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_AUTH_TOKEN_ENV);
    let verify_key_raw = nonempty_env_var(amber_mesh::DYNAMIC_CAPS_TOKEN_VERIFY_KEY_B64_ENV);
    if control_url.is_none() && control_auth_token.is_none() && verify_key_raw.is_none() {
        return Ok(None);
    }
    let run_id =
        required_dynamic_caps_env_var(SCENARIO_RUN_ID_ENV, nonempty_env_var(SCENARIO_RUN_ID_ENV))?;
    Ok(Some(DynamicCapsControllerEnv {
        control_url: required_dynamic_caps_env_var(
            amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_URL_ENV,
            control_url,
        )?,
        control_auth_token: required_dynamic_caps_env_var(
            amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_AUTH_TOKEN_ENV,
            control_auth_token,
        )?,
        verify_key_raw: required_dynamic_caps_env_var(
            amber_mesh::DYNAMIC_CAPS_TOKEN_VERIFY_KEY_B64_ENV,
            verify_key_raw,
        )?,
        run_id,
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use super::*;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn replace(pairs: [(&'static str, Option<&str>); 4]) -> Self {
            let saved = pairs
                .iter()
                .map(|(name, value)| {
                    let previous = env::var(name).ok();
                    unsafe {
                        match value {
                            Some(value) => env::set_var(name, value),
                            None => env::remove_var(name),
                        }
                    }
                    (*name, previous)
                })
                .collect();
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (name, value) in self.saved.drain(..) {
                unsafe {
                    match value {
                        Some(value) => env::set_var(name, value),
                        None => env::remove_var(name),
                    }
                }
            }
        }
    }

    #[test]
    fn resolve_dynamic_caps_controller_env_disables_listener_when_control_env_is_absent() {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock");
        let _env = EnvGuard::replace([
            (amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_URL_ENV, None),
            (
                amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_AUTH_TOKEN_ENV,
                None,
            ),
            (amber_mesh::DYNAMIC_CAPS_TOKEN_VERIFY_KEY_B64_ENV, None),
            (SCENARIO_RUN_ID_ENV, Some("run-1234")),
        ]);

        assert!(
            resolve_dynamic_caps_controller_env()
                .expect("dynamic caps env should resolve")
                .is_none(),
            "sidecars without dynamic caps controller env should leave the listener disabled",
        );
    }

    #[test]
    fn resolve_dynamic_caps_controller_env_rejects_partial_configuration() {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock");
        let _env = EnvGuard::replace([
            (
                amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_URL_ENV,
                Some("http://127.0.0.1:24000"),
            ),
            (
                amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_AUTH_TOKEN_ENV,
                None,
            ),
            (amber_mesh::DYNAMIC_CAPS_TOKEN_VERIFY_KEY_B64_ENV, None),
            (SCENARIO_RUN_ID_ENV, Some("run-1234")),
        ]);

        let err = resolve_dynamic_caps_controller_env().expect_err("partial env must fail");
        assert!(
            matches!(
                &err,
                RouterError::InvalidConfig(message)
                    if message.contains(amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_AUTH_TOKEN_ENV)
            ),
            "partial dynamic caps controller env should fail with the missing variable name: {err}",
        );
    }
}

#[derive(Clone)]
struct DynamicHandleRecordView {
    held_id: String,
    descriptor: DescriptorIr,
}

pub(super) async fn run_dynamic_caps_server(
    state: Arc<DynamicCapsRuntime>,
) -> Result<(), RouterError> {
    let listener = TcpListener::bind(state.listen_addr)
        .await
        .map_err(|source| RouterError::BindFailed {
            addr: state.listen_addr,
            source,
        })?;
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_dynamic_caps_connection(stream, state).await {
                tracing::warn!(target: "amber.internal", "dynamic capability connection failed: {err}");
            }
        });
    }
}

async fn serve_dynamic_caps_connection<IO>(
    stream: IO,
    state: Arc<DynamicCapsRuntime>,
) -> Result<(), hyper::Error>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let state = state.clone();
        async move { dynamic_caps_service(req, state).await }
    });
    http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await
}

async fn dynamic_caps_service(
    req: Request<Incoming>,
    state: Arc<DynamicCapsRuntime>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let path = req.uri().path().to_string();
    if path == "/" || path == "/healthz" {
        return Ok(json_response(
            StatusCode::OK,
            &serde_json::json!({ "ok": true }),
        ));
    }
    if let Some(route) = DynamicCapsRuntime::parse_dynamic_handle_proxy_route(&path) {
        return Ok(state.proxy_dynamic_handle_request(route, req).await);
    }
    match (req.method(), path.as_str()) {
        (&Method::GET, "/v1/held") => {
            let materializations = state.handle_summary_map().await;
            let mut held = match state.control_held_list().await {
                Ok(held) => held,
                Err(err) => return Ok(protocol_response(&err)),
            };
            for entry in &mut held.held {
                entry.materializations = materializations
                    .get(&entry.held_id)
                    .cloned()
                    .unwrap_or_default();
            }
            Ok(json_response(StatusCode::OK, &held))
        }
        (&Method::GET, "/v1/held/watch") => {
            let mut ticker = interval(DYNAMIC_CAPS_WATCH_POLL_INTERVAL);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let stream = futures::stream::unfold(
                (state.clone(), HeldWatchSnapshot::default(), ticker),
                |(state, mut snapshot, mut ticker)| async move {
                    loop {
                        ticker.tick().await;
                        match state.watch_chunk(&mut snapshot).await {
                            Ok(Some(chunk)) => {
                                let frame = Frame::data(chunk);
                                return Some((Ok(frame), (state, snapshot, ticker)));
                            }
                            Ok(None) => {}
                            Err(err) => {
                                let line = serde_json::to_vec(&err)
                                    .unwrap_or_else(|_| br#"{"code":"control_state_unavailable","message":"dynamic capability watch failed"}"#.to_vec());
                                let mut chunk = line;
                                chunk.push(b'\n');
                                let frame = Frame::data(Bytes::from(chunk));
                                return Some((Ok(frame), (state, snapshot, ticker)));
                            }
                        }
                    }
                },
            );
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/x-ndjson")
                .body(http_body_util::BodyExt::boxed(StreamBody::new(stream)))
                .unwrap_or_else(|_| {
                    error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to build watch response",
                    )
                }))
        }
        (&Method::POST, "/v1/share") => {
            let request: ShareRequest = match parse_json_request(req).await {
                Ok(request) => request,
                Err(response) => return Ok(response),
            };
            let source = match request.source {
                ShareSource::Handle { value } => match state.source_from_handle(&value).await {
                    Ok(source) => source,
                    Err(err) => return Ok(protocol_response(&err)),
                },
                ShareSource::HeldId { value } => {
                    let detail = match state.control_held_detail(&value).await {
                        Ok(detail) => detail,
                        Err(err) => return Ok(protocol_response(&err)),
                    };
                    match state.source_from_held_detail(&detail) {
                        Ok(source) => source,
                        Err(err) => return Ok(protocol_response(&err)),
                    }
                }
            };
            let response: ShareResponse = match state
                .control_post_json(
                    DYNAMIC_CAPS_CONTROLLER_SHARE_PATH,
                    &ControlDynamicShareRequest {
                        caller_component_id: state.component_id.to_string(),
                        source,
                        recipient_component_id: request.recipient,
                        idempotency_key: request.idempotency_key,
                        options: request.options,
                    },
                )
                .await
            {
                Ok(response) => response,
                Err(err) => return Ok(protocol_response(&err)),
            };
            Ok(json_response(StatusCode::OK, &response))
        }
        (&Method::POST, "/v1/materialize") => {
            let request: MaterializeRequest = match parse_json_request(req).await {
                Ok(request) => request,
                Err(response) => return Ok(response),
            };
            let response = match state.materialize_request(request).await {
                Ok(response) => response,
                Err(err) => return Ok(protocol_response(&err)),
            };
            Ok(json_response(StatusCode::OK, &response))
        }
        (&Method::POST, "/v1/revoke") => {
            let request: RevokeRequest = match parse_json_request(req).await {
                Ok(request) => request,
                Err(response) => return Ok(response),
            };
            let source = if let Some(held_id) = request.held_id.as_deref() {
                let detail = match state.control_held_detail(held_id).await {
                    Ok(detail) => detail,
                    Err(err) => return Ok(protocol_response(&err)),
                };
                match state.source_from_held_detail(&detail) {
                    Ok(source) => source,
                    Err(err) => return Ok(protocol_response(&err)),
                }
            } else if let Some(raw_ref) = request.r#ref.as_deref() {
                let parsed = match state.parse_ref_for_local_holder(raw_ref) {
                    Ok(parsed) => parsed,
                    Err(err) => return Ok(protocol_response(&err)),
                };
                DynamicCapabilityControlSourceRequest::Grant {
                    grant_id: parsed.claims.grant_id,
                }
            } else {
                return Ok(protocol_response(&ProtocolErrorResponse {
                    code: ProtocolErrorCode::UnknownHandle,
                    message: "revoke requires either held_id or ref".to_string(),
                    details: None,
                }));
            };
            match state
                .control_post_json::<_, RevokeResponse>(
                    DYNAMIC_CAPS_CONTROLLER_REVOKE_PATH,
                    &ControlDynamicRevokeRequest {
                        caller_component_id: state.component_id.to_string(),
                        target: source,
                    },
                )
                .await
            {
                Ok(_) => {}
                Err(err) => return Ok(protocol_response(&err)),
            };
            Ok(json_response(
                StatusCode::OK,
                &RevokeResponse {
                    outcome: "revoked".to_string(),
                },
            ))
        }
        (&Method::POST, "/v1/inspect-ref") => {
            let request: InspectRefRequest = match parse_json_request(req).await {
                Ok(request) => request,
                Err(response) => return Ok(response),
            };
            if let Err(err) = state.parse_ref_for_local_holder(&request.r#ref) {
                return Ok(protocol_response(&err));
            }
            let response: InspectRefResponse = match state
                .control_post_json(
                    DYNAMIC_CAPS_CONTROLLER_INSPECT_REF_PATH,
                    &ControlDynamicInspectRefRequest {
                        holder_component_id: state.component_id.to_string(),
                        r#ref: request.r#ref,
                    },
                )
                .await
            {
                Ok(response) => response,
                Err(err) => return Ok(protocol_response(&err)),
            };
            Ok(json_response(StatusCode::OK, &response))
        }
        (&Method::POST, "/v1/inspect-handle") => {
            let request: InspectHandleRequest = match parse_json_request(req).await {
                Ok(request) => request,
                Err(response) => return Ok(response),
            };
            let response = match state.inspect_handle(request).await {
                Ok(response) => response,
                Err(err) => return Ok(protocol_response(&err)),
            };
            Ok(json_response(StatusCode::OK, &response))
        }
        (&Method::GET, _) if path.starts_with("/v1/held/") => {
            let held_id = path.trim_start_matches("/v1/held/");
            let mut detail = match state.control_held_detail(held_id).await {
                Ok(detail) => detail,
                Err(err) => return Ok(protocol_response(&err)),
            };
            detail.summary.materializations = state
                .handle_summary_map()
                .await
                .get(held_id)
                .cloned()
                .unwrap_or_default();
            Ok(json_response(StatusCode::OK, &detail))
        }
        _ => Ok(error_response(
            StatusCode::NOT_FOUND,
            "unknown dynamic capability route",
        )),
    }
}

pub(super) fn protocol_response(error: &ProtocolErrorResponse) -> Response<BoxBody> {
    json_response(protocol_status(error.code), error)
}

pub(super) fn protocol_status(code: ProtocolErrorCode) -> StatusCode {
    match code {
        ProtocolErrorCode::Unauthorized
        | ProtocolErrorCode::RecipientMismatch
        | ProtocolErrorCode::CallerLacksAuthority => StatusCode::FORBIDDEN,
        ProtocolErrorCode::UnknownSource
        | ProtocolErrorCode::UnknownRef
        | ProtocolErrorCode::UnknownHandle => StatusCode::NOT_FOUND,
        ProtocolErrorCode::IdempotencyConflict | ProtocolErrorCode::AlreadyRevoked => {
            StatusCode::CONFLICT
        }
        ProtocolErrorCode::OriginUnavailable
        | ProtocolErrorCode::PathEstablishmentFailed
        | ProtocolErrorCode::AuthorityPathUnavailable
        | ProtocolErrorCode::ControlStateUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    }
}

async fn parse_json_request<T: DeserializeOwned>(
    req: Request<Incoming>,
) -> Result<T, Response<BoxBody>> {
    let body = req.into_body().collect().await.map_err(|err| {
        error_response(
            StatusCode::BAD_REQUEST,
            &format!("failed to read request body: {err}"),
        )
    })?;
    serde_json::from_slice(&body.to_bytes())
        .map_err(|err| error_response(StatusCode::BAD_REQUEST, &format!("invalid json: {err}")))
}
