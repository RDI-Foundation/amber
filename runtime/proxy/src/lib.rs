use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt, fs,
    hash::{Hash as _, Hasher as _},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

use amber_compiler::{
    mesh::{PROXY_METADATA_FILENAME, PROXY_METADATA_VERSION, ProxyMetadata, external_slot_env_var},
    reporter::{
        direct::DIRECT_PLAN_FILENAME, docker_compose::COMPOSE_FILENAME, vm::VM_PLAN_FILENAME,
    },
};
use amber_manifest::CapabilityTransport;
use amber_mesh::{
    InboundRoute, InboundTarget, MeshConfig, MeshIdentity, MeshIdentityPublic, MeshPeer,
    MeshProtocol, OutboundRoute, TransportConfig, component_route_id, router_export_route_id,
};
use amber_router::control::{PreboundListeners, run_with_listeners};
use base64::Engine as _;
use miette::{Context as _, IntoDiagnostic as _, Result};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    time::{Duration, Instant, sleep},
};
use tracing::{error, warn};
use url::{Url, form_urlencoded};

const CONTROL_UPDATE_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const DIRECT_RUNTIME_STATE_POLL_INTERVAL: Duration = Duration::from_millis(50);
const VM_RUNTIME_STATE_POLL_INTERVAL: Duration = Duration::from_millis(50);
const DIRECT_RUNTIME_STATE_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const TCG_VM_RUNTIME_STATE_WAIT_TIMEOUT: Duration = Duration::from_secs(720);
const EXPORT_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(30);
const ROUTER_IDENTITY_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_CONTAINER_REQUEST_TIMEOUT_SECS: u64 = 2;
const CONTROL_CURL_IMAGE: &str = "curlimages/curl:8.12.1";
const CONTROL_SOCKET_MOUNT_DIR: &str = "/amber/control";
const COMPOSE_PROJECT_NAME_ENV: &str = "COMPOSE_PROJECT_NAME";
const COMPOSE_ROUTER_SERVICE_NAME: &str = "amber-router";
const CONTROL_SOCKET_UID_GID: &str = "65532:65532";

#[derive(Debug)]
pub struct ProxyCommand {
    output: PathBuf,
    project_name: Option<String>,
    slot_bindings: Vec<SlotBinding>,
    export_bindings: Vec<ExportBinding>,
    mesh_addr: Option<String>,
    router_addr: Option<SocketAddr>,
    router_control_addr: Option<ControlEndpoint>,
    router_config: Option<MeshConfig>,
}

#[derive(Debug)]
pub struct PreparedProxy {
    target: ProxyTarget,
    slot_bindings: Vec<SlotBinding>,
    export_bindings: Vec<ExportBinding>,
    control_endpoint: ControlEndpoint,
    router_identity: MeshIdentityPublic,
    router_addr: Option<SocketAddr>,
    proxy_identity: MeshIdentity,
    mesh_addr: Option<String>,
    mesh_listen: SocketAddr,
    reserved_listeners: ReservedProxyListeners,
}

#[derive(Debug)]
struct ReservedTcpListener {
    listener: TcpListener,
}

#[derive(Debug, Default)]
struct ReservedProxyListeners {
    mesh: Option<ReservedTcpListener>,
    outbound: Vec<ReservedTcpListener>,
}

impl ReservedTcpListener {
    fn reserve(listen: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(listen)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to reserve listener at {listen}"))?;
        Ok(Self { listener })
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().into_diagnostic()
    }

    fn into_tokio(self) -> Result<tokio::net::TcpListener> {
        self.listener
            .set_nonblocking(true)
            .into_diagnostic()
            .wrap_err("failed to configure reserved listener as non-blocking")?;
        tokio::net::TcpListener::from_std(self.listener)
            .into_diagnostic()
            .wrap_err("failed to adopt reserved listener")
    }
}

impl ReservedProxyListeners {
    fn into_router_prebound(self, outbound_routes: &[OutboundRoute]) -> Result<PreboundListeners> {
        let mut listeners = PreboundListeners::default();
        if let Some(mesh) = self.mesh {
            listeners = listeners.with_mesh(mesh.into_tokio()?);
        }
        if self.outbound.len() != outbound_routes.len() {
            return Err(miette::miette!(
                "reserved {} outbound listeners for {} outbound routes",
                self.outbound.len(),
                outbound_routes.len()
            ));
        }
        for (route, listener) in outbound_routes.iter().zip(self.outbound) {
            listeners.insert_outbound(route.route_id.clone(), listener.into_tokio()?);
        }
        Ok(listeners)
    }
}

impl ProxyCommand {
    pub fn new(output: impl Into<PathBuf>) -> Self {
        Self {
            output: output.into(),
            project_name: None,
            slot_bindings: Vec::new(),
            export_bindings: Vec::new(),
            mesh_addr: None,
            router_addr: None,
            router_control_addr: None,
            router_config: None,
        }
    }

    pub fn set_project_name(&mut self, project_name: impl Into<String>) -> Result<()> {
        let project_name = project_name.into();
        let trimmed = project_name.trim();
        if trimmed.is_empty() {
            return Err(miette::miette!("--project-name must not be empty"));
        }
        self.project_name = Some(trimmed.to_string());
        Ok(())
    }

    pub fn add_slot_binding(
        &mut self,
        slot: impl Into<String>,
        upstream: SocketAddr,
    ) -> Result<()> {
        let slot = trim_binding_name(slot.into(), "--slot")?;
        if !upstream.ip().is_loopback() {
            return Err(miette::miette!(
                "--slot {} must target a loopback upstream (got {})",
                slot,
                upstream
            ));
        }
        if self
            .slot_bindings
            .iter()
            .any(|binding| binding.slot == slot)
        {
            return Err(miette::miette!("duplicate --slot binding for {}", slot));
        }
        self.slot_bindings.push(SlotBinding { slot, upstream });
        Ok(())
    }

    pub fn add_export_binding(
        &mut self,
        export: impl Into<String>,
        listen: SocketAddr,
    ) -> Result<()> {
        let export = trim_binding_name(export.into(), "--export")?;
        self.export_bindings.push(ExportBinding { export, listen });
        Ok(())
    }

    pub fn set_mesh_addr(&mut self, mesh_addr: impl Into<String>) -> Result<()> {
        let mesh_addr = mesh_addr.into();
        parse_mesh_addr_port(&mesh_addr)?;
        self.mesh_addr = Some(mesh_addr);
        Ok(())
    }

    pub fn set_router_addr(&mut self, router_addr: SocketAddr) {
        self.router_addr = Some(router_addr);
    }

    pub fn set_router_control_tcp(&mut self, addr: impl Into<String>) -> Result<()> {
        let addr = addr.into();
        if addr.trim().is_empty() {
            return Err(miette::miette!("--router-control-addr must not be empty"));
        }
        self.router_control_addr = Some(ControlEndpoint::Tcp(addr));
        Ok(())
    }

    pub fn set_router_control_unix(&mut self, path: impl Into<PathBuf>) -> Result<()> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(miette::miette!(
                "invalid --router-control-addr; expected unix:///absolute/path"
            ));
        }
        self.router_control_addr = Some(ControlEndpoint::Unix(path));
        Ok(())
    }

    pub fn set_router_config(&mut self, config: MeshConfig) {
        self.router_config = Some(config);
    }

    pub async fn prepare(self) -> Result<PreparedProxy> {
        if self.slot_bindings.is_empty() && self.export_bindings.is_empty() {
            return Err(miette::miette!(
                "at least one --slot NAME=ADDR:PORT or --export NAME=ADDR:PORT is required"
            ));
        }

        let target = load_proxy_target(&self.output)?;
        validate_proxy_bindings(&target.metadata, &self.slot_bindings, &self.export_bindings)?;

        let control_endpoint = resolve_control_endpoint(
            self.router_control_addr,
            self.project_name.as_deref(),
            &target,
        )?;
        let router_identity =
            resolve_router_identity(self.router_config.as_ref(), &control_endpoint).await?;
        let router_addr = resolve_router_mesh_addr(
            self.router_addr,
            self.project_name.as_deref(),
            &target,
            !self.export_bindings.is_empty(),
        )
        .await?;
        let proxy_identity = build_proxy_identity("/proxy", &router_identity);

        let (mesh_addr, mesh_listen, mesh_listener) = if self.slot_bindings.is_empty() {
            (None, SocketAddr::from(([127, 0, 0, 1], 0)), None)
        } else {
            let (mesh_addr, mesh_listen, listener) =
                reserve_mesh_addresses(self.mesh_addr.as_deref(), &target)?;
            (Some(mesh_addr), mesh_listen, Some(listener))
        };
        let (export_bindings, mut reserved_listeners) =
            reserve_export_bindings(&self.export_bindings)?;
        reserved_listeners.mesh = mesh_listener;

        Ok(PreparedProxy {
            target,
            slot_bindings: self.slot_bindings,
            export_bindings,
            control_endpoint,
            router_identity,
            router_addr,
            proxy_identity,
            mesh_addr,
            mesh_listen,
            reserved_listeners,
        })
    }

    pub async fn run(self) -> Result<()> {
        self.prepare().await?.run().await
    }
}

impl PreparedProxy {
    pub fn public_identity(&self) -> MeshIdentityPublic {
        MeshIdentityPublic::from_identity(&self.proxy_identity)
    }

    pub async fn run(self) -> Result<()> {
        let router_peer = MeshPeer {
            id: self.router_identity.id.clone(),
            public_key: self.router_identity.public_key,
        };
        let mut inbound = Vec::with_capacity(self.slot_bindings.len());
        let mut outbound = Vec::with_capacity(self.export_bindings.len());

        for binding in &self.export_bindings {
            let export_meta = &self.target.metadata.exports[&binding.export];
            let protocol = mesh_protocol_from_metadata(&export_meta.protocol)?;
            let register_payload =
                ControlExportPayload::new(&self.proxy_identity, &export_meta.protocol);
            register_export_with_retry(
                &self.control_endpoint,
                &binding.export,
                &register_payload,
                EXPORT_REGISTRATION_TIMEOUT,
            )
            .await
            .map_err(|err| match err {
                ExportRegistrationError::Timeout(timeout) => miette::miette!(
                    "timed out after {}s waiting to register export {} via router control ({})",
                    timeout.as_secs(),
                    binding.export,
                    self.control_endpoint
                ),
                ExportRegistrationError::Fatal(reason) => miette::miette!(
                    "failed to register export via router control ({}): {}",
                    self.control_endpoint,
                    reason
                ),
            })?;
            println!(
                "registered export {} via router control ({})",
                binding.export, self.control_endpoint
            );
            outbound.push(OutboundRoute {
                route_id: router_export_route_id(&binding.export, protocol),
                slot: binding.export.clone(),
                capability_kind: None,
                capability_profile: None,
                listen_port: binding.listen.port(),
                listen_addr: Some(binding.listen.ip().to_string()),
                protocol,
                http_plugins: Vec::new(),
                peer_addr: self
                    .router_addr
                    .expect("router address should exist when export bindings are present")
                    .to_string(),
                peer_id: self.router_identity.id.clone(),
                capability: binding.export.clone(),
            });

            let local_url = match protocol {
                MeshProtocol::Http => format!("http://{}", binding.listen),
                MeshProtocol::Tcp => format!("tcp://{}", binding.listen),
            };
            println!("export {} -> {}", binding.export, local_url);
        }

        if let Some(mesh_addr) = self.mesh_addr.as_ref() {
            let peer_key =
                base64::engine::general_purpose::STANDARD.encode(self.proxy_identity.public_key);
            let query = form_urlencoded::Serializer::new(String::new())
                .append_pair("peer_id", &self.proxy_identity.id)
                .append_pair("peer_key", &peer_key)
                .finish();
            let mesh_url = format!("mesh://{mesh_addr}?{query}");
            for binding in &self.slot_bindings {
                let slot_meta = &self.target.metadata.external_slots[&binding.slot];
                inbound.push(InboundRoute {
                    route_id: component_route_id(
                        &self.proxy_identity.id,
                        &binding.slot,
                        MeshProtocol::Http,
                    ),
                    capability: binding.slot.clone(),
                    capability_kind: Some(slot_meta.kind.to_string()),
                    capability_profile: None,
                    protocol: MeshProtocol::Http,
                    http_plugins: Vec::new(),
                    target: InboundTarget::Local {
                        port: binding.upstream.port(),
                    },
                    allowed_issuers: vec![self.router_identity.id.clone()],
                });
                let env_var = if slot_meta.url_env.is_empty() {
                    external_slot_env_var(&binding.slot)
                } else {
                    slot_meta.url_env.clone()
                };
                match try_send_control_update(&self.control_endpoint, &binding.slot, &mesh_url)
                    .await
                {
                    Ok(()) => {
                        println!(
                            "registered slot {} via router control ({})",
                            binding.slot, self.control_endpoint
                        );
                    }
                    Err(ControlUpdateError::Retryable) => {
                        warn!("waiting for router control at {}...", self.control_endpoint);
                        let control_endpoint = self.control_endpoint.clone();
                        let slot = binding.slot.clone();
                        let mesh_url = mesh_url.clone();
                        let env_var = env_var.clone();
                        tokio::spawn(async move {
                            register_control_with_retry(control_endpoint, slot, mesh_url, env_var)
                                .await;
                        });
                    }
                    Err(ControlUpdateError::Fatal(err)) => {
                        error!(
                            "failed to register slot via router control ({}): {err}\nfallback: \
                             set {env_var}={mesh_url} before starting the scenario",
                            self.control_endpoint
                        );
                    }
                }
                println!("slot {} -> http://{}", binding.slot, binding.upstream);
                println!("slot {} mesh endpoint -> {}", binding.slot, mesh_addr);
            }
        }

        let config = MeshConfig {
            identity: self.proxy_identity,
            mesh_listen: self.mesh_listen,
            control_listen: None,
            control_allow: None,
            peers: vec![router_peer],
            inbound,
            outbound,
            transport: TransportConfig::NoiseIk {},
        };
        let prebound_listeners = self
            .reserved_listeners
            .into_router_prebound(&config.outbound)?;

        let mut router = std::pin::pin!(run_with_listeners(config, prebound_listeners));
        let mut shutdown = std::pin::pin!(wait_for_shutdown_signal());
        tokio::select! {
            res = &mut router => res.map_err(|err| miette::miette!("proxy failed: {err}")),
            res = &mut shutdown => {
                res?;
                Ok(())
            }
        }
    }
}

fn trim_binding_name(name: String, flag: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(miette::miette!("{flag} name must not be empty"));
    }
    Ok(trimmed.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyTargetKind {
    DockerCompose,
    Kubernetes,
    Direct,
    Vm,
}

#[derive(Debug)]
struct ProxyTarget {
    kind: ProxyTargetKind,
    metadata: ProxyMetadata,
    source: PathBuf,
}

#[derive(Clone, Debug)]
pub enum ControlEndpoint {
    Tcp(String),
    Unix(PathBuf),
    VolumeSocket { volume: String, socket_path: String },
}

#[derive(Clone, Debug)]
pub struct RouterDiscovery {
    pub control_endpoint: ControlEndpoint,
    pub router_identity: MeshIdentityPublic,
    pub router_addr: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
struct SlotBinding {
    slot: String,
    upstream: SocketAddr,
}

#[derive(Clone, Debug)]
struct ExportBinding {
    export: String,
    listen: SocketAddr,
}

#[derive(Clone, Debug)]
struct ComposeContainerRef {
    runtime: &'static str,
    id: String,
}

#[derive(Debug, Deserialize)]
struct ComposeInspectEntry {
    #[serde(rename = "NetworkSettings")]
    network_settings: ComposeInspectNetworkSettings,
}

#[derive(Debug, Deserialize)]
struct ComposeInspectNetworkSettings {
    #[serde(rename = "Ports")]
    ports: BTreeMap<String, Option<Vec<ComposePortBinding>>>,
}

#[derive(Debug, Deserialize)]
struct ComposePortBinding {
    #[serde(rename = "HostIp")]
    host_ip: String,
    #[serde(rename = "HostPort")]
    host_port: String,
}

#[derive(Debug, Deserialize)]
struct DirectRuntimeState {
    #[serde(default)]
    router_mesh_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct VmRuntimeState {
    #[serde(default)]
    router_mesh_port: Option<u16>,
}

impl fmt::Display for ControlEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(addr) => f.write_str(addr),
            Self::Unix(path) => write!(f, "unix://{}", path.display()),
            Self::VolumeSocket {
                volume,
                socket_path,
            } => write!(f, "volume://{volume}{socket_path}"),
        }
    }
}

pub async fn discover_router_for_output(
    output: impl Into<PathBuf>,
    project_name: Option<&str>,
    requires_router_mesh: bool,
) -> Result<RouterDiscovery> {
    let output = output.into();
    let target = load_proxy_target(&output)?;
    let control_endpoint = resolve_control_endpoint(None, project_name, &target)?;
    let router_identity = resolve_router_identity(None, &control_endpoint).await?;
    let router_addr =
        resolve_router_mesh_addr(None, project_name, &target, requires_router_mesh).await?;
    Ok(RouterDiscovery {
        control_endpoint,
        router_identity,
        router_addr,
    })
}

pub async fn fetch_router_identity(endpoint: &ControlEndpoint) -> Result<MeshIdentityPublic> {
    resolve_router_identity(None, endpoint).await
}

pub async fn register_external_slot_with_retry(
    endpoint: &ControlEndpoint,
    slot: &str,
    url: &str,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        match try_send_control_update(endpoint, slot, url).await {
            Ok(()) => return Ok(()),
            Err(ControlUpdateError::Retryable) if Instant::now() < deadline => {
                sleep(CONTROL_UPDATE_RETRY_INTERVAL).await;
            }
            Err(ControlUpdateError::Retryable) => {
                return Err(miette::miette!(
                    "timed out after {}s waiting to register slot {} via router control ({})",
                    timeout.as_secs(),
                    slot,
                    endpoint
                ));
            }
            Err(ControlUpdateError::Fatal(err)) => {
                return Err(miette::miette!(
                    "failed to register slot {} via router control ({}): {}",
                    slot,
                    endpoint,
                    err
                ));
            }
        }
    }
}

pub async fn clear_external_slot_with_retry(
    endpoint: &ControlEndpoint,
    slot: &str,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        match try_delete_control_update(endpoint, slot).await {
            Ok(()) => return Ok(()),
            Err(ControlUpdateError::Retryable) if Instant::now() < deadline => {
                sleep(CONTROL_UPDATE_RETRY_INTERVAL).await;
            }
            Err(ControlUpdateError::Retryable) => {
                return Err(miette::miette!(
                    "timed out after {}s waiting to clear slot {} via router control ({})",
                    timeout.as_secs(),
                    slot,
                    endpoint
                ));
            }
            Err(ControlUpdateError::Fatal(err)) => {
                return Err(miette::miette!(
                    "failed to clear slot {} via router control ({}): {}",
                    slot,
                    endpoint,
                    err
                ));
            }
        }
    }
}

pub async fn register_export_peer_with_retry(
    endpoint: &ControlEndpoint,
    export: &str,
    peer_id: &str,
    peer_key_b64: &str,
    protocol: &str,
    timeout: Duration,
) -> Result<()> {
    let payload = ControlExportPayload {
        peer_id: peer_id.to_string(),
        peer_key: peer_key_b64.to_string(),
        protocol: protocol.to_string(),
    };
    let deadline = Instant::now() + timeout;
    loop {
        match try_send_export_update(endpoint, export, &payload).await {
            Ok(()) => return Ok(()),
            Err(ControlUpdateError::Retryable) if Instant::now() < deadline => {
                sleep(CONTROL_UPDATE_RETRY_INTERVAL).await;
            }
            Err(ControlUpdateError::Retryable) => {
                return Err(miette::miette!(
                    "timed out after {}s waiting to register export {} via router control ({})",
                    timeout.as_secs(),
                    export,
                    endpoint
                ));
            }
            Err(ControlUpdateError::Fatal(err)) => {
                return Err(miette::miette!(
                    "failed to register export {} via router control ({}): {}",
                    export,
                    endpoint,
                    err
                ));
            }
        }
    }
}

pub async fn unregister_export_peer_with_retry(
    endpoint: &ControlEndpoint,
    export: &str,
    peer_id: &str,
    peer_key_b64: &str,
    protocol: &str,
    timeout: Duration,
) -> Result<()> {
    let payload = ControlExportPayload {
        peer_id: peer_id.to_string(),
        peer_key: peer_key_b64.to_string(),
        protocol: protocol.to_string(),
    };
    let deadline = Instant::now() + timeout;
    loop {
        match try_delete_export_update(endpoint, export, &payload).await {
            Ok(()) => return Ok(()),
            Err(ControlUpdateError::Retryable) if Instant::now() < deadline => {
                sleep(CONTROL_UPDATE_RETRY_INTERVAL).await;
            }
            Err(ControlUpdateError::Retryable) => {
                return Err(miette::miette!(
                    "timed out after {}s waiting to revoke export {} via router control ({})",
                    timeout.as_secs(),
                    export,
                    endpoint
                ));
            }
            Err(ControlUpdateError::Fatal(err)) => {
                return Err(miette::miette!(
                    "failed to revoke export {} via router control ({}): {}",
                    export,
                    endpoint,
                    err
                ));
            }
        }
    }
}

pub async fn apply_route_overlay_with_retry(
    endpoint: &ControlEndpoint,
    overlay_id: &str,
    peers: &[MeshPeer],
    inbound_routes: &[InboundRoute],
    timeout: Duration,
) -> Result<()> {
    let payload = serde_json::json!({
        "peers": peers.iter().map(|peer| serde_json::json!({
            "peer_id": peer.id,
            "peer_key": base64::engine::general_purpose::STANDARD.encode(peer.public_key),
        })).collect::<Vec<_>>(),
        "inbound_routes": inbound_routes,
    });
    let path = format!("/overlays/{overlay_id}");
    let deadline = Instant::now() + timeout;
    loop {
        match send_control_put_json(endpoint, &path, &payload).await {
            Ok(()) => return Ok(()),
            Err(ControlUpdateError::Retryable) if Instant::now() < deadline => {
                sleep(CONTROL_UPDATE_RETRY_INTERVAL).await;
            }
            Err(ControlUpdateError::Retryable) => {
                return Err(miette::miette!(
                    "timed out after {}s waiting to apply overlay {} via router control ({})",
                    timeout.as_secs(),
                    overlay_id,
                    endpoint
                ));
            }
            Err(ControlUpdateError::Fatal(err)) => {
                return Err(miette::miette!(
                    "failed to apply overlay {} via router control ({}): {}",
                    overlay_id,
                    endpoint,
                    err
                ));
            }
        }
    }
}

pub async fn revoke_route_overlay_with_retry(
    endpoint: &ControlEndpoint,
    overlay_id: &str,
    timeout: Duration,
) -> Result<()> {
    let path = format!("/overlays/{overlay_id}");
    let deadline = Instant::now() + timeout;
    loop {
        match send_control_delete_json(endpoint, &path, None).await {
            Ok(()) => return Ok(()),
            Err(ControlUpdateError::Retryable) if Instant::now() < deadline => {
                sleep(CONTROL_UPDATE_RETRY_INTERVAL).await;
            }
            Err(ControlUpdateError::Retryable) => {
                return Err(miette::miette!(
                    "timed out after {}s waiting to revoke overlay {} via router control ({})",
                    timeout.as_secs(),
                    overlay_id,
                    endpoint
                ));
            }
            Err(ControlUpdateError::Fatal(err)) => {
                return Err(miette::miette!(
                    "failed to revoke overlay {} via router control ({}): {}",
                    overlay_id,
                    endpoint,
                    err
                ));
            }
        }
    }
}

fn validate_proxy_bindings(
    metadata: &ProxyMetadata,
    slot_bindings: &[SlotBinding],
    export_bindings: &[ExportBinding],
) -> Result<()> {
    for binding in export_bindings {
        let export_meta = metadata
            .exports
            .get(binding.export.as_str())
            .ok_or_else(|| miette::miette!("export {} not found in output", binding.export))?;
        let _ = mesh_protocol_from_metadata(&export_meta.protocol)?;
    }
    for binding in slot_bindings {
        let slot_meta = metadata
            .external_slots
            .get(binding.slot.as_str())
            .ok_or_else(|| miette::miette!("slot {} not found in output", binding.slot))?;
        if slot_meta.kind.transport() != CapabilityTransport::Http {
            return Err(miette::miette!(
                "slot {} uses {} but amber proxy only supports HTTP-transport slots",
                binding.slot,
                slot_meta.kind
            ));
        }
    }
    Ok(())
}

async fn resolve_router_identity(
    router_config: Option<&MeshConfig>,
    control_endpoint: &ControlEndpoint,
) -> Result<MeshIdentityPublic> {
    if let Some(config) = router_config {
        return Ok(MeshIdentityPublic::from_identity(&config.identity));
    }

    let mut warned = false;
    let deadline = Instant::now() + ROUTER_IDENTITY_FETCH_TIMEOUT;
    loop {
        match try_fetch_router_identity(control_endpoint).await {
            Ok(identity) => return Ok(identity),
            Err(ControlUpdateError::Retryable) => {
                if Instant::now() >= deadline {
                    return Err(miette::miette!(
                        "timed out after {}s waiting to fetch router identity via control ({})",
                        ROUTER_IDENTITY_FETCH_TIMEOUT.as_secs(),
                        control_endpoint
                    ));
                }
                if !warned {
                    eprintln!("waiting for router control at {control_endpoint}...");
                    warned = true;
                }
                sleep(CONTROL_UPDATE_RETRY_INTERVAL).await;
            }
            Err(ControlUpdateError::Fatal(err)) => {
                return Err(miette::miette!(
                    "failed to fetch router identity via control ({}): {}",
                    control_endpoint,
                    err
                ));
            }
        }
    }
}

fn load_proxy_target(output: &Path) -> Result<ProxyTarget> {
    if !output.exists() {
        return Err(miette::miette!(
            "proxy target not found: {}",
            output.display()
        ));
    }
    let abs = if output.is_absolute() {
        output.to_path_buf()
    } else {
        env::current_dir().into_diagnostic()?.join(output)
    };
    let abs = abs
        .canonicalize()
        .map_err(|err| miette::miette!("failed to resolve output path {}: {err}", abs.display()))?;

    if abs.is_dir() {
        let compose_path = abs.join(COMPOSE_FILENAME);
        if compose_path.is_file() {
            let metadata = load_compose_metadata(&compose_path)?;
            validate_proxy_metadata(&metadata, &compose_path)?;
            return Ok(ProxyTarget {
                kind: ProxyTargetKind::DockerCompose,
                metadata,
                source: compose_path,
            });
        }

        let metadata_path = abs.join(PROXY_METADATA_FILENAME);
        if !metadata_path.is_file() {
            return Err(miette::miette!(
                "output directory {} is not a recognized proxy target (missing `{}` and `{}`)",
                abs.display(),
                COMPOSE_FILENAME,
                PROXY_METADATA_FILENAME
            ));
        }
        let metadata = load_proxy_metadata_file(&metadata_path)?;
        validate_proxy_metadata(&metadata, &metadata_path)?;
        let kind = if abs.join(VM_PLAN_FILENAME).is_file() {
            ProxyTargetKind::Vm
        } else if abs.join(DIRECT_PLAN_FILENAME).is_file() {
            ProxyTargetKind::Direct
        } else {
            ProxyTargetKind::Kubernetes
        };
        return Ok(ProxyTarget {
            kind,
            metadata,
            source: if matches!(kind, ProxyTargetKind::Direct | ProxyTargetKind::Vm) {
                abs
            } else {
                metadata_path
            },
        });
    }

    if abs.file_name().and_then(|name| name.to_str()) == Some(PROXY_METADATA_FILENAME) {
        let metadata = load_proxy_metadata_file(&abs)?;
        validate_proxy_metadata(&metadata, &abs)?;
        let kind = if abs
            .parent()
            .is_some_and(|parent| parent.join(VM_PLAN_FILENAME).is_file())
        {
            ProxyTargetKind::Vm
        } else if abs
            .parent()
            .is_some_and(|parent| parent.join(DIRECT_PLAN_FILENAME).is_file())
        {
            ProxyTargetKind::Direct
        } else {
            ProxyTargetKind::Kubernetes
        };
        return Ok(ProxyTarget {
            kind,
            metadata,
            source: if matches!(kind, ProxyTargetKind::Direct | ProxyTargetKind::Vm) {
                abs.parent()
                    .expect("metadata file should have a parent")
                    .to_path_buf()
            } else {
                abs
            },
        });
    }

    Err(miette::miette!(
        "output path {} is not a recognized proxy target; pass the generated compose, direct, or \
         kubernetes output directory",
        abs.display()
    ))
}

pub fn parse_proxy_metadata_json(raw: &str, source: &Path) -> Result<ProxyMetadata> {
    serde_json::from_str(raw)
        .map_err(|err| miette::miette!("invalid proxy metadata {}: {err}", source.display()))
}

pub fn parse_compose_proxy_metadata(raw: &str, source: &Path) -> Result<ProxyMetadata> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(raw)
        .map_err(|err| miette::miette!("invalid docker-compose YAML: {err}"))?;
    let mapping = yaml.as_mapping().ok_or_else(|| {
        miette::miette!("output {} is not a docker-compose file", source.display())
    })?;
    let services_key = serde_yaml::Value::String("services".to_string());
    if !mapping.contains_key(&services_key) {
        return Err(miette::miette!(
            "output {} is not a docker-compose file",
            source.display()
        ));
    }
    let x_amber_key = serde_yaml::Value::String("x-amber".to_string());
    let x_amber = mapping.get(&x_amber_key).ok_or_else(|| {
        miette::miette!(
            "docker-compose output {} is missing x-amber metadata; re-run `amber compile`",
            source.display()
        )
    })?;
    serde_yaml::from_value(x_amber.clone()).map_err(|err| {
        miette::miette!(
            "docker-compose output {} has invalid x-amber metadata: {err}",
            source.display()
        )
    })
}

fn load_proxy_metadata_file(path: &Path) -> Result<ProxyMetadata> {
    let raw = fs::read_to_string(path)
        .map_err(|err| miette::miette!("failed to read {}: {err}", path.display()))?;
    parse_proxy_metadata_json(&raw, path)
}

fn load_compose_metadata(path: &Path) -> Result<ProxyMetadata> {
    let raw = fs::read_to_string(path)
        .map_err(|err| miette::miette!("failed to read {}: {err}", path.display()))?;
    parse_compose_proxy_metadata(&raw, path)
}

fn validate_proxy_metadata(metadata: &ProxyMetadata, path: &Path) -> Result<()> {
    if metadata.version != PROXY_METADATA_VERSION {
        return Err(miette::miette!(
            "proxy metadata version {} in {} is not supported",
            metadata.version,
            path.display()
        ));
    }
    Ok(())
}

fn reserve_mesh_addresses(
    mesh_addr_override: Option<&str>,
    target: &ProxyTarget,
) -> Result<(String, SocketAddr, ReservedTcpListener)> {
    if let Some(mesh_addr) = mesh_addr_override {
        let port = parse_mesh_addr_port(mesh_addr)?;
        let listen_ip = match target.kind {
            ProxyTargetKind::Direct | ProxyTargetKind::Vm => Ipv4Addr::LOCALHOST,
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let listener = ReservedTcpListener::reserve(SocketAddr::new(IpAddr::V4(listen_ip), port))?;
        let actual_listen = listener.local_addr()?;
        let actual_mesh_addr = if port == 0 {
            rewrite_addr_port(mesh_addr, actual_listen.port())?
        } else {
            mesh_addr.to_string()
        };
        return Ok((actual_mesh_addr, actual_listen, listener));
    }

    let listen_ip = match target.kind {
        ProxyTargetKind::Direct | ProxyTargetKind::Vm => Ipv4Addr::LOCALHOST,
        _ => Ipv4Addr::UNSPECIFIED,
    };
    let listener = ReservedTcpListener::reserve(SocketAddr::new(IpAddr::V4(listen_ip), 0))?;
    let actual_listen = listener.local_addr()?;
    let mesh_addr = default_mesh_addr(target, actual_listen.port())?;
    Ok((mesh_addr, actual_listen, listener))
}

fn default_mesh_addr(target: &ProxyTarget, port: u16) -> Result<String> {
    match target.kind {
        ProxyTargetKind::DockerCompose => Ok(format!("host.docker.internal:{port}")),
        ProxyTargetKind::Direct | ProxyTargetKind::Vm => Ok(format!("127.0.0.1:{port}")),
        ProxyTargetKind::Kubernetes => Err(miette::miette!(
            "--mesh-addr is required when proxying against Kubernetes output"
        )),
    }
}

fn parse_mesh_addr_port(addr: &str) -> Result<u16> {
    let url = Url::parse(&format!("mesh://{addr}"))
        .map_err(|err| miette::miette!("invalid --mesh-addr {addr}: {err}"))?;
    url.port_or_known_default()
        .ok_or_else(|| miette::miette!("--mesh-addr must include a port (got {addr})"))
}

fn reserve_export_bindings(
    export_bindings: &[ExportBinding],
) -> Result<(Vec<ExportBinding>, ReservedProxyListeners)> {
    let mut actual_bindings = Vec::with_capacity(export_bindings.len());
    let mut listeners = ReservedProxyListeners::default();
    for binding in export_bindings {
        let listener = ReservedTcpListener::reserve(binding.listen)?;
        let actual_listen = listener.local_addr()?;
        listeners.outbound.push(listener);
        actual_bindings.push(ExportBinding {
            export: binding.export.clone(),
            listen: actual_listen,
        });
    }
    Ok((actual_bindings, listeners))
}

fn rewrite_addr_port(addr: &str, port: u16) -> Result<String> {
    let mut url = Url::parse(&format!("mesh://{addr}"))
        .map_err(|err| miette::miette!("invalid --mesh-addr {addr}: {err}"))?;
    url.set_port(Some(port))
        .map_err(|_| miette::miette!("failed to rewrite --mesh-addr {addr} with port {port}"))?;
    Ok(url[url::Position::BeforeHost..].to_string())
}

async fn resolve_router_mesh_addr(
    router_addr_override: Option<SocketAddr>,
    project_name: Option<&str>,
    target: &ProxyTarget,
    requires_router_mesh: bool,
) -> Result<Option<SocketAddr>> {
    if !requires_router_mesh {
        return Ok(None);
    }
    if router_addr_override.is_some() {
        return Ok(router_addr_override);
    }
    Ok(Some(
        resolve_router_mesh_addr_required(project_name, target).await?,
    ))
}

async fn resolve_router_mesh_addr_required(
    project_name: Option<&str>,
    target: &ProxyTarget,
) -> Result<SocketAddr> {
    let router = target
        .metadata
        .router
        .as_ref()
        .ok_or_else(|| miette::miette!("router metadata missing; re-run `amber compile`"))?;
    let router_addr = match target.kind {
        ProxyTargetKind::DockerCompose => resolve_compose_router_mesh_addr(
            project_name,
            router.compose_project.as_deref(),
            &target.source,
            router.mesh_port,
        )?,
        ProxyTargetKind::Direct if router.mesh_port == 0 => SocketAddr::from((
            [127, 0, 0, 1],
            wait_for_direct_runtime_router_port(&target.source, DIRECT_RUNTIME_STATE_WAIT_TIMEOUT)
                .await?,
        )),
        ProxyTargetKind::Vm if router.mesh_port == 0 => SocketAddr::from((
            [127, 0, 0, 1],
            wait_for_vm_runtime_router_port(&target.source, vm_runtime_state_wait_timeout())
                .await?,
        )),
        _ => {
            if router.mesh_port == 0 {
                return Err(miette::miette!(
                    "router mesh port is 0; compile output is missing router metadata"
                ));
            }
            SocketAddr::from(([127, 0, 0, 1], router.mesh_port))
        }
    };
    Ok(router_addr)
}

fn resolve_compose_router_mesh_addr(
    explicit_project_name: Option<&str>,
    metadata_project_name: Option<&str>,
    compose_file: &Path,
    router_container_port: u16,
) -> Result<SocketAddr> {
    if router_container_port == 0 {
        return Err(miette::miette!(
            "router mesh port is 0; compile output is missing router metadata"
        ));
    }
    let compose_project =
        resolve_compose_project_name(explicit_project_name, metadata_project_name, compose_file)?
            .ok_or_else(|| {
            miette::miette!(
                "could not determine the Compose project name for {}. Pass `--project-name` or \
                 `--router-addr`.",
                compose_file.display()
            )
        })?;
    let container = find_running_compose_service_container(
        compose_file,
        &compose_project,
        COMPOSE_ROUTER_SERVICE_NAME,
    )?;
    let published_addrs = inspect_compose_published_port_addrs(&container, router_container_port)
        .wrap_err_with(|| {
        format!(
            "failed to resolve the published router mesh port for Compose project `{}`",
            compose_project
        )
    })?;
    Ok(published_addrs
        .iter()
        .copied()
        .find(|addr| addr.ip().is_loopback())
        .unwrap_or(published_addrs[0]))
}

fn find_running_compose_service_container(
    compose_file: &Path,
    project_name: &str,
    service_name: &str,
) -> Result<ComposeContainerRef> {
    let mut containers = Vec::new();
    for runtime in ["docker", "podman"] {
        let mut cmd = ProcessCommand::new(runtime);
        cmd.arg("ps")
            .arg("--filter")
            .arg(format!("label=com.docker.compose.project={project_name}"))
            .arg("--filter")
            .arg(format!("label=com.docker.compose.service={service_name}"))
            .arg("--format")
            .arg("{{.ID}}");
        let Ok(output) = cmd.output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        for id in String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            containers.push(ComposeContainerRef {
                runtime,
                id: id.to_string(),
            });
        }
    }

    match containers.len() {
        0 => Err(miette::miette!(
            "failed to find a running `{}` container for Compose project `{}` from {}. Start the \
             stack first or pass `--project-name`/`--router-addr`.",
            service_name,
            project_name,
            compose_file.display()
        )),
        1 => Ok(containers.remove(0)),
        _ => {
            let matches = containers
                .iter()
                .map(|container| format!("{}:{}", container.runtime, container.id))
                .collect::<Vec<_>>()
                .join(", ");
            Err(miette::miette!(
                "multiple running `{}` containers matched Compose project `{}` from {}: {}. Pass \
                 `--router-addr` to disambiguate.",
                service_name,
                project_name,
                compose_file.display(),
                matches
            ))
        }
    }
}

fn inspect_compose_published_port_addrs(
    container: &ComposeContainerRef,
    container_port: u16,
) -> Result<Vec<SocketAddr>> {
    let output = ProcessCommand::new(container.runtime)
        .arg("inspect")
        .arg(&container.id)
        .output()
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to inspect Compose container {} via {}",
                container.id, container.runtime
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        return Err(miette::miette!(
            "failed to inspect Compose container {} via {} (status {}{})",
            container.id,
            container.runtime,
            output.status,
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        ));
    }
    parse_compose_published_port_addrs(&String::from_utf8_lossy(&output.stdout), container_port)
}

fn parse_compose_published_port_addrs(raw: &str, container_port: u16) -> Result<Vec<SocketAddr>> {
    let entries: Vec<ComposeInspectEntry> = serde_json::from_str(raw)
        .map_err(|err| miette::miette!("invalid Compose container inspect output: {err}"))?;
    let entry = entries.into_iter().next().ok_or_else(|| {
        miette::miette!("Compose container inspect output did not include any containers")
    })?;
    let port_key = format!("{container_port}/tcp");
    let bindings = entry
        .network_settings
        .ports
        .get(&port_key)
        .and_then(|bindings| bindings.as_ref())
        .ok_or_else(|| miette::miette!("container port {port_key} is not published on the host"))?;
    let mut addrs = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let host_port = binding.host_port.parse::<u16>().map_err(|err| {
            miette::miette!(
                "invalid published host port {} for container port {}: {}",
                binding.host_port,
                port_key,
                err
            )
        })?;
        let host_ip = parse_compose_published_host_ip(&binding.host_ip)?;
        addrs.push(SocketAddr::new(host_ip, host_port));
    }
    if addrs.is_empty() {
        return Err(miette::miette!(
            "container port {port_key} is not published on the host"
        ));
    }
    Ok(addrs)
}

fn parse_compose_published_host_ip(host_ip: &str) -> Result<IpAddr> {
    let host_ip = host_ip.trim();
    if host_ip.is_empty() {
        return Ok(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
    let host_ip = host_ip.parse::<IpAddr>().map_err(|err| {
        miette::miette!(
            "invalid published host IP `{}` in Compose inspect output: {}",
            host_ip,
            err
        )
    })?;
    if host_ip.is_unspecified() {
        return Ok(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
    Ok(host_ip)
}

fn resolve_control_endpoint(
    control_endpoint_override: Option<ControlEndpoint>,
    explicit_project_name: Option<&str>,
    target: &ProxyTarget,
) -> Result<ControlEndpoint> {
    if let Some(control_endpoint_override) = control_endpoint_override {
        return Ok(control_endpoint_override);
    }

    let router = target
        .metadata
        .router
        .as_ref()
        .ok_or_else(|| miette::miette!("router metadata missing; re-run `amber compile`"))?;
    let compose_project = match target.kind {
        ProxyTargetKind::DockerCompose => resolve_compose_project_name(
            explicit_project_name,
            router.compose_project.as_deref(),
            &target.source,
        )?,
        ProxyTargetKind::Direct | ProxyTargetKind::Vm | ProxyTargetKind::Kubernetes => None,
    };
    if matches!(target.kind, ProxyTargetKind::DockerCompose)
        && let Some(volume) = router.control_socket_volume.as_ref()
    {
        let resolved_volume = expand_env_templates(volume, compose_project.as_deref())?;
        let resolved_socket_path = expand_env_templates(
            router
                .control_socket
                .as_deref()
                .unwrap_or("/amber/control/router-control.sock"),
            compose_project.as_deref(),
        )?;
        return Ok(ControlEndpoint::VolumeSocket {
            volume: resolved_volume,
            socket_path: resolved_socket_path,
        });
    }
    if let Some(socket) = router.control_socket.as_ref() {
        let resolved = expand_env_templates(socket, compose_project.as_deref())?;
        if matches!(target.kind, ProxyTargetKind::Direct | ProxyTargetKind::Vm) {
            let _ = resolved;
            return Ok(ControlEndpoint::Unix(match target.kind {
                ProxyTargetKind::Direct => direct_current_control_socket_path(&target.source),
                ProxyTargetKind::Vm => vm_current_control_socket_path(&target.source),
                _ => unreachable!("local runtime target kind should be direct or vm"),
            }));
        }
        return Ok(ControlEndpoint::Unix(PathBuf::from(resolved)));
    }
    if matches!(target.kind, ProxyTargetKind::DockerCompose) {
        return Err(miette::miette!(
            "docker-compose output is missing router control metadata; re-run `amber compile`"
        ));
    }
    if router.control_port == 0 {
        return Err(miette::miette!(
            "router control endpoint missing in metadata; re-run `amber compile`"
        ));
    }
    Ok(ControlEndpoint::Tcp(format!(
        "127.0.0.1:{}",
        router.control_port
    )))
}

fn resolve_compose_project_name(
    explicit_project_name: Option<&str>,
    metadata_project_name: Option<&str>,
    compose_file: &Path,
) -> Result<Option<String>> {
    if let Some(explicit_project_name) = explicit_project_name {
        return Ok(Some(explicit_project_name.to_string()));
    }

    let env_project = env_var_non_empty(COMPOSE_PROJECT_NAME_ENV).ok();
    let inferred = infer_default_compose_project_name(compose_file);
    if let Some(metadata_project_name) = metadata_project_name {
        return Ok(Some(expand_env_templates(
            metadata_project_name,
            env_project.as_deref().or(inferred.as_deref()),
        )?));
    }
    let discovered = discover_running_compose_projects(compose_file);
    choose_compose_project_name(
        env_project.as_deref(),
        &discovered,
        inferred.as_deref(),
        compose_file,
    )
}

fn choose_compose_project_name(
    env_project: Option<&str>,
    discovered: &BTreeSet<String>,
    inferred: Option<&str>,
    compose_file: &Path,
) -> Result<Option<String>> {
    if let Some(env_project) = env_project {
        return Ok(Some(env_project.to_string()));
    }
    match discovered.len() {
        0 => {}
        1 => return Ok(discovered.iter().next().cloned()),
        _ => {
            let candidates = discovered.iter().cloned().collect::<Vec<_>>().join(", ");
            return Err(miette::miette!(
                "multiple running Compose projects were started from {}: {}. Re-run `amber proxy` \
                 with `--project-name <name>`.",
                compose_file.display(),
                candidates
            ));
        }
    }
    Ok(inferred.map(ToOwned::to_owned))
}

fn discover_running_compose_projects(compose_file: &Path) -> BTreeSet<String> {
    let mut projects = BTreeSet::new();
    for runtime in ["docker", "podman"] {
        let mut cmd = ProcessCommand::new(runtime);
        cmd.arg("ps")
            .arg("--filter")
            .arg(format!(
                "label=com.docker.compose.service={COMPOSE_ROUTER_SERVICE_NAME}"
            ))
            .arg("--format")
            .arg(
                "{{.Label \"com.docker.compose.project\"}}\t{{.Label \
                 \"com.docker.compose.project.config_files\"}}",
            );
        let Ok(output) = cmd.output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        for project in parse_matching_compose_project_names(
            &String::from_utf8_lossy(&output.stdout),
            compose_file,
        ) {
            projects.insert(project);
        }
    }
    projects
}

fn parse_matching_compose_project_names(raw: &str, compose_file: &Path) -> BTreeSet<String> {
    let compose_file = compose_file.display().to_string();
    raw.lines()
        .filter_map(|line| {
            let (project, config_files) = line.split_once('\t')?;
            let project = project.trim();
            if project.is_empty()
                || !compose_project_config_files_match(config_files, &compose_file)
            {
                return None;
            }
            Some(project.to_string())
        })
        .collect()
}

fn compose_project_config_files_match(config_files: &str, compose_file: &str) -> bool {
    config_files
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .any(|value| value == compose_file)
}

fn expand_env_templates(input: &str, compose_project_name: Option<&str>) -> Result<String> {
    let mut out = String::new();
    let mut cursor = 0usize;
    while let Some(rel_start) = input[cursor..].find("${") {
        let start = cursor + rel_start;
        out.push_str(&input[cursor..start]);
        let end = input[start + 2..]
            .find('}')
            .map(|offset| start + 2 + offset)
            .ok_or_else(|| miette::miette!("invalid template in control endpoint: {input}"))?;
        let expr = &input[start + 2..end];
        if let Some((name, default)) = expr.split_once(":-") {
            let value = compose_project_template_value(name, compose_project_name)
                .or_else(|| env_var_non_empty(name).ok())
                .unwrap_or_else(|| default.to_string());
            out.push_str(&value);
        } else {
            let value = compose_project_template_value(expr, compose_project_name)
                .or_else(|| env::var(expr).ok())
                .unwrap_or_default();
            out.push_str(&value);
        }
        cursor = end + 1;
    }
    out.push_str(&input[cursor..]);
    Ok(out)
}

fn compose_project_template_value(
    name: &str,
    compose_project_name: Option<&str>,
) -> Option<String> {
    (name == COMPOSE_PROJECT_NAME_ENV)
        .then_some(compose_project_name)
        .flatten()
        .map(ToOwned::to_owned)
}

fn env_var_non_empty(name: &str) -> Result<String, env::VarError> {
    env::var(name).and_then(|value| {
        if value.is_empty() {
            Err(env::VarError::NotPresent)
        } else {
            Ok(value)
        }
    })
}

fn infer_default_compose_project_name(path: &Path) -> Option<String> {
    let project_dir = path.parent()?;
    let raw = project_dir.file_name()?.to_str()?;
    let normalized = normalize_compose_project_name(raw);
    (!normalized.is_empty()).then_some(normalized)
}

fn normalize_compose_project_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-' {
            out.push(ch);
        }
    }
    while let Some(first) = out.chars().next() {
        if first.is_ascii_lowercase() || first.is_ascii_digit() {
            break;
        }
        out.remove(0);
    }
    out
}

struct ControlExportPayload {
    peer_id: String,
    peer_key: String,
    protocol: String,
}

impl ControlExportPayload {
    fn new(identity: &MeshIdentity, protocol: &str) -> Self {
        let peer_key = base64::engine::general_purpose::STANDARD.encode(identity.public_key);
        Self {
            peer_id: identity.id.clone(),
            peer_key,
            protocol: protocol.to_string(),
        }
    }
}

fn build_proxy_identity(prefix: &str, router_identity: &MeshIdentityPublic) -> MeshIdentity {
    let mut identity = MeshIdentity::generate("proxy", router_identity.mesh_scope.clone());
    let suffix = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&identity.public_key[..6]);
    let prefix = prefix.trim_end_matches('/');
    identity.id = format!("{prefix}/{suffix}");
    identity
}

async fn register_control_with_retry(
    endpoint: ControlEndpoint,
    slot: String,
    url: String,
    env_var: String,
) {
    loop {
        match try_send_control_update(&endpoint, &slot, &url).await {
            Ok(()) => {
                println!("registered slot {slot} via router control ({endpoint})");
                return;
            }
            Err(ControlUpdateError::Retryable) => {
                sleep(CONTROL_UPDATE_RETRY_INTERVAL).await;
            }
            Err(ControlUpdateError::Fatal(err)) => {
                error!(
                    "failed to register slot via router control ({}): {err}\nfallback: set \
                     {env_var}={url} before starting the scenario",
                    endpoint
                );
                return;
            }
        }
    }
}

async fn register_export_with_retry(
    endpoint: &ControlEndpoint,
    export: &str,
    payload: &ControlExportPayload,
    timeout: Duration,
) -> Result<(), ExportRegistrationError> {
    let deadline = Instant::now() + timeout;
    let mut warned = false;
    loop {
        match try_send_export_update(endpoint, export, payload).await {
            Ok(()) => return Ok(()),
            Err(ControlUpdateError::Retryable) => {
                if Instant::now() >= deadline {
                    return Err(ExportRegistrationError::Timeout(timeout));
                }
                if !warned {
                    warn!("waiting for router control at {endpoint}...");
                    warned = true;
                }
                sleep(CONTROL_UPDATE_RETRY_INTERVAL).await;
            }
            Err(ControlUpdateError::Fatal(err)) => {
                return Err(ExportRegistrationError::Fatal(err));
            }
        }
    }
}

enum ExportRegistrationError {
    Timeout(Duration),
    Fatal(String),
}

enum ControlUpdateError {
    Retryable,
    Fatal(String),
}

async fn try_fetch_router_identity(
    endpoint: &ControlEndpoint,
) -> Result<MeshIdentityPublic, ControlUpdateError> {
    let request = "GET /identity HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let response = send_control_request(endpoint, request).await?;
    let (code, body) = parse_http_response(&response).ok_or(ControlUpdateError::Retryable)?;
    control_status(code)?;
    serde_json::from_str(body.trim())
        .map_err(|err| ControlUpdateError::Fatal(format!("invalid router identity payload: {err}")))
}

async fn try_send_control_update(
    endpoint: &ControlEndpoint,
    slot: &str,
    url: &str,
) -> Result<(), ControlUpdateError> {
    send_control_put_json(
        endpoint,
        &format!("/external-slots/{slot}"),
        &serde_json::json!({ "url": url }),
    )
    .await
}

async fn try_delete_control_update(
    endpoint: &ControlEndpoint,
    slot: &str,
) -> Result<(), ControlUpdateError> {
    send_control_delete_json(endpoint, &format!("/external-slots/{slot}"), None).await
}

async fn try_send_export_update(
    endpoint: &ControlEndpoint,
    export: &str,
    payload: &ControlExportPayload,
) -> Result<(), ControlUpdateError> {
    send_control_put_json(
        endpoint,
        &format!("/exports/{export}"),
        &serde_json::json!({
            "peer_id": payload.peer_id,
            "peer_key": payload.peer_key,
            "protocol": payload.protocol,
        }),
    )
    .await
}

async fn try_delete_export_update(
    endpoint: &ControlEndpoint,
    export: &str,
    payload: &ControlExportPayload,
) -> Result<(), ControlUpdateError> {
    send_control_delete_json(
        endpoint,
        &format!("/exports/{export}"),
        Some(&serde_json::json!({
            "peer_id": payload.peer_id,
            "peer_key": payload.peer_key,
            "protocol": payload.protocol,
        })),
    )
    .await
}

fn control_status(code: u16) -> Result<(), ControlUpdateError> {
    if (200..300).contains(&code) {
        return Ok(());
    }
    Err(if code >= 500 {
        ControlUpdateError::Retryable
    } else {
        ControlUpdateError::Fatal(format!("router control returned HTTP {code}"))
    })
}

async fn send_control_put_json(
    endpoint: &ControlEndpoint,
    path: &str,
    payload: &serde_json::Value,
) -> Result<(), ControlUpdateError> {
    let payload = payload.to_string();
    let request = format!(
        "PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: \
         application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    let response = send_control_request(endpoint, &request).await?;
    let (code, _) = parse_http_response(&response).ok_or(ControlUpdateError::Retryable)?;
    control_status(code)
}

async fn send_control_delete_json(
    endpoint: &ControlEndpoint,
    path: &str,
    payload: Option<&serde_json::Value>,
) -> Result<(), ControlUpdateError> {
    let (body, headers) = if let Some(payload) = payload {
        let body = payload.to_string();
        let body_len = body.len();
        (
            body,
            format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body_len
            ),
        )
    } else {
        (String::new(), "Content-Length: 0\r\n".to_string())
    };
    let request = format!(
        "DELETE {path} HTTP/1.1\r\nHost: localhost\r\n{headers}Connection: close\r\n\r\n{body}"
    );
    let response = send_control_request(endpoint, &request).await?;
    let (code, _) = parse_http_response(&response).ok_or(ControlUpdateError::Retryable)?;
    control_status(code)
}

fn parse_http_response(response: &str) -> Option<(u16, &str)> {
    let (head, body) = if let Some((head, body)) = response.split_once("\r\n\r\n") {
        (head, body)
    } else if let Some((head, body)) = response.split_once("\n\n") {
        (head, body)
    } else {
        (response, "")
    };
    let status_line = head.lines().next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())?;
    Some((code, body))
}

async fn send_control_request(
    endpoint: &ControlEndpoint,
    request: &str,
) -> Result<String, ControlUpdateError> {
    match endpoint {
        ControlEndpoint::Tcp(addr) => {
            let stream = tokio::time::timeout(
                CONTROL_REQUEST_TIMEOUT,
                tokio::net::TcpStream::connect(addr),
            )
            .await
            .map_err(|_| ControlUpdateError::Retryable)?
            .map_err(|_| ControlUpdateError::Retryable)?;
            send_request(stream, request).await
        }
        ControlEndpoint::Unix(path) => {
            let stream = tokio::time::timeout(
                CONTROL_REQUEST_TIMEOUT,
                tokio::net::UnixStream::connect(path),
            )
            .await
            .map_err(|_| ControlUpdateError::Retryable)?
            .map_err(|err| {
                if is_retryable_unix_connect_error(&err) {
                    ControlUpdateError::Retryable
                } else {
                    ControlUpdateError::Fatal(format!(
                        "failed to connect to unix control socket {}: {err}",
                        path.display()
                    ))
                }
            })?;
            send_request(stream, request).await
        }
        ControlEndpoint::VolumeSocket {
            volume,
            socket_path,
        } => send_control_request_via_volume(volume, socket_path, request).await,
    }
}

fn is_retryable_unix_connect_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}

async fn send_control_request_via_volume(
    volume: &str,
    socket_path: &str,
    request: &str,
) -> Result<String, ControlUpdateError> {
    if volume.trim().is_empty() {
        return Err(ControlUpdateError::Fatal(
            "invalid router control volume name (empty)".to_string(),
        ));
    }
    if !socket_path.starts_with('/') {
        return Err(ControlUpdateError::Fatal(format!(
            "invalid router control socket path (must be absolute): {socket_path}"
        )));
    }
    let mounted_socket_path = format!("{CONTROL_SOCKET_MOUNT_DIR}{socket_path}");
    send_control_request_via_mount(
        &format!("{volume}:{CONTROL_SOCKET_MOUNT_DIR}"),
        &mounted_socket_path,
        request,
    )
    .await
}

async fn send_control_request_via_mount(
    socket_mount: &str,
    socket_path: &str,
    request: &str,
) -> Result<String, ControlUpdateError> {
    let (method, path, body) = parse_control_request(request)?;
    let mut last_error = None::<String>;
    for runtime in ["docker", "podman"] {
        let mut cmd = ProcessCommand::new(runtime);
        cmd.arg("run")
            .arg("--rm")
            .arg("--network")
            .arg("none")
            .arg("--user")
            .arg(CONTROL_SOCKET_UID_GID)
            .arg("-v")
            .arg(socket_mount)
            .arg(CONTROL_CURL_IMAGE)
            .arg("--unix-socket")
            .arg(socket_path)
            .arg("--connect-timeout")
            .arg(CONTROL_CONTAINER_REQUEST_TIMEOUT_SECS.to_string())
            .arg("--max-time")
            .arg(CONTROL_CONTAINER_REQUEST_TIMEOUT_SECS.to_string())
            .arg("-sS")
            .arg("-i")
            .arg("-X")
            .arg(&method)
            .arg(format!("http://localhost{path}"));
        if let Some(body) = body.as_ref() {
            cmd.arg("-H")
                .arg("Content-Type: application/json")
                .arg("--data-raw")
                .arg(body);
        }

        let output = match cmd.output() {
            Ok(output) => output,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    continue;
                }
                last_error = Some(format!("{runtime} run failed: {err}"));
                continue;
            }
        };

        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if is_retryable_container_connect_error(&stderr) {
            return Err(ControlUpdateError::Retryable);
        }
        last_error = Some(if stderr.is_empty() {
            format!("{runtime} run exited with status {}", output.status)
        } else {
            format!("{runtime} run failed: {stderr}")
        });
    }

    match last_error {
        Some(err) => Err(ControlUpdateError::Fatal(format!(
            "failed to send unix control request via container runtime: {err}"
        ))),
        None => Err(ControlUpdateError::Fatal(
            "failed to send unix control request via container runtime: docker/podman not found"
                .to_string(),
        )),
    }
}

fn is_retryable_container_connect_error(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("could not connect to server")
        || lower.contains("failed to connect")
        || lower.contains("connection refused")
        || lower.contains("timed out")
        || lower.contains("operation timed out")
}

fn parse_control_request(
    request: &str,
) -> Result<(String, String, Option<String>), ControlUpdateError> {
    let (head, body) = request
        .split_once("\r\n\r\n")
        .ok_or_else(|| ControlUpdateError::Fatal("invalid control request payload".to_string()))?;
    let request_line = head
        .lines()
        .next()
        .ok_or_else(|| ControlUpdateError::Fatal("invalid control request line".to_string()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ControlUpdateError::Fatal("missing control request method".to_string()))?;
    let path = parts
        .next()
        .ok_or_else(|| ControlUpdateError::Fatal("missing control request path".to_string()))?;
    let body = (!body.is_empty()).then_some(body.to_string());
    Ok((method.to_string(), path.to_string(), body))
}

async fn send_request<S>(mut stream: S, request: &str) -> Result<String, ControlUpdateError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(
        CONTROL_REQUEST_TIMEOUT,
        stream.write_all(request.as_bytes()),
    )
    .await
    .map_err(|_| ControlUpdateError::Retryable)?
    .map_err(|_| ControlUpdateError::Retryable)?;
    let mut buf = Vec::new();
    tokio::time::timeout(CONTROL_REQUEST_TIMEOUT, stream.read_to_end(&mut buf))
        .await
        .map_err(|_| ControlUpdateError::Retryable)?
        .map_err(|_| ControlUpdateError::Retryable)?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn mesh_protocol_from_metadata(protocol: &str) -> Result<MeshProtocol> {
    Ok(match protocol {
        "http" | "https" => MeshProtocol::Http,
        "tcp" => MeshProtocol::Tcp,
        _ => {
            return Err(miette::miette!(
                "unsupported network protocol for mesh routing"
            ));
        }
    })
}

fn direct_current_control_socket_path(plan_root: &Path) -> PathBuf {
    hashed_temp_socket_path("amber-direct-control", "current", plan_root)
}

fn vm_current_control_socket_path(plan_root: &Path) -> PathBuf {
    hashed_temp_socket_path("amber-vm-control", "current", plan_root)
}

fn hashed_temp_socket_path(dir_name: &str, prefix: &str, path: &Path) -> PathBuf {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    let suffix = hasher.finish();
    env::temp_dir()
        .join(dir_name)
        .join(format!("{prefix}-{suffix:016x}.sock"))
}

fn direct_runtime_state_path(plan_root: &Path) -> PathBuf {
    plan_root.join(".amber").join("direct-runtime.json")
}

fn vm_runtime_state_path(plan_root: &Path) -> PathBuf {
    plan_root.join(".amber").join("vm-runtime.json")
}

fn load_direct_runtime_state(plan_root: &Path) -> Result<Option<DirectRuntimeState>> {
    load_runtime_state(&direct_runtime_state_path(plan_root))
}

fn load_vm_runtime_state(plan_root: &Path) -> Result<Option<VmRuntimeState>> {
    load_runtime_state(&vm_runtime_state_path(plan_root))
}

fn load_runtime_state<T>(path: &Path) -> Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    if !path.is_file() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)
        .map_err(|err| miette::miette!("failed to read {}: {err}", path.display()))?;
    let state = serde_json::from_str(&raw)
        .map_err(|err| miette::miette!("invalid runtime state {}: {err}", path.display()))?;
    Ok(Some(state))
}

async fn wait_for_direct_runtime_router_port(plan_root: &Path, timeout: Duration) -> Result<u16> {
    wait_for_runtime_router_port(
        || {
            load_direct_runtime_state(plan_root)
                .map(|state| state.and_then(|state| state.router_mesh_port))
        },
        timeout,
        DIRECT_RUNTIME_STATE_POLL_INTERVAL,
        "direct runtime router mesh port is unavailable; start `amber run` first or pass \
         --router-addr",
    )
    .await
}

fn vm_runtime_state_wait_timeout() -> Duration {
    if env::var_os("AMBER_VM_FORCE_TCG").is_some() {
        TCG_VM_RUNTIME_STATE_WAIT_TIMEOUT
    } else {
        DIRECT_RUNTIME_STATE_WAIT_TIMEOUT
    }
}

async fn wait_for_vm_runtime_router_port(plan_root: &Path, timeout: Duration) -> Result<u16> {
    wait_for_runtime_router_port(
        || {
            load_vm_runtime_state(plan_root)
                .map(|state| state.and_then(|state| state.router_mesh_port))
        },
        timeout,
        VM_RUNTIME_STATE_POLL_INTERVAL,
        "vm runtime router mesh port is unavailable; start `amber run` first or pass --router-addr",
    )
    .await
}

async fn wait_for_runtime_router_port<F>(
    mut load_port: F,
    timeout: Duration,
    poll_interval: Duration,
    timeout_message: &str,
) -> Result<u16>
where
    F: FnMut() -> Result<Option<u16>>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(port) = load_port()? {
            return Ok(port);
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        sleep((deadline - now).min(poll_interval)).await;
    }
    Err(miette::miette!("{timeout_message}"))
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate())
            .into_diagnostic()
            .wrap_err("failed to install SIGTERM handler")?;
        let mut sighup = signal(SignalKind::hangup())
            .into_diagnostic()
            .wrap_err("failed to install SIGHUP handler")?;

        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                res.into_diagnostic().wrap_err("failed to install Ctrl+C handler")?;
            }
            _ = sigterm.recv() => {}
            _ = sighup.recv() => {}
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .into_diagnostic()
            .wrap_err("failed to install Ctrl+C handler")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
