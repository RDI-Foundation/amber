use std::{
    collections::BTreeSet,
    fmt, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
};

use amber_compiler::{
    CompileOptions, CompileOutput, Compiler, ResolverRegistry,
    bundle::{BundleBuilder, BundleLoader},
    mesh::{PROXY_METADATA_FILENAME, PROXY_METADATA_VERSION, ProxyMetadata, external_slot_env_var},
    reporter::{
        Reporter as _,
        docker_compose::DockerComposeReporter,
        dot::DotReporter,
        kubernetes::{KubernetesReporter, KubernetesReporterConfig},
        metadata::MetadataReporter,
        scenario_ir::ScenarioIrReporter,
    },
};
use amber_manifest::ManifestRef;
use amber_mesh::{
    InboundRoute, InboundTarget, MeshConfig, MeshIdentity, MeshPeer, MeshProtocol, OutboundRoute,
    TransportConfig,
};
use amber_resolver::Resolver;
use amber_router as router;
use base64::Engine as _;
use clap::{ArgAction, Args, Parser, Subcommand};
use miette::{
    Context as _, Diagnostic, GraphicalReportHandler, IntoDiagnostic as _, Result, Severity,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    time::{Duration, sleep},
};
use tracing_error::ErrorLayer;
use tracing_subscriber::{EnvFilter, fmt as tracing_fmt, prelude::*};
use url::{Url, form_urlencoded};

#[derive(Parser)]
#[command(name = "amber")]
#[command(version)]
#[command(about = "Amber CLI")]
struct Cli {
    /// Increase log verbosity (-v, -vv, -vvv, -vvvv).
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Compile(CompileArgs),
    Check(CheckArgs),
    Docs(DocsArgs),
    Proxy(ProxyArgs),
}

#[derive(Args)]
struct CompileArgs {
    /// Treat the given lints as errors (e.g. `warnings`, `manifest::unused_slot`).
    #[arg(short = 'D', long = "deny", value_name = "LINT")]
    deny: Vec<String>,

    /// Write the primary output to this path.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,

    /// Write Graphviz DOT output to this path, or `-` for stdout.
    #[arg(long = "dot", value_name = "FILE", allow_hyphen_values = true)]
    dot: Option<PathBuf>,

    /// Write Docker Compose output to this path, or `-` for stdout.
    #[arg(
        long = "docker-compose",
        visible_alias = "compose",
        value_name = "FILE",
        allow_hyphen_values = true
    )]
    docker_compose: Option<PathBuf>,

    /// Write component metadata (moniker -> metadata JSON) to this path, or `-` for stdout.
    #[arg(long = "metadata", value_name = "FILE", allow_hyphen_values = true)]
    metadata: Option<PathBuf>,

    /// Write a manifest bundle to this directory.
    #[arg(long = "bundle", value_name = "DIR")]
    bundle: Option<PathBuf>,

    /// Write Kubernetes manifests to this directory.
    #[arg(long = "kubernetes", visible_alias = "k8s", value_name = "DIR")]
    kubernetes: Option<PathBuf>,

    /// Disable generation of NetworkPolicy enforcement check resources.
    #[arg(long = "disable-networkpolicy-check", requires = "kubernetes")]
    disable_networkpolicy_check: bool,

    /// Disable compiler optimizations.
    #[arg(long = "no-opt")]
    no_opt: bool,

    /// Root manifest or bundle to compile (URL or local path).
    #[arg(value_name = "MANIFEST")]
    manifest: String,
}

#[derive(Args)]
struct CheckArgs {
    /// Treat the given lints as errors (e.g. `warnings`, `manifest::unused_slot`).
    #[arg(short = 'D', long = "deny", value_name = "LINT")]
    deny: Vec<String>,

    /// Root manifest or bundle to check (URL or local path).
    #[arg(value_name = "MANIFEST")]
    manifest: String,
}

#[derive(Args)]
struct DocsArgs {
    #[command(subcommand)]
    command: DocsCommand,
}

#[derive(Subcommand)]
enum DocsCommand {
    Manifest,
}

#[derive(Args)]
struct ProxyArgs {
    /// Docker Compose file or Kubernetes output directory from `amber compile`.
    #[arg(value_name = "OUTPUT")]
    output: String,

    /// Export name to proxy.
    #[arg(
        long = "export",
        value_name = "NAME",
        conflicts_with = "slot",
        requires = "listen"
    )]
    export: Option<String>,

    /// External slot name to provide into the scenario.
    #[arg(
        long = "slot",
        value_name = "SLOT",
        conflicts_with = "export",
        requires = "upstream"
    )]
    slot: Option<String>,

    /// Local address to listen on (e.g. 127.0.0.1:8080).
    #[arg(long = "listen", value_name = "ADDR:PORT")]
    listen: Option<std::net::SocketAddr>,

    /// Local program address to forward to (slot mode).
    #[arg(long = "upstream", value_name = "ADDR:PORT")]
    upstream: Option<std::net::SocketAddr>,

    /// Mesh address to advertise to the router (slot mode).
    #[arg(long = "mesh-addr", value_name = "HOST:PORT")]
    mesh_addr: Option<String>,

    /// Router mesh address override (defaults to 127.0.0.1:<router mesh port>).
    #[arg(long = "router-addr", value_name = "ADDR:PORT")]
    router_addr: Option<std::net::SocketAddr>,

    /// Router control address override (defaults to 127.0.0.1:<router control port>).
    #[arg(long = "router-control-addr", value_name = "HOST:PORT")]
    router_control_addr: Option<String>,

    /// Router config base64 override.
    #[arg(long = "router-config-b64", value_name = "B64", hide = true)]
    router_config_b64: Option<String>,

    /// Router config file (JSON or base64) override.
    #[arg(long = "router-config", value_name = "FILE", hide = true)]
    router_config: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyTargetKind {
    DockerCompose,
    Kubernetes,
}

struct ProxyTarget {
    kind: ProxyTargetKind,
    metadata: ProxyMetadata,
}

#[tokio::main]
async fn main() -> Result<()> {
    miette::set_panic_hook();
    let cli = Cli::parse();
    init_tracing(cli.verbose)?;

    match cli.command {
        Command::Compile(args) => compile(args).await,
        Command::Check(args) => check(args).await,
        Command::Docs(args) => docs(args),
        Command::Proxy(args) => proxy(args).await,
    }
}

fn init_tracing(verbose: u8) -> Result<()> {
    let filter = if std::env::var_os("RUST_LOG").is_some() {
        EnvFilter::try_from_default_env().into_diagnostic()?
    } else {
        let amber_level = match verbose {
            0 => "error",
            1 => "warn",
            2 => "info",
            3 => "debug",
            _ => "trace",
        };
        EnvFilter::new(format!("error,amber={amber_level},amber_={amber_level}"))
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_fmt::layer())
        .with(ErrorLayer::default())
        .init();

    Ok(())
}

async fn compile(args: CompileArgs) -> Result<()> {
    ensure_outputs_requested(&args)?;
    let outputs = resolve_output_paths(&args)?;

    let resolved = resolve_input(&args.manifest).await?;
    let compiler =
        Compiler::new(resolved.resolver, Default::default()).with_registry(resolved.registry);
    let mut opts = CompileOptions::default();
    if args.no_opt {
        opts.optimize.dce = false;
    }

    let tree = compiler
        .resolve_tree(resolved.manifest.clone(), opts.resolve)
        .await
        .wrap_err("compile failed")?;
    let bundle_tree = args.bundle.as_ref().map(|_| tree.clone());

    let output = compiler
        .compile_from_tree(tree, opts.optimize)
        .wrap_err("compile failed")?;

    let deny = DenySet::new(&args.deny);
    let has_error = print_diagnostics(&output.diagnostics, &deny)?;
    if has_error {
        return Err(miette::miette!("compilation failed"));
    }

    if let Some(primary) = outputs.primary.as_ref() {
        write_primary_output(primary, &output)?;
    }

    if let Some(dot_dest) = outputs.dot {
        let dot = DotReporter.emit(&output).map_err(miette::Report::new)?;
        match dot_dest {
            ArtifactOutput::Stdout => print!("{dot}"),
            ArtifactOutput::File(path) => write_artifact(&path, dot.as_bytes())?,
        }
    }

    if let Some(compose_dest) = outputs.docker_compose {
        let compose = DockerComposeReporter
            .emit(&output)
            .map_err(miette::Report::new)?;
        match compose_dest {
            ArtifactOutput::Stdout => print!("{compose}"),
            ArtifactOutput::File(path) => {
                write_artifact(&path, compose.as_bytes()).wrap_err_with(|| {
                    format!("failed to write docker compose output `{}`", path.display())
                })?
            }
        }
    }

    if let Some(kubernetes_dest) = outputs.kubernetes {
        let reporter = KubernetesReporter {
            config: KubernetesReporterConfig {
                disable_networkpolicy_check: args.disable_networkpolicy_check,
            },
        };
        let artifact = reporter.emit(&output).map_err(miette::Report::new)?;
        write_kubernetes_output(&kubernetes_dest, &artifact)?;
    }

    if let Some(metadata_dest) = outputs.metadata {
        let metadata = MetadataReporter
            .emit(&output)
            .map_err(miette::Report::new)?;
        match metadata_dest {
            ArtifactOutput::Stdout => print!("{metadata}"),
            ArtifactOutput::File(path) => write_artifact(&path, metadata.as_bytes())?,
        }
    }

    if let Some(bundle_root) = resolve_bundle_root(&args)? {
        let tree = bundle_tree.expect("bundle requested");
        prepare_bundle_dir(&bundle_root)?;
        BundleBuilder::build(&tree, compiler.store(), &bundle_root)
            .wrap_err("bundle generation failed")?;
    }

    Ok(())
}

async fn check(args: CheckArgs) -> Result<()> {
    let resolved = resolve_input(&args.manifest).await?;
    let compiler =
        Compiler::new(resolved.resolver, Default::default()).with_registry(resolved.registry);

    let output = compiler
        .check(resolved.manifest, CompileOptions::default())
        .await
        .wrap_err("check failed")?;

    let deny = DenySet::new(&args.deny);
    let has_error = print_diagnostics(&output.diagnostics, &deny)?;
    if has_error || output.has_errors {
        Err(miette::miette!("check failed"))
    } else {
        Ok(())
    }
}

fn docs(args: DocsArgs) -> Result<()> {
    match args.command {
        DocsCommand::Manifest => {
            const MANIFEST_DOCS: &str = include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../manifest/README.md"
            ));
            print!("{MANIFEST_DOCS}");
            Ok(())
        }
    }
}

async fn proxy(args: ProxyArgs) -> Result<()> {
    let target = load_proxy_target(&args.output)?;
    let router_config = load_router_config(&args)?;
    let router_port = router_config.mesh_listen.port();
    if router_port == 0 {
        return Err(miette::miette!(
            "router mesh port is 0; compile output is missing router metadata"
        ));
    }

    let (export, slot) = (args.export.as_ref(), args.slot.as_ref());
    if export.is_none() && slot.is_none() {
        return Err(miette::miette!("--export or --slot is required"));
    }

    if let Some(export) = export {
        let listen = args
            .listen
            .ok_or_else(|| miette::miette!("--listen is required for --export"))?;
        if listen.port() == 0 {
            return Err(miette::miette!("--listen port must be non-zero"));
        }

        let export_meta = target
            .metadata
            .exports
            .get(export)
            .ok_or_else(|| miette::miette!("export {} not found in output", export))?;
        let protocol = mesh_protocol_from_metadata(&export_meta.protocol)?;
        if protocol == MeshProtocol::Udp {
            return Err(miette::miette!("udp exports are not supported yet"));
        }

        let router_addr = args
            .router_addr
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], router_port)));

        let router_id = router_config.identity.id.clone();
        let router_peer = MeshPeer {
            id: router_id.clone(),
            public_key: router_config.identity.public_key,
        };

        let proxy_config = MeshConfig {
            identity: router_config.identity.clone(),
            mesh_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            control_listen: None,
            control_allow: None,
            peers: vec![router_peer.clone()],
            inbound: Vec::new(),
            outbound: vec![OutboundRoute {
                slot: export.to_string(),
                listen_port: listen.port(),
                listen_addr: Some(listen.ip().to_string()),
                protocol,
                peer_addr: router_addr.to_string(),
                peer_id: router_id.clone(),
                capability: export.to_string(),
            }],
            transport: TransportConfig::NoiseIk {},
        };

        let local_url = match protocol {
            MeshProtocol::Http => format!("http://{}", listen),
            MeshProtocol::Tcp => format!("tcp://{}", listen),
            MeshProtocol::Udp => format!("udp://{}", listen),
        };
        println!("{local_url}");

        router::run(proxy_config)
            .await
            .map_err(|err| miette::miette!("proxy failed: {err}"))?;
        return Ok(());
    }

    let slot = slot.expect("slot mode validated");
    let upstream = args
        .upstream
        .ok_or_else(|| miette::miette!("--upstream is required for --slot"))?;
    if !upstream.ip().is_loopback() {
        return Err(miette::miette!(
            "--upstream must be a loopback address (e.g. 127.0.0.1:PORT)"
        ));
    }

    let slot_meta = target
        .metadata
        .external_slots
        .get(slot)
        .ok_or_else(|| miette::miette!("slot {} not found in output", slot))?;
    if !matches!(slot_meta.kind.as_str(), "http" | "https") {
        return Err(miette::miette!(
            "slot {} uses {} but amber proxy only supports http slots",
            slot,
            slot_meta.kind
        ));
    }

    let (mesh_addr, mesh_listen) = resolve_mesh_addresses(&args, &target)?;

    let proxy_id = format!("/proxy/{slot}");
    let identity = MeshIdentity::generate(&proxy_id, None);
    let router_id = router_config.identity.id.clone();
    let router_peer = MeshPeer {
        id: router_id.clone(),
        public_key: router_config.identity.public_key,
    };
    let protocol = MeshProtocol::Http;

    let proxy_config = MeshConfig {
        identity: identity.clone(),
        mesh_listen,
        control_listen: None,
        control_allow: None,
        peers: vec![router_peer.clone()],
        inbound: vec![InboundRoute {
            capability: slot.to_string(),
            protocol,
            target: InboundTarget::Local {
                port: upstream.port(),
            },
            allowed_issuers: vec![router_id.clone()],
        }],
        outbound: Vec::new(),
        transport: TransportConfig::NoiseIk {},
    };

    let peer_key = base64::engine::general_purpose::STANDARD.encode(identity.public_key);
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("peer_id", &identity.id)
        .append_pair("peer_key", &peer_key)
        .finish();
    let mesh_url = format!("mesh://{mesh_addr}?{query}");
    let control_addr = resolve_control_addr(&args, &target)?;
    let env_var = if slot_meta.url_env.is_empty() {
        external_slot_env_var(slot)
    } else {
        slot_meta.url_env.clone()
    };
    match try_send_control_update(&control_addr, slot, &mesh_url).await {
        Ok(()) => {
            println!("registered slot {slot} via router control ({control_addr})");
        }
        Err(ControlUpdateError::Retryable) => {
            eprintln!("waiting for router control at {control_addr}...");
            let control_addr = control_addr.clone();
            let slot = slot.to_string();
            let mesh_url = mesh_url.clone();
            let env_var = env_var.clone();
            tokio::spawn(async move {
                register_control_with_retry(control_addr, slot, mesh_url, env_var).await;
            });
        }
        Err(ControlUpdateError::Fatal(err)) => {
            eprintln!(
                "failed to register slot via router control ({}): {err}\nfallback: set \
                 {env_var}={mesh_url} before starting the scenario",
                control_addr
            );
        }
    }

    router::run(proxy_config)
        .await
        .map_err(|err| miette::miette!("proxy failed: {err}"))?;

    Ok(())
}

fn load_router_config(args: &ProxyArgs) -> Result<MeshConfig> {
    if let Some(b64) = args.router_config_b64.as_ref() {
        return amber_mesh::decode_config_b64(b64)
            .map_err(|err| miette::miette!("invalid router config: {err}"));
    }

    if let Some(path) = args.router_config.as_ref() {
        let raw = fs::read_to_string(path).map_err(|err| {
            miette::miette!("failed to read router config {}: {err}", path.display())
        })?;
        let trimmed = raw.trim();
        if trimmed.starts_with('{') {
            let parsed = serde_json::from_str(trimmed)
                .map_err(|err| miette::miette!("invalid router config: {err}"))?;
            return Ok(parsed);
        }
        return amber_mesh::decode_config_b64(trimmed)
            .map_err(|err| miette::miette!("invalid router config: {err}"));
    }

    if let Ok(b64) = std::env::var("AMBER_ROUTER_CONFIG_B64") {
        return amber_mesh::decode_config_b64(&b64)
            .map_err(|err| miette::miette!("invalid router config: {err}"));
    }

    if let Ok(raw) = std::env::var("AMBER_ROUTER_CONFIG_JSON") {
        let parsed = serde_json::from_str(&raw)
            .map_err(|err| miette::miette!("invalid router config: {err}"))?;
        return Ok(parsed);
    }

    Err(miette::miette!(
        "router config missing; supply --router-config/--router-config-b64 or set \
         AMBER_ROUTER_CONFIG_B64"
    ))
}

fn load_proxy_target(output: &str) -> Result<ProxyTarget> {
    let path = Path::new(output);
    if !path.exists() {
        return Err(miette::miette!("proxy target not found: {}", output));
    }
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().into_diagnostic()?.join(path)
    };
    let abs = abs
        .canonicalize()
        .map_err(|err| miette::miette!("failed to resolve output path {}: {err}", abs.display()))?;

    if abs.is_dir() {
        let metadata_path = abs.join(PROXY_METADATA_FILENAME);
        let metadata = load_proxy_metadata_file(&metadata_path)?;
        validate_proxy_metadata(&metadata, &metadata_path)?;
        return Ok(ProxyTarget {
            kind: ProxyTargetKind::Kubernetes,
            metadata,
        });
    }

    if abs.file_name().and_then(|name| name.to_str()) == Some(PROXY_METADATA_FILENAME) {
        let metadata = load_proxy_metadata_file(&abs)?;
        validate_proxy_metadata(&metadata, &abs)?;
        return Ok(ProxyTarget {
            kind: ProxyTargetKind::Kubernetes,
            metadata,
        });
    }

    let metadata = load_compose_metadata(&abs)?;
    validate_proxy_metadata(&metadata, &abs)?;
    Ok(ProxyTarget {
        kind: ProxyTargetKind::DockerCompose,
        metadata,
    })
}

fn load_proxy_metadata_file(path: &Path) -> Result<ProxyMetadata> {
    let raw = fs::read_to_string(path)
        .map_err(|err| miette::miette!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| miette::miette!("invalid proxy metadata {}: {err}", path.display()))
}

fn load_compose_metadata(path: &Path) -> Result<ProxyMetadata> {
    let raw = fs::read_to_string(path)
        .map_err(|err| miette::miette!("failed to read {}: {err}", path.display()))?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|err| miette::miette!("invalid docker-compose YAML: {err}"))?;
    let mapping = yaml
        .as_mapping()
        .ok_or_else(|| miette::miette!("output {} is not a docker-compose file", path.display()))?;
    let key = serde_yaml::Value::String("services".to_string());
    if !mapping.contains_key(&key) {
        return Err(miette::miette!(
            "output {} is not a docker-compose file",
            path.display()
        ));
    }
    let x_amber_key = serde_yaml::Value::String("x-amber".to_string());
    let x_amber = mapping.get(&x_amber_key).ok_or_else(|| {
        miette::miette!(
            "docker-compose output {} is missing x-amber metadata; re-run `amber compile`",
            path.display()
        )
    })?;
    serde_yaml::from_value(x_amber.clone()).map_err(|err| {
        miette::miette!(
            "docker-compose output {} has invalid x-amber metadata: {err}",
            path.display()
        )
    })
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

fn resolve_mesh_addresses(args: &ProxyArgs, target: &ProxyTarget) -> Result<(String, SocketAddr)> {
    if let Some(mesh_addr) = args.mesh_addr.as_ref() {
        let port = parse_mesh_addr_port(mesh_addr)?;
        let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        return Ok((mesh_addr.to_string(), listen));
    }

    let port = pick_free_port()?;
    let mesh_addr = default_mesh_addr(target, port)?;
    let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    Ok((mesh_addr, listen))
}

fn default_mesh_addr(target: &ProxyTarget, port: u16) -> Result<String> {
    match target.kind {
        ProxyTargetKind::DockerCompose => Ok(format!("host.docker.internal:{port}")),
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

fn pick_free_port() -> Result<u16> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .into_diagnostic()?;
    Ok(listener.local_addr().into_diagnostic()?.port())
}

fn resolve_control_addr(args: &ProxyArgs, target: &ProxyTarget) -> Result<String> {
    if let Some(addr) = args.router_control_addr.as_ref() {
        return Ok(addr.clone());
    }
    let router = target
        .metadata
        .router
        .as_ref()
        .ok_or_else(|| miette::miette!("router metadata missing; re-run `amber compile`"))?;
    Ok(format!("127.0.0.1:{}", router.control_port))
}

async fn register_control_with_retry(addr: String, slot: String, url: String, env_var: String) {
    loop {
        match try_send_control_update(&addr, &slot, &url).await {
            Ok(()) => {
                println!("registered slot {slot} via router control ({addr})");
                return;
            }
            Err(ControlUpdateError::Retryable) => {
                sleep(Duration::from_millis(250)).await;
            }
            Err(ControlUpdateError::Fatal(err)) => {
                eprintln!(
                    "failed to register slot via router control ({}): {err}\nfallback: set \
                     {env_var}={url} before starting the scenario",
                    addr
                );
                return;
            }
        }
    }
}

enum ControlUpdateError {
    Retryable,
    Fatal(String),
}

async fn try_send_control_update(
    addr: &str,
    slot: &str,
    url: &str,
) -> Result<(), ControlUpdateError> {
    let payload = serde_json::json!({ "url": url }).to_string();
    let request = format!(
        "PUT /external-slots/{slot} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: \
         application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|_| ControlUpdateError::Retryable)?;
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| ControlUpdateError::Retryable)?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|_| ControlUpdateError::Retryable)?;
    let response = String::from_utf8_lossy(&buf);
    let status_line = response.lines().next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(ControlUpdateError::Retryable)?;
    if !(200..300).contains(&code) {
        return Err(if code >= 500 {
            ControlUpdateError::Retryable
        } else {
            ControlUpdateError::Fatal(format!("router control returned HTTP {code}"))
        });
    }
    Ok(())
}

fn mesh_protocol_from_metadata(protocol: &str) -> Result<MeshProtocol> {
    Ok(match protocol {
        "http" | "https" => MeshProtocol::Http,
        "tcp" => MeshProtocol::Tcp,
        "udp" => MeshProtocol::Udp,
        _ => {
            return Err(miette::miette!(
                "unsupported network protocol for mesh routing"
            ));
        }
    })
}

#[derive(Default)]
struct DenySet {
    deny_warnings: bool,
    deny_codes: BTreeSet<String>,
}

impl DenySet {
    fn new(deny: &[String]) -> Self {
        let mut set = Self::default();
        for d in deny {
            if d == "warnings" {
                set.deny_warnings = true;
            } else {
                set.deny_codes.insert(d.clone());
            }
        }
        set
    }

    fn is_denied(&self, code: &str) -> bool {
        self.deny_warnings || self.deny_codes.contains(code)
    }
}

fn print_diagnostics(diagnostics: &[miette::Report], deny: &DenySet) -> Result<bool> {
    let mut has_error = false;
    let handler = GraphicalReportHandler::new();

    for report in diagnostics {
        let diagnostic: &dyn Diagnostic = &**report;
        let code = diagnostic.code().map(|c| c.to_string()).unwrap_or_default();
        let severity = diagnostic.severity().unwrap_or(Severity::Error);
        let denied = matches!(severity, Severity::Warning) && deny.is_denied(&code);
        let is_error = denied || matches!(severity, Severity::Error);
        if is_error {
            has_error = true;
        }

        if denied {
            let denied_by = if deny.deny_warnings {
                "-D warnings".to_string()
            } else if code.is_empty() {
                "-D <lint>".to_string()
            } else {
                format!("-D {code}")
            };
            let denied = DeniedDiagnostic {
                inner: diagnostic,
                denied_by,
            };
            render_report(&handler, &denied)?;
        } else {
            render_report(&handler, diagnostic)?;
        }
    }

    Ok(has_error)
}

fn render_report(handler: &GraphicalReportHandler, diagnostic: &dyn Diagnostic) -> Result<()> {
    let mut out = String::new();
    handler
        .render_report(&mut out, diagnostic)
        .map_err(|_| miette::miette!("failed to render diagnostics"))?;
    eprint!("{out}");
    Ok(())
}

#[derive(Debug)]
struct DeniedDiagnostic<'a> {
    inner: &'a dyn Diagnostic,
    denied_by: String,
}

impl fmt::Display for DeniedDiagnostic<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.inner, f)
    }
}

impl std::error::Error for DeniedDiagnostic<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

impl Diagnostic for DeniedDiagnostic<'_> {
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        self.inner.code()
    }

    fn severity(&self) -> Option<Severity> {
        Some(Severity::Error)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        let hint = format!(
            "warning treated as error because it was denied via `{}`",
            self.denied_by
        );
        match self.inner.help() {
            Some(inner) => Some(Box::new(format!("{hint}\n{inner}"))),
            None => Some(Box::new(hint)),
        }
    }

    fn url<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        self.inner.url()
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.inner.source_code()
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        self.inner.labels()
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        self.inner.related()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.inner.diagnostic_source()
    }
}

fn parse_manifest_ref(input: &str) -> Result<ManifestRef> {
    if let Ok(r) = input.parse::<ManifestRef>()
        && let Some(url) = r.url.as_url()
    {
        let is_windows_drive_path = !input.contains("://")
            && url.scheme().len() == 1
            && input.as_bytes().get(1) == Some(&b':');
        if !is_windows_drive_path {
            return Ok(r);
        }
    }

    let path = Path::new(input);
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().into_diagnostic()?.join(path)
    };
    let abs = abs.canonicalize().map_err(|e| {
        miette::miette!("failed to resolve manifest path `{}`: {}", abs.display(), e)
    })?;
    let url = url::Url::from_file_path(&abs)
        .map_err(|_| miette::miette!("could not convert `{}` into a file URL", abs.display()))?;

    Ok(ManifestRef::from_url(url))
}

struct ResolvedInput {
    manifest: ManifestRef,
    resolver: Resolver,
    registry: ResolverRegistry,
}

async fn resolve_input(input: &str) -> Result<ResolvedInput> {
    if let Some(path) = local_input_path(input)?
        && let Some(loader) = BundleLoader::from_path(&path)?
    {
        let bundle = loader.load().await?;
        return Ok(ResolvedInput {
            manifest: bundle.root,
            resolver: bundle.resolver,
            registry: bundle.registry,
        });
    }

    let manifest = parse_manifest_ref(input)?;
    Ok(ResolvedInput {
        manifest,
        resolver: Resolver::new(),
        registry: ResolverRegistry::default(),
    })
}

fn local_input_path(input: &str) -> Result<Option<PathBuf>> {
    if let Ok(url) = Url::parse(input) {
        if url.scheme() == "file" {
            let path = url
                .to_file_path()
                .map_err(|_| miette::miette!("could not convert `{input}` into a file path"))?;
            if !path.exists() {
                return Ok(None);
            }
            let path = path.canonicalize().map_err(|e| {
                miette::miette!("failed to resolve input path `{}`: {}", path.display(), e)
            })?;
            return Ok(Some(path));
        }

        let is_windows_drive_path = !input.contains("://")
            && url.scheme().len() == 1
            && input.as_bytes().get(1) == Some(&b':');
        if !is_windows_drive_path {
            return Ok(None);
        }
    }

    let path = Path::new(input);
    if !path.exists() {
        return Ok(None);
    }
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().into_diagnostic()?.join(path)
    };
    let abs = abs
        .canonicalize()
        .map_err(|e| miette::miette!("failed to resolve input path `{}`: {}", abs.display(), e))?;
    Ok(Some(abs))
}

enum ArtifactOutput {
    Stdout,
    File(PathBuf),
}

struct OutputPaths {
    primary: Option<PathBuf>,
    dot: Option<ArtifactOutput>,
    docker_compose: Option<ArtifactOutput>,
    metadata: Option<ArtifactOutput>,
    kubernetes: Option<PathBuf>,
}

fn ensure_outputs_requested(args: &CompileArgs) -> Result<()> {
    if args.output.is_some()
        || args.dot.is_some()
        || args.docker_compose.is_some()
        || args.metadata.is_some()
        || args.bundle.is_some()
        || args.kubernetes.is_some()
    {
        return Ok(());
    }

    Err(miette::miette!(
        help = "Request at least one output with `--output`, `--dot`, `--docker-compose`, \
                `--metadata`, `--kubernetes`, or `--bundle`.",
        "no outputs requested for `amber compile`"
    ))
}

fn resolve_output_paths(args: &CompileArgs) -> Result<OutputPaths> {
    let primary = args.output.clone();
    let dot = resolve_optional_output(&args.dot);
    let docker_compose = resolve_optional_output(&args.docker_compose);
    let metadata = resolve_optional_output(&args.metadata);
    let kubernetes = args.kubernetes.clone();

    if let (Some(primary_path), Some(ArtifactOutput::File(dot_path))) =
        (primary.as_ref(), dot.as_ref())
        && dot_path == primary_path
    {
        return Err(miette::miette!(
            "dot output path `{}` must not match the primary output path",
            dot_path.display()
        ));
    }

    if let (Some(primary_path), Some(ArtifactOutput::File(compose_path))) =
        (primary.as_ref(), docker_compose.as_ref())
        && compose_path == primary_path
    {
        return Err(miette::miette!(
            "docker compose output path `{}` must not match the primary output path",
            compose_path.display()
        ));
    }

    if let (Some(primary_path), Some(ArtifactOutput::File(metadata_path))) =
        (primary.as_ref(), metadata.as_ref())
        && metadata_path == primary_path
    {
        return Err(miette::miette!(
            "metadata output path `{}` must not match the primary output path",
            metadata_path.display()
        ));
    }

    if let (Some(ArtifactOutput::File(dot_path)), Some(ArtifactOutput::File(compose_path))) =
        (dot.as_ref(), docker_compose.as_ref())
        && dot_path == compose_path
    {
        return Err(miette::miette!(
            "dot output path `{}` must not match docker compose output path",
            dot_path.display()
        ));
    }

    if let (Some(ArtifactOutput::File(dot_path)), Some(ArtifactOutput::File(metadata_path))) =
        (dot.as_ref(), metadata.as_ref())
        && dot_path == metadata_path
    {
        return Err(miette::miette!(
            "dot output path `{}` must not match metadata output path",
            dot_path.display()
        ));
    }

    if let (Some(ArtifactOutput::File(compose_path)), Some(ArtifactOutput::File(metadata_path))) =
        (docker_compose.as_ref(), metadata.as_ref())
        && compose_path == metadata_path
    {
        return Err(miette::miette!(
            "docker compose output path `{}` must not match metadata output path",
            compose_path.display()
        ));
    }

    Ok(OutputPaths {
        primary,
        dot,
        docker_compose,
        metadata,
        kubernetes,
    })
}

fn resolve_optional_output(request: &Option<PathBuf>) -> Option<ArtifactOutput> {
    request.as_ref().map(|path| {
        if path.as_path() == Path::new("-") {
            ArtifactOutput::Stdout
        } else {
            ArtifactOutput::File(path.clone())
        }
    })
}

fn resolve_bundle_root(args: &CompileArgs) -> Result<Option<PathBuf>> {
    Ok(args.bundle.clone())
}

fn prepare_bundle_dir(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(miette::miette!(
            "bundle output directory `{}` already exists; please delete it first",
            path.display()
        ));
    }

    std::fs::create_dir_all(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create bundle directory `{}`", path.display()))?;
    Ok(())
}

fn write_primary_output(path: &Path, output: &CompileOutput) -> Result<()> {
    let ir = ScenarioIrReporter
        .emit(output)
        .map_err(miette::Report::new)?;
    write_artifact(path, ir.as_bytes())
        .wrap_err_with(|| format!("failed to write primary output `{}`", path.display()))
}

fn write_artifact(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create directory `{}`", parent.display()))?;
    }

    std::fs::write(path, contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write `{}`", path.display()))
}

fn write_kubernetes_output(
    root: &Path,
    artifact: &amber_compiler::reporter::kubernetes::KubernetesArtifact,
) -> Result<()> {
    // Clean and recreate the output directory.
    if root.exists() {
        if root.is_dir() {
            std::fs::remove_dir_all(root)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to remove kubernetes output directory `{}`",
                        root.display()
                    )
                })?;
        } else {
            return Err(miette::miette!(
                "kubernetes output path `{}` is not a directory",
                root.display()
            ));
        }
    }

    std::fs::create_dir_all(root)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create kubernetes output directory `{}`",
                root.display()
            )
        })?;

    // Write each file.
    for (rel_path, content) in &artifact.files {
        let full_path = root.join(rel_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create directory `{}`", parent.display()))?;
        }
        std::fs::write(&full_path, content)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to write `{}`", full_path.display()))?;
    }

    Ok(())
}
