use std::{
    collections::BTreeSet,
    fmt, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
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
    InboundRoute, InboundTarget, MeshConfig, MeshIdentity, MeshIdentityPublic, MeshPeer,
    MeshProtocol, OutboundRoute, TransportConfig, component_route_id, router_export_route_id,
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
    time::{Duration, Instant, sleep},
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

    /// External slot binding (repeatable): `name=127.0.0.1:PORT`.
    #[arg(long = "slot", value_name = "NAME=ADDR:PORT")]
    slot: Vec<String>,

    /// Export listener binding (repeatable): `name=127.0.0.1:PORT`.
    #[arg(long = "export", value_name = "NAME=ADDR:PORT")]
    export: Vec<String>,

    /// Mesh address to advertise to the router (slot mode).
    #[arg(long = "mesh-addr", value_name = "HOST:PORT")]
    mesh_addr: Option<String>,

    /// Router mesh address override (defaults to 127.0.0.1:<router mesh port>).
    #[arg(long = "router-addr", value_name = "ADDR:PORT")]
    router_addr: Option<std::net::SocketAddr>,

    /// Router control endpoint override (`HOST:PORT` or `unix:///path/to/socket`).
    #[arg(long = "router-control-addr", value_name = "HOST:PORT|unix:///PATH")]
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
    source: PathBuf,
}

#[derive(Clone, Debug)]
enum ControlEndpoint {
    Tcp(String),
    Unix(PathBuf),
}

impl fmt::Display for ControlEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(addr) => f.write_str(addr),
            Self::Unix(path) => write!(f, "unix://{}", path.display()),
        }
    }
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
    let slot_bindings = parse_slot_bindings(&args)?;
    let export_bindings = parse_export_bindings(&args)?;
    if slot_bindings.is_empty() && export_bindings.is_empty() {
        return Err(miette::miette!(
            "at least one --slot NAME=ADDR:PORT or --export NAME=ADDR:PORT is required"
        ));
    }

    let target = load_proxy_target(&args.output)?;
    let router_meta = target
        .metadata
        .router
        .as_ref()
        .ok_or_else(|| miette::miette!("router metadata missing; re-run `amber compile`"))?;
    let router_port = router_meta.mesh_port;
    if router_port == 0 {
        return Err(miette::miette!(
            "router mesh port is 0; compile output is missing router metadata"
        ));
    }

    let control_endpoint = resolve_control_endpoint(&args, &target)?;
    let router_identity = resolve_router_identity(&args, &control_endpoint).await?;
    let router_peer = MeshPeer {
        id: router_identity.id.clone(),
        public_key: router_identity.public_key,
    };
    let router_addr = args
        .router_addr
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], router_port)));
    let proxy_identity = build_proxy_identity("/proxy", &router_identity);
    let (mesh_addr, mesh_listen) = if slot_bindings.is_empty() {
        (None, SocketAddr::from(([127, 0, 0, 1], 0)))
    } else {
        let (mesh_addr, mesh_listen) = resolve_mesh_addresses(args.mesh_addr.as_deref(), &target)?;
        (Some(mesh_addr), mesh_listen)
    };
    let mut inbound = Vec::with_capacity(slot_bindings.len());
    let mut outbound = Vec::with_capacity(export_bindings.len());

    for binding in &export_bindings {
        let export = binding.export.as_str();
        let export_meta = target
            .metadata
            .exports
            .get(export)
            .ok_or_else(|| miette::miette!("export {} not found in output", export))?;
        let protocol = mesh_protocol_from_metadata(&export_meta.protocol)?;

        let register_payload = ControlExportPayload::new(&proxy_identity, &export_meta.protocol);
        register_export_with_retry(
            &control_endpoint,
            export,
            &register_payload,
            EXPORT_REGISTRATION_TIMEOUT,
        )
        .await
        .map_err(|err| match err {
            ExportRegistrationError::Timeout(timeout) => miette::miette!(
                "timed out after {}s waiting to register export {} via router control ({})",
                timeout.as_secs(),
                export,
                control_endpoint
            ),
            ExportRegistrationError::Fatal(reason) => miette::miette!(
                "failed to register export via router control ({}): {}",
                control_endpoint,
                reason
            ),
        })?;
        println!("registered export {export} via router control ({control_endpoint})");
        outbound.push(OutboundRoute {
            route_id: router_export_route_id(export, protocol),
            slot: export.to_string(),
            listen_port: binding.listen.port(),
            listen_addr: Some(binding.listen.ip().to_string()),
            protocol,
            peer_addr: router_addr.to_string(),
            peer_id: router_identity.id.clone(),
            capability: export.to_string(),
        });

        let local_url = match protocol {
            MeshProtocol::Http => format!("http://{}", binding.listen),
            MeshProtocol::Tcp => format!("tcp://{}", binding.listen),
        };
        println!("export {export} -> {local_url}");
    }

    if let Some(mesh_addr) = mesh_addr.as_ref() {
        let peer_key = base64::engine::general_purpose::STANDARD.encode(proxy_identity.public_key);
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("peer_id", &proxy_identity.id)
            .append_pair("peer_key", &peer_key)
            .finish();
        let mesh_url = format!("mesh://{mesh_addr}?{query}");
        for binding in &slot_bindings {
            let slot = binding.slot.as_str();
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
            inbound.push(InboundRoute {
                route_id: component_route_id(&proxy_identity.id, slot, MeshProtocol::Http),
                capability: slot.to_string(),
                protocol: MeshProtocol::Http,
                target: InboundTarget::Local {
                    port: binding.upstream.port(),
                },
                allowed_issuers: vec![router_identity.id.clone()],
            });
            let env_var = if slot_meta.url_env.is_empty() {
                external_slot_env_var(slot)
            } else {
                slot_meta.url_env.clone()
            };
            match try_send_control_update(&control_endpoint, slot, &mesh_url).await {
                Ok(()) => {
                    println!("registered slot {slot} via router control ({control_endpoint})");
                }
                Err(ControlUpdateError::Retryable) => {
                    eprintln!("waiting for router control at {control_endpoint}...");
                    let control_endpoint = control_endpoint.clone();
                    let slot = slot.to_string();
                    let mesh_url = mesh_url.clone();
                    let env_var = env_var.clone();
                    tokio::spawn(async move {
                        register_control_with_retry(control_endpoint, slot, mesh_url, env_var)
                            .await;
                    });
                }
                Err(ControlUpdateError::Fatal(err)) => {
                    eprintln!(
                        "failed to register slot via router control ({}): {err}\nfallback: set \
                         {env_var}={mesh_url} before starting the scenario",
                        control_endpoint
                    );
                }
            }
            println!("slot {slot} -> http://{}", binding.upstream);
            println!("slot {slot} mesh endpoint -> {mesh_addr}");
        }
    }

    let config = MeshConfig {
        identity: proxy_identity,
        mesh_listen,
        control_listen: None,
        control_allow: None,
        peers: vec![router_peer],
        inbound,
        outbound,
        transport: TransportConfig::NoiseIk {},
    };

    router::run(config)
        .await
        .map_err(|err| miette::miette!("proxy failed: {err}"))
}

async fn resolve_router_identity(
    args: &ProxyArgs,
    control_endpoint: &ControlEndpoint,
) -> Result<MeshIdentityPublic> {
    if let Some(config) = load_router_config_optional(args)? {
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
                        "timed out after {}s waiting to fetch router identity via control \
                         ({})\nfallback: pass --router-config/--router-config-b64 or set \
                         AMBER_ROUTER_CONFIG_B64",
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
                    "failed to fetch router identity via control ({}): {err}\nfallback: pass \
                     --router-config/--router-config-b64 or set AMBER_ROUTER_CONFIG_B64",
                    control_endpoint
                ));
            }
        }
    }
}

fn load_router_config_optional(args: &ProxyArgs) -> Result<Option<MeshConfig>> {
    if let Some(b64) = args.router_config_b64.as_ref() {
        return amber_mesh::decode_config_b64(b64)
            .map(Some)
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
            return Ok(Some(parsed));
        }
        return amber_mesh::decode_config_b64(trimmed)
            .map(Some)
            .map_err(|err| miette::miette!("invalid router config: {err}"));
    }

    if let Ok(b64) = std::env::var("AMBER_ROUTER_CONFIG_B64") {
        return amber_mesh::decode_config_b64(&b64)
            .map(Some)
            .map_err(|err| miette::miette!("invalid router config: {err}"));
    }

    if let Ok(raw) = std::env::var("AMBER_ROUTER_CONFIG_JSON") {
        let parsed = serde_json::from_str(&raw)
            .map_err(|err| miette::miette!("invalid router config: {err}"))?;
        return Ok(Some(parsed));
    }

    Ok(None)
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
            source: metadata_path,
        });
    }

    if abs.file_name().and_then(|name| name.to_str()) == Some(PROXY_METADATA_FILENAME) {
        let metadata = load_proxy_metadata_file(&abs)?;
        validate_proxy_metadata(&metadata, &abs)?;
        return Ok(ProxyTarget {
            kind: ProxyTargetKind::Kubernetes,
            metadata,
            source: abs,
        });
    }

    let metadata = load_compose_metadata(&abs)?;
    validate_proxy_metadata(&metadata, &abs)?;
    Ok(ProxyTarget {
        kind: ProxyTargetKind::DockerCompose,
        metadata,
        source: abs,
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

fn parse_slot_bindings(args: &ProxyArgs) -> Result<Vec<SlotBinding>> {
    let mut bindings = Vec::with_capacity(args.slot.len());
    let mut seen_slots = BTreeSet::new();
    for raw in &args.slot {
        let (slot, upstream) = parse_named_socket_addr(raw, "--slot")?;
        if !seen_slots.insert(slot.clone()) {
            return Err(miette::miette!("duplicate --slot binding for {}", slot));
        }
        if !upstream.ip().is_loopback() {
            return Err(miette::miette!(
                "--slot {} must target a loopback upstream (got {})",
                slot,
                upstream
            ));
        }
        bindings.push(SlotBinding { slot, upstream });
    }
    Ok(bindings)
}

fn parse_export_bindings(args: &ProxyArgs) -> Result<Vec<ExportBinding>> {
    let mut bindings = Vec::with_capacity(args.export.len());
    for raw in &args.export {
        let (export, listen) = parse_named_socket_addr(raw, "--export")?;
        bindings.push(ExportBinding { export, listen });
    }
    Ok(bindings)
}

fn parse_named_socket_addr(value: &str, flag: &str) -> Result<(String, SocketAddr)> {
    let (name, addr) = value.split_once('=').ok_or_else(|| {
        miette::miette!("invalid {} value {}; expected NAME=ADDR:PORT", flag, value)
    })?;
    let name = name.trim();
    if name.is_empty() {
        return Err(miette::miette!(
            "invalid {} value {}; name must not be empty",
            flag,
            value
        ));
    }
    let addr = addr.trim().parse::<SocketAddr>().map_err(|err| {
        miette::miette!(
            "invalid {} value {}; address must be ADDR:PORT ({})",
            flag,
            value,
            err
        )
    })?;
    if addr.port() == 0 {
        return Err(miette::miette!(
            "invalid {} value {}; port must be non-zero",
            flag,
            value
        ));
    }
    Ok((name.to_string(), addr))
}

fn resolve_mesh_addresses(
    mesh_addr_override: Option<&str>,
    target: &ProxyTarget,
) -> Result<(String, SocketAddr)> {
    if let Some(mesh_addr) = mesh_addr_override {
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

fn resolve_control_endpoint(args: &ProxyArgs, target: &ProxyTarget) -> Result<ControlEndpoint> {
    if let Some(value) = args.router_control_addr.as_ref() {
        return parse_control_endpoint(value);
    }

    let router = target
        .metadata
        .router
        .as_ref()
        .ok_or_else(|| miette::miette!("router metadata missing; re-run `amber compile`"))?;
    if let Some(socket) = router.control_socket.as_ref() {
        let compose_project = match target.kind {
            ProxyTargetKind::DockerCompose => infer_default_compose_project_name(&target.source),
            ProxyTargetKind::Kubernetes => None,
        };
        let resolved = expand_env_templates(socket, compose_project.as_deref())?;
        return Ok(ControlEndpoint::Unix(PathBuf::from(resolved)));
    }
    if matches!(target.kind, ProxyTargetKind::DockerCompose) {
        return Err(miette::miette!(
            "docker-compose output is missing router control socket metadata; re-run `amber \
             compile`"
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

fn parse_control_endpoint(value: &str) -> Result<ControlEndpoint> {
    if let Some(path) = value.strip_prefix("unix://") {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err(miette::miette!(
                "invalid --router-control-addr {}; expected unix:///absolute/path",
                value
            ));
        }
        if !Path::new(trimmed).is_absolute() {
            return Err(miette::miette!(
                "invalid --router-control-addr {}; expected unix:///absolute/path",
                value
            ));
        }
        return Ok(ControlEndpoint::Unix(PathBuf::from(trimmed)));
    }
    Ok(ControlEndpoint::Tcp(value.to_string()))
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
            let value = env_var_non_empty(name)
                .ok()
                .or_else(|| {
                    (name == "COMPOSE_PROJECT_NAME")
                        .then(|| compose_project_name.map(ToOwned::to_owned))
                        .flatten()
                })
                .unwrap_or_else(|| default.to_string());
            out.push_str(&value);
        } else {
            let value = std::env::var(expr)
                .ok()
                .or_else(|| {
                    (expr == "COMPOSE_PROJECT_NAME")
                        .then(|| compose_project_name.map(ToOwned::to_owned))
                        .flatten()
                })
                .unwrap_or_default();
            out.push_str(&value);
        }
        cursor = end + 1;
    }
    out.push_str(&input[cursor..]);
    Ok(out)
}

fn env_var_non_empty(name: &str) -> Result<String, std::env::VarError> {
    std::env::var(name).and_then(|value| {
        if value.is_empty() {
            Err(std::env::VarError::NotPresent)
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

const CONTROL_UPDATE_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const EXPORT_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(30);
const ROUTER_IDENTITY_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const CONTROL_CURL_IMAGE: &str = "curlimages/curl:8.12.1";

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
                eprintln!(
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
            Ok(()) => {
                return Ok(());
            }
            Err(ControlUpdateError::Retryable) => {
                if Instant::now() >= deadline {
                    return Err(ExportRegistrationError::Timeout(timeout));
                }
                if !warned {
                    eprintln!("waiting for router control at {endpoint}...");
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
    let identity: MeshIdentityPublic = serde_json::from_str(body.trim()).map_err(|err| {
        ControlUpdateError::Fatal(format!("invalid router identity payload: {err}"))
    })?;
    Ok(identity)
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
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|_| ControlUpdateError::Retryable)?;
            send_request(stream, request).await
        }
        ControlEndpoint::Unix(path) => match tokio::net::UnixStream::connect(path).await {
            Ok(stream) => match send_request(stream, request).await {
                Ok(response) if looks_like_http_response(&response) => Ok(response),
                Ok(_) => send_control_request_via_container(path, request).await,
                Err(ControlUpdateError::Retryable) => {
                    send_control_request_via_container(path, request).await
                }
                Err(err) => Err(err),
            },
            Err(err) if is_retryable_unix_connect_error(&err) => {
                send_control_request_via_container(path, request).await
            }
            Err(_) => send_control_request_via_container(path, request).await,
        },
    }
}

fn looks_like_http_response(response: &str) -> bool {
    response
        .lines()
        .next()
        .is_some_and(|line| line.starts_with("HTTP/"))
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

async fn send_control_request_via_container(
    socket_path: &Path,
    request: &str,
) -> Result<String, ControlUpdateError> {
    let (method, path, body) = parse_control_request(request)?;
    let socket_dir = socket_path.parent().ok_or_else(|| {
        ControlUpdateError::Fatal(format!(
            "invalid unix control path (missing parent): {}",
            socket_path.display()
        ))
    })?;
    let socket_file = socket_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ControlUpdateError::Fatal(format!(
                "invalid unix control path (missing filename): {}",
                socket_path.display()
            ))
        })?;

    let mut last_error = None::<String>;
    for runtime in ["docker", "podman"] {
        let socket_mount = format!("{}:/amber/control", socket_dir.display());
        let mut cmd = ProcessCommand::new(runtime);
        cmd.arg("run")
            .arg("--rm")
            .arg("--network")
            .arg("none")
            .arg("-v")
            .arg(socket_mount)
            .arg(CONTROL_CURL_IMAGE)
            .arg("--unix-socket")
            .arg(format!("/amber/control/{socket_file}"))
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
        let message = if stderr.is_empty() {
            format!("{runtime} run exited with status {}", output.status)
        } else {
            format!("{runtime} run failed: {stderr}")
        };
        last_error = Some(message);
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
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| ControlUpdateError::Retryable)?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
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
        && r.url.as_url().is_some()
    {
        return Ok(r);
    }

    let abs = canonicalize_user_path(Path::new(input), "manifest path")?;
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
            return canonicalize_user_path(&path, "input path").map(Some);
        }
        return Ok(None);
    }

    let path = Path::new(input);
    if !path.exists() {
        return Ok(None);
    }
    canonicalize_user_path(path, "input path").map(Some)
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

    let outputs = [
        ("primary output", primary.as_deref()),
        ("dot output", artifact_file_path(dot.as_ref())),
        (
            "docker compose output",
            artifact_file_path(docker_compose.as_ref()),
        ),
        ("metadata output", artifact_file_path(metadata.as_ref())),
    ];
    for (index, (left_name, left_path)) in outputs.iter().enumerate() {
        let Some(left_path) = left_path else {
            continue;
        };
        for (right_name, right_path) in outputs.iter().skip(index + 1) {
            if right_path.is_some_and(|right_path| right_path == *left_path) {
                return Err(miette::miette!(
                    "{} path `{}` must not match {} path",
                    left_name,
                    left_path.display(),
                    right_name
                ));
            }
        }
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

fn artifact_file_path(output: Option<&ArtifactOutput>) -> Option<&Path> {
    match output {
        Some(ArtifactOutput::File(path)) => Some(path.as_path()),
        _ => None,
    }
}

fn canonicalize_user_path(path: &Path, context: &str) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().into_diagnostic()?.join(path)
    };
    path.canonicalize()
        .map_err(|err| miette::miette!("failed to resolve {context} `{}`: {err}", path.display()))
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
