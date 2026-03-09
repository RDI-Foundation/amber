mod docs;

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::io::Read as _;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env, fmt, fs,
    hash::{Hash as _, Hasher as _},
    io::Write as _,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
};

use amber_compiler::{
    CompileOptions, Compiler, ResolverRegistry,
    bundle::{BundleBuilder, BundleLoader},
    mesh::{PROXY_METADATA_FILENAME, PROXY_METADATA_VERSION, ProxyMetadata, external_slot_env_var},
    reporter::{
        CompiledScenario, Reporter as _,
        direct::{
            DIRECT_PLAN_FILENAME, DIRECT_PLAN_VERSION, DirectArtifact, DirectComponentPlan,
            DirectPlan, DirectProgramExecutionPlan, DirectReporter, DirectRuntimeAddressPlan,
            DirectRuntimeConfigPayload, DirectRuntimeUrlSource, RUN_SCRIPT_FILENAME,
        },
        docker_compose::{COMPOSE_FILENAME, DockerComposeReporter},
        dot::DotReporter,
        kubernetes::KubernetesReporter,
        metadata::MetadataReporter,
        scenario_ir::ScenarioIrReporter,
    },
};
use amber_manifest::ManifestRef;
use amber_mesh::{
    InboundRoute, InboundTarget, MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME,
    MESH_PROVISION_PLAN_VERSION, MeshConfig, MeshConfigPublic, MeshIdentity, MeshIdentityPublic,
    MeshIdentitySecret, MeshPeer, MeshProtocol, MeshProvisionOutput, MeshProvisionPlan,
    MeshProvisionTarget, OutboundRoute, TransportConfig, component_route_id,
    router_export_route_id,
    telemetry::{
        OtlpIdentity, OtlpInstallMode, SubscriberFormat, SubscriberOptions, init_otel_tracer,
        init_subscriber, observability_log_scope_name, shutdown_tracer_provider,
        suppress_otlp_bridge_target,
    },
};
use amber_resolver::Resolver;
use amber_router as router;
use amber_scenario::{SCENARIO_IR_SCHEMA, ScenarioIr};
use amber_template::{
    ProgramArgTemplate, RuntimeSlotObject, RuntimeTemplateContext, TemplatePart, TemplateSpec,
};
use base64::Engine as _;
use clap::{ArgAction, Args, Parser, Subcommand};
use miette::{
    Context as _, Diagnostic, GraphicalReportHandler, IntoDiagnostic as _, Result, Severity,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    process::Command as TokioCommand,
    time::{Duration, Instant, sleep},
};
use tracing_subscriber::EnvFilter;
use url::{Url, form_urlencoded};

const CLI_LONG_ABOUT: &str = "\
Compile, inspect, and run Amber scenarios.

Amber resolves a root manifest or bundle, validates the component graph, and writes the artifacts \
                              you need to inspect or run the scenario.

Use `amber <command> --help` to drill into a specific workflow.";

const CLI_AFTER_HELP: &str = "\
Common workflows:
  amber check path/to/root.json5
      Validate manifests and print diagnostics without writing outputs.

  amber compile path/to/root.json5 --docker-compose /tmp/amber-compose
      Generate runtime artifacts. `amber compile --help` lists every output format.

  amber compile path/to/root.json5 --direct /tmp/amber-direct
  amber run /tmp/amber-direct
      Build and start the direct/native runtime locally.

  amber proxy /tmp/amber-compose --export public=127.0.0.1:18080
      Expose scenario exports or wire external slots on localhost.

  amber docs readme
      Read the embedded project and CLI reference from the binary.";

const COMPILE_LONG_ABOUT: &str = "\
Resolve a root manifest or bundle, run the Amber compiler, print diagnostics, and write one or \
                                  more requested outputs.

If you only want validation, use `amber check` instead.

At least one output flag is required.";

const COMPILE_AFTER_HELP: &str = "\
Outputs:
  --output FILE
      Scenario IR JSON for inspection or downstream tooling.

  --dot FILE
      Graphviz DOT for visualizing the resolved graph.

  --docker-compose DIR
      Docker Compose runtime directory with embedded proxy metadata for `amber proxy`.

  --metadata FILE
      Per-component metadata JSON for tooling or debugging.

  --kubernetes DIR
      Kubernetes manifests plus proxy metadata.

  --direct DIR
      Native/direct runtime artifacts for `amber run` and `amber proxy`.

  --bundle DIR
      Self-contained manifest bundle for offline or reproducible compilation.

Examples:
  amber compile path/to/root.json5 --output /tmp/scenario.json
  amber compile path/to/root.json5 --docker-compose /tmp/amber-compose
  amber compile path/to/root.json5 --direct /tmp/amber-direct";

const CHECK_LONG_ABOUT: &str = "\
Resolve a root manifest or bundle, run the same validation and lint passes as `amber compile`, \
                                print diagnostics, and stop before emitting artifacts.";

const CHECK_AFTER_HELP: &str = "\
Examples:
  amber check path/to/root.json5
  amber check -D warnings path/to/root.json5

Use `amber compile --help` when you are ready to write outputs.";

const DOCS_LONG_ABOUT: &str = "\
Print documentation that ships inside the CLI.

Use this when you want README material, schema docs, or embedded examples without browsing the \
                               repo.";

const DOCS_AFTER_HELP: &str = "\
Docs subcommands:
  amber docs readme
      Project overview plus CLI reference.

  amber docs manifest
      Full manifest schema and examples.

  amber docs examples
      List embedded examples.

  amber docs examples reexport
      Dump one example's files.";

const DOCS_README_LONG_ABOUT: &str = "\
Print the top-level Amber README that ships inside the CLI.

This is the quickest way to get the project overview, common workflows, and the CLI reference \
                                      without opening the repo.";

const DOCS_EXAMPLES_LONG_ABOUT: &str = "\
List the examples embedded into the CLI, or print every file from one named example.

Use this to discover example scenarios from the terminal, then inspect a specific example without \
                                        opening the repo.";

const DOCS_EXAMPLES_AFTER_HELP: &str = "\
Examples:
  amber docs examples
  amber docs examples reexport";

const DOCS_MANIFEST_LONG_ABOUT: &str = "\
Print the manifest schema README that ships inside the CLI.

Use this for the detailed manifest format, field semantics, and authoring examples.";

const RUN_LONG_ABOUT: &str = "\
Start a previously compiled direct output directory or a `direct-plan.json` file.

This command only understands direct/native artifacts produced by `amber compile --direct`.";

const RUN_AFTER_HELP: &str = "\
Examples:
  amber run /tmp/amber-direct
  amber run /tmp/amber-direct/direct-plan.json
  amber run /tmp/amber-direct --storage-root /srv/amber-state

Runtime requirements:
  Linux: `bwrap` and `slirp4netns`
  macOS: `/usr/bin/sandbox-exec`";

const PROXY_LONG_ABOUT: &str = "\
Attach a local proxy to compiled Amber output.

Use `--export` to expose a scenario export on localhost, `--slot` to connect a scenario slot to a \
                                local upstream, or both at once.

Pass at least one `--export` or `--slot` binding.

The output can be a Docker Compose output directory, a Kubernetes output directory, or a direct \
                                output directory.";

const PROXY_AFTER_HELP: &str = "\
Examples:
  amber proxy /tmp/amber-compose --export public=127.0.0.1:18080

  amber proxy /tmp/amber-compose \\
    --slot ext_api=127.0.0.1:38081 \\
    --export public=127.0.0.1:38080

  amber proxy /tmp/amber-k8s \\
    --mesh-addr 127.0.0.1:24000 \\
    --router-addr 127.0.0.1:24000 \\
    --router-control-addr 127.0.0.1:24100 \\
    --export public=127.0.0.1:18080

Notes:
  At least one `--slot NAME=ADDR:PORT` or `--export NAME=ADDR:PORT` is required.
  Docker Compose and direct outputs usually infer router control metadata automatically.
  If you start Docker Compose with `-p <name>` before the stack is running, pass the same \
                                `--project-name <name>` to `amber proxy`.
  Kubernetes output requires `--mesh-addr` when you use `--slot`, unless you are supplying an \
                                equivalent override.";

const DASHBOARD_LONG_ABOUT: &str = "\
Start the dashboard container that Amber scenarios can send OpenTelemetry data to.

This is mainly useful when debugging scenarios locally or following one of the observability \
                                    tutorials.";

const DASHBOARD_AFTER_HELP: &str = concat!(
    "Examples:\n",
    "  amber dashboard\n",
    "  amber dashboard --detach\n\n",
    "Requirements:\n",
    "  Docker CLI plus a running Docker daemon.\n\n",
    "Default UI address: http://127.0.0.1:18888"
);

#[derive(Parser)]
#[command(name = "amber")]
#[command(version)]
#[command(about = "Compile, inspect, and run Amber scenarios")]
#[command(long_about = CLI_LONG_ABOUT)]
#[command(after_help = CLI_AFTER_HELP)]
struct Cli {
    /// Increase log verbosity (-v, -vv, -vvv, -vvvv).
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(
        about = "Compile a manifest into Scenario IR and runtime artifacts",
        long_about = COMPILE_LONG_ABOUT,
        after_help = COMPILE_AFTER_HELP
    )]
    Compile(CompileArgs),
    #[command(
        about = "Validate a manifest tree without writing outputs",
        long_about = CHECK_LONG_ABOUT,
        after_help = CHECK_AFTER_HELP
    )]
    Check(CheckArgs),
    #[command(
        about = "Read embedded Amber documentation",
        long_about = DOCS_LONG_ABOUT,
        after_help = DOCS_AFTER_HELP
    )]
    Docs(DocsArgs),
    #[command(
        about = "Run a direct/native Amber artifact locally",
        long_about = RUN_LONG_ABOUT,
        after_help = RUN_AFTER_HELP
    )]
    Run(RunArgs),
    #[command(
        about = "Bridge scenario exports and external slots to the host",
        long_about = PROXY_LONG_ABOUT,
        after_help = PROXY_AFTER_HELP
    )]
    Proxy(ProxyArgs),
    #[command(
        about = "Run the Aspire dashboard for Amber telemetry",
        long_about = DASHBOARD_LONG_ABOUT,
        after_help = DASHBOARD_AFTER_HELP
    )]
    Dashboard(DashboardArgs),
    #[command(hide = true, name = "run-direct-init")]
    RunDirectInit(RunDirectInitArgs),
}

#[derive(Args)]
struct CompileArgs {
    /// Treat the given lints as errors (e.g. `warnings`, `manifest::unused_slot`).
    #[arg(short = 'D', long = "deny", value_name = "LINT")]
    deny: Vec<String>,

    /// Write Scenario IR JSON to this path.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,

    /// Write Graphviz DOT output to this path, or `-` for stdout.
    #[arg(long = "dot", value_name = "FILE", allow_hyphen_values = true)]
    dot: Option<PathBuf>,

    /// Write Docker Compose runtime artifacts to this directory.
    #[arg(long = "docker-compose", visible_alias = "compose", value_name = "DIR")]
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

    /// Write direct/native runtime artifact files to this directory.
    #[arg(long = "direct", value_name = "DIR")]
    direct: Option<PathBuf>,

    /// Disable compiler optimizations.
    #[arg(long = "no-opt")]
    no_opt: bool,

    /// Root manifest, bundle, or Scenario IR to compile (URL or local path).
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
    #[command(
        about = "Print the top-level Amber README",
        long_about = DOCS_README_LONG_ABOUT
    )]
    Readme,

    #[command(
        about = "List embedded examples or print one example's files",
        long_about = DOCS_EXAMPLES_LONG_ABOUT,
        after_help = DOCS_EXAMPLES_AFTER_HELP
    )]
    Examples(DocsExamplesArgs),

    #[command(
        about = "Print the manifest schema README",
        long_about = DOCS_MANIFEST_LONG_ABOUT
    )]
    Manifest,
}

#[derive(Args)]
struct DocsExamplesArgs {
    /// Example name to dump. Omit to list available examples.
    #[arg(value_name = "EXAMPLE")]
    example: Option<String>,
}

#[derive(Args)]
struct RunArgs {
    /// Direct output directory or `direct-plan.json` file from `amber compile --direct`.
    #[arg(value_name = "OUTPUT")]
    output: String,

    /// Override where Amber stores persistent direct runtime state.
    #[arg(long = "storage-root", value_name = "DIR")]
    storage_root: Option<PathBuf>,
}

#[derive(Args)]
struct RunDirectInitArgs {
    /// Path to a direct runtime plan JSON file.
    #[arg(long = "plan", value_name = "FILE")]
    plan: PathBuf,

    /// Override where Amber stores persistent direct runtime state.
    #[arg(long = "storage-root", value_name = "DIR")]
    storage_root: Option<PathBuf>,
}

#[derive(Args)]
struct ProxyArgs {
    /// Docker Compose output directory, direct output directory, or Kubernetes output directory from `amber compile`.
    #[arg(value_name = "OUTPUT")]
    output: String,

    /// Compose project name override for Docker Compose outputs.
    #[arg(long = "project-name", value_name = "NAME")]
    project_name: Option<String>,

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

#[derive(Args)]
struct DashboardArgs {
    /// Docker image to run for the dashboard.
    #[arg(long = "image", value_name = "IMAGE")]
    image: Option<String>,

    /// Docker container name for the dashboard.
    #[arg(long = "name", value_name = "NAME", default_value = "amber-dashboard")]
    name: String,

    /// Dashboard frontend listen address on the host.
    #[arg(
        long = "ui-addr",
        value_name = "HOST:PORT",
        default_value = "127.0.0.1:18888"
    )]
    ui_addr: SocketAddr,

    /// Dashboard OTLP/gRPC listen address on the host.
    #[arg(
        long = "otlp-grpc-addr",
        value_name = "HOST:PORT",
        default_value = "127.0.0.1:18889"
    )]
    otlp_grpc_addr: SocketAddr,

    /// Dashboard OTLP/HTTP (protobuf) listen address on the host.
    #[arg(
        long = "otlp-http-addr",
        value_name = "HOST:PORT",
        default_value = "127.0.0.1:18890"
    )]
    otlp_http_addr: SocketAddr,

    /// Run the dashboard in the background.
    #[arg(long = "detach")]
    detach: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyTargetKind {
    DockerCompose,
    Kubernetes,
    Direct,
}

struct ProxyTarget {
    kind: ProxyTargetKind,
    metadata: ProxyMetadata,
    source: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunTargetKind {
    Direct,
}

struct RunTarget {
    kind: RunTargetKind,
    plan: PathBuf,
}

#[derive(Clone, Debug)]
enum ControlEndpoint {
    Tcp(String),
    Unix(PathBuf),
    VolumeSocket { volume: String, socket_path: String },
}

impl fmt::Display for ControlEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(addr) => f.write_str(addr),
            Self::Unix(path) => write!(f, "unix://{}", path.display()),
            Self::VolumeSocket {
                volume,
                socket_path,
            } => {
                write!(f, "volume://{volume}{socket_path}")
            }
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
    let verbose = cli.verbose;

    let result = match cli.command {
        Command::Proxy(args) => proxy(args, verbose).await,
        command => {
            init_tracing(verbose, None)?;
            match command {
                Command::Compile(args) => compile(args).await,
                Command::Check(args) => check(args).await,
                Command::Docs(args) => docs(args),
                Command::Run(args) => run(args).await,
                Command::Dashboard(args) => dashboard(args).await,
                Command::RunDirectInit(args) => run_direct_init(args).await,
                Command::Proxy(_) => unreachable!("handled above"),
            }
        }
    };

    shutdown_tracer_provider();
    result
}

async fn dashboard(args: DashboardArgs) -> Result<()> {
    let image = args
        .image
        .unwrap_or_else(|| "mcr.microsoft.com/dotnet/nightly/aspire-dashboard".to_string());

    println!("dashboard ui: http://{}", args.ui_addr);
    println!("dashboard otlp grpc: http://{}", args.otlp_grpc_addr);
    println!("dashboard otlp http: http://{}", args.otlp_http_addr);
    println!(
        "from docker compose containers use: http://host.docker.internal:{}",
        args.otlp_http_addr.port()
    );

    let mut cmd = ProcessCommand::new("docker");
    cmd.arg("run");
    if args.detach {
        cmd.arg("-d");
    } else {
        cmd.arg("--rm");
    }
    cmd.args(["--name", &args.name]);
    cmd.args([
        "-p",
        &format!("{}:18888", args.ui_addr),
        "-p",
        &format!("{}:18889", args.otlp_grpc_addr),
        "-p",
        &format!("{}:18890", args.otlp_http_addr),
    ]);
    cmd.args([
        "-e",
        "DOTNET_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS=true",
        "-e",
        "ASPNETCORE_URLS=http://0.0.0.0:18888",
        "-e",
        "DOTNET_DASHBOARD_OTLP_ENDPOINT_URL=http://0.0.0.0:18889",
        "-e",
        "DOTNET_DASHBOARD_OTLP_HTTP_ENDPOINT_URL=http://0.0.0.0:18890",
    ]);
    cmd.arg(image);

    let status = cmd
        .status()
        .map_err(|err| miette::miette!("failed to run docker: {err}"))?;
    if !status.success() {
        return Err(miette::miette!("dashboard exited with status {status}"));
    }
    Ok(())
}

fn verbosity_level(verbose: u8) -> &'static str {
    match verbose {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    }
}

fn console_filter_spec(verbose: u8) -> String {
    let level = verbosity_level(verbose);
    format!(
        "error,amber={level},amber_={level},amber_router={level},amber.binding={level},amber.\
         proxy={level}"
    )
}

fn proxy_telemetry_filter_spec(verbose: u8) -> String {
    let amber_level = verbosity_level(verbose);
    let router_level = match verbose {
        0..=2 => "info",
        3 => "debug",
        _ => "trace",
    };
    format!(
        "error,amber={amber_level},amber_={amber_level},amber_router={router_level},amber.\
         proxy={amber_level}"
    )
}

fn init_tracing(verbose: u8, otel_identity: Option<&MeshIdentity>) -> Result<()> {
    let (filter, telemetry_filter) = if std::env::var_os("RUST_LOG").is_some() {
        let filter = EnvFilter::try_from_default_env().into_diagnostic()?;
        let telemetry_filter = otel_identity.is_some().then(|| {
            suppress_otlp_bridge_target(
                suppress_otlp_bridge_target(filter.clone(), "amber.binding"),
                "amber.internal",
            )
        });
        (filter, telemetry_filter)
    } else {
        let filter = EnvFilter::new(console_filter_spec(verbose));
        let telemetry_filter = otel_identity.is_some().then(|| {
            suppress_otlp_bridge_target(
                suppress_otlp_bridge_target(
                    EnvFilter::new(proxy_telemetry_filter_spec(verbose)),
                    "amber.binding",
                ),
                "amber.internal",
            )
        });
        (filter, telemetry_filter)
    };

    let tracer = if let Some(identity) = otel_identity {
        match init_otel_tracer(
            OtlpIdentity {
                moniker: identity.id.as_str(),
                component_kind: None,
                scenario_scope: identity.mesh_scope.as_deref(),
            },
            OtlpInstallMode::BatchTokio,
        ) {
            Ok(tracer) => tracer,
            Err(err) => {
                eprintln!("warning: failed to initialize OTLP tracing: {err}");
                None
            }
        }
    } else {
        None
    };
    init_subscriber(
        filter,
        tracer,
        SubscriberFormat::CliText,
        SubscriberOptions {
            include_error_layer: true,
            telemetry_filter,
            log_scope_name: otel_identity.map(|_| observability_log_scope_name(None)),
        },
    );

    Ok(())
}

async fn compile(args: CompileArgs) -> Result<()> {
    ensure_outputs_requested(&args)?;
    let outputs = resolve_output_paths(&args)?;

    let mut bundle_tree = None;
    let mut bundle_store = None;
    let compiled = match resolve_compile_input(&args.manifest).await? {
        CompileInput::Manifest(resolved) => {
            let compiler = Compiler::new(resolved.resolver, Default::default())
                .with_registry(resolved.registry);
            let mut opts = CompileOptions::default();
            if args.no_opt {
                opts.optimize.dce = false;
            }

            let tree = compiler
                .resolve_tree(resolved.manifest.clone(), opts.resolve)
                .await
                .wrap_err("compile failed")?;
            if args.bundle.is_some() {
                bundle_tree = Some(tree.clone());
                bundle_store = Some(compiler.store().clone());
            }

            let output = compiler
                .compile_from_tree(tree, opts.optimize)
                .wrap_err("compile failed")?;

            let deny = DenySet::new(&args.deny);
            let has_error = print_diagnostics(&output.diagnostics, &deny)?;
            if has_error {
                return Err(miette::miette!("compilation failed"));
            }

            CompiledScenario::from_compile_output(&output)
                .into_diagnostic()
                .wrap_err("failed to convert compiler output into Scenario IR")?
        }
        CompileInput::ScenarioIr(compiled) => {
            if args.bundle.is_some() {
                return Err(miette::miette!(
                    help = "Re-run `amber compile` from a manifest or bundle when you need \
                            `--bundle`; Scenario IR does not include manifest source bytes.",
                    "bundle output is not supported when compiling from Scenario IR"
                ));
            }
            compiled
        }
    };

    if let Some(primary) = outputs.primary.as_ref() {
        write_primary_output(primary, &compiled)?;
    }

    if let Some(dot_dest) = outputs.dot {
        let dot = DotReporter.emit(&compiled).map_err(miette::Report::new)?;
        match dot_dest {
            ArtifactOutput::Stdout => print!("{dot}"),
            ArtifactOutput::File(path) => write_artifact(&path, dot.as_bytes())?,
        }
    }

    if let Some(compose_root) = outputs.docker_compose.as_ref() {
        let compose = DockerComposeReporter
            .emit(&compiled)
            .map_err(miette::Report::new)?;
        write_docker_compose_output(compose_root, &compose)?;
    }

    if let Some(kubernetes_dest) = outputs.kubernetes {
        let artifact = KubernetesReporter
            .emit(&compiled)
            .map_err(miette::Report::new)?;
        write_kubernetes_output(&kubernetes_dest, &artifact)?;
    }

    if let Some(direct_dest) = outputs.direct {
        let artifact = DirectReporter
            .emit(&compiled)
            .map_err(miette::Report::new)?;
        write_direct_output(&direct_dest, &artifact)?;
    }

    if let Some(metadata_dest) = outputs.metadata {
        let metadata = MetadataReporter
            .emit(&compiled)
            .map_err(miette::Report::new)?;
        match metadata_dest {
            ArtifactOutput::Stdout => print!("{metadata}"),
            ArtifactOutput::File(path) => write_artifact(&path, metadata.as_bytes())?,
        }
    }

    if let Some(bundle_root) = resolve_bundle_root(&args)? {
        let tree = bundle_tree.expect("bundle requested from manifest input");
        let store = bundle_store.expect("bundle requested from manifest input");
        prepare_bundle_dir(&bundle_root)?;
        BundleBuilder::build(&tree, &store, &bundle_root).wrap_err("bundle generation failed")?;
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
    docs::run(args)
}

async fn run(args: RunArgs) -> Result<()> {
    let target = load_run_target(&args.output)?;
    match target.kind {
        RunTargetKind::Direct => {
            run_direct_init(RunDirectInitArgs {
                plan: target.plan,
                storage_root: args.storage_root,
            })
            .await
        }
    }
}

fn load_run_target(output: &str) -> Result<RunTarget> {
    let output_path = Path::new(output);
    if !output_path.exists() {
        return Err(miette::miette!("run target not found: {}", output));
    }
    let abs = canonicalize_user_path(output_path, "run target")?;

    if abs.is_dir() {
        let plan = abs.join(DIRECT_PLAN_FILENAME);
        if plan.is_file() {
            return Ok(RunTarget {
                kind: RunTargetKind::Direct,
                plan,
            });
        }
        return Err(miette::miette!(
            "output directory {} is not a recognized runnable artifact (missing {})",
            abs.display(),
            DIRECT_PLAN_FILENAME
        ));
    }

    if abs.file_name().and_then(|name| name.to_str()) == Some(DIRECT_PLAN_FILENAME) {
        return Ok(RunTarget {
            kind: RunTargetKind::Direct,
            plan: abs,
        });
    }

    Err(miette::miette!(
        "output path {} is not a direct artifact directory or plan file",
        abs.display()
    ))
}

#[derive(Debug)]
struct ManagedChild {
    name: String,
    child: tokio::process::Child,
}

#[derive(Debug)]
struct ProcessSpec {
    name: String,
    program: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    work_dir: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    read_only_mounts: Vec<ReadOnlyMount>,
    writable_dirs: Vec<PathBuf>,
    bind_dirs: Vec<PathBuf>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    bind_mounts: Vec<BindMount>,
    hidden_paths: Vec<PathBuf>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    network: ProcessNetwork,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadOnlyMount {
    source: PathBuf,
    dest: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BindMount {
    source: PathBuf,
    dest: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum ProcessNetwork {
    Host,
    Isolated,
    Join(u32),
}

#[derive(Debug)]
enum RuntimeExitReason {
    CtrlC,
    ChildExited {
        name: String,
        status: std::process::ExitStatus,
    },
}

const DIRECT_SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);
const DIRECT_CHILD_POLL_INTERVAL: Duration = Duration::from_millis(150);
const DIRECT_RUNTIME_STATE_POLL_INTERVAL: Duration = Duration::from_millis(50);
const DIRECT_RUNTIME_STATE_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectControlSocketPaths {
    artifact_link: PathBuf,
    current_link: PathBuf,
    runtime: PathBuf,
}

async fn run_direct_init(args: RunDirectInitArgs) -> Result<()> {
    let plan_path = canonicalize_user_path(&args.plan, "direct plan")?;
    let plan_root = plan_path
        .parent()
        .ok_or_else(|| miette::miette!("invalid direct plan path {}", plan_path.display()))?
        .to_path_buf();
    let storage_root = direct_storage_root(&plan_root, args.storage_root.as_deref())
        .into_diagnostic()
        .wrap_err("failed to resolve direct storage root")?;
    let plan_raw = fs::read_to_string(&plan_path)
        .map_err(|err| miette::miette!("failed to read {}: {err}", plan_path.display()))?;
    let direct_plan: DirectPlan = serde_json::from_str(&plan_raw)
        .map_err(|err| miette::miette!("invalid direct plan {}: {err}", plan_path.display()))?;
    if direct_plan.version != DIRECT_PLAN_VERSION {
        return Err(miette::miette!(
            "unsupported direct plan version {} in {}; expected {}",
            direct_plan.version,
            plan_path.display(),
            DIRECT_PLAN_VERSION
        ));
    }

    let mesh_plan_path = plan_root.join(&direct_plan.mesh_provision_plan);
    let mesh_raw = fs::read_to_string(&mesh_plan_path)
        .map_err(|err| miette::miette!("failed to read {}: {err}", mesh_plan_path.display()))?;
    let mesh_plan: MeshProvisionPlan = serde_json::from_str(&mesh_raw).map_err(|err| {
        miette::miette!(
            "invalid mesh provision plan {}: {err}",
            mesh_plan_path.display()
        )
    })?;

    let runtime_dir = tempfile::Builder::new()
        .prefix("amber-direct-")
        .tempdir()
        .into_diagnostic()
        .wrap_err("failed to create direct runtime workspace")?;
    let runtime_root = runtime_dir.path().to_path_buf();
    let runtime_state_path = direct_runtime_state_path(&plan_root);
    let mut children = Vec::<ManagedChild>::new();
    let mut log_tasks = Vec::new();
    let mut component_sidecar_pid_by_id = HashMap::new();
    let mut control_socket_paths = None;

    let supervision = async {
        provision_mesh_filesystem(&mesh_plan, &runtime_root)?;
        if runtime_state_path.exists() {
            let _ = fs::remove_file(&runtime_state_path);
        }

        let mut sandbox = DirectSandbox::detect(&runtime_root);
        if !sandbox.is_available() {
            return Err(miette::miette!(
                "direct runtime requires a sandbox backend for process isolation; {}",
                missing_direct_sandbox_help()
            ));
        }
        #[cfg(target_os = "linux")]
        let slirp4netns = find_in_path("slirp4netns").ok_or_else(|| {
            miette::miette!(
                "direct runtime requires `slirp4netns` on Linux for isolated component networking"
            )
        })?;
        let runtime_state = assign_direct_runtime_ports(&runtime_root, &direct_plan)?;
        write_direct_runtime_state(&plan_root, &runtime_state)?;
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        let mesh_network =
            configure_direct_mesh_network(&runtime_root, &runtime_state, &direct_plan)?;

        let router_binary = resolve_runtime_binary("amber-router")?;
        if let Some(router) = direct_plan.router.as_ref() {
            let paths = DirectControlSocketPaths {
                artifact_link: resolve_direct_artifact_path(
                    &plan_root,
                    &router.control_socket_path,
                ),
                current_link: direct_current_control_socket_path(&plan_root),
                runtime: direct_runtime_control_socket_path(&runtime_root),
            };
            let direct_control_artifact_link_dir = paths
                .artifact_link
                .parent()
                .ok_or_else(|| miette::miette!("invalid direct control socket path"))?
                .to_path_buf();
            let direct_control_current_link_dir = paths
                .current_link
                .parent()
                .ok_or_else(|| miette::miette!("invalid current control socket path"))?
                .to_path_buf();
            let direct_control_runtime_dir = paths
                .runtime
                .parent()
                .ok_or_else(|| miette::miette!("invalid runtime control socket path"))?
                .to_path_buf();
            let mut env = BTreeMap::new();
            env.insert(
                "AMBER_ROUTER_CONFIG_PATH".to_string(),
                runtime_root
                    .join(&router.mesh_config_path)
                    .display()
                    .to_string(),
            );
            env.insert(
                "AMBER_ROUTER_IDENTITY_PATH".to_string(),
                runtime_root
                    .join(&router.mesh_identity_path)
                    .display()
                    .to_string(),
            );
            env.insert(
                "AMBER_ROUTER_CONTROL_SOCKET_PATH".to_string(),
                paths.runtime.display().to_string(),
            );
            for passthrough in &router.env_passthrough {
                if let Ok(value) = env::var(passthrough) {
                    env.insert(passthrough.clone(), value);
                }
            }
            let work_dir = runtime_root.join("work/router");
            fs::create_dir_all(&work_dir)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to create router runtime directory {}",
                        work_dir.display()
                    )
                })?;
            fs::create_dir_all(&direct_control_artifact_link_dir)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to create router control directory {}",
                        direct_control_artifact_link_dir.display()
                    )
                })?;
            fs::create_dir_all(&direct_control_current_link_dir)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to create current router control directory {}",
                        direct_control_current_link_dir.display()
                    )
                })?;
            fs::create_dir_all(&direct_control_runtime_dir)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to create runtime router control directory {}",
                        direct_control_runtime_dir.display()
                    )
                })?;
            if paths.runtime.exists() {
                fs::remove_file(&paths.runtime)
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!(
                            "failed to remove stale runtime router control socket {}",
                            paths.runtime.display()
                        )
                    })?;
            }
            ensure_direct_control_socket_link(
                &paths.artifact_link,
                &paths.current_link,
                "router control symlink",
            )?;
            ensure_direct_control_socket_link(
                &paths.current_link,
                &paths.runtime,
                "runtime router control symlink",
            )?;
            let spec = ProcessSpec {
                name: "router".to_string(),
                program: router_binary.clone(),
                args: Vec::new(),
                env,
                work_dir,
                read_only_mounts: vec![ReadOnlyMount {
                    source: runtime_root.join("mesh"),
                    dest: runtime_root.join("mesh"),
                }],
                writable_dirs: Vec::new(),
                bind_dirs: vec![direct_control_runtime_dir.clone()],
                bind_mounts: Vec::new(),
                hidden_paths: Vec::new(),
                network: ProcessNetwork::Host,
            };
            let _ =
                spawn_managed_process(spec, &mut sandbox, &mut children, &mut log_tasks).await?;
            control_socket_paths = Some(paths);
        }

        let mut components_by_id = HashMap::new();
        for component in &direct_plan.components {
            components_by_id.insert(component.id, component);
        }

        for component in &direct_plan.components {
            let mut env = BTreeMap::new();
            env.insert(
                "AMBER_ROUTER_CONFIG_PATH".to_string(),
                runtime_root
                    .join(&component.sidecar.mesh_config_path)
                    .display()
                    .to_string(),
            );
            env.insert(
                "AMBER_ROUTER_IDENTITY_PATH".to_string(),
                runtime_root
                    .join(&component.sidecar.mesh_identity_path)
                    .display()
                    .to_string(),
            );
            let work_dir = runtime_root.join(&component.program.work_dir);
            fs::create_dir_all(&work_dir)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to create component runtime directory {}",
                        work_dir.display()
                    )
                })?;
            let spec = ProcessSpec {
                name: component.sidecar.log_name.clone(),
                program: router_binary.clone(),
                args: Vec::new(),
                env,
                work_dir,
                read_only_mounts: vec![ReadOnlyMount {
                    source: runtime_root.join("mesh"),
                    dest: runtime_root.join("mesh"),
                }],
                writable_dirs: Vec::new(),
                bind_dirs: Vec::new(),
                bind_mounts: Vec::new(),
                hidden_paths: Vec::new(),
                network: {
                    #[cfg(target_os = "linux")]
                    {
                        ProcessNetwork::Isolated
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        ProcessNetwork::Host
                    }
                },
            };
            let sidecar_pid =
                spawn_managed_process(spec, &mut sandbox, &mut children, &mut log_tasks).await?;
            #[cfg(target_os = "linux")]
            {
                let mesh_port = mesh_network
                    .component_mesh_port_by_id
                    .get(&component.id)
                    .copied()
                    .ok_or_else(|| {
                        miette::miette!(
                            "missing sidecar mesh listen port for component {}",
                            component.moniker
                        )
                    })?;
                spawn_component_slirp4netns(
                    &slirp4netns,
                    &runtime_root,
                    component,
                    sidecar_pid,
                    mesh_port,
                    &mut children,
                    &mut log_tasks,
                )
                .await?;
            }
            component_sidecar_pid_by_id.insert(component.id, sidecar_pid);
        }

        for component_id in &direct_plan.startup_order {
            let component = components_by_id.get(component_id).ok_or_else(|| {
                miette::miette!(
                    "direct plan startup order references unknown component id {}",
                    component_id
                )
            })?;
            let mut spec = component_program_spec(
                &runtime_root,
                &storage_root,
                component,
                &direct_plan.runtime_addresses,
                &runtime_state,
            )?;
            spec.hidden_paths.push(runtime_root.join("mesh"));
            #[cfg(target_os = "linux")]
            {
                let pid = component_sidecar_pid_by_id
                    .get(component_id)
                    .copied()
                    .ok_or_else(|| {
                        miette::miette!("missing sidecar pid for component {}", component.moniker)
                    })?;
                spec.network = ProcessNetwork::Join(pid);
            }
            let _ =
                spawn_managed_process(spec, &mut sandbox, &mut children, &mut log_tasks).await?;
        }

        supervise_children(&mut children).await
    }
    .await;
    cleanup_direct_runtime(
        &mut children,
        log_tasks,
        &runtime_state_path,
        control_socket_paths.as_ref(),
        runtime_dir,
    )
    .await;

    let (reason, exit_code) = supervision?;
    match reason {
        RuntimeExitReason::CtrlC => Ok(()),
        RuntimeExitReason::ChildExited { name, status } => {
            if status.success() {
                Ok(())
            } else {
                eprintln!(
                    "direct runtime stopped because {} exited (status: {}, exit code: {})",
                    name, status, exit_code
                );
                std::process::exit(exit_code);
            }
        }
    }
}

fn resolve_direct_artifact_path(plan_root: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        plan_root.join(path)
    }
}

fn direct_storage_root(plan_root: &Path, override_root: Option<&Path>) -> std::io::Result<PathBuf> {
    if let Some(override_root) = override_root {
        return Ok(if override_root.is_absolute() {
            override_root.to_path_buf()
        } else {
            std::env::current_dir()?.join(override_root)
        });
    }

    let name = plan_root
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("amber-direct");
    let parent = plan_root.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!(".{name}.amber-state")))
}

fn direct_current_control_socket_path(plan_root: &Path) -> PathBuf {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    plan_root.hash(&mut hasher);
    let suffix = hasher.finish();
    env::temp_dir()
        .join("amber-direct-control")
        .join(format!("current-{suffix:016x}.sock"))
}

fn direct_runtime_control_socket_path(runtime_root: &Path) -> PathBuf {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    runtime_root.hash(&mut hasher);
    let suffix = hasher.finish();
    env::temp_dir()
        .join("amber-direct-control")
        .join(format!("runtime-{suffix:016x}.sock"))
}

#[cfg(unix)]
fn ensure_direct_control_socket_link(link: &Path, target: &Path, description: &str) -> Result<()> {
    if fs::read_link(link)
        .ok()
        .is_some_and(|existing_target| existing_target == target)
    {
        return Ok(());
    }

    if fs::symlink_metadata(link).is_ok() {
        fs::remove_file(link)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove stale {description} {}", link.display()))?;
    }

    std::os::unix::fs::symlink(target, link)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create {description} {} -> {}",
                link.display(),
                target.display()
            )
        })
}

#[cfg(not(unix))]
fn ensure_direct_control_socket_link(link: &Path, target: &Path, description: &str) -> Result<()> {
    let _ = (link, target, description);
    Err(miette::miette!(
        "direct runtime control sockets require unix symlink support"
    ))
}

fn remove_direct_control_socket_link(paths: &DirectControlSocketPaths) {
    #[cfg(unix)]
    {
        if fs::read_link(&paths.current_link)
            .ok()
            .is_some_and(|target| target == paths.runtime)
        {
            let _ = fs::remove_file(&paths.current_link);
        }
    }

    #[cfg(not(unix))]
    {
        let _ = fs::remove_file(&paths.current_link);
    }
}

async fn cleanup_direct_runtime(
    children: &mut [ManagedChild],
    log_tasks: Vec<tokio::task::JoinHandle<()>>,
    runtime_state_path: &Path,
    control_socket_paths: Option<&DirectControlSocketPaths>,
    runtime_dir: tempfile::TempDir,
) {
    terminate_children(children).await;
    for task in log_tasks {
        let _ = task.await;
    }
    if let Some(paths) = control_socket_paths {
        remove_direct_control_socket_link(paths);
        let _ = fs::remove_file(&paths.runtime);
    }
    let _ = fs::remove_file(runtime_state_path);
    drop(runtime_dir);
}

fn direct_runtime_state_path(plan_root: &Path) -> PathBuf {
    plan_root.join(".amber").join("direct-runtime.json")
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct DirectRuntimeState {
    #[serde(default)]
    slot_ports_by_component: BTreeMap<usize, BTreeMap<String, u16>>,
    #[serde(default)]
    slot_route_ports_by_component: BTreeMap<usize, BTreeMap<String, Vec<u16>>>,
    #[serde(default)]
    component_mesh_port_by_id: BTreeMap<usize, u16>,
    #[serde(default)]
    router_mesh_port: Option<u16>,
}

#[derive(Debug, Default)]
struct DirectMeshNetworkPlan {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    component_mesh_port_by_id: HashMap<usize, u16>,
}

fn assign_direct_runtime_ports(
    runtime_root: &Path,
    direct_plan: &DirectPlan,
) -> Result<DirectRuntimeState> {
    let mut state = DirectRuntimeState::default();
    let mut reserved = BTreeSet::new();
    let mut mesh_port_by_peer_id = HashMap::<String, u16>::new();
    let mut component_configs = Vec::new();

    for component in &direct_plan.components {
        let path = runtime_root.join(&component.sidecar.mesh_config_path);
        let mut config = read_mesh_config_public(path.as_path())?;
        let mesh_port = allocate_direct_runtime_port(&mut reserved)?;
        mesh_port_by_peer_id.insert(config.identity.id.clone(), mesh_port);
        config.mesh_listen = SocketAddr::new(config.mesh_listen.ip(), mesh_port);

        let mut slot_route_ports: BTreeMap<String, Vec<(u16, u16)>> = BTreeMap::new();
        for route in &mut config.outbound {
            let authored_port = route.listen_port;
            let port = allocate_direct_runtime_port(&mut reserved)?;
            route.listen_port = port;
            slot_route_ports
                .entry(route.slot.clone())
                .or_default()
                .push((authored_port, port));
        }
        for ports in slot_route_ports.values_mut() {
            // Placeholder listen ports are allocated in authored binding order during compile.
            // Preserve that order when assigning ephemeral direct-runtime ports so `${item...}`
            // continues to match the compiled item indices.
            ports.sort_unstable_by_key(|(authored_port, _)| *authored_port);
        }
        let slot_route_ports: BTreeMap<String, Vec<u16>> = slot_route_ports
            .into_iter()
            .map(|(slot, ports)| {
                (
                    slot,
                    ports
                        .into_iter()
                        .map(|(_, runtime_port)| runtime_port)
                        .collect(),
                )
            })
            .collect();

        let slot_ports = slot_route_ports
            .iter()
            .filter_map(|(slot, ports)| (ports.len() == 1).then_some((slot.clone(), ports[0])))
            .collect();

        state
            .component_mesh_port_by_id
            .insert(component.id, mesh_port);
        state
            .slot_ports_by_component
            .insert(component.id, slot_ports);
        state
            .slot_route_ports_by_component
            .insert(component.id, slot_route_ports);
        component_configs.push((path, config));
    }

    let mut router_config = if let Some(router) = direct_plan.router.as_ref() {
        let path = runtime_root.join(&router.mesh_config_path);
        let mut config = read_mesh_config_public(path.as_path())?;
        let mesh_port = allocate_direct_runtime_port(&mut reserved)?;
        mesh_port_by_peer_id.insert(config.identity.id.clone(), mesh_port);
        config.mesh_listen = SocketAddr::new(config.mesh_listen.ip(), mesh_port);
        state.router_mesh_port = Some(mesh_port);
        Some((path, config))
    } else {
        None
    };

    for (_, config) in &mut component_configs {
        rewrite_direct_mesh_peer_addrs(config, &mesh_port_by_peer_id)?;
    }
    if let Some((_, config)) = router_config.as_mut() {
        rewrite_direct_mesh_peer_addrs(config, &mesh_port_by_peer_id)?;
    }

    for (path, config) in component_configs {
        write_mesh_config_public(path.as_path(), &config)?;
    }
    if let Some((path, config)) = router_config {
        write_mesh_config_public(path.as_path(), &config)?;
    }

    Ok(state)
}

fn allocate_direct_runtime_port(reserved: &mut BTreeSet<u16>) -> Result<u16> {
    for _ in 0..256 {
        let port = pick_free_port()?;
        if reserved.insert(port) {
            return Ok(port);
        }
    }
    Err(miette::miette!(
        "ran out of ports while allocating direct runtime ports"
    ))
}

fn rewrite_direct_mesh_peer_addrs(
    config: &mut MeshConfigPublic,
    mesh_port_by_peer_id: &HashMap<String, u16>,
) -> Result<()> {
    for route in &mut config.outbound {
        let port = mesh_port_by_peer_id
            .get(route.peer_id.as_str())
            .copied()
            .ok_or_else(|| miette::miette!("missing mesh port for peer {}", route.peer_id))?;
        let addr = route.peer_addr.parse::<SocketAddr>().map_err(|err| {
            miette::miette!("invalid mesh peer address {}: {err}", route.peer_addr)
        })?;
        route.peer_addr = SocketAddr::new(addr.ip(), port).to_string();
    }

    for route in &mut config.inbound {
        if let InboundTarget::MeshForward {
            peer_addr, peer_id, ..
        } = &mut route.target
        {
            let port = mesh_port_by_peer_id
                .get(peer_id.as_str())
                .copied()
                .ok_or_else(|| miette::miette!("missing mesh port for peer {}", peer_id))?;
            let addr = peer_addr
                .parse::<SocketAddr>()
                .map_err(|err| miette::miette!("invalid mesh peer address {}: {err}", peer_addr))?;
            peer_addr.clear();
            peer_addr.push_str(&SocketAddr::new(addr.ip(), port).to_string());
        }
    }

    Ok(())
}

fn write_direct_runtime_state(plan_root: &Path, state: &DirectRuntimeState) -> Result<()> {
    let path = direct_runtime_state_path(plan_root);
    let parent = path
        .parent()
        .ok_or_else(|| miette::miette!("invalid direct runtime state path"))?;
    fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create direct runtime state dir {}",
                parent.display()
            )
        })?;
    let json = serde_json::to_string_pretty(state)
        .map_err(|err| miette::miette!("failed to serialize direct runtime state: {err}"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create temporary direct runtime state file in {}",
                parent.display()
            )
        })?;
    temp.write_all(json.as_bytes())
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to write temporary direct runtime state {}",
                path.display()
            )
        })?;
    temp.flush().into_diagnostic().wrap_err_with(|| {
        format!(
            "failed to flush temporary direct runtime state {}",
            path.display()
        )
    })?;
    let _ = temp.persist(&path).map_err(|err| {
        miette::miette!(
            "failed to write direct runtime state {}: {err}",
            path.display()
        )
    })?;
    Ok(())
}

fn load_direct_runtime_state(plan_root: &Path) -> Result<Option<DirectRuntimeState>> {
    let path = direct_runtime_state_path(plan_root);
    if !path.is_file() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .map_err(|err| miette::miette!("failed to read {}: {err}", path.display()))?;
    let state = serde_json::from_str(&raw)
        .map_err(|err| miette::miette!("invalid direct runtime state {}: {err}", path.display()))?;
    Ok(Some(state))
}

async fn wait_for_direct_runtime_router_port(plan_root: &Path, timeout: Duration) -> Result<u16> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(port) =
            load_direct_runtime_state(plan_root)?.and_then(|state| state.router_mesh_port)
        {
            return Ok(port);
        }

        let now = Instant::now();
        if now >= deadline {
            break;
        }

        let remaining = deadline - now;
        sleep(remaining.min(DIRECT_RUNTIME_STATE_POLL_INTERVAL)).await;
    }

    Err(miette::miette!(
        "direct runtime router mesh port is unavailable; start `amber run` first or pass \
         --router-addr"
    ))
}

fn configure_direct_mesh_network(
    runtime_root: &Path,
    runtime_state: &DirectRuntimeState,
    direct_plan: &DirectPlan,
) -> Result<DirectMeshNetworkPlan> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = runtime_root;
        let _ = runtime_state;
        let _ = direct_plan;
        Ok(DirectMeshNetworkPlan::default())
    }

    #[cfg(target_os = "linux")]
    {
        let mut plan = DirectMeshNetworkPlan::default();
        for component in &direct_plan.components {
            let path = runtime_root.join(&component.sidecar.mesh_config_path);
            let mut config = read_mesh_config_public(path.as_path())?;
            let mesh_port = runtime_state
                .component_mesh_port_by_id
                .get(&component.id)
                .copied()
                .ok_or_else(|| {
                    miette::miette!(
                        "missing runtime mesh port for component {}",
                        component.moniker
                    )
                })?;
            plan.component_mesh_port_by_id
                .insert(component.id, mesh_port);
            config.mesh_listen = rewrite_mesh_listen_for_slirp_guest(config.mesh_listen);

            for route in &mut config.outbound {
                route.peer_addr = rewrite_peer_addr_for_slirp_gateway(route.peer_addr.as_str());
            }
            for route in &mut config.inbound {
                if let InboundTarget::MeshForward { peer_addr, .. } = &mut route.target {
                    *peer_addr = rewrite_peer_addr_for_slirp_gateway(peer_addr.as_str());
                }
            }

            write_mesh_config_public(path.as_path(), &config)?;
        }
        Ok(plan)
    }
}

#[cfg(target_os = "linux")]
fn rewrite_mesh_listen_for_slirp_guest(mesh_listen: SocketAddr) -> SocketAddr {
    if mesh_listen.ip().is_loopback() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, mesh_listen.port()))
    } else {
        mesh_listen
    }
}

#[cfg(target_os = "linux")]
fn rewrite_peer_addr_for_slirp_gateway(peer_addr: &str) -> String {
    let Ok(addr) = peer_addr.parse::<SocketAddr>() else {
        return peer_addr.to_string();
    };
    if !addr.ip().is_loopback() {
        return peer_addr.to_string();
    }

    SocketAddr::from((Ipv4Addr::new(10, 0, 2, 2), addr.port())).to_string()
}

fn read_mesh_config_public(path: &Path) -> Result<MeshConfigPublic> {
    let raw = fs::read_to_string(path)
        .map_err(|err| miette::miette!("failed to read mesh config {}: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| miette::miette!("invalid mesh config {}: {err}", path.display()))
}

fn write_mesh_config_public(path: &Path, config: &MeshConfigPublic) -> Result<()> {
    let json = serde_json::to_string_pretty(config).map_err(|err| {
        miette::miette!("failed to serialize mesh config {}: {err}", path.display())
    })?;
    fs::write(path, json)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write mesh config {}", path.display()))
}

fn component_program_spec(
    runtime_root: &Path,
    storage_root: &Path,
    component: &DirectComponentPlan,
    runtime_addresses: &DirectRuntimeAddressPlan,
    runtime_state: &DirectRuntimeState,
) -> Result<ProcessSpec> {
    let source_dir = component_source_dir(component)?;
    let work_dir = runtime_root.join(&component.program.work_dir);
    let mut writable_dirs = vec![work_dir.clone()];
    let read_only_mounts = component_program_read_only_mounts(component, source_dir.as_deref())?;
    let bind_mounts = direct_storage_bind_mounts(storage_root, component)?;
    match &component.program.execution {
        DirectProgramExecutionPlan::Direct { entrypoint, env } => {
            let (program, args) = split_entrypoint(entrypoint)?;
            let program =
                ensure_absolute_direct_program_path(&program, component.moniker.as_str())?;
            Ok(ProcessSpec {
                name: component.program.log_name.clone(),
                program,
                args,
                env: env.clone(),
                work_dir,
                read_only_mounts,
                writable_dirs,
                bind_dirs: Vec::new(),
                bind_mounts,
                hidden_paths: Vec::new(),
                network: ProcessNetwork::Host,
            })
        }
        DirectProgramExecutionPlan::HelperRunner {
            entrypoint_b64,
            env_b64,
            template_spec_b64,
            runtime_config,
            mount_spec_b64,
        } => {
            let helper_binary = resolve_runtime_binary("amber-helper")?;
            let mut env = BTreeMap::new();
            if let Some(value) = entrypoint_b64.as_ref() {
                env.insert("AMBER_RESOLVED_ENTRYPOINT_B64".to_string(), value.clone());
            }
            if let Some(value) = env_b64.as_ref() {
                env.insert("AMBER_RESOLVED_ENV_B64".to_string(), value.clone());
            }
            if let Some(value) = template_spec_b64.as_ref() {
                env.insert("AMBER_TEMPLATE_SPEC_B64".to_string(), value.clone());
            }
            if let Some(value) = mount_spec_b64.as_ref() {
                env.insert("AMBER_MOUNT_SPEC_B64".to_string(), value.clone());
            }
            if let Some(payload) = runtime_config {
                append_runtime_config_env(&mut env, payload)?;
            }
            append_runtime_template_context_env(&mut env, runtime_addresses, runtime_state)?;
            if let Some(b64) = mount_spec_b64 {
                writable_dirs.extend(decode_mount_parent_dirs(b64)?);
            }
            Ok(ProcessSpec {
                name: component.program.log_name.clone(),
                program: helper_binary.to_string(),
                args: vec!["run".to_string()],
                env,
                work_dir,
                read_only_mounts,
                writable_dirs,
                bind_dirs: Vec::new(),
                bind_mounts,
                hidden_paths: Vec::new(),
                network: ProcessNetwork::Host,
            })
        }
    }
}

fn direct_storage_bind_mounts(
    storage_root: &Path,
    component: &DirectComponentPlan,
) -> Result<Vec<BindMount>> {
    let mut mounts = Vec::new();
    for mount in &component.program.storage_mounts {
        let source = storage_root.join(&mount.state_subdir);
        fs::create_dir_all(&source)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to create persistent storage directory {} for component {}",
                    source.display(),
                    component.moniker
                )
            })?;
        mounts.push(BindMount {
            source,
            dest: PathBuf::from(&mount.mount_path),
        });
    }
    Ok(mounts)
}

fn append_runtime_template_context_env(
    env_map: &mut BTreeMap<String, String>,
    runtime_addresses: &DirectRuntimeAddressPlan,
    runtime_state: &DirectRuntimeState,
) -> Result<()> {
    if runtime_addresses.slots_by_scope.is_empty()
        && runtime_addresses.slot_items_by_scope.is_empty()
    {
        return Ok(());
    }

    let context = build_runtime_template_context(runtime_addresses, runtime_state)?;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&context).map_err(
            |err| miette::miette!("failed to serialize direct runtime template context: {err}"),
        )?);
    env_map.insert("AMBER_RUNTIME_TEMPLATE_CONTEXT_B64".to_string(), encoded);
    Ok(())
}

fn build_runtime_template_context(
    runtime_addresses: &DirectRuntimeAddressPlan,
    runtime_state: &DirectRuntimeState,
) -> Result<RuntimeTemplateContext> {
    let mut context = RuntimeTemplateContext::default();

    for (scope, entries) in &runtime_addresses.slots_by_scope {
        let mut urls = BTreeMap::new();
        for (name, source) in entries {
            let url = runtime_url_for_source(source, runtime_state)?;
            urls.insert(
                name.clone(),
                serde_json::to_string(&RuntimeSlotObject { url: url.clone() }).map_err(|err| {
                    miette::miette!(
                        "failed to serialize direct runtime slot object for scope {} slot {}: \
                         {err}",
                        scope,
                        name
                    )
                })?,
            );
            urls.insert(format!("{name}.url"), url);
        }
        if !urls.is_empty() {
            context.slots_by_scope.insert(*scope as u64, urls);
        }
    }

    for (scope, entries) in &runtime_addresses.slot_items_by_scope {
        let mut urls = BTreeMap::new();
        for (name, sources) in entries {
            let mut items = Vec::with_capacity(sources.len());
            for source in sources {
                items.push(RuntimeSlotObject {
                    url: runtime_url_for_source(source, runtime_state)?,
                });
            }
            urls.insert(name.clone(), items);
        }
        if !urls.is_empty() {
            context.slot_items_by_scope.insert(*scope as u64, urls);
        }
    }

    Ok(context)
}

fn runtime_url_for_source(
    source: &DirectRuntimeUrlSource,
    runtime_state: &DirectRuntimeState,
) -> Result<String> {
    match source {
        DirectRuntimeUrlSource::Slot {
            component_id,
            slot,
            scheme,
        } => {
            let port = runtime_state
                .slot_ports_by_component
                .get(component_id)
                .and_then(|slots| slots.get(slot.as_str()))
                .copied()
                .ok_or_else(|| {
                    miette::miette!(
                        "missing runtime slot port for component {} slot {}",
                        component_id,
                        slot
                    )
                })?;
            Ok(format!("{scheme}://127.0.0.1:{port}"))
        }
        DirectRuntimeUrlSource::SlotItem {
            component_id,
            slot,
            item_index,
            scheme,
        } => {
            let port = runtime_state
                .slot_route_ports_by_component
                .get(component_id)
                .and_then(|slots| slots.get(slot.as_str()))
                .and_then(|ports| ports.get(*item_index))
                .copied()
                .ok_or_else(|| {
                    miette::miette!(
                        "missing runtime slot item {} for component {} slot {}",
                        item_index,
                        component_id,
                        slot
                    )
                })?;
            Ok(format!("{scheme}://127.0.0.1:{port}"))
        }
    }
}

fn append_runtime_config_env(
    env_map: &mut BTreeMap<String, String>,
    payload: &DirectRuntimeConfigPayload,
) -> Result<()> {
    env_map.insert(
        "AMBER_ROOT_CONFIG_SCHEMA_B64".to_string(),
        payload.root_schema_b64.clone(),
    );
    env_map.insert(
        "AMBER_COMPONENT_CONFIG_SCHEMA_B64".to_string(),
        payload.component_schema_b64.clone(),
    );
    env_map.insert(
        "AMBER_COMPONENT_CONFIG_TEMPLATE_B64".to_string(),
        payload.component_cfg_template_b64.clone(),
    );
    for path in &payload.allowed_root_leaf_paths {
        let env_var = amber_config::env_var_for_path(path)
            .map_err(|err| miette::miette!("failed to map config path {}: {err}", path))?;
        if let Ok(value) = env::var(&env_var) {
            env_map.insert(env_var, value);
        }
    }
    Ok(())
}

fn split_entrypoint(entrypoint: &[String]) -> Result<(String, Vec<String>)> {
    let Some(program) = entrypoint.first() else {
        return Err(miette::miette!("program entrypoint must not be empty"));
    };
    Ok((program.clone(), entrypoint[1..].to_vec()))
}

fn component_source_dir(component: &DirectComponentPlan) -> Result<Option<PathBuf>> {
    let Some(raw) = component.source_dir.as_deref() else {
        return Ok(None);
    };
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(miette::miette!(
            "direct plan has non-absolute source directory {} for component {}",
            path.display(),
            component.moniker
        ));
    }
    Ok(Some(path))
}

fn component_program_read_only_mounts(
    component: &DirectComponentPlan,
    source_dir: Option<&Path>,
) -> Result<Vec<ReadOnlyMount>> {
    let mut mounts = BTreeMap::<PathBuf, ReadOnlyMount>::new();
    if let Some(source_dir) = source_dir
        && source_dir.is_absolute()
    {
        mounts.insert(
            source_dir.to_path_buf(),
            ReadOnlyMount {
                source: source_dir.to_path_buf(),
                dest: source_dir.to_path_buf(),
            },
        );
    }

    let Some(program_path) = component_execution_program_path(component)? else {
        return Ok(mounts.into_values().collect());
    };
    let program_path =
        ensure_absolute_direct_program_path(&program_path, component.moniker.as_str())?;
    let program_path = Path::new(&program_path);
    if let Some(parent) = program_path.parent() {
        mounts.entry(parent.to_path_buf()).or_insert(ReadOnlyMount {
            source: parent.to_path_buf(),
            dest: parent.to_path_buf(),
        });
    }

    Ok(mounts.into_values().collect())
}

fn component_execution_program_path(component: &DirectComponentPlan) -> Result<Option<String>> {
    match &component.program.execution {
        DirectProgramExecutionPlan::Direct { entrypoint, .. } => Ok(entrypoint.first().cloned()),
        DirectProgramExecutionPlan::HelperRunner {
            entrypoint_b64,
            template_spec_b64,
            ..
        } => {
            if let Some(raw) = entrypoint_b64.as_ref() {
                return decode_entrypoint_payload_program(raw).map(Some);
            }
            if let Some(raw) = template_spec_b64.as_ref() {
                return decode_template_spec_program(raw).map(Some);
            }
            Ok(None)
        }
    }
}

fn decode_entrypoint_payload_program(raw_b64: &str) -> Result<String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw_b64.as_bytes())
        .map_err(|err| miette::miette!("invalid entrypoint payload: {err}"))?;
    let entrypoint: Vec<String> = serde_json::from_slice(&decoded)
        .map_err(|err| miette::miette!("invalid entrypoint payload: {err}"))?;
    entrypoint
        .into_iter()
        .next()
        .ok_or_else(|| miette::miette!("entrypoint payload is empty"))
}

fn decode_template_spec_program(raw_b64: &str) -> Result<String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw_b64.as_bytes())
        .map_err(|err| miette::miette!("invalid template spec payload: {err}"))?;
    let spec: TemplateSpec = serde_json::from_slice(&decoded)
        .map_err(|err| miette::miette!("invalid template spec payload: {err}"))?;
    let path_template = spec
        .program
        .entrypoint
        .first()
        .ok_or_else(|| miette::miette!("template spec program entrypoint is empty"))?;
    render_program_arg_template_literal(path_template)
}

fn render_program_arg_template_literal(arg: &ProgramArgTemplate) -> Result<String> {
    let ProgramArgTemplate::Arg(parts) = arg else {
        return Err(miette::miette!(
            "internal error: template spec program entrypoint starts with a conditional arg group"
        ));
    };
    render_template_string_literal(parts)
}

fn render_template_string_literal(parts: &[TemplatePart]) -> Result<String> {
    let mut out = String::new();
    for part in parts {
        match part {
            TemplatePart::Lit { lit } => out.push_str(lit),
            TemplatePart::Config { config } => {
                return Err(miette::miette!(
                    "internal error: unresolved runtime config interpolation `{config}` in direct \
                     program path"
                ));
            }
            TemplatePart::Slot { slot, .. } => {
                return Err(miette::miette!(
                    "internal error: unresolved slot interpolation `{slot}` in direct program path"
                ));
            }
            TemplatePart::Item { item, .. } => {
                return Err(miette::miette!(
                    "internal error: unresolved repeated item interpolation `{item}` in direct \
                     program path"
                ));
            }
        }
    }
    if out.is_empty() {
        return Err(miette::miette!(
            "internal error: template spec program entrypoint is empty"
        ));
    }
    Ok(out)
}

fn ensure_absolute_direct_program_path(program: &str, component_moniker: &str) -> Result<String> {
    if Path::new(program).is_absolute() {
        return Ok(program.to_string());
    }

    Err(miette::miette!(
        "direct plan for component {} contains non-absolute program path `{}`; re-run `amber \
         compile --direct` with a build that resolves direct executable paths at compile time",
        component_moniker,
        program
    ))
}

fn decode_mount_parent_dirs(raw_b64: &str) -> Result<Vec<PathBuf>> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw_b64.as_bytes())
        .map_err(|err| miette::miette!("invalid AMBER_MOUNT_SPEC_B64: {err}"))?;
    let value: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|err| miette::miette!("invalid mount spec payload: {err}"))?;
    let mut parents = BTreeSet::new();
    let items = value
        .as_array()
        .ok_or_else(|| miette::miette!("invalid mount spec payload: expected array"))?;
    for item in items {
        let path = item
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| miette::miette!("invalid mount spec payload: missing path field"))?;
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(miette::miette!(
                "invalid mount path {}: expected absolute path",
                path.display()
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            miette::miette!(
                "invalid mount path {}: missing parent directory",
                path.display()
            )
        })?;
        parents.insert(parent.to_path_buf());
    }
    Ok(parents.into_iter().collect())
}

async fn spawn_managed_process(
    spec: ProcessSpec,
    sandbox: &mut DirectSandbox,
    children: &mut Vec<ManagedChild>,
    log_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<u32> {
    let (program, args) = sandbox.wrap_command(&spec)?;
    #[cfg(target_os = "linux")]
    let mut args = args;
    #[cfg(target_os = "linux")]
    let namespace_join = if matches!(sandbox, DirectSandbox::Bubblewrap { .. }) {
        match spec.network {
            ProcessNetwork::Join(pid) => prepare_linux_namespace_join(pid)?,
            _ => None,
        }
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let pid_capture = if matches!(sandbox, DirectSandbox::Bubblewrap { .. })
        && matches!(spec.network, ProcessNetwork::Isolated)
    {
        insert_bubblewrap_info_fd(&mut args, 3)?;
        SpawnPidCapture::BubblewrapChild
    } else {
        SpawnPidCapture::WrapperProcess
    };
    let mut command = TokioCommand::new(program);
    command.args(args);
    command.current_dir(&spec.work_dir);
    configure_managed_command_env(&mut command, &spec.work_dir, &spec.env);
    spawn_managed_command(
        spec.name,
        command,
        #[cfg(target_os = "linux")]
        namespace_join,
        #[cfg(target_os = "linux")]
        pid_capture,
        children,
        log_tasks,
    )
    .await
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpawnPidCapture {
    WrapperProcess,
    BubblewrapChild,
}

#[cfg(target_os = "linux")]
struct LinuxNamespaceJoin {
    user: Option<CString>,
    net: Option<CString>,
}

#[cfg(target_os = "linux")]
struct BubblewrapInfoPipe {
    read: OwnedFd,
    write: OwnedFd,
}

#[cfg(target_os = "linux")]
fn insert_bubblewrap_info_fd(args: &mut Vec<String>, fd: RawFd) -> Result<()> {
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| miette::miette!("bubblewrap args are missing the `--` command separator"))?;
    args.splice(
        separator..separator,
        ["--info-fd".to_string(), fd.to_string()],
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn prepare_bubblewrap_info_pipe(command: &mut TokioCommand) -> Result<BubblewrapInfoPipe> {
    const BUBBLEWRAP_INFO_FD: RawFd = 3;

    let mut raw_fds = [-1; 2];
    if unsafe { libc::pipe2(raw_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(miette::miette!(
            "failed to create bubblewrap info pipe: {}",
            std::io::Error::last_os_error()
        ));
    }

    let read = unsafe { OwnedFd::from_raw_fd(raw_fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(raw_fds[1]) };
    let read_fd = read.as_raw_fd();
    let write_fd = write.as_raw_fd();

    unsafe {
        command.pre_exec(move || {
            if libc::close(read_fd) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if write_fd != BUBBLEWRAP_INFO_FD
                && libc::dup2(write_fd, BUBBLEWRAP_INFO_FD) != BUBBLEWRAP_INFO_FD
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(BUBBLEWRAP_INFO_FD, libc::F_SETFD, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if write_fd != BUBBLEWRAP_INFO_FD && libc::close(write_fd) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    Ok(BubblewrapInfoPipe { read, write })
}

async fn spawn_managed_command(
    name: String,
    mut command: TokioCommand,
    #[cfg(target_os = "linux")] namespace_join: Option<LinuxNamespaceJoin>,
    #[cfg(target_os = "linux")] pid_capture: SpawnPidCapture,
    children: &mut Vec<ManagedChild>,
    log_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<u32> {
    #[cfg(target_os = "linux")]
    let bubblewrap_info_pipe = match pid_capture {
        SpawnPidCapture::WrapperProcess => None,
        SpawnPidCapture::BubblewrapChild => Some(prepare_bubblewrap_info_pipe(&mut command)?),
    };
    #[cfg(target_os = "linux")]
    if let Some(namespace_join) = namespace_join {
        unsafe {
            command.pre_exec(move || enter_linux_namespaces(&namespace_join));
        }
    }

    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to spawn process {name}"))?;

    #[cfg(target_os = "linux")]
    let pid = if let Some(pipe) = bubblewrap_info_pipe {
        match read_bubblewrap_child_pid(pipe).await {
            Ok(pid) => pid,
            Err(err) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(err).wrap_err_with(|| {
                    format!("failed to capture bubblewrap child pid for {name}")
                });
            }
        }
    } else {
        child
            .id()
            .ok_or_else(|| miette::miette!("failed to capture process id for {name}"))?
    };

    #[cfg(not(target_os = "linux"))]
    let pid = child
        .id()
        .ok_or_else(|| miette::miette!("failed to capture process id for {name}"))?;

    if let Some(stdout) = child.stdout.take() {
        let name = name.clone();
        log_tasks.push(tokio::spawn(async move {
            stream_logs(stdout, name, false).await;
        }));
    }
    if let Some(stderr) = child.stderr.take() {
        let name = name.clone();
        log_tasks.push(tokio::spawn(async move {
            stream_logs(stderr, name, true).await;
        }));
    }

    children.push(ManagedChild { name, child });
    Ok(pid)
}

#[cfg(target_os = "linux")]
fn prepare_linux_namespace_join(pid: u32) -> Result<Option<LinuxNamespaceJoin>> {
    let self_user = fs::read_link("/proc/self/ns/user")
        .into_diagnostic()
        .wrap_err("failed to read current user namespace")?;
    let target_user_path = format!("/proc/{pid}/ns/user");
    let target_user = fs::read_link(&target_user_path)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to read target user namespace for process {pid} ({})",
                target_user_path
            )
        })?;

    let self_net = fs::read_link("/proc/self/ns/net")
        .into_diagnostic()
        .wrap_err("failed to read current network namespace")?;
    let target_net_path = format!("/proc/{pid}/ns/net");
    let target_net = fs::read_link(&target_net_path)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to read target network namespace for process {pid} ({})",
                target_net_path
            )
        })?;

    let user = if self_user != target_user {
        Some(
            CString::new(target_user_path.as_str())
                .into_diagnostic()
                .wrap_err("user namespace path unexpectedly contains NUL bytes")?,
        )
    } else {
        None
    };
    let net = if self_net != target_net {
        Some(
            CString::new(target_net_path.as_str())
                .into_diagnostic()
                .wrap_err("network namespace path unexpectedly contains NUL bytes")?,
        )
    } else {
        None
    };

    if user.is_none() && net.is_none() {
        Ok(None)
    } else {
        Ok(Some(LinuxNamespaceJoin { user, net }))
    }
}

#[cfg(target_os = "linux")]
fn enter_linux_namespaces(namespace_join: &LinuxNamespaceJoin) -> std::io::Result<()> {
    if let Some(user) = namespace_join.user.as_ref() {
        enter_linux_namespace(
            user,
            libc::CLONE_NEWUSER,
            b"failed to open component user namespace\n",
            b"failed to join component user namespace\n",
        )?;
    }
    if let Some(net) = namespace_join.net.as_ref() {
        enter_linux_namespace(
            net,
            libc::CLONE_NEWNET,
            b"failed to open component network namespace\n",
            b"failed to join component network namespace\n",
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn enter_linux_namespace(
    path: &CString,
    namespace_kind: libc::c_int,
    open_error: &[u8],
    join_error: &[u8],
) -> std::io::Result<()> {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        let _ = unsafe {
            libc::write(
                libc::STDERR_FILENO,
                open_error.as_ptr().cast(),
                open_error.len(),
            )
        };
        return Err(err);
    }

    if unsafe { libc::setns(fd, namespace_kind) } != 0 {
        let err = std::io::Error::last_os_error();
        let _ = unsafe {
            libc::write(
                libc::STDERR_FILENO,
                join_error.as_ptr().cast(),
                join_error.len(),
            )
        };
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    unsafe {
        libc::close(fd);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn read_bubblewrap_child_pid(pipe: BubblewrapInfoPipe) -> Result<u32> {
    drop(pipe.write);
    let read = pipe.read;
    let raw = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || -> Result<String> {
            let mut file: fs::File = read.into();
            let mut raw = String::new();
            file.read_to_string(&mut raw)
                .into_diagnostic()
                .wrap_err("failed to read bubblewrap info payload")?;
            Ok(raw)
        }),
    )
    .await
    .into_diagnostic()
    .wrap_err("timed out waiting for bubblewrap info payload")?
    .into_diagnostic()
    .wrap_err("bubblewrap info reader task failed")??;
    parse_bubblewrap_child_pid(raw.as_str())
}

#[cfg(target_os = "linux")]
fn parse_bubblewrap_child_pid(raw: &str) -> Result<u32> {
    let payload: serde_json::Value = serde_json::from_str(raw.trim())
        .map_err(|err| miette::miette!("invalid bubblewrap info payload: {err}"))?;
    let child_pid = payload
        .get("child-pid")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| miette::miette!("bubblewrap info payload is missing `child-pid`"))?;
    u32::try_from(child_pid)
        .into_diagnostic()
        .wrap_err("bubblewrap child pid is out of range")
}

#[cfg(target_os = "linux")]
async fn spawn_component_slirp4netns(
    slirp4netns: &Path,
    runtime_root: &Path,
    component: &DirectComponentPlan,
    sidecar_pid: u32,
    mesh_port: u16,
    children: &mut Vec<ManagedChild>,
    log_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<()> {
    let slirp_root = runtime_root.join("network/slirp4netns");
    fs::create_dir_all(&slirp_root)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create slirp runtime directory {}",
                slirp_root.display()
            )
        })?;
    let api_socket_path = slirp_root.join(format!("c{}.sock", component.id));
    if api_socket_path.exists() {
        fs::remove_file(&api_socket_path)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to remove stale slirp api socket {}",
                    api_socket_path.display()
                )
            })?;
    }

    let mut command = TokioCommand::new(slirp4netns);
    command.args([
        "--configure".to_string(),
        "--mtu=65520".to_string(),
        "--api-socket".to_string(),
        api_socket_path.display().to_string(),
        sidecar_pid.to_string(),
        "tap0".to_string(),
    ]);
    command.current_dir(runtime_root);
    configure_managed_command_env(&mut command, runtime_root, &BTreeMap::new());
    let log_name = format!("{}-slirp4netns", component.sidecar.log_name);
    spawn_managed_command(
        log_name.clone(),
        command,
        None,
        SpawnPidCapture::WrapperProcess,
        children,
        log_tasks,
    )
    .await?;

    slirp4netns_add_hostfwd(&api_socket_path, mesh_port)
        .await
        .map_err(|err| {
            miette::miette!(
                "failed to expose mesh port {} for component {} via slirp4netns ({}): {err}",
                mesh_port,
                component.moniker,
                log_name
            )
        })
}

#[cfg(target_os = "linux")]
fn slirp4netns_add_hostfwd_payload(mesh_port: u16) -> serde_json::Value {
    serde_json::json!({
        "execute": "add_hostfwd",
        "arguments": {
            "proto": "tcp",
            "host_addr": "127.0.0.1",
            "host_port": mesh_port,
            // Let slirp target its configured guest address (10.0.2.100 by default).
            "guest_port": mesh_port,
        }
    })
}

#[cfg(target_os = "linux")]
async fn slirp4netns_add_hostfwd(api_socket_path: &Path, mesh_port: u16) -> Result<()> {
    use std::io::ErrorKind;

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::net::UnixStream::connect(api_socket_path).await {
            Ok(mut stream) => {
                let payload = slirp4netns_add_hostfwd_payload(mesh_port);
                let payload = serde_json::to_vec(&payload).into_diagnostic()?;
                stream
                    .write_all(&payload)
                    .await
                    .into_diagnostic()
                    .wrap_err("failed to write slirp4netns add_hostfwd request")?;
                stream
                    .shutdown()
                    .await
                    .into_diagnostic()
                    .wrap_err("failed to finalize slirp4netns add_hostfwd request")?;

                let mut response = Vec::new();
                stream
                    .read_to_end(&mut response)
                    .await
                    .into_diagnostic()
                    .wrap_err("failed to read slirp4netns add_hostfwd response")?;
                let response: serde_json::Value = serde_json::from_slice(&response)
                    .into_diagnostic()
                    .wrap_err("invalid slirp4netns add_hostfwd response")?;
                if let Some(error) = response.get("error") {
                    return Err(miette::miette!(
                        "slirp4netns add_hostfwd rejected request: {}",
                        error
                    ));
                }
                return Ok(());
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::NotFound
                        | ErrorKind::ConnectionRefused
                        | ErrorKind::ConnectionAborted
                ) =>
            {
                if Instant::now() >= deadline {
                    break;
                }
                sleep(Duration::from_millis(25)).await;
            }
            Err(err) => {
                return Err(miette::miette!(
                    "failed to connect to slirp4netns api socket {}: {err}",
                    api_socket_path.display()
                ));
            }
        }
    }

    Err(miette::miette!(
        "timed out waiting for slirp4netns api socket {}",
        api_socket_path.display()
    ))
}

async fn stream_logs<R>(reader: R, name: String, stderr: bool)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if stderr {
                    eprintln!("[{name}] {line}");
                } else {
                    println!("[{name}] {line}");
                }
            }
            Ok(None) => break,
            Err(err) => {
                eprintln!("[{name}] log stream error: {err}");
                break;
            }
        }
    }
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

async fn supervise_children(children: &mut [ManagedChild]) -> Result<(RuntimeExitReason, i32)> {
    let mut shutdown = std::pin::pin!(wait_for_shutdown_signal());
    loop {
        tokio::select! {
            res = &mut shutdown => {
                res?;
                return Ok((RuntimeExitReason::CtrlC, 0));
            }
            _ = sleep(DIRECT_CHILD_POLL_INTERVAL) => {
                for child in children.iter_mut() {
                    if let Some(status) = child.child.try_wait().into_diagnostic()? {
                        let exit_code = if status.success() {
                            0
                        } else {
                            status.code().unwrap_or(1).max(1)
                        };
                        return Ok((
                            RuntimeExitReason::ChildExited {
                                name: child.name.clone(),
                                status,
                            },
                            exit_code,
                        ));
                    }
                }
            }
        }
    }
}

async fn terminate_children(children: &mut [ManagedChild]) {
    for child in children.iter_mut() {
        if child.child.try_wait().ok().flatten().is_some() {
            continue;
        }
        if let Some(pid) = child.child.id() {
            #[cfg(unix)]
            {
                let _ = send_sigterm(pid);
            }
            #[cfg(not(unix))]
            {
                let _ = child.child.start_kill();
            }
        }
    }

    let deadline = Instant::now() + DIRECT_SHUTDOWN_GRACE_PERIOD;
    loop {
        let mut all_exited = true;
        for child in children.iter_mut() {
            if child.child.try_wait().ok().flatten().is_none() {
                all_exited = false;
            }
        }
        if all_exited || Instant::now() >= deadline {
            break;
        }
        sleep(DIRECT_CHILD_POLL_INTERVAL).await;
    }

    for child in children.iter_mut() {
        if child.child.try_wait().ok().flatten().is_none() {
            let _ = child.child.start_kill();
        }
    }
    for child in children.iter_mut() {
        let _ = child.child.wait().await;
    }
}

#[cfg(unix)]
fn send_sigterm(pid: u32) -> std::result::Result<(), ()> {
    let pid = i32::try_from(pid).map_err(|_| ())?;
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc == 0 { Ok(()) } else { Err(()) }
}

#[derive(Debug)]
enum DirectSandbox {
    #[cfg(target_os = "linux")]
    Bubblewrap {
        binary: PathBuf,
    },
    #[cfg(target_os = "macos")]
    Seatbelt {
        binary: PathBuf,
        profiles_dir: PathBuf,
        next_profile_id: usize,
    },
    None,
}

impl DirectSandbox {
    fn detect(runtime_root: &Path) -> Self {
        #[cfg(not(target_os = "macos"))]
        let _ = runtime_root;

        #[cfg(target_os = "linux")]
        if let Some(binary) = find_in_path("bwrap") {
            return Self::Bubblewrap { binary };
        }

        #[cfg(target_os = "macos")]
        if PathBuf::from("/usr/bin/sandbox-exec").is_file() {
            return Self::Seatbelt {
                binary: PathBuf::from("/usr/bin/sandbox-exec"),
                profiles_dir: runtime_root.join("seatbelt"),
                next_profile_id: 0,
            };
        }

        Self::None
    }

    fn is_available(&self) -> bool {
        !matches!(self, Self::None)
    }

    fn wrap_command(&mut self, spec: &ProcessSpec) -> Result<(String, Vec<String>)> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Bubblewrap { binary } => {
                let mut args = vec![
                    "--die-with-parent".to_string(),
                    "--new-session".to_string(),
                    "--unshare-pid".to_string(),
                    "--unshare-ipc".to_string(),
                    "--unshare-uts".to_string(),
                    "--proc".to_string(),
                    "/proc".to_string(),
                    "--dir".to_string(),
                    "/dev".to_string(),
                    "--tmpfs".to_string(),
                    "/dev/shm".to_string(),
                    "--symlink".to_string(),
                    "/proc/self/fd".to_string(),
                    "/dev/fd".to_string(),
                    "--symlink".to_string(),
                    "/proc/self/fd/0".to_string(),
                    "/dev/stdin".to_string(),
                    "--symlink".to_string(),
                    "/proc/self/fd/1".to_string(),
                    "/dev/stdout".to_string(),
                    "--symlink".to_string(),
                    "/proc/self/fd/2".to_string(),
                    "/dev/stderr".to_string(),
                    "--tmpfs".to_string(),
                    "/tmp".to_string(),
                    "--tmpfs".to_string(),
                    "/run".to_string(),
                    "--dir".to_string(),
                    "/var".to_string(),
                    "--symlink".to_string(),
                    "../run".to_string(),
                    "/var/run".to_string(),
                    "--symlink".to_string(),
                    "../tmp".to_string(),
                    "/var/tmp".to_string(),
                    "--bind".to_string(),
                    spec.work_dir.display().to_string(),
                    spec.work_dir.display().to_string(),
                    "--chdir".to_string(),
                    spec.work_dir.display().to_string(),
                ];
                if matches!(spec.network, ProcessNetwork::Isolated) {
                    args.push("--unshare-net".to_string());
                }
                let read_only_mounts = linux_read_only_mounts(spec);
                let normalized_work_dir = normalize_linux_writable_dir(&spec.work_dir);
                let run_root = Path::new("/run");
                let tmp_root = Path::new("/tmp");
                let mut bind_dirs = BTreeSet::new();
                for dir in &spec.bind_dirs {
                    if !dir.is_absolute() {
                        continue;
                    }
                    let dir = normalize_linux_writable_dir(dir);
                    if dir == normalized_work_dir {
                        continue;
                    }
                    bind_dirs.insert(dir);
                }
                let mut bind_mounts = BTreeSet::new();
                for mount in &spec.bind_mounts {
                    if !mount.source.is_absolute() || !mount.dest.is_absolute() {
                        continue;
                    }
                    bind_mounts.insert((mount.source.clone(), mount.dest.clone()));
                }

                let mut candidate_set = BTreeSet::new();
                for dir in &spec.writable_dirs {
                    if !dir.is_absolute() {
                        continue;
                    }
                    let dir = normalize_linux_writable_dir(dir);
                    if dir.starts_with(&normalized_work_dir)
                        || dir.starts_with(run_root)
                        || dir.starts_with(tmp_root)
                    {
                        continue;
                    }
                    candidate_set.insert(dir);
                }

                // Avoid nested tmpfs mounts: if a writable dir is already covered by a parent tmpfs
                // mount, the runtime can create subdirectories when needed.
                let mut candidates = candidate_set.into_iter().collect::<Vec<_>>();
                candidates.sort_by(|a, b| {
                    linux_path_depth(a)
                        .cmp(&linux_path_depth(b))
                        .then_with(|| a.cmp(b))
                });
                let mut tmpfs_dirs: Vec<PathBuf> = Vec::new();
                for dir in candidates {
                    if tmpfs_dirs.iter().any(|parent| dir.starts_with(parent)) {
                        continue;
                    }
                    tmpfs_dirs.push(dir);
                }

                let mut dirs_to_create_set = BTreeSet::new();
                for mount in &read_only_mounts {
                    linux_insert_mount_dest_dirs(
                        &mut dirs_to_create_set,
                        &mount.dest,
                        mount.source.is_dir(),
                    );
                }
                for dir in &tmpfs_dirs {
                    linux_insert_mount_dest_dirs(&mut dirs_to_create_set, dir, true);
                }
                for dir in &bind_dirs {
                    linux_insert_mount_dest_dirs(&mut dirs_to_create_set, dir, true);
                }
                for (_, dest) in &bind_mounts {
                    linux_insert_mount_dest_dirs(&mut dirs_to_create_set, dest, true);
                }
                let mut dirs_to_create = dirs_to_create_set.into_iter().collect::<Vec<_>>();
                dirs_to_create.sort_by(|a, b| {
                    linux_path_depth(a)
                        .cmp(&linux_path_depth(b))
                        .then_with(|| a.cmp(b))
                });

                for dir in dirs_to_create {
                    if dir == Path::new("/dev")
                        || dir == Path::new("/run")
                        || dir == Path::new("/tmp")
                        || dir == Path::new("/var")
                    {
                        continue;
                    }
                    args.push("--dir".to_string());
                    args.push(dir.display().to_string());
                }
                for mount in read_only_mounts {
                    args.push("--ro-bind".to_string());
                    args.push(mount.source.display().to_string());
                    args.push(mount.dest.display().to_string());
                }
                for hidden in &spec.hidden_paths {
                    if !hidden.is_absolute() {
                        continue;
                    }
                    linux_push_mount_dest_dirs(&mut args, hidden, true);
                    args.push("--tmpfs".to_string());
                    args.push(hidden.display().to_string());
                }
                for dir in tmpfs_dirs {
                    args.push("--tmpfs".to_string());
                    args.push(dir.display().to_string());
                }
                for dir in bind_dirs {
                    let rendered = dir.display().to_string();
                    args.push("--bind".to_string());
                    args.push(rendered.clone());
                    args.push(rendered);
                }
                for (source, dest) in bind_mounts {
                    args.push("--bind".to_string());
                    args.push(source.display().to_string());
                    args.push(dest.display().to_string());
                }
                for device in LINUX_DEFAULT_DEVICE_PATHS {
                    let device = Path::new(device);
                    if !device.exists() {
                        continue;
                    }
                    args.push("--dev-bind".to_string());
                    args.push(device.display().to_string());
                    args.push(device.display().to_string());
                }
                args.push("--".to_string());
                args.push(spec.program.clone());
                args.extend(spec.args.iter().cloned());

                if matches!(spec.network, ProcessNetwork::Join(_)) {
                    return Ok((binary.display().to_string(), args));
                }

                Ok((binary.display().to_string(), args))
            }
            #[cfg(target_os = "macos")]
            Self::Seatbelt {
                binary,
                profiles_dir,
                next_profile_id,
            } => {
                if spec
                    .bind_mounts
                    .iter()
                    .any(|mount| mount.source != mount.dest)
                {
                    return Err(miette::miette!(
                        "direct storage mounts require Linux bubblewrap-style bind mounts; macOS \
                         direct output cannot remap {}",
                        spec.bind_mounts
                            .iter()
                            .find(|mount| mount.source != mount.dest)
                            .map(|mount| mount.dest.display().to_string())
                            .unwrap_or_else(|| "storage mount".to_string())
                    ));
                }
                fs::create_dir_all(profiles_dir.as_path())
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!(
                            "failed to create seatbelt profile directory {}",
                            profiles_dir.display()
                        )
                    })?;
                let profile_path = profiles_dir.join(format!("profile-{next_profile_id}.sb"));
                *next_profile_id += 1;
                let profile = render_seatbelt_profile(spec);
                fs::write(&profile_path, profile)
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!(
                            "failed to write seatbelt profile {}",
                            profile_path.display()
                        )
                    })?;

                let mut args = vec![
                    "-f".to_string(),
                    profile_path.display().to_string(),
                    spec.program.clone(),
                ];
                args.extend(spec.args.iter().cloned());
                Ok((binary.display().to_string(), args))
            }
            Self::None => {
                if spec
                    .bind_mounts
                    .iter()
                    .any(|mount| mount.source != mount.dest)
                {
                    return Err(miette::miette!(
                        "direct storage mounts require a runtime that can bind {} into place",
                        spec.bind_mounts
                            .iter()
                            .find(|mount| mount.source != mount.dest)
                            .map(|mount| mount.dest.display().to_string())
                            .unwrap_or_else(|| "storage mount".to_string())
                    ));
                }
                Ok((spec.program.clone(), spec.args.clone()))
            }
        }
    }
}

const MANAGED_PROCESS_PATH: &str = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/\
                                    local/sbin:/usr/bin:/bin:/usr/sbin:/sbin";

#[cfg(target_os = "linux")]
const LINUX_DEFAULT_READ_ONLY_PATHS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/opt",
    "/nix/store",
    "/etc/alternatives",
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/localtime",
    "/etc/passwd",
    "/etc/group",
    "/etc/ld.so.cache",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/etc/protocols",
    "/etc/services",
];

#[cfg(target_os = "linux")]
const LINUX_DEFAULT_DEVICE_PATHS: &[&str] =
    &["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"];

fn configure_managed_command_env(
    command: &mut TokioCommand,
    work_dir: &Path,
    extra_env: &BTreeMap<String, String>,
) {
    command.env_clear();
    command.env("PATH", MANAGED_PROCESS_PATH);
    command.env("HOME", work_dir);
    command.env("TMPDIR", "/tmp");
    command.envs(extra_env);
}

#[cfg(target_os = "linux")]
fn linux_read_only_mounts(spec: &ProcessSpec) -> Vec<ReadOnlyMount> {
    let mut mounts = BTreeMap::<PathBuf, ReadOnlyMount>::new();
    for mount in linux_default_read_only_mounts() {
        mounts.insert(mount.dest.clone(), mount);
    }
    if let Some(mount) = linux_program_support_mount(spec.program.as_str()) {
        mounts.entry(mount.dest.clone()).or_insert(mount);
    }
    for mount in &spec.read_only_mounts {
        if let Some(mount) = linux_normalize_read_only_mount(mount) {
            mounts.insert(mount.dest.clone(), mount);
        }
    }
    mounts.into_values().collect()
}

#[cfg(target_os = "linux")]
fn linux_default_read_only_mounts() -> Vec<ReadOnlyMount> {
    LINUX_DEFAULT_READ_ONLY_PATHS
        .iter()
        .filter_map(|path| linux_same_path_read_only_mount(Path::new(path)))
        .collect()
}

#[cfg(target_os = "linux")]
fn linux_program_support_mount(program: &str) -> Option<ReadOnlyMount> {
    let program = Path::new(program);
    if !program.is_absolute() {
        return None;
    }
    linux_same_path_read_only_mount(program.parent()?)
}

#[cfg(target_os = "linux")]
fn linux_same_path_read_only_mount(path: &Path) -> Option<ReadOnlyMount> {
    if !path.is_absolute() || !path.exists() {
        return None;
    }
    Some(ReadOnlyMount {
        source: fs::canonicalize(path)
            .ok()
            .unwrap_or_else(|| path.to_path_buf()),
        dest: path.to_path_buf(),
    })
}

#[cfg(target_os = "linux")]
fn linux_normalize_read_only_mount(mount: &ReadOnlyMount) -> Option<ReadOnlyMount> {
    if !mount.source.is_absolute() || !mount.dest.is_absolute() || !mount.source.exists() {
        return None;
    }
    Some(ReadOnlyMount {
        source: fs::canonicalize(&mount.source)
            .ok()
            .unwrap_or_else(|| mount.source.clone()),
        dest: mount.dest.clone(),
    })
}

#[cfg(target_os = "linux")]
fn normalize_linux_writable_dir(path: &Path) -> PathBuf {
    if !path.is_absolute() {
        return path.to_path_buf();
    }

    let mut existing_prefix = path;
    let mut suffix = Vec::new();
    while !existing_prefix.exists() {
        let Some(name) = existing_prefix.file_name() else {
            return path.to_path_buf();
        };
        suffix.push(name.to_os_string());
        let Some(parent) = existing_prefix.parent() else {
            return path.to_path_buf();
        };
        existing_prefix = parent;
    }

    let Ok(mut normalized) = fs::canonicalize(existing_prefix) else {
        return path.to_path_buf();
    };
    for segment in suffix.into_iter().rev() {
        normalized.push(segment);
    }
    normalized
}

#[cfg(target_os = "linux")]
fn linux_path_depth(path: &Path) -> usize {
    use std::path::Component;

    path.components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count()
}

#[cfg(target_os = "linux")]
fn linux_insert_mount_dest_dirs(out: &mut BTreeSet<PathBuf>, path: &Path, include_self: bool) {
    for dir in linux_mount_dest_dirs(path, include_self) {
        out.insert(dir);
    }
}

#[cfg(target_os = "linux")]
fn linux_push_mount_dest_dirs(args: &mut Vec<String>, path: &Path, include_self: bool) {
    for dir in linux_mount_dest_dirs(path, include_self) {
        args.push("--dir".to_string());
        args.push(dir.display().to_string());
    }
}

#[cfg(target_os = "linux")]
fn linux_mount_dest_dirs(path: &Path, include_self: bool) -> Vec<PathBuf> {
    use std::path::Component;

    if !path.is_absolute() {
        return Vec::new();
    }

    let mut current = PathBuf::from("/");
    let mut out = Vec::new();
    for component in path.components() {
        if let Component::Normal(segment) = component {
            current.push(segment);
            out.push(current.clone());
        }
    }
    if !include_self {
        out.pop();
    }
    out
}

#[cfg(target_os = "macos")]
fn render_seatbelt_profile(spec: &ProcessSpec) -> String {
    let mut allowed = BTreeSet::new();
    insert_seatbelt_path_variants(&mut allowed, &spec.work_dir);
    allowed.insert("/tmp".to_string());
    allowed.insert("/private/tmp".to_string());
    for dir in &spec.writable_dirs {
        insert_seatbelt_path_variants(&mut allowed, dir);
    }
    for dir in &spec.bind_dirs {
        insert_seatbelt_path_variants(&mut allowed, dir);
    }

    let mut profile = String::new();
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n");
    profile.push_str("(import \"system.sb\")\n");
    profile.push_str("(allow process*)\n");
    profile.push_str("(allow network*)\n");
    for path in &spec.hidden_paths {
        let mut variants = BTreeSet::new();
        insert_seatbelt_path_variants(&mut variants, path);
        for rendered in variants {
            profile.push_str("(deny file-read* (subpath \"");
            profile.push_str(&rendered.replace('\\', "\\\\").replace('\"', "\\\""));
            profile.push_str("\"))\n");
            profile.push_str("(deny file-write* (subpath \"");
            profile.push_str(&rendered.replace('\\', "\\\\").replace('\"', "\\\""));
            profile.push_str("\"))\n");
        }
    }
    profile.push_str("(allow file-read*)\n");
    profile.push_str("(allow file-write*");
    for path in allowed {
        profile.push_str(" (subpath \"");
        profile.push_str(&path.replace('\\', "\\\\").replace('\"', "\\\""));
        profile.push_str("\")");
    }
    profile.push_str(")\n");
    profile
}

#[cfg(target_os = "macos")]
fn insert_seatbelt_path_variants(out: &mut BTreeSet<String>, path: &Path) {
    let raw = path.display().to_string();
    out.insert(raw.clone());
    if let Some(alias) = seatbelt_private_alias(raw.as_str()) {
        out.insert(alias);
    }

    if let Ok(canonical) = fs::canonicalize(path) {
        let canonical = canonical.display().to_string();
        out.insert(canonical.clone());
        if let Some(alias) = seatbelt_private_alias(canonical.as_str()) {
            out.insert(alias);
        }
    }
}

#[cfg(target_os = "macos")]
fn seatbelt_private_alias(path: &str) -> Option<String> {
    if path == "/private" {
        return Some("/".to_string());
    }
    if let Some(rest) = path.strip_prefix("/private/") {
        return Some(format!("/{rest}"));
    }
    if path == "/var" || path.starts_with("/var/") {
        return Some(format!("/private{path}"));
    }
    None
}

fn missing_direct_sandbox_help() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "install bubblewrap (`bwrap`) and ensure it is available in PATH (direct mode also uses \
         `slirp4netns`)"
    }
    #[cfg(target_os = "macos")]
    {
        "enable /usr/bin/sandbox-exec"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "this platform is not currently supported for `amber run` direct mode"
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for path in env::split_paths(&path_var) {
        let candidate = path.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn resolve_runtime_binary(name: &str) -> Result<String> {
    if let Ok(dir) = env::var("AMBER_RUNTIME_BIN_DIR") {
        let candidate = Path::new(&dir).join(name);
        if candidate.is_file() {
            return Ok(candidate.display().to_string());
        }
        return Err(miette::miette!(
            "runtime binary `{name}` was not found in AMBER_RUNTIME_BIN_DIR ({})",
            Path::new(&dir).display()
        ));
    }

    if let Ok(current_exe) = env::current_exe()
        && let Some(bin_dir) = current_exe.parent()
    {
        for dir in [Some(bin_dir), bin_dir.parent()].into_iter().flatten() {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate.display().to_string());
            }
        }
    }

    if let Some(candidate) = find_in_path(name) {
        return Ok(candidate.display().to_string());
    }

    Err(miette::miette!(
        "could not locate runtime binary `{name}`; set AMBER_RUNTIME_BIN_DIR, place it next to \
         the `amber` binary, or add it to PATH"
    ))
}

fn provision_mesh_filesystem(plan: &MeshProvisionPlan, root: &Path) -> Result<()> {
    if plan.version != MESH_PROVISION_PLAN_VERSION {
        return Err(miette::miette!(
            "unsupported mesh provision plan version {}",
            plan.version
        ));
    }

    let mut identities: HashMap<String, MeshIdentity> = HashMap::new();
    for target in &plan.targets {
        let id = target.config.identity.id.clone();
        identities.entry(id).or_insert_with(|| {
            MeshIdentity::generate(
                target.config.identity.id.clone(),
                target.config.identity.mesh_scope.clone(),
            )
        });
    }

    for target in &plan.targets {
        let output_dir = output_dir_for_target(root, target)?;
        fs::create_dir_all(&output_dir)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to create mesh output directory {}",
                    output_dir.display()
                )
            })?;

        let identity = identities
            .get(&target.config.identity.id)
            .ok_or_else(|| {
                miette::miette!(
                    "missing generated identity for {}",
                    target.config.identity.id
                )
            })?
            .clone();
        let identity_secret = MeshIdentitySecret::from_identity(&identity);
        let public_config = target.config.to_public_config(&identities).map_err(|err| {
            miette::miette!(
                "failed to render mesh config for {}: {err}",
                target.config.identity.id
            )
        })?;

        let identity_path = output_dir.join(MESH_IDENTITY_FILENAME);
        let config_path = output_dir.join(MESH_CONFIG_FILENAME);
        let identity_json = serde_json::to_string_pretty(&identity_secret)
            .map_err(|err| miette::miette!("failed to serialize mesh identity: {err}"))?;
        let config_json = serde_json::to_string_pretty(&public_config)
            .map_err(|err| miette::miette!("failed to serialize mesh config: {err}"))?;
        fs::write(&identity_path, identity_json)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("failed to write mesh identity {}", identity_path.display())
            })?;
        fs::write(&config_path, config_json)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to write mesh config {}", config_path.display()))?;
    }

    Ok(())
}

fn output_dir_for_target(root: &Path, target: &MeshProvisionTarget) -> Result<PathBuf> {
    match &target.output {
        MeshProvisionOutput::Filesystem { dir } => {
            let path = Path::new(dir);
            if path.is_absolute() {
                return Err(miette::miette!(
                    "mesh provision plan contains absolute filesystem output path {}",
                    path.display()
                ));
            }
            Ok(root.join(path))
        }
        MeshProvisionOutput::KubernetesSecret { name, .. } => Err(miette::miette!(
            "direct runtime does not support kubernetes provision target {}",
            name
        )),
    }
}

async fn proxy(args: ProxyArgs, verbose: u8) -> Result<()> {
    let slot_bindings = parse_slot_bindings(&args)?;
    let export_bindings = parse_export_bindings(&args)?;
    if slot_bindings.is_empty() && export_bindings.is_empty() {
        return Err(miette::miette!(
            "at least one --slot NAME=ADDR:PORT or --export NAME=ADDR:PORT is required"
        ));
    }

    let target = load_proxy_target(&args.output)?;
    for binding in &export_bindings {
        let export = binding.export.as_str();
        let export_meta = target
            .metadata
            .exports
            .get(export)
            .ok_or_else(|| miette::miette!("export {export} not found in output"))?;
        let _ = mesh_protocol_from_metadata(&export_meta.protocol)?;
    }
    for binding in &slot_bindings {
        let slot = binding.slot.as_str();
        let slot_meta = target
            .metadata
            .external_slots
            .get(slot)
            .ok_or_else(|| miette::miette!("slot {slot} not found in output"))?;
        if !matches!(slot_meta.kind.as_str(), "http" | "https") {
            return Err(miette::miette!(
                "slot {slot} uses {} but amber proxy only supports http slots",
                slot_meta.kind
            ));
        }
    }

    let control_endpoint = resolve_control_endpoint(&args, &target)?;
    let router_identity = resolve_router_identity(&args, &control_endpoint).await?;
    let router_peer = MeshPeer {
        id: router_identity.id.clone(),
        public_key: router_identity.public_key,
    };
    let router_addr = match args.router_addr {
        Some(addr) => addr,
        None => {
            let router_meta = target.metadata.router.as_ref().ok_or_else(|| {
                miette::miette!("router metadata missing; re-run `amber compile`")
            })?;
            let router_port = match target.kind {
                ProxyTargetKind::Direct if router_meta.mesh_port == 0 => {
                    wait_for_direct_runtime_router_port(
                        &target.source,
                        DIRECT_RUNTIME_STATE_WAIT_TIMEOUT,
                    )
                    .await?
                }
                _ => router_meta.mesh_port,
            };
            if router_port == 0 {
                return Err(miette::miette!(
                    "router mesh port is 0; compile output is missing router metadata"
                ));
            }
            SocketAddr::from(([127, 0, 0, 1], router_port))
        }
    };
    let proxy_identity = build_proxy_identity("/proxy", &router_identity);

    init_tracing(verbose, Some(&proxy_identity))?;

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
        let export_meta = &target.metadata.exports[export];
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
            capability_kind: None,
            capability_profile: None,
            listen_port: binding.listen.port(),
            listen_addr: Some(binding.listen.ip().to_string()),
            protocol,
            http_plugins: Vec::new(),
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
            let slot_meta = &target.metadata.external_slots[slot];
            inbound.push(InboundRoute {
                route_id: component_route_id(&proxy_identity.id, slot, MeshProtocol::Http),
                capability: slot.to_string(),
                capability_kind: Some(slot_meta.kind.clone()),
                capability_profile: None,
                protocol: MeshProtocol::Http,
                http_plugins: Vec::new(),
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
                    tracing::warn!("waiting for router control at {control_endpoint}...");
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
                    tracing::error!(
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

    let mut router = std::pin::pin!(router::run(config));
    let mut shutdown = std::pin::pin!(wait_for_shutdown_signal());
    tokio::select! {
        res = &mut router => res.map_err(|err| miette::miette!("proxy failed: {err}")),
        res = &mut shutdown => {
            res?;
            Ok(())
        }
    }
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
        let kind = if abs.join(DIRECT_PLAN_FILENAME).is_file() {
            ProxyTargetKind::Direct
        } else {
            ProxyTargetKind::Kubernetes
        };
        return Ok(ProxyTarget {
            kind,
            metadata,
            source: if matches!(kind, ProxyTargetKind::Direct) {
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
            .is_some_and(|parent| parent.join(DIRECT_PLAN_FILENAME).is_file())
        {
            ProxyTargetKind::Direct
        } else {
            ProxyTargetKind::Kubernetes
        };
        return Ok(ProxyTarget {
            kind,
            metadata,
            source: if matches!(kind, ProxyTargetKind::Direct) {
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
        let listen_ip = match target.kind {
            ProxyTargetKind::Direct => Ipv4Addr::LOCALHOST,
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let listen = SocketAddr::new(IpAddr::V4(listen_ip), port);
        return Ok((mesh_addr.to_string(), listen));
    }

    let port = pick_free_port()?;
    let mesh_addr = default_mesh_addr(target, port)?;
    let listen_ip = match target.kind {
        ProxyTargetKind::Direct => Ipv4Addr::LOCALHOST,
        _ => Ipv4Addr::UNSPECIFIED,
    };
    let listen = SocketAddr::new(IpAddr::V4(listen_ip), port);
    Ok((mesh_addr, listen))
}

fn default_mesh_addr(target: &ProxyTarget, port: u16) -> Result<String> {
    match target.kind {
        ProxyTargetKind::DockerCompose => Ok(format!("host.docker.internal:{port}")),
        ProxyTargetKind::Direct => Ok(format!("127.0.0.1:{port}")),
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
    let compose_project = match target.kind {
        ProxyTargetKind::DockerCompose => resolve_compose_project_name(args, &target.source)?,
        ProxyTargetKind::Direct => None,
        ProxyTargetKind::Kubernetes => None,
    };
    if matches!(target.kind, ProxyTargetKind::DockerCompose)
        && let Some(volume) = router.control_socket_volume.as_ref()
    {
        let resolved_volume = expand_env_templates(volume, compose_project.as_deref())?;
        let raw_socket_path = router
            .control_socket
            .as_deref()
            .unwrap_or("/amber/control/router-control.sock");
        let socket_path = Path::new(raw_socket_path)
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| format!("/{name}"))
            .unwrap_or_else(|| raw_socket_path.to_string());
        return Ok(ControlEndpoint::VolumeSocket {
            volume: resolved_volume,
            socket_path,
        });
    }
    if let Some(socket) = router.control_socket.as_ref() {
        let resolved = expand_env_templates(socket, compose_project.as_deref())?;
        if matches!(target.kind, ProxyTargetKind::Direct) {
            let _ = resolved;
            return Ok(ControlEndpoint::Unix(direct_current_control_socket_path(
                &target.source,
            )));
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

fn resolve_compose_project_name(args: &ProxyArgs, compose_file: &Path) -> Result<Option<String>> {
    if let Some(explicit) = args.project_name.as_deref() {
        let explicit = explicit.trim();
        if explicit.is_empty() {
            return Err(miette::miette!("--project-name must not be empty"));
        }
        return Ok(Some(explicit.to_string()));
    }

    let env_project = env_var_non_empty(COMPOSE_PROJECT_NAME_ENV).ok();
    let discovered = discover_running_compose_projects(compose_file);
    choose_compose_project_name(
        env_project.as_deref(),
        &discovered,
        infer_default_compose_project_name(compose_file).as_deref(),
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
    let compose_file = compose_file.display().to_string();

    for runtime in ["docker", "podman"] {
        let mut cmd = ProcessCommand::new(runtime);
        cmd.arg("ps")
            .arg("--filter")
            .arg(format!(
                "label=com.docker.compose.project.config_files={compose_file}"
            ))
            .arg("--filter")
            .arg("label=com.docker.compose.service=amber-router")
            .arg("--format")
            .arg("{{.Label \"com.docker.compose.project\"}}");
        let Ok(output) = cmd.output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        for project in parse_compose_project_names(&String::from_utf8_lossy(&output.stdout)) {
            projects.insert(project);
        }
    }

    projects
}

fn parse_compose_project_names(raw: &str) -> BTreeSet<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
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
            let value = compose_project_template_value(name, compose_project_name)
                .or_else(|| env_var_non_empty(name).ok())
                .unwrap_or_else(|| default.to_string());
            out.push_str(&value);
        } else {
            let value = compose_project_template_value(expr, compose_project_name)
                .or_else(|| std::env::var(expr).ok())
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
const CONTROL_SOCKET_MOUNT_DIR: &str = "/amber/control";
const COMPOSE_PROJECT_NAME_ENV: &str = "COMPOSE_PROJECT_NAME";
const CONTROL_SOCKET_UID_GID: &str = "65532:65532";

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
                tracing::error!(
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
                    tracing::warn!("waiting for router control at {endpoint}...");
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
        ControlEndpoint::Unix(path) => {
            let stream = tokio::net::UnixStream::connect(path).await.map_err(|err| {
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
    let socket_file = Path::new(socket_path)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ControlUpdateError::Fatal(format!(
                "invalid router control socket path (missing filename): {socket_path}"
            ))
        })?;
    let mounted_socket_path = format!("{CONTROL_SOCKET_MOUNT_DIR}/{socket_file}");
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

enum CompileInput {
    Manifest(ResolvedInput),
    ScenarioIr(CompiledScenario),
}

async fn resolve_compile_input(input: &str) -> Result<CompileInput> {
    if let Some(path) = local_input_path(input)?
        && let Some(compiled) = load_compiled_scenario_ir(&path)?
    {
        return Ok(CompileInput::ScenarioIr(compiled));
    }

    resolve_input(input).await.map(CompileInput::Manifest)
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

fn load_compiled_scenario_ir(path: &Path) -> Result<Option<CompiledScenario>> {
    if !path.is_file() {
        return Ok(None);
    }

    let bytes = fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read Scenario IR input `{}`", path.display()))?;
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };

    let Some(obj) = value.as_object() else {
        return Ok(None);
    };
    let Some(schema) = obj.get("schema").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    if schema != SCENARIO_IR_SCHEMA {
        return Ok(None);
    }

    let ir: ScenarioIr = serde_json::from_value(value)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid Scenario IR input `{}`", path.display()))?;
    CompiledScenario::from_ir(ir)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid Scenario IR input `{}`", path.display()))
        .map(Some)
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
    docker_compose: Option<PathBuf>,
    metadata: Option<ArtifactOutput>,
    kubernetes: Option<PathBuf>,
    direct: Option<PathBuf>,
}

fn ensure_outputs_requested(args: &CompileArgs) -> Result<()> {
    if args.output.is_some()
        || args.dot.is_some()
        || args.docker_compose.is_some()
        || args.metadata.is_some()
        || args.bundle.is_some()
        || args.kubernetes.is_some()
        || args.direct.is_some()
    {
        return Ok(());
    }

    Err(miette::miette!(
        help = "Request at least one output with `--output`, `--dot`, `--docker-compose`, \
                `--metadata`, `--kubernetes`, `--direct`, or `--bundle`.",
        "no outputs requested for `amber compile`"
    ))
}

fn resolve_output_paths(args: &CompileArgs) -> Result<OutputPaths> {
    let primary = args.output.clone();
    let dot = resolve_optional_output(&args.dot);
    let docker_compose = args.docker_compose.clone();
    let metadata = resolve_optional_output(&args.metadata);
    let kubernetes = args.kubernetes.clone();
    let direct = args.direct.clone();

    let file_outputs = [
        ("primary output", primary.as_deref()),
        ("dot output", artifact_file_path(dot.as_ref())),
        ("metadata output", artifact_file_path(metadata.as_ref())),
    ];
    for (index, (left_name, left_path)) in file_outputs.iter().enumerate() {
        let Some(left_path) = left_path else {
            continue;
        };
        for (right_name, right_path) in file_outputs.iter().skip(index + 1) {
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

    let directory_outputs = [
        ("docker compose output directory", docker_compose.as_ref()),
        ("kubernetes output directory", kubernetes.as_ref()),
        ("direct output directory", direct.as_ref()),
    ];
    for (name, dir) in [
        ("docker compose output directory", docker_compose.as_ref()),
        ("kubernetes output directory", kubernetes.as_ref()),
        ("direct output directory", direct.as_ref()),
    ] {
        let Some(dir) = dir else {
            continue;
        };
        for (file_name, file_path) in file_outputs {
            if file_path.is_some_and(|file_path| file_path == dir.as_path()) {
                return Err(miette::miette!(
                    "{} `{}` must not match {} path",
                    name,
                    dir.display(),
                    file_name
                ));
            }
        }
    }

    for (index, (left_name, left_dir)) in directory_outputs.iter().enumerate() {
        let Some(left_dir) = left_dir else {
            continue;
        };
        for (right_name, right_dir) in directory_outputs.iter().skip(index + 1) {
            if right_dir.is_some_and(|right_dir| right_dir == *left_dir) {
                return Err(miette::miette!(
                    "{} `{}` must not match {}",
                    left_name,
                    left_dir.display(),
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
        direct,
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

fn write_primary_output(path: &Path, compiled: &CompiledScenario) -> Result<()> {
    let ir = ScenarioIrReporter
        .emit(compiled)
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

fn write_docker_compose_output(
    root: &Path,
    artifact: &amber_compiler::reporter::docker_compose::DockerComposeArtifact,
) -> Result<()> {
    write_directory_output(
        root,
        "docker compose output directory",
        &artifact.files,
        None,
    )
}

fn write_kubernetes_output(
    root: &Path,
    artifact: &amber_compiler::reporter::kubernetes::KubernetesArtifact,
) -> Result<()> {
    write_directory_output(root, "kubernetes output directory", &artifact.files, None)
}

fn write_direct_output(root: &Path, artifact: &DirectArtifact) -> Result<()> {
    write_directory_output(
        root,
        "direct output directory",
        &artifact.files,
        Some(Path::new(RUN_SCRIPT_FILENAME)),
    )
}

fn write_directory_output(
    root: &Path,
    label: &str,
    files: &BTreeMap<PathBuf, String>,
    executable_rel_path: Option<&Path>,
) -> Result<()> {
    if root.exists() {
        if root.is_dir() {
            std::fs::remove_dir_all(root)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to remove {label} `{}`", root.display()))?;
        } else {
            return Err(miette::miette!(
                "{} `{}` is not a directory",
                label,
                root.display()
            ));
        }
    }

    std::fs::create_dir_all(root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {label} `{}`", root.display()))?;

    for (rel_path, content) in files {
        let full_path = root.join(rel_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create directory `{}`", parent.display()))?;
        }
        std::fs::write(&full_path, content)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to write `{}`", full_path.display()))?;
        #[cfg(unix)]
        if executable_rel_path.is_some_and(|expected| rel_path.as_path() == expected) {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = std::fs::metadata(&full_path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to stat `{}`", full_path.display()))?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&full_path, perms)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to chmod `{}`", full_path.display()))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EnvVarRestore {
        name: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarRestore {
        fn set(name: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(name);
            unsafe {
                std::env::set_var(name, value);
            }
            Self { name, previous }
        }
    }

    impl Drop for EnvVarRestore {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => unsafe {
                    std::env::set_var(self.name, value);
                },
                None => unsafe {
                    std::env::remove_var(self.name);
                },
            }
        }
    }

    fn test_proxy_args() -> ProxyArgs {
        ProxyArgs {
            output: String::new(),
            project_name: None,
            slot: Vec::new(),
            export: Vec::new(),
            mesh_addr: None,
            router_addr: None,
            router_control_addr: None,
            router_config_b64: None,
            router_config: None,
        }
    }

    #[test]
    fn verbosity_levels_follow_v_flag_ladder() {
        assert_eq!(verbosity_level(0), "error");
        assert_eq!(verbosity_level(1), "warn");
        assert_eq!(verbosity_level(2), "info");
        assert_eq!(verbosity_level(3), "debug");
        assert_eq!(verbosity_level(4), "trace");
        assert_eq!(verbosity_level(9), "trace");
    }

    #[test]
    fn proxy_console_is_quiet_by_default() {
        assert_eq!(
            console_filter_spec(0),
            "error,amber=error,amber_=error,amber_router=error,amber.binding=error,amber.\
             proxy=error"
        );
    }

    #[test]
    fn parse_compose_project_names_ignores_empty_lines() {
        let projects = parse_compose_project_names("alpha\n\n beta \n");
        assert_eq!(
            projects,
            BTreeSet::from(["alpha".to_string(), "beta".to_string()])
        );
    }

    #[test]
    fn choose_compose_project_name_prefers_single_running_stack() {
        let discovered = BTreeSet::from(["custom-stack".to_string()]);
        let selected = choose_compose_project_name(
            None,
            &discovered,
            Some("tmp"),
            Path::new("/tmp/amber.yaml"),
        )
        .expect("selection should succeed");
        assert_eq!(selected.as_deref(), Some("custom-stack"));
    }

    #[test]
    fn choose_compose_project_name_prefers_env_override() {
        let discovered = BTreeSet::from(["custom-stack".to_string()]);
        let selected = choose_compose_project_name(
            Some("from-env"),
            &discovered,
            Some("tmp"),
            Path::new("/tmp/amber.yaml"),
        )
        .expect("selection should succeed");
        assert_eq!(selected.as_deref(), Some("from-env"));
    }

    #[test]
    fn choose_compose_project_name_rejects_multiple_running_stacks() {
        let discovered = BTreeSet::from(["stack-a".to_string(), "stack-b".to_string()]);
        let err = choose_compose_project_name(
            None,
            &discovered,
            Some("tmp"),
            Path::new("/tmp/amber.yaml"),
        )
        .expect_err("selection should fail");
        let rendered = err.to_string();
        assert!(rendered.contains("stack-a"), "{rendered}");
        assert!(rendered.contains("stack-b"), "{rendered}");
        assert!(rendered.contains("--project-name"), "{rendered}");
    }

    #[test]
    fn expand_env_templates_prefers_explicit_compose_project_name() {
        let _compose_project = EnvVarRestore::set(COMPOSE_PROJECT_NAME_ENV, "from-env");

        let result = expand_env_templates(
            "${COMPOSE_PROJECT_NAME}/router/${COMPOSE_PROJECT_NAME:-fallback}",
            Some("from-flag"),
        )
        .expect("template should render");

        assert_eq!(result, "from-flag/router/from-flag");
    }

    #[test]
    fn expand_env_templates_uses_env_for_other_names() {
        let _test_env = EnvVarRestore::set("AMBER_TEMPLATE_TEST", "from-env");

        let result = expand_env_templates(
            "${AMBER_TEMPLATE_TEST}/${AMBER_TEMPLATE_TEST:-fallback}",
            Some("from-flag"),
        )
        .expect("template should render");

        assert_eq!(result, "from-env/from-env");
    }

    #[test]
    fn ensure_absolute_direct_program_path_rejects_relative_paths() {
        let err = ensure_absolute_direct_program_path("./bin/server", "app")
            .expect_err("relative program path should fail");
        let rendered = err.to_string();
        assert!(rendered.contains("non-absolute program path"), "{rendered}");
        assert!(rendered.contains("amber compile --direct"), "{rendered}");
    }

    #[test]
    fn proxy_telemetry_keeps_router_info_without_verbose_output() {
        assert_eq!(
            proxy_telemetry_filter_spec(0),
            "error,amber=error,amber_=error,amber_router=info,amber.proxy=error"
        );
    }

    #[test]
    fn component_program_read_only_mounts_resolve_parent_escape_paths() {
        let component = DirectComponentPlan {
            id: 3,
            moniker: "app".to_string(),
            log_name: "app".to_string(),
            source_dir: Some("/workspace/scenarios/app".to_string()),
            depends_on: Vec::new(),
            sidecar: amber_compiler::reporter::direct::DirectSidecarPlan {
                log_name: "app-sidecar".to_string(),
                mesh_port: 0,
                mesh_config_path: "mesh/components/app/mesh-config.json".to_string(),
                mesh_identity_path: "mesh/components/app/mesh-identity.json".to_string(),
            },
            program: amber_compiler::reporter::direct::DirectProgramPlan {
                log_name: "app-program".to_string(),
                work_dir: "work/components/app".to_string(),
                storage_mounts: Vec::new(),
                execution: DirectProgramExecutionPlan::Direct {
                    entrypoint: vec!["/workspace/scenarios/app/../bin/tool".to_string()],
                    env: BTreeMap::new(),
                },
            },
        };

        let mounts = component_program_read_only_mounts(
            &component,
            Some(Path::new("/workspace/scenarios/app")),
        )
        .expect("mounts should resolve");

        assert!(
            mounts
                .iter()
                .any(|mount| mount.source == Path::new("/workspace/scenarios/app"))
        );
        assert!(
            mounts
                .iter()
                .any(|mount| mount.source == Path::new("/workspace/scenarios/app/../bin"))
        );
    }

    #[test]
    fn build_runtime_template_context_uses_runtime_slot_ports() {
        let runtime_addresses = DirectRuntimeAddressPlan {
            slots_by_scope: BTreeMap::from([(
                3,
                BTreeMap::from([(
                    "api".to_string(),
                    DirectRuntimeUrlSource::Slot {
                        component_id: 7,
                        slot: "api".to_string(),
                        scheme: "http".to_string(),
                    },
                )]),
            )]),
            slot_items_by_scope: BTreeMap::from([(
                5,
                BTreeMap::from([(
                    "upstream".to_string(),
                    vec![
                        DirectRuntimeUrlSource::SlotItem {
                            component_id: 8,
                            slot: "upstream".to_string(),
                            item_index: 0,
                            scheme: "http".to_string(),
                        },
                        DirectRuntimeUrlSource::SlotItem {
                            component_id: 8,
                            slot: "upstream".to_string(),
                            item_index: 1,
                            scheme: "http".to_string(),
                        },
                    ],
                )]),
            )]),
        };
        let runtime_state = DirectRuntimeState {
            slot_ports_by_component: BTreeMap::from([(
                7,
                BTreeMap::from([("api".to_string(), 31001)]),
            )]),
            slot_route_ports_by_component: BTreeMap::from([(
                8,
                BTreeMap::from([("upstream".to_string(), vec![32001, 32002])]),
            )]),
            component_mesh_port_by_id: BTreeMap::new(),
            router_mesh_port: None,
        };

        let context =
            build_runtime_template_context(&runtime_addresses, &runtime_state).expect("context");

        assert_eq!(
            context
                .slots_by_scope
                .get(&3)
                .and_then(|values| values.get("api")),
            Some(&r#"{"url":"http://127.0.0.1:31001"}"#.to_string())
        );
        assert_eq!(
            context
                .slots_by_scope
                .get(&3)
                .and_then(|values| values.get("api.url")),
            Some(&"http://127.0.0.1:31001".to_string())
        );
        assert_eq!(
            context
                .slot_items_by_scope
                .get(&5)
                .and_then(|values| values.get("upstream"))
                .map(|items| items
                    .iter()
                    .map(|item| item.url.as_str())
                    .collect::<Vec<_>>()),
            Some(vec!["http://127.0.0.1:32001", "http://127.0.0.1:32002"])
        );
    }

    #[test]
    fn assign_direct_runtime_ports_preserves_repeated_slot_item_order() {
        let temp = tempfile::tempdir().expect("temp dir should be created");
        let mesh_config_rel = PathBuf::from("mesh/components/app/mesh-config.json");
        let mesh_config_path = temp.path().join(&mesh_config_rel);
        fs::create_dir_all(
            mesh_config_path
                .parent()
                .expect("mesh config should have a parent"),
        )
        .expect("mesh config dir should be created");

        let config = MeshConfigPublic {
            identity: MeshIdentityPublic {
                id: "/app".to_string(),
                public_key: [7; 32],
                mesh_scope: None,
            },
            mesh_listen: "127.0.0.1:19000".parse().expect("mesh listen"),
            control_listen: None,
            control_allow: None,
            peers: Vec::new(),
            inbound: Vec::new(),
            outbound: vec![
                OutboundRoute {
                    route_id: "route-b".to_string(),
                    slot: "upstream".to_string(),
                    capability_kind: Some("http".to_string()),
                    capability_profile: None,
                    listen_port: 20001,
                    listen_addr: None,
                    protocol: MeshProtocol::Http,
                    http_plugins: Vec::new(),
                    peer_addr: "127.0.0.1:18081".to_string(),
                    peer_id: "/app".to_string(),
                    capability: "api".to_string(),
                },
                OutboundRoute {
                    route_id: "route-a".to_string(),
                    slot: "upstream".to_string(),
                    capability_kind: Some("http".to_string()),
                    capability_profile: None,
                    listen_port: 20000,
                    listen_addr: None,
                    protocol: MeshProtocol::Http,
                    http_plugins: Vec::new(),
                    peer_addr: "127.0.0.1:18080".to_string(),
                    peer_id: "/app".to_string(),
                    capability: "api".to_string(),
                },
            ],
            transport: TransportConfig::NoiseIk {},
        };
        write_mesh_config_public(&mesh_config_path, &config)
            .expect("mesh config should be written");

        let direct_plan = DirectPlan {
            version: DIRECT_PLAN_VERSION.to_string(),
            mesh_provision_plan: "{}".to_string(),
            startup_order: vec![7],
            components: vec![DirectComponentPlan {
                id: 7,
                moniker: "/app".to_string(),
                log_name: "app".to_string(),
                source_dir: None,
                depends_on: Vec::new(),
                sidecar: amber_compiler::reporter::direct::DirectSidecarPlan {
                    log_name: "app-sidecar".to_string(),
                    mesh_port: 0,
                    mesh_config_path: mesh_config_rel.display().to_string(),
                    mesh_identity_path: "mesh/components/app/mesh-identity.json".to_string(),
                },
                program: amber_compiler::reporter::direct::DirectProgramPlan {
                    log_name: "app-program".to_string(),
                    work_dir: "work/components/app".to_string(),
                    storage_mounts: Vec::new(),
                    execution: DirectProgramExecutionPlan::Direct {
                        entrypoint: vec!["/bin/echo".to_string()],
                        env: BTreeMap::new(),
                    },
                },
            }],
            runtime_addresses: DirectRuntimeAddressPlan {
                slots_by_scope: BTreeMap::new(),
                slot_items_by_scope: BTreeMap::from([(
                    7,
                    BTreeMap::from([(
                        "upstream".to_string(),
                        vec![
                            DirectRuntimeUrlSource::SlotItem {
                                component_id: 7,
                                slot: "upstream".to_string(),
                                item_index: 0,
                                scheme: "http".to_string(),
                            },
                            DirectRuntimeUrlSource::SlotItem {
                                component_id: 7,
                                slot: "upstream".to_string(),
                                item_index: 1,
                                scheme: "http".to_string(),
                            },
                        ],
                    )]),
                )]),
            },
            router: None,
        };

        let runtime_state =
            assign_direct_runtime_ports(temp.path(), &direct_plan).expect("ports should assign");
        let rewritten =
            read_mesh_config_public(&mesh_config_path).expect("mesh config should be rewritten");
        let runtime_ports = runtime_state
            .slot_route_ports_by_component
            .get(&7)
            .and_then(|slots| slots.get("upstream"))
            .expect("runtime slot ports should exist");
        let route_ports: Vec<u16> = rewritten
            .outbound
            .iter()
            .map(|route| route.listen_port)
            .collect();

        assert_eq!(runtime_ports.len(), 2);
        assert_eq!(route_ports.len(), 2);
        assert_eq!(runtime_ports[0], route_ports[1]);
        assert_eq!(runtime_ports[1], route_ports[0]);

        let context =
            build_runtime_template_context(&direct_plan.runtime_addresses, &runtime_state)
                .expect("context should build");
        let item_urls = context
            .slot_items_by_scope
            .get(&7)
            .and_then(|slots| slots.get("upstream"))
            .expect("runtime item urls should exist");
        assert_eq!(item_urls.len(), 2);
        assert_eq!(
            item_urls[0].url,
            format!("http://127.0.0.1:{}", runtime_ports[0])
        );
        assert_eq!(
            item_urls[1].url,
            format!("http://127.0.0.1:{}", runtime_ports[1])
        );
    }

    #[test]
    fn resolve_control_endpoint_uses_short_direct_control_socket_alias() {
        let source = PathBuf::from(
            "/home/runner/work/amber/amber/target/cli-test-outputs/direct-smoke-FOF9wf/out",
        );
        let target = ProxyTarget {
            kind: ProxyTargetKind::Direct,
            metadata: ProxyMetadata {
                version: PROXY_METADATA_VERSION.to_string(),
                router: Some(amber_compiler::mesh::RouterMetadata {
                    mesh_port: 0,
                    control_port: 0,
                    control_socket: Some(".amber/router-control.sock".to_string()),
                    control_socket_volume: None,
                }),
                ..Default::default()
            },
            source: source.clone(),
        };

        let endpoint =
            resolve_control_endpoint(&test_proxy_args(), &target).expect("endpoint should resolve");

        let ControlEndpoint::Unix(path) = endpoint else {
            panic!("expected unix control endpoint");
        };
        assert_eq!(path, direct_current_control_socket_path(&source));
        assert!(
            path.as_os_str().len() < 100,
            "direct control alias should stay well below unix socket path limits: {}",
            path.display()
        );
    }

    #[test]
    fn direct_runtime_control_socket_path_is_unique_per_run() {
        let first = tempfile::tempdir().expect("temp dir should be created");
        let second = tempfile::tempdir().expect("temp dir should be created");

        assert_ne!(
            direct_runtime_control_socket_path(first.path()),
            direct_runtime_control_socket_path(second.path())
        );
    }

    #[test]
    fn direct_storage_root_defaults_next_to_output() {
        let root = direct_storage_root(Path::new("/tmp/out"), None).expect("storage root");
        assert_eq!(root, Path::new("/tmp/.out.amber-state"));
    }

    #[test]
    fn direct_storage_root_uses_explicit_override() {
        let root = direct_storage_root(
            Path::new("/tmp/out"),
            Some(Path::new("custom-storage-root")),
        )
        .expect("storage root");
        assert!(
            root.ends_with("custom-storage-root"),
            "override should be used verbatim: {}",
            root.display()
        );
    }

    #[tokio::test]
    async fn wait_for_direct_runtime_router_port_reads_state_written_after_startup() {
        let temp = tempfile::tempdir().expect("temp dir should be created");
        let plan_root = temp.path().to_path_buf();

        let writer = tokio::spawn({
            let plan_root = plan_root.clone();
            async move {
                sleep(Duration::from_millis(100)).await;
                let state = DirectRuntimeState {
                    slot_ports_by_component: BTreeMap::new(),
                    slot_route_ports_by_component: BTreeMap::new(),
                    component_mesh_port_by_id: BTreeMap::new(),
                    router_mesh_port: Some(32123),
                };
                write_direct_runtime_state(&plan_root, &state).expect("state should write");
            }
        });

        let port = wait_for_direct_runtime_router_port(&plan_root, Duration::from_secs(1))
            .await
            .expect("router port should become available");
        writer.await.expect("writer task should finish");

        assert_eq!(port, 32123);
    }

    #[cfg(unix)]
    #[test]
    fn remove_direct_control_socket_link_preserves_newer_run_symlink() {
        let plan_root = tempfile::tempdir().expect("temp dir should be created");
        let runtime_one = tempfile::tempdir().expect("temp dir should be created");
        let runtime_two = tempfile::tempdir().expect("temp dir should be created");
        let paths_one = DirectControlSocketPaths {
            artifact_link: plan_root.path().join(".amber/router-control.sock"),
            current_link: direct_current_control_socket_path(plan_root.path()),
            runtime: direct_runtime_control_socket_path(runtime_one.path()),
        };
        let runtime_two_socket = direct_runtime_control_socket_path(runtime_two.path());
        fs::create_dir_all(paths_one.current_link.parent().expect("link parent"))
            .expect("link parent should be created");
        std::os::unix::fs::symlink(&runtime_two_socket, &paths_one.current_link)
            .expect("symlink should be created");

        remove_direct_control_socket_link(&paths_one);

        assert_eq!(
            fs::read_link(&paths_one.current_link).expect("newer run symlink should remain"),
            runtime_two_socket
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cleanup_direct_runtime_removes_partial_startup_artifacts() {
        let plan_root = tempfile::tempdir().expect("temp dir should be created");
        let runtime_dir = tempfile::Builder::new()
            .prefix("amber-direct-test-")
            .tempdir()
            .expect("runtime dir should be created");
        let runtime_root = runtime_dir.path().to_path_buf();
        let runtime_state_path = direct_runtime_state_path(plan_root.path());
        fs::create_dir_all(runtime_state_path.parent().expect("state parent"))
            .expect("state parent should be created");
        fs::write(&runtime_state_path, "{}").expect("state file should be written");

        let control_socket_paths = DirectControlSocketPaths {
            artifact_link: plan_root.path().join(".amber/router-control.sock"),
            current_link: direct_current_control_socket_path(plan_root.path()),
            runtime: direct_runtime_control_socket_path(&runtime_root),
        };
        fs::create_dir_all(
            control_socket_paths
                .artifact_link
                .parent()
                .expect("link parent"),
        )
        .expect("link parent should be created");
        fs::create_dir_all(
            control_socket_paths
                .current_link
                .parent()
                .expect("current link parent"),
        )
        .expect("current link parent should be created");
        fs::create_dir_all(
            control_socket_paths
                .runtime
                .parent()
                .expect("runtime parent"),
        )
        .expect("runtime parent should be created");
        fs::write(&control_socket_paths.runtime, "").expect("runtime socket placeholder");
        std::os::unix::fs::symlink(
            &control_socket_paths.current_link,
            &control_socket_paths.artifact_link,
        )
        .expect("artifact symlink should be created");
        std::os::unix::fs::symlink(
            &control_socket_paths.runtime,
            &control_socket_paths.current_link,
        )
        .expect("symlink should be created");

        let child = TokioCommand::new("sh")
            .arg("-c")
            .arg("sleep 30")
            .spawn()
            .expect("child should spawn");
        let mut children = vec![ManagedChild {
            name: "partial-startup-child".to_string(),
            child,
        }];

        cleanup_direct_runtime(
            &mut children,
            Vec::new(),
            &runtime_state_path,
            Some(&control_socket_paths),
            runtime_dir,
        )
        .await;

        assert!(
            fs::symlink_metadata(&control_socket_paths.artifact_link).is_ok(),
            "artifact control socket link should remain available for future runs"
        );
        assert_eq!(
            fs::read_link(&control_socket_paths.artifact_link)
                .expect("artifact link should still point at current alias"),
            control_socket_paths.current_link
        );
        assert!(
            fs::symlink_metadata(&control_socket_paths.current_link).is_err(),
            "current control socket link should be removed"
        );
        assert!(
            fs::metadata(&control_socket_paths.runtime).is_err(),
            "runtime control socket should be removed"
        );
        assert!(
            fs::metadata(&runtime_state_path).is_err(),
            "runtime state should be removed"
        );
        assert!(
            fs::metadata(&runtime_root).is_err(),
            "runtime workspace should be removed"
        );

        let status = children[0]
            .child
            .wait()
            .await
            .expect("child should be reaped after cleanup");
        assert!(
            !status.success(),
            "cleanup should terminate partial-startup child"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supervise_children_treats_zero_exit_as_success() {
        let child = TokioCommand::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("child should spawn");
        let mut children = vec![ManagedChild {
            name: "ok-child".to_string(),
            child,
        }];

        let (reason, exit_code) = supervise_children(&mut children)
            .await
            .expect("supervision should succeed");
        assert_eq!(exit_code, 0);
        match reason {
            RuntimeExitReason::ChildExited { name, status } => {
                assert_eq!(name, "ok-child");
                assert!(status.success());
            }
            RuntimeExitReason::CtrlC => panic!("unexpected Ctrl+C reason"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supervise_children_propagates_non_zero_exit() {
        let child = TokioCommand::new("sh")
            .arg("-c")
            .arg("exit 7")
            .spawn()
            .expect("child should spawn");
        let mut children = vec![ManagedChild {
            name: "fail-child".to_string(),
            child,
        }];

        let (reason, exit_code) = supervise_children(&mut children)
            .await
            .expect("supervision should succeed");
        assert_eq!(exit_code, 7);
        match reason {
            RuntimeExitReason::ChildExited { name, status } => {
                assert_eq!(name, "fail-child");
                assert_eq!(status.code(), Some(7));
            }
            RuntimeExitReason::CtrlC => panic!("unexpected Ctrl+C reason"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn normalize_linux_writable_dir_resolves_symlink_prefix() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temp dir should be created");
        let real_root = temp.path().join("real");
        fs::create_dir_all(&real_root).expect("real root should be created");
        let symlink_root = temp.path().join("symlink");
        symlink(&real_root, &symlink_root).expect("symlink should be created");

        let normalized = normalize_linux_writable_dir(&symlink_root.join("nested/dir"));
        assert_eq!(normalized, real_root.join("nested/dir"));
    }

    #[cfg(target_os = "linux")]
    fn linux_test_process_spec() -> ProcessSpec {
        ProcessSpec {
            name: "component".to_string(),
            program: "/bin/echo".to_string(),
            args: vec!["ok".to_string()],
            env: BTreeMap::new(),
            work_dir: PathBuf::from("/tmp/amber-work"),
            read_only_mounts: Vec::new(),
            writable_dirs: Vec::new(),
            bind_dirs: Vec::new(),
            bind_mounts: Vec::new(),
            hidden_paths: Vec::new(),
            network: ProcessNetwork::Host,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rewrite_mesh_listen_for_slirp_guest_rewrites_loopback_only() {
        assert_eq!(
            rewrite_mesh_listen_for_slirp_guest("127.0.0.1:23000".parse().expect("addr")),
            "0.0.0.0:23000".parse().expect("addr")
        );
        assert_eq!(
            rewrite_mesh_listen_for_slirp_guest("192.168.1.10:23000".parse().expect("addr")),
            "192.168.1.10:23000".parse().expect("addr")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rewrite_peer_addr_for_slirp_gateway_rewrites_loopback_only() {
        assert_eq!(
            rewrite_peer_addr_for_slirp_gateway("127.0.0.1:23000"),
            "10.0.2.2:23000"
        );
        assert_eq!(
            rewrite_peer_addr_for_slirp_gateway("[::1]:24000"),
            "10.0.2.2:24000"
        );
        assert_eq!(
            rewrite_peer_addr_for_slirp_gateway("192.168.1.10:25000"),
            "192.168.1.10:25000"
        );
        assert_eq!(
            rewrite_peer_addr_for_slirp_gateway("not-a-socket"),
            "not-a-socket"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn slirp4netns_add_hostfwd_payload_uses_guest_default_address() {
        let payload = slirp4netns_add_hostfwd_payload(23000);
        assert_eq!(payload["execute"], "add_hostfwd");
        assert_eq!(payload["arguments"]["proto"], "tcp");
        assert_eq!(payload["arguments"]["host_addr"], "127.0.0.1");
        assert_eq!(payload["arguments"]["host_port"], 23000);
        assert_eq!(payload["arguments"]["guest_port"], 23000);
        assert!(
            payload["arguments"].get("guest_addr").is_none(),
            "guest_addr should be omitted so slirp targets its configured guest address"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bubblewrap_does_not_emit_tmpfs_for_var_run_symlink_path() {
        let mut sandbox = DirectSandbox::Bubblewrap {
            binary: PathBuf::from("/usr/bin/bwrap"),
        };
        let spec = ProcessSpec {
            writable_dirs: vec![PathBuf::from("/var/run"), PathBuf::from("/run")],
            ..linux_test_process_spec()
        };

        let (_, args) = sandbox
            .wrap_command(&spec)
            .expect("command should be wrapped");
        assert!(
            !args
                .windows(2)
                .any(|pair| pair[0] == "--tmpfs" && pair[1] == "/var/run"),
            "bubblewrap args unexpectedly include --tmpfs /var/run: {args:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bubblewrap_creates_missing_tmpfs_mountpoints() {
        let mut sandbox = DirectSandbox::Bubblewrap {
            binary: PathBuf::from("/usr/bin/bwrap"),
        };
        let spec = ProcessSpec {
            writable_dirs: vec![PathBuf::from("/__amber_bwrap_test__/nested")],
            ..linux_test_process_spec()
        };

        let (_, args) = sandbox
            .wrap_command(&spec)
            .expect("command should be wrapped");

        let parent_pos = args
            .windows(2)
            .position(|pair| pair[0] == "--dir" && pair[1] == "/__amber_bwrap_test__")
            .expect("expected --dir for parent tmpfs mountpoint");
        let nested_pos = args
            .windows(2)
            .position(|pair| pair[0] == "--dir" && pair[1] == "/__amber_bwrap_test__/nested")
            .expect("expected --dir for tmpfs mountpoint");
        let tmpfs_pos = args
            .windows(2)
            .position(|pair| pair[0] == "--tmpfs" && pair[1] == "/__amber_bwrap_test__/nested")
            .expect("expected --tmpfs for mountpoint");

        assert!(
            parent_pos < nested_pos,
            "--dir parent should precede nested: {args:?}"
        );
        assert!(
            nested_pos < tmpfs_pos,
            "--dir should precede --tmpfs for the same mountpoint: {args:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bubblewrap_isolated_network_adds_unshare_net() {
        let mut sandbox = DirectSandbox::Bubblewrap {
            binary: PathBuf::from("/usr/bin/bwrap"),
        };
        let spec = ProcessSpec {
            network: ProcessNetwork::Isolated,
            ..linux_test_process_spec()
        };

        let (_, args) = sandbox
            .wrap_command(&spec)
            .expect("command should be wrapped");
        assert!(
            args.contains(&"--unshare-net".to_string()),
            "bubblewrap args missing --unshare-net: {args:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bubblewrap_uses_curated_linux_mounts() {
        let mut sandbox = DirectSandbox::Bubblewrap {
            binary: PathBuf::from("/usr/bin/bwrap"),
        };
        let spec = linux_test_process_spec();

        let (_, args) = sandbox
            .wrap_command(&spec)
            .expect("command should be wrapped");
        assert!(
            !args.contains(&"--dev".to_string()),
            "bubblewrap args unexpectedly include --dev: {args:?}"
        );
        assert!(
            !args
                .windows(3)
                .any(|window| { window[0] == "--ro-bind" && window[1] == "/" && window[2] == "/" }),
            "bubblewrap args unexpectedly include a full host root bind: {args:?}"
        );
        assert!(
            args.windows(3)
                .any(|window| { window[0] == "--ro-bind" && window[2] == "/usr" }),
            "bubblewrap args should include the standard /usr mount: {args:?}"
        );
        assert!(
            args.windows(3).any(|window| {
                window[0] == "--dev-bind" && window[1] == "/dev/null" && window[2] == "/dev/null"
            }),
            "bubblewrap args should bind /dev/null explicitly: {args:?}"
        );
        assert!(
            !args.windows(3).any(|window| {
                window[0] == "--dev-bind" && window[1] == "/dev" && window[2] == "/dev"
            }),
            "bubblewrap args unexpectedly include the full host /dev tree: {args:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn insert_bubblewrap_info_fd_places_flag_before_command_separator() {
        let mut args = vec![
            "--die-with-parent".to_string(),
            "--tmpfs".to_string(),
            "/tmp".to_string(),
            "--".to_string(),
            "/bin/echo".to_string(),
            "ok".to_string(),
        ];

        insert_bubblewrap_info_fd(&mut args, 3).expect("info fd should be inserted");

        assert_eq!(
            args,
            vec![
                "--die-with-parent".to_string(),
                "--tmpfs".to_string(),
                "/tmp".to_string(),
                "--info-fd".to_string(),
                "3".to_string(),
                "--".to_string(),
                "/bin/echo".to_string(),
                "ok".to_string(),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_bubblewrap_child_pid_reads_payload() {
        let raw = r#"{
            "child-pid": 4242,
            "child-pidns": "pid:[4026532834]"
        }"#;

        let pid = parse_bubblewrap_child_pid(raw).expect("bubblewrap info payload should parse");
        assert_eq!(pid, 4242);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bubblewrap_join_network_reuses_existing_namespace() {
        let mut sandbox = DirectSandbox::Bubblewrap {
            binary: PathBuf::from("/usr/bin/bwrap"),
        };
        let spec = ProcessSpec {
            network: ProcessNetwork::Join(12345),
            ..linux_test_process_spec()
        };

        let (program, args) = sandbox
            .wrap_command(&spec)
            .expect("command should be wrapped");
        assert_eq!(program, "/usr/bin/bwrap");
        assert!(
            !args.contains(&"--unshare-net".to_string()),
            "join mode should not unshare net: {args:?}"
        );
    }
}
