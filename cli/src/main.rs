mod command_support;
mod direct_runtime;
mod docs;
mod framework_component;
mod mixed_run;
mod run_inputs;
mod run_logs;
mod site_proxy_metadata;
mod tcp_readiness;
mod vm_runtime;

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
    net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
};

use amber_compiler::{
    CompileOptions, Compiler, ResolverRegistry,
    bundle::{BundleBuilder, BundleLoader},
    reporter::{
        CompiledScenario, Reporter as _,
        direct::{
            DIRECT_PLAN_FILENAME, DIRECT_PLAN_VERSION, DirectComponentPlan, DirectPlan,
            DirectProgramExecutionPlan, DirectRuntimeAddressPlan, DirectRuntimeConfigPayload,
            DirectRuntimeUrlSource, RUN_SCRIPT_FILENAME,
        },
        dot::DotReporter,
        metadata::MetadataReporter,
        scenario_ir::ScenarioIrReporter,
        vm::VM_PLAN_FILENAME,
    },
    run_plan::{
        PlacementFile, RUN_PLAN_SCHEMA, RunPlan, SiteKind, build_homogeneous_export_run_plan,
        build_run_plan, build_unmanaged_export, parse_placement_file,
    },
};
use amber_config::{self as config, CONFIG_ENV_PREFIX};
use amber_manifest::ManifestRef;
use amber_mesh::{
    InboundTarget, MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME, MESH_PROVISION_PLAN_VERSION,
    MeshConfig, MeshConfigPublic, MeshIdentity, MeshIdentityPublic, MeshIdentitySecret,
    MeshProvisionOutput, MeshProvisionPlan, MeshProvisionTarget,
    telemetry::{
        OtlpIdentity, OtlpInstallMode, SubscriberFormat, SubscriberOptions, init_otel_tracer,
        init_subscriber, observability_log_scope_name, shutdown_tracer_provider,
        suppress_otlp_bridge_target,
    },
};
#[cfg(test)]
use amber_mesh::{MeshProtocol, OutboundRoute, TransportConfig};
use amber_proxy::ProxyCommand;
use amber_resolver::Resolver;
use amber_scenario::{SCENARIO_IR_SCHEMA, ScenarioIr};
#[cfg(any(target_os = "linux", test))]
use amber_template::TemplatePart;
use amber_template::{ConfigTemplatePayload, MountSpec, RuntimeSlotObject, RuntimeTemplateContext};
#[cfg(target_os = "linux")]
use amber_template::{ProgramArgTemplate, TemplateSpec};
use base64::Engine as _;
use clap::{ArgAction, Args, Parser, Subcommand};
use miette::{
    Context as _, Diagnostic, GraphicalReportHandler, IntoDiagnostic as _, Result, Severity,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt as _, BufReader},
    process::Command as TokioCommand,
    time::{Duration, Instant, sleep},
};
use tracing_subscriber::EnvFilter;
use url::Url;

use self::command_support::*;
pub(crate) use self::direct_runtime::*;
use crate::{
    run_inputs::{
        RunInterface, ambient_run_env, collect_run_interface, load_run_env,
        missing_required_external_slots, missing_required_root_inputs, project_env_path,
        prompt_for_missing_inputs, render_resolved_input_lines, render_root_reuse_env,
        resolve_manifest_entry_path, run_interactive, select_external_slot_env, select_root_env,
        slot_url_from_socket,
    },
    run_logs::{RunLogOptions, print_run_logs, print_run_ps, stream_run_logs_until},
    tcp_readiness::wait_for_stable_endpoint,
};

const CLI_LONG_ABOUT: &str = "\
Compile, inspect, and run Amber scenarios.

Amber resolves a root manifest or bundle, validates the component graph, and writes the artifacts \
                              you need to inspect or run the scenario.

Use `amber <command> --help` to drill into a specific workflow.";

const CLI_AFTER_HELP: &str = "\
Common workflows:
  amber check path/to/root.json5
      Validate manifests and print diagnostics without writing outputs.

  amber compile path/to/root.json5 --run-plan /tmp/amber-run-plan.json
      Generate the mixed-site run plan consumed by `amber run`.

  amber compile path/to/root.json5 --docker-compose /tmp/amber-compose
      Generate runtime artifacts. `amber compile --help` lists every output format.

  amber compile path/to/root.json5 --direct /tmp/amber-direct
  amber run /tmp/amber-direct
      Build and start the direct/native runtime locally.

  amber compile path/to/root.json5 --vm /tmp/amber-vm
  amber run /tmp/amber-vm
      Build and start the VM runtime locally.

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

  --run-plan FILE
      Mixed-site execution plan JSON for `amber run`.

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

  --vm DIR
      VM runtime artifacts for `amber run` and `amber proxy`.

  --bundle DIR
      Self-contained manifest bundle for offline or reproducible compilation.

Examples:
  amber compile path/to/root.json5 --output /tmp/scenario.json
  amber compile path/to/root.json5 --run-plan /tmp/run-plan.json
  amber compile path/to/root.json5 --docker-compose /tmp/amber-compose
  amber compile path/to/root.json5 --direct /tmp/amber-direct
  amber compile path/to/root.json5 --vm /tmp/amber-vm";

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
Start a compiled Amber runtime artifact, a mixed-site run plan, or a manifest/bundle.

This command understands direct/native artifacts from `amber compile --direct`, VM artifacts from \
                              `amber compile --vm`, mixed-site run plans from `amber compile \
                              --run-plan`, and manifest or bundle inputs that Amber can compile \
                              into a run plan on the fly.";

const RUN_AFTER_HELP: &str = "\
Examples:
  amber run .
  amber run path/to/root.json5
  amber run path/to/root.json5 --placement local-sites.json
  amber run path/to/root.json5 --env-file dev.env
  amber run -Z unstable-options path/to/root.json5 --dry-run --emit-launch-bundle /tmp/amber-launch
  amber run /tmp/amber-run-plan.json
  amber run /tmp/amber-direct
  amber run /tmp/amber-direct/direct-plan.json
  amber run /tmp/amber-vm
  amber run /tmp/amber-direct --storage-root /srv/amber-state

Runtime requirements:
  Linux: `bwrap` and `slirp4netns`
  macOS: `/usr/bin/sandbox-exec` or QEMU/HVF";

const PROXY_LONG_ABOUT: &str = "\
Attach a local proxy to compiled Amber output.

Use `--export` to expose a scenario export on localhost, `--slot` to connect a scenario slot to a \
                                local upstream, or both at once.

Pass at least one `--export` or `--slot` binding.

The output can be a Docker Compose output directory, a Kubernetes output directory, a direct \
                                output directory, or a VM output directory.";

const PROXY_AFTER_HELP: &str = "\
Examples:
  amber proxy /tmp/amber-compose --export public=127.0.0.1:18080

  amber proxy <run-id> --export public=127.0.0.1:18080

  amber proxy <run-id> --site direct_local --export public=127.0.0.1:18080

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
  Mixed-site run ids expose the whole running scenario by default; add `--site` only when you need \
                                a specific internal site surface.
  Docker Compose outputs auto-detect router control and, for exports, the published router mesh \
                                port.
  Direct and VM outputs usually infer local router metadata automatically.
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

const CLI_VERSION: &str = env!("AMBER_CLI_VERSION");

#[derive(Parser)]
#[command(name = "amber")]
#[command(version = CLI_VERSION)]
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
        about = "Run a manifest, run plan, or Amber runtime artifact",
        long_about = RUN_LONG_ABOUT,
        after_help = RUN_AFTER_HELP
    )]
    Run(RunArgs),
    #[command(about = "Stop a mixed-site run by run id")]
    Stop(StopArgs),
    #[command(about = "List active mixed-site runs")]
    Ps(PsArgs),
    #[command(about = "Print persisted logs for a mixed-site run")]
    Logs(LogsArgs),
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
    #[command(hide = true, name = "run-vm-init")]
    RunVmInit(RunVmInitArgs),
    #[command(hide = true, name = "run-site-supervisor")]
    RunSiteSupervisor(RunSiteSupervisorArgs),
    #[command(hide = true, name = "run-site-actuator")]
    RunSiteActuator(RunSiteActuatorArgs),
    #[command(hide = true, name = "run-framework-control-state")]
    RunFrameworkControlState(RunFrameworkControlStateArgs),
    #[command(hide = true, name = "run-framework-ccs")]
    RunFrameworkCcs(RunFrameworkCcsArgs),
    #[command(hide = true, name = "run-detached-coordinator")]
    RunDetachedCoordinator(RunDetachedCoordinatorArgs),
    #[command(hide = true, name = "run-observability-sink")]
    RunObservabilitySink(RunObservabilitySinkArgs),
    #[command(hide = true, name = "run-outside-proxy")]
    RunOutsideProxy(RunOutsideProxyArgs),
    #[command(hide = true, name = "run-vm-guestfwd-bridge")]
    RunVmGuestfwdBridge(RunVmGuestfwdBridgeArgs),
    #[command(hide = true, name = "run-direct-local-probe")]
    RunDirectLocalProbe(RunDirectLocalProbeArgs),
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

    /// Write a mixed-site run plan JSON file.
    #[arg(long = "run-plan", value_name = "FILE")]
    run_plan: Option<PathBuf>,

    /// Write a manifest bundle to this directory.
    #[arg(long = "bundle", value_name = "DIR")]
    bundle: Option<PathBuf>,

    /// Write Kubernetes manifests to this directory.
    #[arg(long = "kubernetes", visible_alias = "k8s", value_name = "DIR")]
    kubernetes: Option<PathBuf>,

    /// Write direct/native runtime artifact files to this directory.
    #[arg(long = "direct", value_name = "DIR")]
    direct: Option<PathBuf>,

    /// Write VM runtime artifact files to this directory.
    #[arg(long = "vm", value_name = "DIR")]
    vm: Option<PathBuf>,

    /// Disable compiler optimizations.
    #[arg(long = "no-opt")]
    no_opt: bool,

    /// Placement file used when building the mixed-site run plan.
    #[arg(long = "placement", value_name = "FILE")]
    placement: Option<PathBuf>,

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
    /// Enable unstable CLI options.
    #[arg(short = 'Z', value_name = "FLAG")]
    unstable: Vec<String>,

    /// Manifest, bundle, mixed-site run plan, or direct/vm runnable output from `amber compile`.
    #[arg(value_name = "TARGET")]
    output: String,

    /// Override where Amber stores persistent runtime state.
    #[arg(long = "storage-root", value_name = "DIR")]
    storage_root: Option<PathBuf>,

    /// Placement file used when compiling a manifest or bundle into a mixed-site run plan.
    #[arg(long = "placement", value_name = "FILE")]
    placement: Option<PathBuf>,

    /// Load runtime inputs from an env file. Repeat to merge multiple files.
    #[arg(long = "env-file", value_name = "FILE")]
    env_file: Vec<PathBuf>,

    /// Start a mixed-site run in detached mode.
    #[arg(long = "detach")]
    detach: bool,

    /// Managed observability mode for mixed-site runs (`local` or an OTLP/HTTP endpoint URL).
    #[arg(long = "observability", value_name = "local|URL")]
    observability: Option<String>,

    /// Materialize the mixed-site launch bundle without starting workloads.
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Write the materialized mixed-site launch bundle to this directory.
    #[arg(long = "emit-launch-bundle", value_name = "DIR")]
    emit_launch_bundle: Option<PathBuf>,
}

#[derive(Args)]
struct RunDirectInitArgs {
    /// Path to a direct runtime plan JSON file.
    #[arg(long = "plan", value_name = "FILE")]
    plan: PathBuf,

    /// Override where Amber stores persistent direct runtime state.
    #[arg(long = "storage-root", value_name = "DIR")]
    storage_root: Option<PathBuf>,

    /// Persistent runtime workspace used by the mixed-site supervisor.
    #[arg(long = "runtime-root", value_name = "DIR", hide = true)]
    runtime_root: Option<PathBuf>,

    /// Fixed router mesh port used by the mixed-site supervisor.
    #[arg(long = "router-mesh-port", value_name = "PORT", hide = true)]
    router_mesh_port: Option<u16>,

    /// JSON file containing preexisting mesh peer ids mapped to fixed mesh ports.
    #[arg(long = "existing-peer-ports", value_name = "FILE", hide = true)]
    existing_peer_ports: Option<PathBuf>,

    /// JSON file containing preexisting mesh peer identities keyed by peer id.
    #[arg(long = "existing-peer-identities", value_name = "FILE", hide = true)]
    existing_peer_identities: Option<PathBuf>,

    /// Reuse an already-running site router instead of spawning the router from this plan.
    #[arg(long = "skip-router", hide = true)]
    skip_router: bool,
}

#[derive(Args)]
struct RunVmGuestfwdBridgeArgs {
    /// Loopback upstream that receives one forwarded guest connection.
    #[arg(value_name = "ADDR:PORT")]
    upstream: SocketAddr,
}

#[derive(Args)]
struct RunVmInitArgs {
    /// Path to a VM runtime plan JSON file.
    #[arg(long = "plan", value_name = "FILE")]
    plan: PathBuf,

    /// Override where Amber stores persistent VM runtime state.
    #[arg(long = "storage-root", value_name = "DIR")]
    storage_root: Option<PathBuf>,

    /// Persistent runtime workspace used by the mixed-site supervisor.
    #[arg(long = "runtime-root", value_name = "DIR", hide = true)]
    runtime_root: Option<PathBuf>,

    /// Fixed router mesh port used by the mixed-site supervisor.
    #[arg(long = "router-mesh-port", value_name = "PORT", hide = true)]
    router_mesh_port: Option<u16>,

    /// JSON file containing preexisting mesh peer ids mapped to fixed mesh ports.
    #[arg(long = "existing-peer-ports", value_name = "FILE", hide = true)]
    existing_peer_ports: Option<PathBuf>,

    /// JSON file containing preexisting mesh peer identities keyed by peer id.
    #[arg(long = "existing-peer-identities", value_name = "FILE", hide = true)]
    existing_peer_identities: Option<PathBuf>,

    /// Reuse an already-running site router instead of spawning the router from this plan.
    #[arg(long = "skip-router", hide = true)]
    skip_router: bool,
}

#[derive(Args)]
struct RunDirectLocalProbeArgs {
    /// Loopback endpoint inside a direct component namespace.
    #[arg(value_name = "ADDR:PORT")]
    addr: SocketAddr,

    /// Maximum time to wait for the endpoint to accept stable connections.
    #[arg(long = "timeout-ms", value_name = "MILLIS")]
    timeout_ms: u64,
}

#[derive(Args)]
struct RunOutsideProxyArgs {
    /// Path to a run outside proxy plan JSON file.
    #[arg(long = "plan", value_name = "FILE")]
    plan: PathBuf,
}

#[derive(Args)]
struct RunSiteSupervisorArgs {
    /// Path to a mixed-site supervisor plan JSON file.
    #[arg(long = "plan", value_name = "FILE")]
    plan: PathBuf,
}

#[derive(Args)]
struct RunSiteActuatorArgs {
    /// Path to a mixed-site site-actuator plan JSON file.
    #[arg(long = "plan", value_name = "FILE")]
    plan: PathBuf,
}

#[derive(Args)]
struct RunFrameworkControlStateArgs {
    /// Path to a framework control-state service plan JSON file.
    #[arg(long = "plan", value_name = "FILE")]
    plan: PathBuf,
}

#[derive(Args)]
struct RunFrameworkCcsArgs {
    /// Path to a framework CCS plan JSON file.
    #[arg(long = "plan", value_name = "FILE")]
    plan: PathBuf,
}

#[derive(Args)]
struct RunDetachedCoordinatorArgs {
    /// Path to a mixed-site run plan JSON file.
    #[arg(long = "plan", value_name = "FILE")]
    plan: PathBuf,

    /// Run id reserved by the foreground CLI before detaching.
    #[arg(long = "run-id", value_name = "RUN_ID")]
    run_id: String,

    /// Override where Amber stores persistent runtime state.
    #[arg(long = "storage-root", value_name = "DIR")]
    storage_root: Option<PathBuf>,

    /// Original user-supplied plan path when detaching from an existing run plan.
    #[arg(long = "source-plan", value_name = "FILE")]
    source_plan: Option<PathBuf>,

    /// Managed observability mode for mixed-site runs (`local` or an OTLP/HTTP endpoint URL).
    #[arg(long = "observability", value_name = "local|URL")]
    observability: Option<String>,
}

#[derive(Args)]
struct PsArgs {
    /// Override where Amber stores persistent mixed-run state.
    #[arg(long = "storage-root", value_name = "DIR")]
    storage_root: Option<PathBuf>,
}

#[derive(Args)]
struct LogsArgs {
    /// Mixed-site run id.
    #[arg(value_name = "RUN_ID")]
    run_id: String,

    /// Override where Amber stores persistent mixed-run state.
    #[arg(long = "storage-root", value_name = "DIR")]
    storage_root: Option<PathBuf>,

    /// Keep streaming new log output.
    #[arg(short = 'f', long = "follow")]
    follow: bool,
}

#[derive(Args)]
struct RunObservabilitySinkArgs {
    /// Path to an observability sink plan JSON file.
    #[arg(long = "plan", value_name = "FILE")]
    plan: PathBuf,
}

#[derive(Args)]
struct StopArgs {
    /// Run id to stop.
    #[arg(value_name = "RUN_ID")]
    run_id: String,

    /// Override where Amber stores persistent mixed-run state.
    #[arg(long = "storage-root", value_name = "DIR")]
    storage_root: Option<PathBuf>,
}

#[derive(Args)]
struct ProxyArgs {
    /// Docker Compose output directory, direct output directory, VM output directory, Kubernetes output directory, run root, or mixed-site run id.
    #[arg(value_name = "OUTPUT")]
    output: String,

    /// Site id to attach when proxying against a mixed-site run.
    #[arg(long = "site", value_name = "SITE_ID")]
    site: Option<String>,

    /// Override where Amber stores persistent mixed-run state when `OUTPUT` is a run id.
    #[arg(long = "storage-root", value_name = "DIR")]
    storage_root: Option<PathBuf>,

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

    /// Router mesh address override (Compose export mode auto-detects the published host port).
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
enum RunTargetKind {
    Direct,
    Vm,
    MixedRunPlan,
}

struct RunTarget {
    kind: RunTargetKind,
    plan: PathBuf,
}

#[derive(Clone, Debug)]
struct PreparedMixedRunInputs {
    interface: RunInterface,
    root_env: BTreeMap<String, String>,
    external_slot_env: BTreeMap<String, String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    miette::set_panic_hook();
    let cli = Cli::parse();
    let verbose = cli.verbose;

    let result = match cli.command {
        Command::Proxy(args) => proxy(args, verbose).await,
        Command::RunVmGuestfwdBridge(args) => run_vm_guestfwd_bridge(args).await,
        Command::RunDirectLocalProbe(args) => run_direct_local_probe(args).await,
        command => {
            init_tracing(verbose)?;
            match command {
                Command::Compile(args) => compile(args).await,
                Command::Check(args) => check(args).await,
                Command::Docs(args) => docs(args),
                Command::Run(args) => run(args).await,
                Command::Stop(args) => stop(args).await,
                Command::Ps(args) => ps(args),
                Command::Logs(args) => logs(args).await,
                Command::Dashboard(args) => dashboard(args).await,
                Command::RunDirectInit(args) => run_direct_init(args).await,
                Command::RunVmInit(args) => {
                    vm_runtime::run_vm_init(
                        args.plan,
                        args.storage_root,
                        args.runtime_root,
                        args.router_mesh_port,
                        args.existing_peer_ports,
                        args.existing_peer_identities,
                        args.skip_router,
                    )
                    .await
                }
                Command::RunSiteSupervisor(args) => mixed_run::run_site_supervisor(args.plan).await,
                Command::RunSiteActuator(args) => mixed_run::run_site_actuator(args.plan).await,
                Command::RunFrameworkControlState(args) => {
                    framework_component::run_framework_control_state(args.plan).await
                }
                Command::RunFrameworkCcs(args) => {
                    framework_component::run_framework_ccs(args.plan).await
                }
                Command::RunDetachedCoordinator(args) => run_detached_coordinator(args).await,
                Command::RunObservabilitySink(args) => {
                    mixed_run::run_observability_sink(args.plan).await
                }
                Command::RunOutsideProxy(args) => mixed_run::run_outside_proxy(args.plan).await,
                Command::RunVmGuestfwdBridge(_) => unreachable!("handled above"),
                Command::RunDirectLocalProbe(_) => unreachable!("handled above"),
                Command::Proxy(_) => unreachable!("handled above"),
            }
        }
    };

    tokio::task::block_in_place(shutdown_tracer_provider);
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

async fn run_vm_guestfwd_bridge(args: RunVmGuestfwdBridgeArgs) -> Result<()> {
    let mut upstream = TcpStream::connect(args.upstream)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to connect VM slot bridge upstream {}",
                args.upstream
            )
        })?;
    let mut upstream_read = upstream
        .try_clone()
        .into_diagnostic()
        .wrap_err("failed to clone VM slot bridge upstream socket")?;
    let writer = std::thread::spawn(move || -> Result<()> {
        let mut stdin = std::io::stdin().lock();
        std::io::copy(&mut stdin, &mut upstream)
            .into_diagnostic()
            .wrap_err("failed to forward guest request to upstream")?;
        upstream
            .shutdown(Shutdown::Write)
            .into_diagnostic()
            .wrap_err("failed to finish guest request forwarding")
    });
    let mut stdout = std::io::stdout().lock();
    std::io::copy(&mut upstream_read, &mut stdout)
        .into_diagnostic()
        .wrap_err("failed to forward upstream response to guest")?;
    stdout
        .flush()
        .into_diagnostic()
        .wrap_err("failed to flush guest response")?;
    writer
        .join()
        .map_err(|_| miette::miette!("vm slot bridge writer thread panicked"))??;
    Ok(())
}

async fn run_direct_local_probe(args: RunDirectLocalProbeArgs) -> Result<()> {
    wait_for_stable_endpoint(args.addr, Duration::from_millis(args.timeout_ms))
        .wrap_err_with(|| format!("direct local endpoint {} did not become ready", args.addr))
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

fn init_tracing(verbose: u8) -> Result<()> {
    let filter = if std::env::var_os("RUST_LOG").is_some() {
        EnvFilter::try_from_default_env().into_diagnostic()?
    } else {
        EnvFilter::new(console_filter_spec(verbose))
    };
    init_subscriber(
        filter,
        None,
        SubscriberFormat::CliText,
        SubscriberOptions {
            include_error_layer: true,
            telemetry_filter: None,
            log_scope_name: None,
        },
    );

    Ok(())
}

fn init_proxy_tracing(verbose: u8, identity: &MeshIdentityPublic) -> Result<()> {
    let (filter, telemetry_filter) = if std::env::var_os("RUST_LOG").is_some() {
        let filter = EnvFilter::try_from_default_env().into_diagnostic()?;
        let telemetry_filter = suppress_otlp_bridge_target(
            suppress_otlp_bridge_target(filter.clone(), "amber.binding"),
            "amber.internal",
        );
        (filter, telemetry_filter)
    } else {
        let filter = EnvFilter::new(console_filter_spec(verbose));
        let telemetry_filter = suppress_otlp_bridge_target(
            suppress_otlp_bridge_target(
                EnvFilter::new(proxy_telemetry_filter_spec(verbose)),
                "amber.binding",
            ),
            "amber.internal",
        );
        (filter, telemetry_filter)
    };

    let tracer = match init_otel_tracer(
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
    };
    init_subscriber(
        filter,
        tracer,
        SubscriberFormat::CliText,
        SubscriberOptions {
            include_error_layer: true,
            telemetry_filter: Some(telemetry_filter),
            log_scope_name: Some(observability_log_scope_name(None)),
        },
    );

    Ok(())
}

async fn compile(args: CompileArgs) -> Result<()> {
    ensure_outputs_requested(&args)?;
    let outputs = resolve_output_paths(&args)?;
    let placement = load_placement_file(args.placement.as_deref())?;

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

    if placement.is_some()
        && (outputs.docker_compose.is_some()
            || outputs.kubernetes.is_some()
            || outputs.direct.is_some()
            || outputs.vm.is_some())
    {
        return Err(miette::miette!(
            "`amber compile --docker-compose`, `--kubernetes`, `--direct`, and `--vm` do not \
             accept `--placement`; use `--run-plan` for placed mixed-site planning"
        ));
    }

    let run_plan = if outputs.run_plan.is_some() {
        Some(
            build_run_plan(&compiled, placement.as_ref())
                .into_diagnostic()
                .wrap_err("failed to build mixed-site run plan")?,
        )
    } else {
        None
    };

    if let Some(run_plan_path) = outputs.run_plan.as_ref() {
        write_run_plan_output(
            run_plan_path,
            run_plan.as_ref().expect("run plan should be built"),
        )?;
    }

    if let Some(dot_dest) = outputs.dot {
        let dot = DotReporter.emit(&compiled).map_err(miette::Report::new)?;
        match dot_dest {
            ArtifactOutput::Stdout => print!("{dot}"),
            ArtifactOutput::File(path) => write_artifact(&path, dot.as_bytes())?,
        }
    }

    if let Some(compose_root) = outputs.docker_compose.as_ref() {
        let run_plan = build_homogeneous_export_run_plan(&compiled, SiteKind::Compose)
            .into_diagnostic()
            .wrap_err("failed to build homogeneous compose export plan")?;
        write_unmanaged_export_output(compose_root, &run_plan, SiteKind::Compose)?;
    }

    if let Some(kubernetes_dest) = outputs.kubernetes {
        let run_plan = build_homogeneous_export_run_plan(&compiled, SiteKind::Kubernetes)
            .into_diagnostic()
            .wrap_err("failed to build homogeneous kubernetes export plan")?;
        write_unmanaged_export_output(&kubernetes_dest, &run_plan, SiteKind::Kubernetes)?;
    }

    if let Some(direct_dest) = outputs.direct {
        let run_plan = build_homogeneous_export_run_plan(&compiled, SiteKind::Direct)
            .into_diagnostic()
            .wrap_err("failed to build homogeneous direct export plan")?;
        write_unmanaged_export_output(&direct_dest, &run_plan, SiteKind::Direct)?;
    }

    if let Some(vm_dest) = outputs.vm {
        let run_plan = build_homogeneous_export_run_plan(&compiled, SiteKind::Vm)
            .into_diagnostic()
            .wrap_err("failed to build homogeneous vm export plan")?;
        write_unmanaged_export_output(&vm_dest, &run_plan, SiteKind::Vm)?;
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
    let unstable_options = args.unstable.iter().any(|flag| flag == "unstable-options");
    let interactive = run_interactive();
    if (args.dry_run || args.emit_launch_bundle.is_some()) && !unstable_options {
        return Err(miette::miette!(
            "`amber run --dry-run` and `--emit-launch-bundle` are unstable; pass `-Z \
             unstable-options`"
        ));
    }
    if args.detach && (args.dry_run || args.emit_launch_bundle.is_some()) {
        return Err(miette::miette!(
            "`amber run --detach` does not support `--dry-run` or `--emit-launch-bundle`"
        ));
    }
    if args.dry_run && args.emit_launch_bundle.is_none() {
        return Err(miette::miette!(
            "`amber run --dry-run` requires `--emit-launch-bundle <dir>`"
        ));
    }
    if args.emit_launch_bundle.is_some() && !args.dry_run {
        return Err(miette::miette!(
            "`--emit-launch-bundle` currently requires `--dry-run`"
        ));
    }

    let placement = load_placement_file(args.placement.as_deref())?;
    let explicit_env = load_run_env(None, &args.env_file)?;
    if let Some(target) = try_load_run_target(&args.output)? {
        return match target.kind {
            RunTargetKind::Direct => {
                if args.detach || args.dry_run {
                    return Err(miette::miette!(
                        "`amber run --detach` and `amber run --dry-run` only support mixed-site \
                         manifests and run plans"
                    ));
                }
                with_scoped_run_env(&explicit_env, || async {
                    run_direct_init(RunDirectInitArgs {
                        plan: target.plan,
                        storage_root: args.storage_root,
                        runtime_root: None,
                        router_mesh_port: None,
                        existing_peer_ports: None,
                        existing_peer_identities: None,
                        skip_router: false,
                    })
                    .await
                })
                .await
            }
            RunTargetKind::Vm => {
                if args.detach || args.dry_run {
                    return Err(miette::miette!(
                        "`amber run --detach` and `amber run --dry-run` only support mixed-site \
                         manifests and run plans"
                    ));
                }
                with_scoped_run_env(&explicit_env, || async {
                    vm_runtime::run_vm_init(
                        target.plan,
                        args.storage_root,
                        None,
                        None,
                        None,
                        None,
                        false,
                    )
                    .await
                })
                .await
            }
            RunTargetKind::MixedRunPlan => {
                let run_plan_raw = fs::read_to_string(&target.plan)
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!("failed to read run plan {}", target.plan.display())
                    })?;
                let run_plan: RunPlan = serde_json::from_str(&run_plan_raw).map_err(|err| {
                    miette::miette!("invalid run plan {}: {err}", target.plan.display())
                })?;
                let prepared = prepare_mixed_run_inputs(
                    &run_plan,
                    None,
                    &args.env_file,
                    interactive,
                    !args.dry_run,
                )?;
                if args.dry_run {
                    let bundle_root = args
                        .emit_launch_bundle
                        .as_deref()
                        .expect("dry-run bundle path should be validated");
                    return mixed_run::dry_run_run_plan(
                        Some(&target.plan),
                        &run_plan,
                        bundle_root,
                        args.observability.as_deref(),
                        &merged_env_maps(&prepared.root_env, &prepared.external_slot_env),
                    )
                    .map(|_| ());
                }
                if args.detach {
                    return run_detached(
                        &run_plan,
                        args.storage_root.as_deref(),
                        Some(&target.plan),
                        args.observability.as_deref(),
                        &merged_env_maps(&prepared.root_env, &prepared.external_slot_env),
                    )
                    .await;
                }
                if interactive {
                    return run_attached_mixed_run(
                        &args.output,
                        Some(&target.plan),
                        &run_plan,
                        args.storage_root.as_deref(),
                        args.observability.as_deref(),
                        prepared,
                    )
                    .await;
                }
                mixed_run::run_run_plan(
                    Some(&target.plan),
                    &run_plan,
                    args.storage_root.as_deref(),
                    args.observability.as_deref(),
                    &merged_env_maps(&prepared.root_env, &prepared.external_slot_env),
                )
                .await
                .map(|receipt| {
                    println!("run_id={}", receipt.run_id);
                    println!("run_root={}", receipt.run_root);
                })
            }
        };
    }

    let compiled = compile_for_run(&args.output).await?;
    let run_plan = build_run_plan(&compiled, placement.as_ref())
        .into_diagnostic()
        .wrap_err("failed to build mixed-site run plan")?;
    let project_env_root = project_env_root_for_run_input(&args.output)?;
    let prepared = prepare_mixed_run_inputs(
        &run_plan,
        project_env_root.as_deref(),
        &args.env_file,
        interactive,
        !args.dry_run,
    )?;
    if args.detach {
        return run_detached(
            &run_plan,
            args.storage_root.as_deref(),
            None,
            args.observability.as_deref(),
            &merged_env_maps(&prepared.root_env, &prepared.external_slot_env),
        )
        .await;
    }
    if args.dry_run {
        let bundle_root = args
            .emit_launch_bundle
            .as_deref()
            .expect("dry-run bundle path should be validated");
        return mixed_run::dry_run_run_plan(
            None,
            &run_plan,
            bundle_root,
            args.observability.as_deref(),
            &merged_env_maps(&prepared.root_env, &prepared.external_slot_env),
        )
        .map(|_| ());
    }
    if interactive {
        return run_attached_mixed_run(
            &args.output,
            None,
            &run_plan,
            args.storage_root.as_deref(),
            args.observability.as_deref(),
            prepared,
        )
        .await;
    }
    mixed_run::run_run_plan(
        None,
        &run_plan,
        args.storage_root.as_deref(),
        args.observability.as_deref(),
        &merged_env_maps(&prepared.root_env, &prepared.external_slot_env),
    )
    .await
    .map(|receipt| {
        println!("run_id={}", receipt.run_id);
        println!("run_root={}", receipt.run_root);
    })
}

async fn run_detached(
    run_plan: &RunPlan,
    storage_root_override: Option<&Path>,
    source_plan_path: Option<&Path>,
    observability: Option<&str>,
    site_launch_env: &BTreeMap<String, String>,
) -> Result<()> {
    let storage_root = mixed_run::mixed_run_storage_root(storage_root_override)?;
    let run_id = mixed_run::new_run_id();
    let run_root = storage_root.join("runs").join(&run_id);
    fs::create_dir_all(&run_root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create detached run root {}", run_root.display()))?;

    let plan_path = run_root.join("run-plan.json");
    write_run_plan_output(&plan_path, run_plan)?;
    let log_path = run_root.join("coordinator.log");
    let source_plan = source_plan_path.map(|path| canonicalize_user_path(path, "source run plan"));
    let source_plan = source_plan.transpose()?;
    mixed_run::spawn_detached_child(&run_root, &log_path, |cmd| {
        cmd.arg("run-detached-coordinator")
            .arg("--plan")
            .arg(&plan_path)
            .arg("--run-id")
            .arg(&run_id)
            .arg("--storage-root")
            .arg(&storage_root)
            .envs(site_launch_env);
        if let Some(source_plan) = source_plan.as_ref() {
            cmd.arg("--source-plan").arg(source_plan);
        }
        if let Some(observability) = observability {
            cmd.arg("--observability").arg(observability);
        }
    })?;

    println!("run_id={run_id}");
    println!("run_root={}", run_root.display());
    Ok(())
}

async fn run_detached_coordinator(args: RunDetachedCoordinatorArgs) -> Result<()> {
    let plan_path = canonicalize_user_path(&args.plan, "mixed-site run plan")?;
    let run_plan_raw = fs::read_to_string(&plan_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read run plan {}", plan_path.display()))?;
    let run_plan: RunPlan = serde_json::from_str(&run_plan_raw)
        .map_err(|err| miette::miette!("invalid run plan {}: {err}", plan_path.display()))?;
    mixed_run::run_run_plan_with_id(
        args.source_plan.as_deref(),
        &run_plan,
        args.storage_root.as_deref(),
        args.observability.as_deref(),
        &args.run_id,
        &ambient_run_env(),
    )
    .await
    .map(|_| ())
}

fn project_env_root_for_run_input(input: &str) -> Result<Option<PathBuf>> {
    let Some(path) = local_input_path(input)? else {
        return Ok(None);
    };
    if BundleLoader::from_path(&path)?.is_some() {
        return Ok(None);
    }
    let manifest_path = resolve_manifest_entry_path(&path)?;
    Ok(manifest_path.parent().map(Path::to_path_buf))
}

fn prepare_mixed_run_inputs(
    run_plan: &RunPlan,
    project_env_root: Option<&Path>,
    env_files: &[PathBuf],
    interactive: bool,
    require_complete_inputs: bool,
) -> Result<PreparedMixedRunInputs> {
    let interface = collect_run_interface(run_plan)?;
    let mut env = load_run_env(project_env_root, env_files)?;
    if interactive {
        prompt_for_missing_inputs(&mut env, &interface)?;
    }

    let missing_root = missing_required_root_inputs(&env, &interface);
    let missing_slots = missing_required_external_slots(&env, &interface);
    if require_complete_inputs && (!missing_root.is_empty() || !missing_slots.is_empty()) {
        let mut message = String::from("missing required runtime inputs:");
        for input in missing_root {
            message.push_str(&format!(
                "\n  - {} for config.{}",
                input.env_var, input.path
            ));
        }
        for slot in missing_slots {
            message.push_str(&format!("\n  - {} for slot.{}", slot.env_var, slot.name));
        }
        if let Some(project_env_root) = project_env_root {
            message.push_str(&format!(
                "\n\nProvide them via ambient environment, `--env-file`, or {}",
                project_env_path(project_env_root).display()
            ));
        } else {
            message.push_str("\n\nProvide them via ambient environment or `--env-file`.");
        }
        return Err(miette::miette!(message));
    }

    Ok(PreparedMixedRunInputs {
        root_env: select_root_env(&env, &interface),
        external_slot_env: select_external_slot_env(&env, &interface),
        interface,
    })
}

fn merged_env_maps(
    left: &BTreeMap<String, String>,
    right: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut merged = left.clone();
    merged.extend(right.clone());
    merged
}

fn export_listener_url(protocol: &str, addr: SocketAddr) -> String {
    match protocol {
        "tcp" => format!("tcp://{addr}"),
        _ => format!("http://{addr}"),
    }
}

async fn with_scoped_run_env<F, Fut, T>(vars: &BTreeMap<String, String>, run: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let _guard = ScopedRunEnv::apply(vars);
    run().await
}

async fn run_attached_mixed_run(
    target: &str,
    source_plan_path: Option<&Path>,
    run_plan: &RunPlan,
    storage_root_override: Option<&Path>,
    observability: Option<&str>,
    prepared: PreparedMixedRunInputs,
) -> Result<()> {
    let receipt = mixed_run::run_run_plan(
        source_plan_path,
        run_plan,
        storage_root_override,
        observability,
        &prepared.root_env,
    )
    .await?;
    let run_root = PathBuf::from(&receipt.run_root);

    let export_bindings = prepared
        .interface
        .exports
        .iter()
        .map(|export| {
            Ok((
                export.name.clone(),
                SocketAddr::from(([127, 0, 0, 1], mixed_run::reserve_loopback_port()?)),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let slot_bindings = prepared
        .interface
        .external_slots
        .iter()
        .filter_map(|slot| {
            prepared
                .external_slot_env
                .get(&slot.env_var)
                .map(|value| (slot.name.clone(), value.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let mut proxy_child = if slot_bindings.is_empty() && export_bindings.is_empty() {
        None
    } else {
        Some(mixed_run::spawn_run_outside_proxy(
            &run_root,
            &slot_bindings,
            &export_bindings,
        )?)
    };
    if proxy_child.is_some()
        && let Err(err) = mixed_run::wait_for_run_outside_proxy_ready(&run_root).await
    {
        if let Some(proxy_child) = proxy_child.as_mut() {
            let _ = proxy_child.kill();
            let _ = proxy_child.wait();
        }
        let _ = mixed_run::stop_run(&receipt.run_id, storage_root_override).await;
        return Err(err);
    }

    let reuse_path = if prepared.interface.root_inputs.is_empty() {
        None
    } else {
        let path = run_root.join("root-config.env");
        fs::write(
            &path,
            render_root_reuse_env(&prepared.root_env, &prepared.interface),
        )
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))?;
        Some(path)
    };

    for line in render_resolved_input_lines(
        &merged_env_maps(&prepared.root_env, &prepared.external_slot_env),
        &prepared.interface,
    ) {
        println!("{line}");
    }
    if !prepared.interface.root_inputs.is_empty() || !prepared.interface.external_slots.is_empty() {
        println!();
    }
    println!("Ready.");
    for (name, addr) in &export_bindings {
        let protocol = prepared
            .interface
            .exports
            .iter()
            .find(|export| export.name == *name)
            .map(|export| export.protocol.as_str())
            .unwrap_or("http");
        println!("  {name}  {}", export_listener_url(protocol, *addr));
    }
    if let Some(path) = reuse_path.as_ref() {
        println!();
        println!("Reuse:");
        println!("  amber run {target} --env-file {}", path.display());
    }

    let result = stream_run_logs_until(
        &run_root,
        RunLogOptions {
            follow: true,
            print_existing: false,
        },
    )
    .await;
    let stop_result = mixed_run::stop_run(&receipt.run_id, storage_root_override).await;
    if let Some(proxy_child) = proxy_child.as_mut() {
        let _ = proxy_child.kill();
        let _ = proxy_child.wait();
    }
    result?;
    stop_result
}

fn ps(args: PsArgs) -> Result<()> {
    let storage_root = mixed_run::mixed_run_storage_root(args.storage_root.as_deref())?;
    print_run_ps(&storage_root)
}

async fn logs(args: LogsArgs) -> Result<()> {
    let storage_root = mixed_run::mixed_run_storage_root(args.storage_root.as_deref())?;
    let run_root = storage_root.join("runs").join(&args.run_id);
    if args.follow {
        stream_run_logs_until(
            &run_root,
            RunLogOptions {
                follow: true,
                print_existing: true,
            },
        )
        .await
    } else {
        print_run_logs(&run_root)
    }
}

struct ScopedRunEnv {
    saved: Vec<(String, Option<String>)>,
}

impl ScopedRunEnv {
    fn apply(vars: &BTreeMap<String, String>) -> Self {
        let saved = vars
            .keys()
            .map(|key| (key.clone(), env::var(key).ok()))
            .collect::<Vec<_>>();
        for (key, value) in vars {
            // These vars are only scoped to the current amber process and any children it spawns.
            unsafe {
                env::set_var(key, value);
            }
        }
        Self { saved }
    }
}

impl Drop for ScopedRunEnv {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..) {
            if let Some(value) = value {
                unsafe {
                    env::set_var(key, value);
                }
            } else {
                unsafe {
                    env::remove_var(key);
                }
            }
        }
    }
}

fn try_load_run_target(output: &str) -> Result<Option<RunTarget>> {
    let output_path = Path::new(output);
    if !output_path.exists() {
        return Ok(None);
    }
    let abs = canonicalize_user_path(output_path, "run target")?;

    if abs.is_dir() {
        let plan = abs.join(DIRECT_PLAN_FILENAME);
        if plan.is_file() {
            return Ok(Some(RunTarget {
                kind: RunTargetKind::Direct,
                plan,
            }));
        }
        let plan = abs.join(VM_PLAN_FILENAME);
        if plan.is_file() {
            return Ok(Some(RunTarget {
                kind: RunTargetKind::Vm,
                plan,
            }));
        }
        let plan = abs.join("run-plan.json");
        if plan.is_file() {
            return Ok(Some(RunTarget {
                kind: RunTargetKind::MixedRunPlan,
                plan,
            }));
        }
        return Ok(None);
    }

    if abs.file_name().and_then(|name| name.to_str()) == Some(DIRECT_PLAN_FILENAME) {
        return Ok(Some(RunTarget {
            kind: RunTargetKind::Direct,
            plan: abs,
        }));
    }
    if abs.file_name().and_then(|name| name.to_str()) == Some(VM_PLAN_FILENAME) {
        return Ok(Some(RunTarget {
            kind: RunTargetKind::Vm,
            plan: abs,
        }));
    }
    if is_run_plan_file(&abs)? {
        return Ok(Some(RunTarget {
            kind: RunTargetKind::MixedRunPlan,
            plan: abs,
        }));
    }

    Ok(None)
}

async fn stop(_args: StopArgs) -> Result<()> {
    mixed_run::stop_run(&_args.run_id, _args.storage_root.as_deref()).await
}

async fn compile_for_run(input: &str) -> Result<CompiledScenario> {
    match resolve_compile_input(input).await? {
        CompileInput::ScenarioIr(compiled) => Ok(compiled),
        CompileInput::Manifest(resolved) => {
            let compiler = Compiler::new(resolved.resolver, Default::default())
                .with_registry(resolved.registry);
            let output = compiler
                .compile_from_tree(
                    compiler
                        .resolve_tree(resolved.manifest, CompileOptions::default().resolve)
                        .await
                        .wrap_err("compile failed")?,
                    CompileOptions::default().optimize,
                )
                .wrap_err("compile failed")?;
            let has_error = print_diagnostics(&output.diagnostics, &DenySet::default())?;
            if has_error {
                return Err(miette::miette!("compilation failed"));
            }
            CompiledScenario::from_compile_output(&output)
                .into_diagnostic()
                .wrap_err("failed to convert compiler output into Scenario IR")
        }
    }
}

#[cfg(test)]
mod tests;
