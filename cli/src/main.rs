use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
};

use amber_compiler::{
    CompileOptions, CompileOutput, Compiler, ResolverRegistry,
    bundle::{BundleBuilder, BundleLoader},
    reporter::{
        Reporter as _,
        docker_compose::DockerComposeReporter,
        dot::DotReporter,
        kubernetes::{KubernetesReporter, KubernetesReporterConfig},
        scenario_ir::ScenarioIrReporter,
    },
};
use amber_manifest::ManifestRef;
use amber_resolver::Resolver;
use clap::{ArgAction, Args, Parser, Subcommand};
use miette::{
    Context as _, Diagnostic, GraphicalReportHandler, IntoDiagnostic as _, Result, Severity,
};
use tracing_error::ErrorLayer;
use tracing_subscriber::{EnvFilter, fmt as tracing_fmt, prelude::*};
use url::Url;

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

    /// Write a manifest bundle to this directory.
    #[arg(long = "bundle", value_name = "DIR")]
    bundle: Option<PathBuf>,

    /// Write Kubernetes manifests to this directory.
    #[arg(long = "kubernetes", visible_alias = "k8s", value_name = "DIR")]
    kubernetes: Option<PathBuf>,

    /// Disable generation of NetworkPolicy enforcement check resources.
    #[arg(long = "disable-networkpolicy-check", requires = "kubernetes")]
    disable_networkpolicy_check: bool,

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

#[tokio::main]
async fn main() -> Result<()> {
    miette::set_panic_hook();
    let cli = Cli::parse();
    init_tracing(cli.verbose)?;

    match cli.command {
        Command::Compile(args) => compile(args).await,
        Command::Check(args) => check(args).await,
        Command::Docs(args) => docs(args),
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
    let opts = CompileOptions::default();

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
            ArtifactOutput::File(path) => write_artifact(&path, compose.as_bytes())?,
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
    kubernetes: Option<PathBuf>,
}

fn ensure_outputs_requested(args: &CompileArgs) -> Result<()> {
    if args.output.is_some()
        || args.dot.is_some()
        || args.docker_compose.is_some()
        || args.bundle.is_some()
        || args.kubernetes.is_some()
    {
        return Ok(());
    }

    Err(miette::miette!(
        help = "Request at least one output with `--output`, `--dot`, `--docker-compose`, \
                `--kubernetes`, or `--bundle`.",
        "no outputs requested for `amber compile`"
    ))
}

fn resolve_output_paths(args: &CompileArgs) -> Result<OutputPaths> {
    let primary = args.output.clone();
    let dot = resolve_optional_output(&args.dot);
    let docker_compose = resolve_optional_output(&args.docker_compose);
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

    if let (Some(ArtifactOutput::File(dot_path)), Some(ArtifactOutput::File(compose_path))) =
        (dot.as_ref(), docker_compose.as_ref())
        && dot_path == compose_path
    {
        return Err(miette::miette!(
            "dot output path `{}` must not match docker compose output path",
            dot_path.display()
        ));
    }

    Ok(OutputPaths {
        primary,
        dot,
        docker_compose,
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
        if path.is_dir() {
            std::fs::remove_dir_all(path)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("failed to remove bundle directory `{}`", path.display())
                })?;
        } else {
            return Err(miette::miette!(
                "bundle output path `{}` is not a directory",
                path.display()
            ));
        }
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
