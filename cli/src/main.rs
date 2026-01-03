use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
};

use amber_compiler::{
    CompileOptions, Compiler,
    reporter::{DotReporter, Reporter as _},
};
use amber_manifest::ManifestRef;
use amber_resolver::Resolver;
use clap::{ArgAction, Args, Parser, Subcommand};
use miette::{
    Context as _, Diagnostic, GraphicalReportHandler, IntoDiagnostic as _, Result, Severity,
};
use tracing_error::ErrorLayer;
use tracing_subscriber::{EnvFilter, fmt as tracing_fmt, prelude::*};

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
}

#[derive(Args)]
struct CompileArgs {
    /// Treat the given lints as errors (e.g. `warnings`, `manifest::unused_slot`).
    #[arg(short = 'D', long = "deny", value_name = "LINT")]
    deny: Vec<String>,

    /// Directory for default output files (defaults to the current directory).
    #[arg(long = "out-dir", value_name = "DIR", conflicts_with = "output")]
    out_dir: Option<PathBuf>,

    /// Write the primary output to this path.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,

    /// Write Graphviz DOT output to this path, or `-` for stdout.
    ///
    /// If omitted, defaults to next to the primary output.
    #[arg(
        long = "dot",
        value_name = "FILE",
        num_args = 0..=1,
        require_equals = true,
        allow_hyphen_values = true
    )]
    dot: Option<Option<PathBuf>>,

    /// Root manifest to compile (URL or local path).
    #[arg(value_name = "MANIFEST")]
    manifest: String,
}

#[derive(Args)]
struct CheckArgs {
    /// Treat the given lints as errors (e.g. `warnings`, `manifest::unused_slot`).
    #[arg(short = 'D', long = "deny", value_name = "LINT")]
    deny: Vec<String>,

    /// Root manifest to check (URL or local path).
    #[arg(value_name = "MANIFEST")]
    manifest: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    miette::set_panic_hook();
    let cli = Cli::parse();
    init_tracing(cli.verbose)?;

    match cli.command {
        Command::Compile(args) => compile(args).await,
        Command::Check(args) => check(args).await,
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
    let manifest = parse_manifest_ref(&args.manifest)?;
    let compiler = Compiler::new(Resolver::new(), Default::default());

    let output = compiler
        .compile(manifest.clone(), CompileOptions::default())
        .await
        .wrap_err("compile failed")?;

    let deny = DenySet::new(&args.deny);
    let has_error = print_diagnostics(&output.diagnostics, &deny)?;
    if has_error {
        return Err(miette::miette!("compilation failed"));
    }

    let outputs = resolve_output_paths(&args, &manifest)?;
    write_primary_output(&outputs.primary, &manifest)?;

    if let Some(dot_dest) = outputs.dot {
        let dot = DotReporter.emit(&output).into_diagnostic()?;
        match dot_dest {
            DotOutput::Stdout => print!("{dot}"),
            DotOutput::File(path) => write_artifact(&path, dot.as_bytes())?,
        }
    }

    Ok(())
}

async fn check(args: CheckArgs) -> Result<()> {
    let manifest = parse_manifest_ref(&args.manifest)?;
    let compiler = Compiler::new(Resolver::new(), Default::default());

    let output = compiler
        .check(manifest, CompileOptions::default())
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

enum DotOutput {
    Stdout,
    File(PathBuf),
}

struct OutputPaths {
    primary: PathBuf,
    dot: Option<DotOutput>,
}

fn resolve_output_paths(args: &CompileArgs, manifest: &ManifestRef) -> Result<OutputPaths> {
    let primary = match args.output.as_ref() {
        Some(path) => path.clone(),
        None => {
            let dir = args.out_dir.clone().unwrap_or_else(|| PathBuf::from("."));
            dir.join(default_output_stem(manifest))
        }
    };

    let dot = match args.dot.as_ref() {
        None => None,
        Some(None) => Some(DotOutput::File(primary.with_extension("dot"))),
        Some(Some(path)) if path.as_path() == Path::new("-") => Some(DotOutput::Stdout),
        Some(Some(path)) => Some(DotOutput::File(path.clone())),
    };

    if let Some(DotOutput::File(dot_path)) = dot.as_ref()
        && dot_path == &primary
    {
        return Err(miette::miette!(
            "dot output path `{}` must not match the primary output path",
            dot_path.display()
        ));
    }

    Ok(OutputPaths { primary, dot })
}

fn default_output_stem(manifest: &ManifestRef) -> String {
    let url = manifest
        .url
        .as_url()
        .expect("CLI resolves manifest refs into absolute URLs");

    let file_name = if url.scheme() == "file" {
        url.to_file_path().ok().and_then(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
        })
    } else {
        url.path_segments()
            .and_then(|mut segments| segments.next_back())
            .map(str::to_string)
    };

    file_name
        .as_deref()
        .and_then(|name| Path::new(name).file_stem().and_then(|s| s.to_str()))
        .filter(|s| !s.is_empty())
        .unwrap_or("amber")
        .to_string()
}

fn write_primary_output(path: &Path, manifest: &ManifestRef) -> Result<()> {
    let url = manifest
        .url
        .as_url()
        .expect("CLI resolves manifest refs into absolute URLs");

    let contents = format!(
        "amber output placeholder\nmanifest: {url}\n\nNOTE: the primary output format is not \
         implemented yet.\n"
    );

    write_artifact(path, contents.as_bytes())
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
