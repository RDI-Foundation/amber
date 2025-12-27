use std::{collections::BTreeSet, path::Path, process::ExitCode};

use amber_compiler::{
    CompileOptions, Compiler, DiagnosticLevel,
    backend::{Backend as _, DotBackend},
};
use amber_manifest::ManifestRef;
use amber_resolver::Resolver;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use color_eyre::eyre::{Context as _, Result, eyre};
use tracing_error::ErrorLayer;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

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
    /// Treat the given lints as errors (e.g. `warnings`, `manifest::unused-slot`).
    #[arg(short = 'D', long = "deny", value_name = "LINT")]
    deny: Vec<String>,

    /// Select the emitted output.
    #[arg(long = "emit", value_enum, default_value_t = EmitKind::Dot)]
    emit: EmitKind,

    /// Root manifest to compile (URL or local path).
    #[arg(value_name = "MANIFEST")]
    manifest: String,
}

#[derive(Args)]
struct CheckArgs {
    /// Treat the given lints as errors (e.g. `warnings`, `manifest::unused-slot`).
    #[arg(short = 'D', long = "deny", value_name = "LINT")]
    deny: Vec<String>,

    /// Root manifest to check (URL or local path).
    #[arg(value_name = "MANIFEST")]
    manifest: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum EmitKind {
    Dot,
    DockerCompose,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode> {
    color_eyre::install()?;
    let cli = Cli::parse();
    init_tracing(cli.verbose)?;

    match cli.command {
        Command::Compile(args) => compile(args).await,
        Command::Check(args) => check(args).await,
    }
}

fn init_tracing(verbose: u8) -> Result<()> {
    let filter = if std::env::var_os("RUST_LOG").is_some() {
        EnvFilter::try_from_default_env().wrap_err("invalid RUST_LOG")?
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
        .with(fmt::layer())
        .with(ErrorLayer::default())
        .init();

    Ok(())
}

async fn compile(args: CompileArgs) -> Result<ExitCode> {
    let manifest = parse_manifest_ref(&args.manifest)?;
    let compiler = Compiler::new(Resolver::new(), Default::default());

    let output = compiler
        .compile(manifest, CompileOptions::default())
        .await
        .wrap_err("compile failed")?;

    let deny = DenySet::new(&args.deny);
    let exit = print_diagnostics(&output.diagnostics, &deny);
    if exit == ExitCode::FAILURE {
        return Ok(exit);
    }

    match args.emit {
        EmitKind::Dot => {
            let dot = DotBackend.emit(&output)?;
            print!("{dot}");
            Ok(ExitCode::SUCCESS)
        }
        EmitKind::DockerCompose => Err(eyre!("emit kind `docker-compose` is not implemented yet")),
    }
}

async fn check(args: CheckArgs) -> Result<ExitCode> {
    let manifest = parse_manifest_ref(&args.manifest)?;
    let compiler = Compiler::new(Resolver::new(), Default::default());

    let output = compiler
        .compile(manifest, CompileOptions::default())
        .await
        .wrap_err("check failed")?;

    let deny = DenySet::new(&args.deny);
    Ok(print_diagnostics(&output.diagnostics, &deny))
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

fn print_diagnostics(diagnostics: &[amber_compiler::Diagnostic], deny: &DenySet) -> ExitCode {
    let mut has_error = false;

    for d in diagnostics {
        let (effective_level, denied) = match d.level {
            DiagnosticLevel::Warning if deny.is_denied(d.code) => (DiagnosticLevel::Error, true),
            other => (other, false),
        };

        let level = match effective_level {
            DiagnosticLevel::Warning => "warning",
            DiagnosticLevel::Error => "error",
        };
        if effective_level == DiagnosticLevel::Error {
            has_error = true;
        }

        let denied_note = if denied { " (denied)" } else { "" };
        eprintln!(
            "{level}[{}]{denied_note} {}: {}",
            d.code, d.component_path, d.message
        );
    }

    if has_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
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
        std::env::current_dir()?.join(path)
    };
    let abs = abs
        .canonicalize()
        .wrap_err_with(|| format!("failed to resolve manifest path `{}`", abs.display()))?;
    let url = url::Url::from_file_path(&abs)
        .map_err(|_| eyre!("could not convert `{}` into a file URL", abs.display()))?;

    Ok(ManifestRef::from_url(url))
}
