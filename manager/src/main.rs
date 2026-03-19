use clap::Parser;
use miette::{IntoDiagnostic, WrapErr};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> miette::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();

    let config = amber_manager::ManagerConfig::parse();
    amber_manager::run(config)
        .await
        .into_diagnostic()
        .wrap_err("amber-manager failed")
}
