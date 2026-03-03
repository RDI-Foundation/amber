use amber_docker_gateway::{DockerGatewayConfig, run};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    init_tracing();

    let config = match DockerGatewayConfig::from_env() {
        Ok(config) => config,
        Err(err) => {
            tracing::error!("docker gateway config error: {err}");
            std::process::exit(1);
        }
    };

    if let Err(err) = run(config).await {
        tracing::error!("docker gateway failed: {err}");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();
}
