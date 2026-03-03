use amber_docker_gateway::{DockerGatewayConfig, run};

#[tokio::main]
async fn main() {
    let config = match DockerGatewayConfig::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("docker gateway config error: {err}");
            std::process::exit(1);
        }
    };

    if let Err(err) = run(config).await {
        eprintln!("docker gateway failed: {err}");
        std::process::exit(1);
    }
}
