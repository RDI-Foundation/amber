use amber_router::{RouterConfig, run};

#[tokio::main]
async fn main() {
    let config = match RouterConfig::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("router config error: {err}");
            std::process::exit(1);
        }
    };

    if let Err(err) = run(config).await {
        eprintln!("router failed: {err}");
        std::process::exit(1);
    }
}
