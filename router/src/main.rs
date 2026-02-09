use amber_router::{config_from_env, run};

#[tokio::main]
async fn main() {
    let config = match config_from_env() {
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
