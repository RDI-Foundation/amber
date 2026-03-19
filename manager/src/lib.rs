mod api;
mod compiler;
mod config;
mod domain;
mod ids;
mod runtime;
mod store;
mod worker;

#[cfg(test)]
mod e2e_tests;

use std::sync::Arc;

use api::router;
use axum::serve;
pub use config::ManagerConfig;
use sqlx::sqlite::SqlitePoolOptions;
use store::Store;
use tokio::{net::TcpListener, sync::Notify};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use worker::{HealthMonitor, OperationWorker};

pub async fn run(config: ManagerConfig) -> Result<(), config::ConfigError> {
    let file_config = config.load_file_config().await?;
    tokio::fs::create_dir_all(config.data_dir())
        .await
        .map_err(config::ConfigError::Io)?;

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(config.database_connect_options())
        .await
        .map_err(config::ConfigError::Database)?;
    let store = Store::new(pool);
    store
        .migrate()
        .await
        .map_err(|err| config::ConfigError::Io(std::io::Error::other(err)))?;

    let runtime = runtime::RuntimeSupervisor::new(config.data_dir().to_path_buf());
    let notify = Arc::new(Notify::new());
    let state = Arc::new(worker::AppState::new(
        config.clone(),
        file_config,
        store,
        runtime,
        notify.clone(),
    )?);

    let worker = OperationWorker::new(state.clone());
    worker.enqueue_startup_reconciles().await;
    tokio::spawn(async move {
        worker.run().await;
    });

    let health_monitor = HealthMonitor::new(state.clone());
    tokio::spawn(async move {
        health_monitor.run().await;
    });

    let listener = TcpListener::bind(config.listen_addr())
        .await
        .map_err(config::ConfigError::Io)?;
    info!("amber-manager listening on {}", config.listen_addr());
    serve(
        listener,
        router(state)
            .layer(TraceLayer::new_for_http())
            .into_make_service(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|err| {
        warn!("server failed: {err}");
        config::ConfigError::Io(std::io::Error::other(err))
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};

        signal(SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(unix)]
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    #[cfg(not(unix))]
    ctrl_c.await;

    info!("shutdown signal received");
}
