use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use clap::Parser;
use serde::Deserialize;
use sqlx::sqlite::SqliteConnectOptions;
use thiserror::Error;
use url::Url;

use crate::domain::ServiceProtocol;

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:4100";

#[derive(Clone, Debug, Parser)]
#[command(name = "amber-manager")]
#[command(about = "Run the Amber scenario manager daemon.")]
pub struct ManagerConfig {
    #[arg(long, value_name = "ADDR", default_value = DEFAULT_LISTEN_ADDR)]
    listen: SocketAddr,

    #[arg(long, value_name = "DIR", default_value = ".amber-manager")]
    data_dir: PathBuf,

    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    #[arg(long, value_name = "COUNT", default_value_t = 5)]
    max_restart_attempts: u32,

    #[arg(long, value_name = "MILLIS", default_value_t = 2_000)]
    base_backoff_ms: u64,
}

impl ManagerConfig {
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn max_restart_attempts(&self) -> u32 {
        self.max_restart_attempts
    }

    pub fn base_backoff_ms(&self) -> u64 {
        self.base_backoff_ms
    }

    pub fn database_url(&self) -> String {
        let path = self.data_dir.join("manager.sqlite");
        format!("sqlite://{}", path.display())
    }

    pub(crate) fn database_connect_options(&self) -> SqliteConnectOptions {
        SqliteConnectOptions::new()
            .filename(self.data_dir.join("manager.sqlite"))
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5))
    }

    pub async fn load_file_config(&self) -> Result<ManagerFileConfig, ConfigError> {
        let Some(path) = self.config.as_ref() else {
            return Ok(ManagerFileConfig::default());
        };
        let raw = tokio::fs::read_to_string(path)
            .await
            .map_err(ConfigError::Io)?;
        serde_json::from_str(&raw).map_err(ConfigError::InvalidConfigFile)
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerFileConfig {
    #[serde(default)]
    pub bindable_services: BTreeMap<String, OperatorBindableServiceConfig>,

    #[serde(default)]
    pub scenario_source_allowlist: Option<BTreeSet<String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorBindableServiceConfig {
    pub protocol: ServiceProtocol,
    pub provider: OperatorServiceProvider,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperatorServiceProvider {
    DirectUrl { url: Url },
    LoopbackUpstream { upstream: SocketAddr },
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config or state path: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid manager config file: {0}")]
    InvalidConfigFile(serde_json::Error),

    #[error("invalid manager configuration: {0}")]
    InvalidConfig(String),

    #[error("database error: {0}")]
    Database(sqlx::Error),

    #[error(transparent)]
    InstanceLock(#[from] crate::instance_lock::InstanceLockError),
}
