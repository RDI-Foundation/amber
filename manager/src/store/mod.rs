mod models;
mod operations;
mod scenarios;

pub use models::{
    ClaimedScenarioWork, InterruptedScenarioWork, NewDependency, NewExportService,
    NewPendingScenario, NewScenarioRevision, ScenarioRevisionApplication, ScenarioStateUpdate,
    StoreError, StoredDependency, StoredExportService, StoredOperation, StoredRevision,
    StoredScenario,
};
use sqlx::SqlitePool;

pub(super) const MANAGER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub(super) const AMBER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(StoreError::Migration)
    }
}
