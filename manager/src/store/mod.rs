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

// Bump this only when persisted manager-owned revision/runtime semantics change in a way that
// future releases may need to special-case while reading old state.
pub(crate) const MANAGER_STORAGE_VERSION: &str = "v1";

// Amber compatibility follows the repo's image/runtime version series rather than Cargo package
// versions, which are intentionally not used to version shipped binaries.
pub(crate) const AMBER_COMPAT_VERSION: &str = amber_images::AMBER_CLI.tag;

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

pub(super) fn is_retryable_database_error(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(err) if err.message().contains("locked"))
}
