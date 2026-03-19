use super::{
    Store,
    models::{OperationRow, StoreError, StoredOperation, encode_json},
};
use crate::domain::{IMPLICIT_OWNER_ID, OperationKind, OperationPayload, OperationStatus};

impl Store {
    pub async fn create_pending_scenario_with_operation(
        &self,
        new_scenario: super::NewPendingScenario<'_>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query(
            r#"
            INSERT INTO scenarios (
                id,
                owner_id,
                source_url,
                active_revision,
                compose_project,
                desired_state,
                observed_state,
                metadata_json,
                root_config_json,
                telemetry_json,
                external_slots_json,
                exports_json,
                failure_count,
                backoff_until_ms,
                last_error,
                created_at_ms,
                updated_at_ms
            ) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)
            "#,
        )
        .bind(new_scenario.scenario_id)
        .bind(IMPLICIT_OWNER_ID)
        .bind(new_scenario.source_url)
        .bind(new_scenario.compose_project)
        .bind(new_scenario.desired_state.as_str())
        .bind(new_scenario.observed_state.as_str())
        .bind(encode_json(new_scenario.metadata)?)
        .bind(encode_json(new_scenario.root_config)?)
        .bind(encode_json(new_scenario.telemetry)?)
        .bind(encode_json(new_scenario.external_slots)?)
        .bind(encode_json(new_scenario.exports)?)
        .bind(new_scenario.now_ms)
        .bind(new_scenario.now_ms)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        sqlx::query(
            r#"
            INSERT INTO operations (
                id,
                owner_id,
                kind,
                scenario_id,
                payload_json,
                status,
                phase,
                retry_count,
                backoff_until_ms,
                last_error,
                result_json,
                created_at_ms,
                updated_at_ms,
                started_at_ms,
                finished_at_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, ?, ?, NULL, NULL)
            "#,
        )
        .bind(new_scenario.operation_id)
        .bind(IMPLICIT_OWNER_ID)
        .bind(OperationKind::Create.as_str())
        .bind(new_scenario.scenario_id)
        .bind(encode_json(new_scenario.payload)?)
        .bind(OperationStatus::Queued.as_str())
        .bind("queued")
        .bind(new_scenario.now_ms)
        .bind(new_scenario.now_ms)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        tx.commit().await.map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn enqueue_operation(
        &self,
        operation_id: &str,
        kind: OperationKind,
        scenario_id: Option<&str>,
        payload: &OperationPayload,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO operations (
                id,
                owner_id,
                kind,
                scenario_id,
                payload_json,
                status,
                phase,
                retry_count,
                backoff_until_ms,
                last_error,
                result_json,
                created_at_ms,
                updated_at_ms,
                started_at_ms,
                finished_at_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, ?, ?, NULL, NULL)
            "#,
        )
        .bind(operation_id)
        .bind(IMPLICIT_OWNER_ID)
        .bind(kind.as_str())
        .bind(scenario_id)
        .bind(encode_json(payload)?)
        .bind(OperationStatus::Queued.as_str())
        .bind("queued")
        .bind(now_ms)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn get_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<StoredOperation>, StoreError> {
        let row = sqlx::query_as::<_, OperationRow>(
            r#"
            SELECT id, kind, scenario_id, payload_json, status, phase, retry_count,
                   backoff_until_ms, last_error, result_json, created_at_ms, updated_at_ms,
                   started_at_ms, finished_at_ms
            FROM operations
            WHERE id = ?
            "#,
        )
        .bind(operation_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn claim_next_operation(
        &self,
        now_ms: i64,
    ) -> Result<Option<StoredOperation>, StoreError> {
        loop {
            let mut tx = match self.pool.begin().await {
                Ok(tx) => tx,
                Err(err) if is_sqlite_lock_error(&err) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
                Err(err) => return Err(StoreError::Database(err)),
            };
            let row = sqlx::query_as::<_, OperationRow>(
                r#"
                SELECT id, kind, scenario_id, payload_json, status, phase, retry_count,
                       backoff_until_ms, last_error, result_json, created_at_ms, updated_at_ms,
                       started_at_ms, finished_at_ms
                FROM operations
                WHERE status = 'queued'
                  AND (backoff_until_ms IS NULL OR backoff_until_ms <= ?)
                ORDER BY created_at_ms, id
                LIMIT 1
                "#,
            )
            .bind(now_ms)
            .fetch_optional(&mut *tx)
            .await;

            let row = match row {
                Ok(row) => row,
                Err(err) if is_sqlite_lock_error(&err) => {
                    drop(tx);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
                Err(err) => return Err(StoreError::Database(err)),
            };

            let Some(row) = row else {
                match tx.commit().await {
                    Ok(()) => {}
                    Err(err) if is_sqlite_lock_error(&err) => {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        continue;
                    }
                    Err(err) => return Err(StoreError::Database(err)),
                }
                return Ok(None);
            };

            let claim = sqlx::query(
                r#"
                UPDATE operations
                SET status = 'running',
                    phase = 'running',
                    updated_at_ms = ?,
                    started_at_ms = COALESCE(started_at_ms, ?)
                WHERE id = ?
                  AND status = 'queued'
                "#,
            )
            .bind(now_ms)
            .bind(now_ms)
            .bind(&row.id)
            .execute(&mut *tx)
            .await;

            let claim = match claim {
                Ok(claim) => claim,
                Err(err) if is_sqlite_lock_error(&err) => {
                    drop(tx);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
                Err(err) => return Err(StoreError::Database(err)),
            };

            match tx.commit().await {
                Ok(()) => {}
                Err(err) if is_sqlite_lock_error(&err) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
                Err(err) => return Err(StoreError::Database(err)),
            }

            if claim.rows_affected() == 0 {
                continue;
            }

            let mut stored: StoredOperation = row.try_into()?;
            stored.status = OperationStatus::Running;
            stored.phase = "running".to_string();
            stored.started_at_ms = Some(now_ms);
            stored.updated_at_ms = now_ms;
            return Ok(Some(stored));
        }
    }

    pub async fn list_running_operations(&self) -> Result<Vec<StoredOperation>, StoreError> {
        let rows = sqlx::query_as::<_, OperationRow>(
            r#"
            SELECT id, kind, scenario_id, payload_json, status, phase, retry_count,
                   backoff_until_ms, last_error, result_json, created_at_ms, updated_at_ms,
                   started_at_ms, finished_at_ms
            FROM operations
            WHERE status = 'running'
            ORDER BY created_at_ms, id
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
    }

    pub async fn mark_operation_succeeded(
        &self,
        operation_id: &str,
        result: Option<&serde_json::Value>,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE operations
            SET status = 'succeeded',
                phase = 'completed',
                backoff_until_ms = NULL,
                last_error = NULL,
                result_json = ?,
                updated_at_ms = ?,
                finished_at_ms = ?
            WHERE id = ?
            "#,
        )
        .bind(result.map(encode_json).transpose()?)
        .bind(now_ms)
        .bind(now_ms)
        .bind(operation_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn reschedule_operation(
        &self,
        operation_id: &str,
        retry_count: u32,
        phase: &str,
        backoff_until_ms: i64,
        error: &str,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE operations
            SET status = 'queued',
                phase = ?,
                retry_count = ?,
                backoff_until_ms = ?,
                last_error = ?,
                updated_at_ms = ?
            WHERE id = ?
            "#,
        )
        .bind(phase)
        .bind(i64::from(retry_count))
        .bind(backoff_until_ms)
        .bind(error)
        .bind(now_ms)
        .bind(operation_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn mark_operation_failed(
        &self,
        operation_id: &str,
        error: &str,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE operations
            SET status = 'failed',
                phase = 'failed',
                last_error = ?,
                updated_at_ms = ?,
                finished_at_ms = ?
            WHERE id = ?
            "#,
        )
        .bind(error)
        .bind(now_ms)
        .bind(now_ms)
        .bind(operation_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn has_inflight_operation(&self, scenario_id: &str) -> Result<bool, StoreError> {
        let existing = sqlx::query_scalar::<_, String>(
            r#"
            SELECT id
            FROM operations
            WHERE scenario_id = ?
              AND status IN ('queued', 'running')
            LIMIT 1
            "#,
        )
        .bind(scenario_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(existing.is_some())
    }

    pub async fn enqueue_reconcile_if_absent(
        &self,
        scenario_id: &str,
        cleanup_runtime: bool,
        now_ms: i64,
    ) -> Result<Option<String>, StoreError> {
        let op_id = crate::ids::new_operation_id();
        let result = sqlx::query(
            r#"
            INSERT OR IGNORE INTO operations (
                id,
                owner_id,
                kind,
                scenario_id,
                payload_json,
                status,
                phase,
                retry_count,
                backoff_until_ms,
                last_error,
                result_json,
                created_at_ms,
                updated_at_ms,
                started_at_ms,
                finished_at_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, ?, ?, NULL, NULL)
            "#,
        )
        .bind(&op_id)
        .bind(IMPLICIT_OWNER_ID)
        .bind(OperationKind::Reconcile.as_str())
        .bind(scenario_id)
        .bind(encode_json(&OperationPayload::Reconcile {
            cleanup_runtime,
        })?)
        .bind(OperationStatus::Queued.as_str())
        .bind("queued")
        .bind(now_ms)
        .bind(now_ms)
        .execute(&self.pool)
        .await?;
        Ok((result.rows_affected() == 1).then_some(op_id))
    }
}

fn is_sqlite_lock_error(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(err) => err.message().contains("locked"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{path::Path, time::Duration};

    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use tempfile::TempDir;

    use super::*;

    async fn open_test_store(db_path: &Path, max_connections: u32) -> Store {
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(db_path)
            .expect("create sqlite db");
        let connect_options = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect_with(connect_options)
            .await
            .expect("connect sqlite");
        Store::new(pool)
    }

    async fn test_store() -> (TempDir, Store) {
        let tempdir = TempDir::new().expect("tempdir");
        let db_path = tempdir.path().join("operations-test.db");
        let store = open_test_store(&db_path, 2).await;
        store.migrate().await.expect("run migrations");
        (tempdir, store)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enqueue_reconcile_if_absent_returns_none_for_duplicate_inflight_work() {
        let (_tempdir, store) = test_store().await;

        let first = store
            .enqueue_reconcile_if_absent("scn_test", false, 1)
            .await
            .expect("enqueue first reconcile");
        let second = store
            .enqueue_reconcile_if_absent("scn_test", true, 2)
            .await
            .expect("dedupe duplicate reconcile");

        assert!(first.is_some());
        assert_eq!(second, None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reconcile_uniqueness_only_applies_to_inflight_operations() {
        let (_tempdir, store) = test_store().await;
        let payload = OperationPayload::Reconcile {
            cleanup_runtime: false,
        };

        store
            .enqueue_operation(
                "op_reconcile_1",
                OperationKind::Reconcile,
                Some("scn_test"),
                &payload,
                1,
            )
            .await
            .expect("enqueue first reconcile");

        let err = store
            .enqueue_operation(
                "op_reconcile_2",
                OperationKind::Reconcile,
                Some("scn_test"),
                &payload,
                2,
            )
            .await
            .expect_err("duplicate inflight reconcile should be rejected");
        assert!(matches!(err, StoreError::Database(_)));

        store
            .mark_operation_failed("op_reconcile_1", "failed", 3)
            .await
            .expect("mark first reconcile failed");

        store
            .enqueue_operation(
                "op_reconcile_2",
                OperationKind::Reconcile,
                Some("scn_test"),
                &payload,
                4,
            )
            .await
            .expect("enqueue reconcile after inflight operation finishes");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_claims_across_store_instances_only_claim_once() {
        let tempdir = TempDir::new().expect("tempdir");
        let db_path = tempdir.path().join("operations-test.db");
        let first_store = open_test_store(&db_path, 1).await;
        first_store.migrate().await.expect("run migrations");
        let second_store = open_test_store(&db_path, 1).await;

        first_store
            .enqueue_operation(
                "op_claim_once",
                OperationKind::Pause,
                Some("scn_test"),
                &OperationPayload::Pause,
                1,
            )
            .await
            .expect("enqueue operation");

        let (first_claim, second_claim) = tokio::join!(
            first_store.claim_next_operation(2),
            second_store.claim_next_operation(2)
        );
        let claimed = [first_claim, second_claim]
            .into_iter()
            .map(|result| result.expect("claim should succeed"))
            .filter(Option::is_some)
            .count();

        assert_eq!(claimed, 1);
    }
}
