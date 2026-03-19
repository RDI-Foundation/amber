use super::{
    Store,
    models::{OperationRow, ScenarioStateUpdate, StoreError, StoredOperation, encode_json},
};
use crate::domain::{
    DesiredState, IMPLICIT_OWNER_ID, ObservedState, OperationKind, OperationPayload,
    OperationStatus,
};

impl Store {
    pub async fn create_pending_scenario_with_operation(
        &self,
        new_scenario: super::NewPendingScenario<'_>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        insert_operation(
            &mut *tx,
            OperationInsert {
                operation_id: new_scenario.operation_id,
                kind: OperationKind::Create,
                scenario_id: Some(new_scenario.scenario_id),
                payload: new_scenario.payload,
                status: OperationStatus::Queued,
                phase: "queued",
                retry_count: 0,
                backoff_until_ms: None,
                last_error: None,
                result: None,
                created_at_ms: new_scenario.now_ms,
                updated_at_ms: new_scenario.now_ms,
                started_at_ms: None,
                finished_at_ms: None,
            },
        )
        .await?;

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
                updated_at_ms,
                desired_generation,
                applied_generation,
                processing_generation,
                work_status,
                cleanup_generation,
                pending_operation_id,
                running_operation_id
            ) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?, 1, 0, NULL, 'idle', 0, ?, NULL)
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
        .bind(new_scenario.operation_id)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        tx.commit().await.map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn stage_scenario_operation(
        &self,
        scenario_id: &str,
        operation_id: &str,
        kind: OperationKind,
        payload: &OperationPayload,
        state_update: ScenarioStateUpdate,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        insert_operation(
            &mut *tx,
            OperationInsert {
                operation_id,
                kind,
                scenario_id: Some(scenario_id),
                payload,
                status: OperationStatus::Queued,
                phase: "queued",
                retry_count: 0,
                backoff_until_ms: None,
                last_error: None,
                result: None,
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
                started_at_ms: None,
                finished_at_ms: None,
            },
        )
        .await?;

        let update = sqlx::query(
            r#"
            UPDATE scenarios
            SET desired_state = COALESCE(?, desired_state),
                observed_state = COALESCE(?, observed_state),
                failure_count = 0,
                backoff_until_ms = NULL,
                last_error = NULL,
                desired_generation = desired_generation + 1,
                updated_at_ms = ?,
                pending_operation_id = ?
            WHERE id = ?
              AND pending_operation_id IS NULL
              AND running_operation_id IS NULL
            "#,
        )
        .bind(state_update.desired_state.map(DesiredState::as_str))
        .bind(state_update.observed_state.map(ObservedState::as_str))
        .bind(now_ms)
        .bind(operation_id)
        .bind(scenario_id)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        if update.rows_affected() == 0 {
            return Ok(false);
        }

        tx.commit().await.map_err(StoreError::Database)?;
        Ok(true)
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

    pub async fn mark_operation_running(
        &self,
        operation_id: &str,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        mark_operation_running_in_executor(&self.pool, operation_id, now_ms).await
    }

    pub async fn succeed_operation_and_complete_work(
        &self,
        scenario_id: &str,
        generation: i64,
        operation_id: &str,
        result: Option<&serde_json::Value>,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        mark_operation_succeeded_in_executor(&mut *tx, operation_id, result, now_ms).await?;
        complete_scenario_work_in_executor(&mut *tx, scenario_id, generation, now_ms).await?;
        tx.commit().await.map_err(StoreError::Database)
    }

    pub async fn fail_operation_and_complete_work(
        &self,
        scenario_id: &str,
        generation: i64,
        operation_id: &str,
        error: &str,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        mark_operation_failed_in_executor(&mut *tx, operation_id, error, now_ms).await?;
        complete_scenario_work_in_executor(&mut *tx, scenario_id, generation, now_ms).await?;
        tx.commit().await.map_err(StoreError::Database)
    }

    pub async fn retry_operation_and_release_work(
        &self,
        scenario_id: &str,
        operation_id: &str,
        retry_count: u32,
        backoff_until_ms: i64,
        error: &str,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        reschedule_operation_in_executor(
            &mut *tx,
            operation_id,
            retry_count,
            "backing_off",
            backoff_until_ms,
            error,
            now_ms,
        )
        .await?;
        release_work_for_retry_in_executor(&mut *tx, scenario_id, now_ms).await?;
        tx.commit().await.map_err(StoreError::Database)
    }

    pub async fn requeue_interrupted_operation(
        &self,
        scenario_id: &str,
        operation_id: &str,
        retry_count: u32,
        error: &str,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        reschedule_operation_in_executor(
            &mut *tx,
            operation_id,
            retry_count,
            "requeued_after_manager_restart",
            now_ms,
            error,
            now_ms,
        )
        .await?;
        requeue_interrupted_work_in_executor(&mut *tx, scenario_id, Some(operation_id), now_ms)
            .await?;
        tx.commit().await.map_err(StoreError::Database)
    }
}

pub(super) async fn requeue_interrupted_work_in_executor<'e, E>(
    executor: E,
    scenario_id: &str,
    operation_id: Option<&str>,
    now_ms: i64,
) -> Result<(), StoreError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        r#"
            UPDATE scenarios
            SET work_status = 'idle',
                processing_generation = NULL,
                pending_operation_id = COALESCE(pending_operation_id, ?),
                running_operation_id = NULL,
                updated_at_ms = ?
            WHERE id = ?
            "#,
    )
    .bind(operation_id)
    .bind(now_ms)
    .bind(scenario_id)
    .execute(executor)
    .await
    .map_err(StoreError::Database)?;
    Ok(())
}

pub(super) async fn release_work_for_retry_in_executor<'e, E>(
    executor: E,
    scenario_id: &str,
    now_ms: i64,
) -> Result<(), StoreError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        r#"
            UPDATE scenarios
            SET work_status = 'idle',
                processing_generation = NULL,
                updated_at_ms = ?
            WHERE id = ?
            "#,
    )
    .bind(now_ms)
    .bind(scenario_id)
    .execute(executor)
    .await
    .map_err(StoreError::Database)?;
    Ok(())
}

pub(super) async fn complete_scenario_work_in_executor<'e, E>(
    executor: E,
    scenario_id: &str,
    generation: i64,
    now_ms: i64,
) -> Result<(), StoreError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        r#"
            UPDATE scenarios
            SET work_status = 'idle',
                processing_generation = NULL,
                running_operation_id = NULL,
                applied_generation = MAX(applied_generation, ?),
                updated_at_ms = ?
            WHERE id = ?
            "#,
    )
    .bind(generation)
    .bind(now_ms)
    .bind(scenario_id)
    .execute(executor)
    .await
    .map_err(StoreError::Database)?;
    Ok(())
}

pub(super) async fn mark_operation_running_in_executor<'e, E>(
    executor: E,
    operation_id: &str,
    now_ms: i64,
) -> Result<(), StoreError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        r#"
            UPDATE operations
            SET status = 'running',
                phase = 'running',
                updated_at_ms = ?,
                started_at_ms = COALESCE(started_at_ms, ?)
            WHERE id = ?
            "#,
    )
    .bind(now_ms)
    .bind(now_ms)
    .bind(operation_id)
    .execute(executor)
    .await
    .map_err(StoreError::Database)?;
    Ok(())
}

pub(super) async fn mark_operation_succeeded_in_executor<'e, E>(
    executor: E,
    operation_id: &str,
    result: Option<&serde_json::Value>,
    now_ms: i64,
) -> Result<(), StoreError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
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
    .execute(executor)
    .await
    .map_err(StoreError::Database)?;
    Ok(())
}

pub(super) async fn reschedule_operation_in_executor<'e, E>(
    executor: E,
    operation_id: &str,
    retry_count: u32,
    phase: &str,
    backoff_until_ms: i64,
    error: &str,
    now_ms: i64,
) -> Result<(), StoreError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
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
    .execute(executor)
    .await
    .map_err(StoreError::Database)?;
    Ok(())
}

pub(super) async fn mark_operation_failed_in_executor<'e, E>(
    executor: E,
    operation_id: &str,
    error: &str,
    now_ms: i64,
) -> Result<(), StoreError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
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
    .execute(executor)
    .await
    .map_err(StoreError::Database)?;
    Ok(())
}

async fn insert_operation<'e, E>(executor: E, op: OperationInsert<'_>) -> Result<(), StoreError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
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
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(op.operation_id)
    .bind(IMPLICIT_OWNER_ID)
    .bind(op.kind.as_str())
    .bind(op.scenario_id)
    .bind(encode_json(op.payload)?)
    .bind(op.status.as_str())
    .bind(op.phase)
    .bind(i64::from(op.retry_count))
    .bind(op.backoff_until_ms)
    .bind(op.last_error)
    .bind(op.result.map(encode_json).transpose()?)
    .bind(op.created_at_ms)
    .bind(op.updated_at_ms)
    .bind(op.started_at_ms)
    .bind(op.finished_at_ms)
    .execute(executor)
    .await
    .map_err(StoreError::Database)?;
    Ok(())
}

struct OperationInsert<'a> {
    operation_id: &'a str,
    kind: OperationKind,
    scenario_id: Option<&'a str>,
    payload: &'a OperationPayload,
    status: OperationStatus,
    phase: &'a str,
    retry_count: u32,
    backoff_until_ms: Option<i64>,
    last_error: Option<&'a str>,
    result: Option<&'a serde_json::Value>,
    created_at_ms: i64,
    updated_at_ms: i64,
    started_at_ms: Option<i64>,
    finished_at_ms: Option<i64>,
}

#[cfg(test)]
mod tests {
    use std::{path::Path, time::Duration};

    use serde_json::json;
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

    async fn seed_scenario(store: &Store, seed: ScenarioSeed<'_>) {
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
                updated_at_ms,
                desired_generation,
                applied_generation,
                processing_generation,
                work_status,
                cleanup_generation,
                pending_operation_id,
                running_operation_id
            ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?, ?, ?, ?, ?, 0, ?, ?)
            "#,
        )
        .bind(seed.scenario_id)
        .bind(IMPLICIT_OWNER_ID)
        .bind("https://example.com/scenario")
        .bind(format!("amber_{}", seed.scenario_id))
        .bind(DesiredState::Running.as_str())
        .bind(ObservedState::Running.as_str())
        .bind("{}")
        .bind(Some(json!({})).map(|value| serde_json::to_string(&value).expect("root config")))
        .bind(encode_json(&crate::domain::ScenarioTelemetryRequest::default()).expect("telemetry"))
        .bind("{}")
        .bind("{}")
        .bind(1_i64)
        .bind(1_i64)
        .bind(seed.desired_generation)
        .bind(seed.applied_generation)
        .bind(seed.processing_generation)
        .bind(seed.work_status)
        .bind(seed.pending_operation_id)
        .bind(seed.running_operation_id)
        .execute(&store.pool)
        .await
        .expect("seed scenario");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stage_scenario_operation_rejects_second_explicit_operation() {
        let (_tempdir, store) = test_store().await;
        seed_scenario(&store, ScenarioSeed::idle("scn_test")).await;

        let first = store
            .stage_scenario_operation(
                "scn_test",
                "op_pause",
                OperationKind::Pause,
                &OperationPayload::Pause,
                ScenarioStateUpdate {
                    desired_state: Some(DesiredState::Paused),
                    observed_state: None,
                },
                1,
            )
            .await
            .expect("stage pause operation");
        let second = store
            .stage_scenario_operation(
                "scn_test",
                "op_resume",
                OperationKind::Resume,
                &OperationPayload::Resume,
                ScenarioStateUpdate {
                    desired_state: Some(DesiredState::Running),
                    observed_state: Some(ObservedState::Starting),
                },
                2,
            )
            .await
            .expect("attempt second explicit operation");

        assert!(first);
        assert!(!second);
        assert!(
            store
                .get_operation("op_pause")
                .await
                .expect("load first operation")
                .is_some()
        );
        assert!(
            store
                .get_operation("op_resume")
                .await
                .expect("load second operation")
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_claims_across_store_instances_only_claim_once() {
        let tempdir = TempDir::new().expect("tempdir");
        let db_path = tempdir.path().join("operations-test.db");
        let first_store = open_test_store(&db_path, 1).await;
        first_store.migrate().await.expect("run migrations");
        let second_store = open_test_store(&db_path, 1).await;

        seed_scenario(
            &first_store,
            ScenarioSeed {
                scenario_id: "scn_claim_once",
                desired_generation: 1,
                applied_generation: 0,
                processing_generation: None,
                work_status: "idle",
                pending_operation_id: None,
                running_operation_id: None,
            },
        )
        .await;

        let (first_claim, second_claim) = tokio::join!(
            first_store.claim_next_scenario_work(2),
            second_store.claim_next_scenario_work(2)
        );
        let claimed = [first_claim, second_claim]
            .into_iter()
            .map(|result| result.expect("claim should succeed"))
            .filter(Option::is_some)
            .count();

        assert_eq!(claimed, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multiple_reconcile_requests_coalesce_into_a_single_claim() {
        let (_tempdir, store) = test_store().await;
        seed_scenario(&store, ScenarioSeed::idle("scn_reconcile")).await;

        assert!(
            store
                .schedule_reconcile("scn_reconcile", true, 1)
                .await
                .expect("schedule first reconcile")
        );
        assert!(
            store
                .schedule_reconcile("scn_reconcile", false, 2)
                .await
                .expect("schedule second reconcile")
        );

        let claimed = store
            .claim_next_scenario_work(2)
            .await
            .expect("claim coalesced reconcile")
            .expect("coalesced reconcile work");
        assert_eq!(claimed.scenario_id, "scn_reconcile");
        assert_eq!(claimed.generation, 2);
        assert!(claimed.cleanup_runtime);
        assert_eq!(claimed.operation_id, None);

        store
            .complete_scenario_work("scn_reconcile", claimed.generation, 3)
            .await
            .expect("complete reconcile");
        assert!(
            store
                .claim_next_scenario_work(3)
                .await
                .expect("check for extra reconcile")
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stale_running_operation_rows_do_not_block_future_scheduling() {
        let (_tempdir, store) = test_store().await;
        insert_operation(
            &store.pool,
            OperationInsert {
                operation_id: "op_stale",
                kind: OperationKind::Pause,
                scenario_id: Some("scn_stale"),
                payload: &OperationPayload::Pause,
                status: OperationStatus::Running,
                phase: "running",
                retry_count: 0,
                backoff_until_ms: None,
                last_error: None,
                result: None,
                created_at_ms: 1,
                updated_at_ms: 1,
                started_at_ms: Some(1),
                finished_at_ms: None,
            },
        )
        .await
        .expect("seed stale operation");
        seed_scenario(
            &store,
            ScenarioSeed {
                scenario_id: "scn_stale",
                desired_generation: 1,
                applied_generation: 0,
                processing_generation: Some(1),
                work_status: "running",
                pending_operation_id: None,
                running_operation_id: Some("op_stale"),
            },
        )
        .await;

        store
            .complete_scenario_work("scn_stale", 1, 2)
            .await
            .expect("complete stale work");
        assert!(
            store
                .schedule_reconcile("scn_stale", false, 3)
                .await
                .expect("schedule follow-up reconcile")
        );

        let claimed = store
            .claim_next_scenario_work(3)
            .await
            .expect("claim follow-up work")
            .expect("follow-up work");
        assert_eq!(claimed.scenario_id, "scn_stale");
        assert_eq!(claimed.generation, 2);
    }

    struct ScenarioSeed<'a> {
        scenario_id: &'a str,
        desired_generation: i64,
        applied_generation: i64,
        processing_generation: Option<i64>,
        work_status: &'a str,
        pending_operation_id: Option<&'a str>,
        running_operation_id: Option<&'a str>,
    }

    impl<'a> ScenarioSeed<'a> {
        fn idle(scenario_id: &'a str) -> Self {
            Self {
                scenario_id,
                desired_generation: 0,
                applied_generation: 0,
                processing_generation: None,
                work_status: "idle",
                pending_operation_id: None,
                running_operation_id: None,
            }
        }
    }
}
