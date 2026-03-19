use serde_json::{Map, Value};

use super::{
    AMBER_COMPAT_VERSION, MANAGER_STORAGE_VERSION, Store,
    models::{
        ClaimedScenarioWork, ExportServiceRow, InterruptedScenarioWork, NewDependency,
        NewExportService, NewScenarioRevision, RevisionRow, ScenarioRevisionApplication,
        ScenarioRow, StoreError, StoredDependency, StoredExportService, StoredRevision,
        StoredRevisionSummary, StoredScenario, decode_json_with_context, encode_json,
    },
    operations::{
        complete_scenario_work_in_executor, release_work_for_retry_in_executor,
        requeue_interrupted_work_in_executor,
    },
};
use crate::domain::ObservedState;

impl Store {
    pub async fn list_scenarios(&self) -> Result<Vec<StoredScenario>, StoreError> {
        let rows = sqlx::query_as::<_, ScenarioRow>(
            r#"
            SELECT id, source_url, active_revision, compose_project, desired_state, observed_state,
                   metadata_json, root_config_json, telemetry_json, external_slots_json, exports_json,
                   failure_count, backoff_until_ms, last_error, updated_at_ms
            FROM scenarios
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

    pub async fn load_scenario(
        &self,
        scenario_id: &str,
    ) -> Result<Option<StoredScenario>, StoreError> {
        let row = sqlx::query_as::<_, ScenarioRow>(
            r#"
            SELECT id, source_url, active_revision, compose_project, desired_state, observed_state,
                   metadata_json, root_config_json, telemetry_json, external_slots_json, exports_json,
                   failure_count, backoff_until_ms, last_error, updated_at_ms
            FROM scenarios
            WHERE id = ?
            "#,
        )
        .bind(scenario_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn list_revisions(
        &self,
        scenario_id: &str,
    ) -> Result<Vec<StoredRevisionSummary>, StoreError> {
        sqlx::query_as::<_, StoredRevisionSummary>(
            r#"
            SELECT revision, source_url, bundle_root IS NOT NULL AS bundle_stored, created_at_ms
            FROM scenario_revisions
            WHERE scenario_id = ?
            ORDER BY revision
            "#,
        )
        .bind(scenario_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    pub async fn load_revision(
        &self,
        scenario_id: &str,
        revision: i64,
    ) -> Result<Option<StoredRevision>, StoreError> {
        let row = sqlx::query_as::<_, RevisionRow>(
            r#"
            SELECT scenario_ir_json, bundle_root, manager_version, amber_version, ir_version
            FROM scenario_revisions
            WHERE scenario_id = ? AND revision = ?
            "#,
        )
        .bind(scenario_id)
        .bind(revision)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn load_secret_config(&self, scenario_id: &str) -> Result<Value, StoreError> {
        let raw = sqlx::query_scalar::<_, String>(
            r#"
            SELECT secret_config_json
            FROM scenario_secrets
            WHERE scenario_id = ?
            "#,
        )
        .bind(scenario_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        match raw {
            Some(raw) => decode_json_with_context("scenario_secrets.secret_config_json", &raw),
            None => Ok(Value::Object(Map::new())),
        }
    }

    pub async fn next_revision_number(&self, scenario_id: &str) -> Result<i64, StoreError> {
        let next = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(MAX(revision), 0) + 1 FROM scenario_revisions WHERE scenario_id = ?",
        )
        .bind(scenario_id)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(next)
    }

    pub async fn persist_revision_state(
        &self,
        new_revision: NewScenarioRevision<'_>,
        application: ScenarioRevisionApplication<'_>,
        dependencies: &[NewDependency],
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query(
            r#"
            INSERT INTO scenario_revisions (
                scenario_id, revision, source_url, scenario_ir_json, bundle_root,
                manager_version, amber_version, ir_version, created_at_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(new_revision.scenario_id)
        .bind(new_revision.revision)
        .bind(new_revision.source_url)
        .bind(new_revision.scenario_ir_json)
        .bind(new_revision.bundle_root)
        .bind(MANAGER_STORAGE_VERSION)
        .bind(AMBER_COMPAT_VERSION)
        .bind(new_revision.ir_version)
        .bind(new_revision.created_at_ms)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        sqlx::query(
            r#"
            UPDATE scenarios
            SET source_url = ?,
                active_revision = ?,
                desired_state = ?,
                observed_state = ?,
                metadata_json = ?,
                root_config_json = ?,
                telemetry_json = ?,
                external_slots_json = ?,
                exports_json = ?,
                failure_count = 0,
                backoff_until_ms = NULL,
                last_error = ?,
                updated_at_ms = ?
            WHERE id = ?
            "#,
        )
        .bind(application.source_url)
        .bind(application.revision)
        .bind(application.desired_state.as_str())
        .bind(application.observed_state.as_str())
        .bind(encode_json(application.metadata)?)
        .bind(encode_json(application.root_config)?)
        .bind(encode_json(application.telemetry)?)
        .bind(encode_json(application.external_slots)?)
        .bind(encode_json(application.exports)?)
        .bind(application.last_error)
        .bind(application.now_ms)
        .bind(application.scenario_id)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        sqlx::query(
            r#"
            INSERT INTO scenario_secrets (scenario_id, secret_config_json, updated_at_ms)
            VALUES (?, ?, ?)
            ON CONFLICT(scenario_id) DO UPDATE
            SET secret_config_json = excluded.secret_config_json,
                updated_at_ms = excluded.updated_at_ms
            "#,
        )
        .bind(application.scenario_id)
        .bind(encode_json(application.secret_config)?)
        .bind(application.now_ms)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        sqlx::query("DELETE FROM scenario_dependencies WHERE consumer_scenario_id = ?")
            .bind(application.scenario_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        for dep in dependencies {
            sqlx::query(
                r#"
                INSERT INTO scenario_dependencies (
                    consumer_scenario_id,
                    slot_name,
                    bindable_service_id,
                    provider_scenario_id,
                    created_at_ms
                ) VALUES (?, ?, ?, ?, ?)
                "#,
            )
            .bind(application.scenario_id)
            .bind(&dep.slot_name)
            .bind(&dep.bindable_service_id)
            .bind(dep.provider_scenario_id.as_deref())
            .bind(application.now_ms)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        }

        tx.commit().await.map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn set_scenario_states(
        &self,
        scenario_id: &str,
        desired_state: crate::domain::DesiredState,
        observed_state: crate::domain::ObservedState,
        last_error: Option<&str>,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE scenarios
            SET desired_state = ?,
                observed_state = ?,
                failure_count = 0,
                backoff_until_ms = NULL,
                last_error = ?,
                updated_at_ms = ?
            WHERE id = ?
            "#,
        )
        .bind(desired_state.as_str())
        .bind(observed_state.as_str())
        .bind(last_error)
        .bind(now_ms)
        .bind(scenario_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn set_observed_state(
        &self,
        scenario_id: &str,
        observed_state: crate::domain::ObservedState,
        last_error: Option<&str>,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE scenarios
            SET observed_state = ?,
                last_error = ?,
                updated_at_ms = ?
            WHERE id = ?
            "#,
        )
        .bind(observed_state.as_str())
        .bind(last_error)
        .bind(now_ms)
        .bind(scenario_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn set_scenario_retry_state(
        &self,
        scenario_id: &str,
        observed_state: crate::domain::ObservedState,
        failure_count: u32,
        backoff_until_ms: Option<i64>,
        error: &str,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE scenarios
            SET observed_state = ?,
                failure_count = ?,
                backoff_until_ms = ?,
                last_error = ?,
                updated_at_ms = ?
            WHERE id = ?
            "#,
        )
        .bind(observed_state.as_str())
        .bind(i64::from(failure_count))
        .bind(backoff_until_ms)
        .bind(error)
        .bind(now_ms)
        .bind(scenario_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn set_scenario_backoff(
        &self,
        scenario_id: &str,
        failure_count: u32,
        backoff_until_ms: i64,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE scenarios
            SET failure_count = ?,
                backoff_until_ms = ?,
                updated_at_ms = ?
            WHERE id = ?
            "#,
        )
        .bind(i64::from(failure_count))
        .bind(backoff_until_ms)
        .bind(now_ms)
        .bind(scenario_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn clear_scenario_backoff(
        &self,
        scenario_id: &str,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE scenarios
            SET failure_count = 0,
                backoff_until_ms = NULL,
                updated_at_ms = ?
            WHERE id = ?
            "#,
        )
        .bind(now_ms)
        .bind(scenario_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn schedule_reconcile(
        &self,
        scenario_id: &str,
        cleanup_runtime: bool,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE scenarios
            SET desired_generation = desired_generation + 1,
                cleanup_generation = CASE
                    WHEN ? THEN desired_generation + 1
                    ELSE cleanup_generation
                END,
                updated_at_ms = ?
            WHERE id = ?
            "#,
        )
        .bind(if cleanup_runtime { 1_i64 } else { 0_i64 })
        .bind(now_ms)
        .bind(scenario_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn claim_next_scenario_work(
        &self,
        now_ms: i64,
    ) -> Result<Option<ClaimedScenarioWork>, StoreError> {
        loop {
            let mut tx = match self.pool.begin().await {
                Ok(tx) => tx,
                Err(err) if super::is_retryable_database_error(&err) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
                Err(err) => return Err(StoreError::Database(err)),
            };

            let row = sqlx::query_as::<_, ScenarioWorkRow>(
                r#"
                SELECT id, desired_generation, applied_generation, cleanup_generation,
                       COALESCE(running_operation_id, pending_operation_id) AS operation_id
                FROM scenarios
                WHERE work_status = 'idle'
                  AND desired_generation > applied_generation
                  AND (backoff_until_ms IS NULL OR backoff_until_ms <= ?)
                ORDER BY updated_at_ms, id
                LIMIT 1
                "#,
            )
            .bind(now_ms)
            .fetch_optional(&mut *tx)
            .await;

            let row = match row {
                Ok(row) => row,
                Err(err) if super::is_retryable_database_error(&err) => {
                    drop(tx);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
                Err(err) => return Err(StoreError::Database(err)),
            };

            let Some(row) = row else {
                match tx.commit().await {
                    Ok(()) => {}
                    Err(err) if super::is_retryable_database_error(&err) => {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        continue;
                    }
                    Err(err) => return Err(StoreError::Database(err)),
                }
                return Ok(None);
            };

            let claim = sqlx::query(
                r#"
                UPDATE scenarios
                SET work_status = 'running',
                    processing_generation = desired_generation,
                    running_operation_id = COALESCE(pending_operation_id, running_operation_id),
                    pending_operation_id = NULL
                WHERE id = ?
                  AND work_status = 'idle'
                  AND desired_generation = ?
                  AND applied_generation = ?
                "#,
            )
            .bind(&row.id)
            .bind(row.desired_generation)
            .bind(row.applied_generation)
            .execute(&mut *tx)
            .await;

            let claim = match claim {
                Ok(claim) => claim,
                Err(err) if super::is_retryable_database_error(&err) => {
                    drop(tx);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
                Err(err) => return Err(StoreError::Database(err)),
            };

            match tx.commit().await {
                Ok(()) => {}
                Err(err) if super::is_retryable_database_error(&err) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
                Err(err) => return Err(StoreError::Database(err)),
            }

            if claim.rows_affected() == 0 {
                continue;
            }

            return Ok(Some(ClaimedScenarioWork {
                scenario_id: row.id,
                generation: row.desired_generation,
                cleanup_runtime: row.cleanup_generation > row.applied_generation,
                operation_id: row.operation_id,
            }));
        }
    }

    pub async fn list_interrupted_work(&self) -> Result<Vec<InterruptedScenarioWork>, StoreError> {
        let rows = sqlx::query_as::<_, InterruptedWorkRow>(
            r#"
            SELECT id, processing_generation, running_operation_id
            FROM scenarios
            WHERE work_status = 'running'
            ORDER BY updated_at_ms, id
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(rows
            .into_iter()
            .map(|row| InterruptedScenarioWork {
                scenario_id: row.id,
                generation: row.processing_generation.unwrap_or_default(),
                operation_id: row.running_operation_id,
            })
            .collect())
    }

    pub async fn requeue_interrupted_work(
        &self,
        scenario_id: &str,
        operation_id: Option<&str>,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        requeue_interrupted_work_in_executor(&self.pool, scenario_id, operation_id, now_ms).await
    }

    pub async fn release_work_for_retry(
        &self,
        scenario_id: &str,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        release_work_for_retry_in_executor(&self.pool, scenario_id, now_ms).await
    }

    pub async fn complete_scenario_work(
        &self,
        scenario_id: &str,
        generation: i64,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        complete_scenario_work_in_executor(&self.pool, scenario_id, generation, now_ms).await
    }

    pub async fn set_export_services(
        &self,
        scenario_id: &str,
        services: &[NewExportService],
        now_ms: i64,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query("DELETE FROM scenario_export_services WHERE scenario_id = ?")
            .bind(scenario_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        for service in services {
            sqlx::query(
                r#"
                INSERT INTO scenario_export_services (
                    service_id, owner_id, scenario_id, export_name, protocol,
                    listen_addr, listen_port, available, created_at_ms, updated_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                "#,
            )
            .bind(&service.service_id)
            .bind(crate::domain::IMPLICIT_OWNER_ID)
            .bind(scenario_id)
            .bind(&service.export_name)
            .bind(&service.protocol)
            .bind(service.listen_addr.to_string())
            .bind(i64::from(service.listen_port))
            .bind(now_ms)
            .bind(now_ms)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        }
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn set_export_services_available(
        &self,
        scenario_id: &str,
        available: bool,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE scenario_export_services
            SET available = ?,
                updated_at_ms = ?
            WHERE scenario_id = ?
            "#,
        )
        .bind(if available { 1_i64 } else { 0_i64 })
        .bind(now_ms)
        .bind(scenario_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn clear_export_services(&self, scenario_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM scenario_export_services WHERE scenario_id = ?")
            .bind(scenario_id)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn list_export_services(&self) -> Result<Vec<StoredExportService>, StoreError> {
        let rows = sqlx::query_as::<_, ExportServiceRow>(
            r#"
            SELECT service_id, scenario_id, export_name, protocol, listen_addr, listen_port, available
            FROM scenario_export_services
            ORDER BY scenario_id, export_name
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
    }

    pub async fn list_export_services_for_scenario(
        &self,
        scenario_id: &str,
    ) -> Result<Vec<StoredExportService>, StoreError> {
        let rows = sqlx::query_as::<_, ExportServiceRow>(
            r#"
            SELECT service_id, scenario_id, export_name, protocol, listen_addr, listen_port, available
            FROM scenario_export_services
            WHERE scenario_id = ?
            ORDER BY export_name
            "#,
        )
        .bind(scenario_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
    }

    pub async fn list_dependencies(&self) -> Result<Vec<StoredDependency>, StoreError> {
        sqlx::query_as::<_, StoredDependency>(
            r#"
            SELECT consumer_scenario_id, slot_name, bindable_service_id, provider_scenario_id
            FROM scenario_dependencies
            ORDER BY consumer_scenario_id, slot_name
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    pub async fn list_dependencies_for_consumer(
        &self,
        scenario_id: &str,
    ) -> Result<Vec<StoredDependency>, StoreError> {
        sqlx::query_as::<_, StoredDependency>(
            r#"
            SELECT consumer_scenario_id, slot_name, bindable_service_id, provider_scenario_id
            FROM scenario_dependencies
            WHERE consumer_scenario_id = ?
            ORDER BY slot_name
            "#,
        )
        .bind(scenario_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    pub async fn list_dependencies_for_provider(
        &self,
        scenario_id: &str,
    ) -> Result<Vec<StoredDependency>, StoreError> {
        sqlx::query_as::<_, StoredDependency>(
            r#"
            SELECT consumer_scenario_id, slot_name, bindable_service_id, provider_scenario_id
            FROM scenario_dependencies
            WHERE provider_scenario_id = ?
            ORDER BY consumer_scenario_id, slot_name
            "#,
        )
        .bind(scenario_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    pub async fn list_dependency_blockers(
        &self,
        provider_scenario_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT d.consumer_scenario_id
            FROM scenario_dependencies d
            JOIN scenarios s ON s.id = d.consumer_scenario_id
            WHERE d.provider_scenario_id = ?
              AND s.observed_state IN (?, ?, ?)
            ORDER BY d.consumer_scenario_id
            "#,
        )
        .bind(provider_scenario_id)
        .bind(ObservedState::DEPENDENCY_BLOCKING_STATES[0])
        .bind(ObservedState::DEPENDENCY_BLOCKING_STATES[1])
        .bind(ObservedState::DEPENDENCY_BLOCKING_STATES[2])
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    pub async fn delete_scenario(&self, scenario_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM scenarios WHERE id = ?")
            .bind(scenario_id)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct ScenarioWorkRow {
    id: String,
    desired_generation: i64,
    applied_generation: i64,
    cleanup_generation: i64,
    operation_id: Option<String>,
}

#[derive(sqlx::FromRow)]
struct InterruptedWorkRow {
    id: String,
    processing_generation: Option<i64>,
    running_operation_id: Option<String>,
}
