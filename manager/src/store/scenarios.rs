use serde_json::{Map, Value};

use super::{
    AMBER_VERSION, MANAGER_VERSION, Store,
    models::{
        ExportServiceRow, NewDependency, NewExportService, NewScenarioRevision, RevisionRow,
        ScenarioRevisionApplication, ScenarioRow, StoreError, StoredDependency,
        StoredExportService, StoredRevision, StoredRevisionSummary, StoredScenario,
        decode_json_with_context, encode_json,
    },
};

impl Store {
    pub async fn list_scenarios(&self) -> Result<Vec<StoredScenario>, StoreError> {
        let rows = sqlx::query_as::<_, ScenarioRow>(
            r#"
            SELECT id, source_url, active_revision, compose_project, desired_state, observed_state,
                   metadata_json, root_config_json, telemetry_json, external_slots_json, exports_json,
                   failure_count, backoff_until_ms, last_error
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
                   failure_count, backoff_until_ms, last_error
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
        .bind(MANAGER_VERSION)
        .bind(AMBER_VERSION)
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

    pub async fn list_dependencies(&self) -> Result<Vec<StoredDependency>, StoreError> {
        sqlx::query_as::<_, StoredDependency>(
            r#"
            SELECT consumer_scenario_id, slot_name, bindable_service_id, provider_scenario_id, created_at_ms
            FROM scenario_dependencies
            ORDER BY consumer_scenario_id, slot_name
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    pub async fn list_running_dependency_blockers(
        &self,
        provider_scenario_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        sqlx::query_scalar::<_, String>(
            r#"
            SELECT d.consumer_scenario_id
            FROM scenario_dependencies d
            JOIN scenarios s ON s.id = d.consumer_scenario_id
            WHERE d.provider_scenario_id = ?
              AND s.desired_state = 'running'
            ORDER BY d.consumer_scenario_id
            "#,
        )
        .bind(provider_scenario_id)
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
