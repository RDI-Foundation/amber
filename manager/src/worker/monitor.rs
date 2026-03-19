use std::sync::Arc;

use tokio::time::sleep;
use tracing::warn;

use super::{AppState, HEALTH_MONITOR_INTERVAL, STARTUP_HEALTH_GRACE, now_ms};
use crate::{
    domain::{DesiredState, ObservedState},
    runtime::ScenarioHealth,
};

#[derive(Clone, Debug)]
pub struct HealthMonitor {
    state: Arc<AppState>,
}

impl HealthMonitor {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub async fn run(self) {
        loop {
            self.poll_once().await;
            sleep(HEALTH_MONITOR_INTERVAL).await;
        }
    }

    async fn poll_once(&self) {
        let now = now_ms();
        let scenarios = match self.state.store.list_scenarios().await {
            Ok(scenarios) => scenarios,
            Err(err) => {
                warn!("health monitor failed to list scenarios: {err}");
                return;
            }
        };

        for scenario in scenarios {
            if scenario.desired_state != DesiredState::Running {
                continue;
            }
            let Some(revision) = scenario.active_revision else {
                continue;
            };
            if scenario
                .backoff_until_ms
                .is_some_and(|backoff_until| backoff_until > now)
            {
                continue;
            }
            if scenario.failure_count >= self.state.config.max_restart_attempts()
                && scenario.observed_state == ObservedState::Failed
            {
                continue;
            }

            let compose_dir = self.state.runtime.runtime_dir(&scenario.id, revision);
            match self
                .state
                .runtime
                .scenario_health(&scenario.id, &compose_dir, &scenario.compose_project)
                .await
            {
                Ok(ScenarioHealth::Healthy) => {
                    if scenario.observed_state != ObservedState::Running
                        && let Err(err) = self
                            .state
                            .store
                            .set_scenario_states(
                                &scenario.id,
                                DesiredState::Running,
                                ObservedState::Running,
                                None,
                                now,
                            )
                            .await
                    {
                        warn!(
                            "health monitor failed to mark {} running: {}",
                            scenario.id, err
                        );
                    }
                }
                Ok(ScenarioHealth::Transitioning(message)) => {
                    if startup_grace_active(now, scenario.updated_at_ms) {
                        continue;
                    }
                    self.mark_unhealthy(&scenario.id, &message, now).await;
                }
                Ok(ScenarioHealth::Failed(message)) => {
                    self.mark_unhealthy(&scenario.id, &message, now).await;
                }
                Err(err) => warn!(
                    "health monitor failed to probe scenario {}: {}",
                    scenario.id, err
                ),
            }
        }
    }

    async fn mark_unhealthy(&self, scenario_id: &str, message: &str, now: i64) {
        if let Err(err) = self
            .state
            .store
            .set_observed_state(scenario_id, ObservedState::Failed, Some(message), now)
            .await
        {
            warn!(
                "health monitor failed to mark {} unhealthy: {}",
                scenario_id, err
            );
            return;
        }
        match self
            .state
            .store
            .schedule_reconcile(scenario_id, true, now)
            .await
        {
            Ok(true) => self.state.wake_worker(),
            Ok(false) => {}
            Err(err) => warn!(
                "health monitor failed to enqueue reconcile for {}: {}",
                scenario_id, err
            ),
        }
    }
}

fn startup_grace_active(now_ms: i64, updated_at_ms: i64) -> bool {
    let grace_ms = i64::try_from(STARTUP_HEALTH_GRACE.as_millis()).unwrap_or(i64::MAX);
    now_ms < updated_at_ms.saturating_add(grace_ms)
}

#[cfg(test)]
mod tests {
    use super::startup_grace_active;

    #[test]
    fn startup_grace_is_active_until_deadline() {
        assert!(startup_grace_active(9_999, 0));
        assert!(!startup_grace_active(10_000, 0));
    }

    #[test]
    fn startup_grace_uses_saturating_math() {
        assert!(startup_grace_active(i64::MAX - 1, i64::MAX - 5));
        assert!(!startup_grace_active(i64::MAX, 0));
    }
}
