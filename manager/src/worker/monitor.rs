use std::sync::Arc;

use tokio::time::sleep;
use tracing::warn;

use super::{AppState, HEALTH_MONITOR_INTERVAL, now_ms};
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
                Ok(ScenarioHealth::Healthy) => {}
                Ok(ScenarioHealth::Failed(message)) => {
                    if let Err(err) = self
                        .state
                        .store
                        .set_observed_state(
                            &scenario.id,
                            ObservedState::Failed,
                            Some(&message),
                            now,
                        )
                        .await
                    {
                        warn!(
                            "health monitor failed to mark {} unhealthy: {}",
                            scenario.id, err
                        );
                        continue;
                    }
                    match self
                        .state
                        .store
                        .schedule_reconcile(&scenario.id, true, now)
                        .await
                    {
                        Ok(true) => self.state.wake_worker(),
                        Ok(false) => {}
                        Err(err) => warn!(
                            "health monitor failed to enqueue reconcile for {}: {}",
                            scenario.id, err
                        ),
                    }
                }
                Err(err) => warn!(
                    "health monitor failed to probe scenario {}: {}",
                    scenario.id, err
                ),
            }
        }
    }
}
