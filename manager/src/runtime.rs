#[cfg(not(test))]
use std::net::{IpAddr, Ipv4Addr};
#[cfg(test)]
use std::sync::atomic::{AtomicU16, Ordering};
use std::{
    collections::{BTreeSet, HashMap},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::Arc,
};

use amber_proxy::ProxyCommand;
use serde::Deserialize;
use thiserror::Error;
use tokio::{fs, process::Command, sync::Mutex, task::JoinHandle};
use tracing::{error, info};

const EXPECTED_EXITED_SERVICES: &[&str] = &[
    "amber-init",
    "amber-provisioner",
    "amber-router-control-init",
];

#[derive(Clone, Debug)]
pub struct RuntimeSupervisor {
    data_dir: PathBuf,
    backend: RuntimeBackend,
}

#[derive(Clone, Debug)]
enum RuntimeBackend {
    Real {
        proxy_tasks: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    },
    #[cfg(test)]
    Fake { state: Arc<Mutex<FakeRuntimeState>> },
}

impl RuntimeSupervisor {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            backend: RuntimeBackend::Real {
                proxy_tasks: Arc::new(Mutex::new(HashMap::new())),
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn for_tests(data_dir: PathBuf) -> (Self, FakeRuntimeController) {
        let state = Arc::new(Mutex::new(FakeRuntimeState::default()));
        (
            Self {
                data_dir,
                backend: RuntimeBackend::Fake {
                    state: state.clone(),
                },
            },
            FakeRuntimeController { state },
        )
    }

    pub fn scenario_dir(&self, scenario_id: &str) -> PathBuf {
        self.data_dir.join("scenarios").join(scenario_id)
    }

    pub fn revision_dir(&self, scenario_id: &str, revision: i64) -> PathBuf {
        self.scenario_dir(scenario_id)
            .join("revisions")
            .join(revision.to_string())
    }

    pub fn runtime_dir(&self, scenario_id: &str, revision: i64) -> PathBuf {
        self.revision_dir(scenario_id, revision).join("runtime")
    }

    pub async fn apply_running_state(
        &self,
        spec: &RunningScenarioSpec,
    ) -> Result<(), RuntimeError> {
        match &self.backend {
            RuntimeBackend::Real { proxy_tasks } => {
                stop_proxy_task(proxy_tasks, spec.scenario_id()).await;
                validate_published_listeners(&spec.proxy_plan)?;
                run_docker_compose_up(spec.compose_dir(), spec.compose_project()).await?;
                if spec.proxy_plan.export_bindings.is_empty()
                    && spec.proxy_plan.slot_bindings.is_empty()
                {
                    return Ok(());
                }

                let mut command = ProxyCommand::new(spec.compose_dir());
                command
                    .set_project_name(spec.compose_project())
                    .map_err(|err| RuntimeError::Proxy(err.to_string()))?;
                for binding in &spec.proxy_plan.slot_bindings {
                    command
                        .add_slot_binding(binding.slot.clone(), binding.upstream)
                        .map_err(|err| RuntimeError::Proxy(err.to_string()))?;
                }
                for binding in &spec.proxy_plan.export_bindings {
                    command
                        .add_export_binding(binding.export.clone(), binding.listen)
                        .map_err(|err| RuntimeError::Proxy(err.to_string()))?;
                }
                let prepared = command
                    .prepare()
                    .await
                    .map_err(|err| RuntimeError::Proxy(err.to_string()))?;
                let scenario_id = spec.scenario_id().to_string();
                let task = tokio::spawn(async move {
                    if let Err(err) = prepared.run().await {
                        error!("proxy task for {scenario_id} exited: {err}");
                    }
                });
                proxy_tasks
                    .lock()
                    .await
                    .insert(spec.scenario_id().to_string(), task);
                Ok(())
            }
            #[cfg(test)]
            RuntimeBackend::Fake { state } => {
                let mut state = state.lock().await;
                state
                    .apply_attempt_counts
                    .entry(spec.scenario_id().to_string())
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
                if let Some(remaining) = state.fail_next_apply.get_mut(spec.scenario_id())
                    && *remaining > 0
                {
                    *remaining -= 1;
                    return Err(RuntimeError::Compose(format!(
                        "fake runtime apply failure for {}",
                        spec.scenario_id()
                    )));
                }
                if state.fail_any_apply_remaining > 0 {
                    state.fail_any_apply_remaining -= 1;
                    return Err(RuntimeError::Compose(format!(
                        "fake runtime apply failure for {}",
                        spec.scenario_id()
                    )));
                }
                state
                    .apply_counts
                    .entry(spec.scenario_id().to_string())
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
                state
                    .running_specs
                    .insert(spec.scenario_id().to_string(), spec.clone());
                state.health_failures.remove(spec.scenario_id());
                Ok(())
            }
        }
    }

    pub async fn stop_scenario(
        &self,
        scenario_id: &str,
        compose_dir: &Path,
        compose_project: &str,
        destroy_storage: bool,
    ) -> Result<(), RuntimeError> {
        match &self.backend {
            RuntimeBackend::Real { proxy_tasks } => {
                stop_proxy_task(proxy_tasks, scenario_id).await;
                if !compose_file_exists(compose_dir) {
                    return Ok(());
                }
                run_docker_compose_down(compose_dir, compose_project, destroy_storage).await
            }
            #[cfg(test)]
            RuntimeBackend::Fake { state } => {
                let mut state = state.lock().await;
                if let Some(remaining) = state.fail_next_stop.get_mut(scenario_id)
                    && *remaining > 0
                {
                    *remaining -= 1;
                    return Err(RuntimeError::Compose(format!(
                        "fake runtime stop failure for {}",
                        scenario_id
                    )));
                }
                state.running_specs.remove(scenario_id);
                state.health_failures.remove(scenario_id);
                Ok(())
            }
        }
    }

    pub async fn purge_scenario_state(&self, scenario_id: &str) -> Result<(), RuntimeError> {
        let scenario_dir = self.scenario_dir(scenario_id);
        match &self.backend {
            RuntimeBackend::Real { proxy_tasks } => {
                stop_proxy_task(proxy_tasks, scenario_id).await;
            }
            #[cfg(test)]
            RuntimeBackend::Fake { state } => {
                let mut state = state.lock().await;
                state.running_specs.remove(scenario_id);
                state.health_failures.remove(scenario_id);
            }
        }

        match fs::remove_dir_all(&scenario_dir).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(RuntimeError::Compose(format!(
                "failed to remove scenario state {}: {err}",
                scenario_dir.display()
            ))),
        }
    }

    pub async fn stop_proxy(&self, scenario_id: &str) {
        match &self.backend {
            RuntimeBackend::Real { proxy_tasks } => {
                stop_proxy_task(proxy_tasks, scenario_id).await;
            }
            #[cfg(test)]
            RuntimeBackend::Fake { state } => {
                state.lock().await.health_failures.remove(scenario_id);
            }
        }
    }

    pub async fn scenario_health(
        &self,
        scenario_id: &str,
        compose_dir: &Path,
        compose_project: &str,
    ) -> Result<ScenarioHealth, RuntimeError> {
        match &self.backend {
            RuntimeBackend::Real { proxy_tasks } => {
                if let Some(task) = proxy_tasks.lock().await.get(scenario_id)
                    && task.is_finished()
                {
                    return Ok(ScenarioHealth::Failed("proxy task exited".to_string()));
                }

                let services = docker_compose_ps(compose_dir, compose_project).await?;
                Ok(classify_compose_services(&services))
            }
            #[cfg(test)]
            RuntimeBackend::Fake { state } => {
                let state = state.lock().await;
                if let Some(message) = state.health_failures.get(scenario_id) {
                    return Ok(ScenarioHealth::Failed(message.clone()));
                }
                if state.running_specs.contains_key(scenario_id) {
                    Ok(ScenarioHealth::Healthy)
                } else {
                    Ok(ScenarioHealth::Failed(format!(
                        "scenario {} is not running",
                        scenario_id
                    )))
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScenarioHealth {
    Healthy,
    Transitioning(String),
    Failed(String),
}

#[derive(Clone, Debug, Default)]
pub struct ProxyPlan {
    pub slot_bindings: Vec<SlotBinding>,
    pub export_bindings: Vec<ExportBinding>,
    pub published_listeners: Vec<SocketAddr>,
}

#[derive(Clone, Debug)]
pub struct SlotBinding {
    pub slot: String,
    pub upstream: SocketAddr,
}

#[derive(Clone, Debug)]
pub struct ExportBinding {
    pub export: String,
    pub listen: SocketAddr,
}

#[derive(Clone, Debug)]
pub struct RunningScenarioSpec {
    scenario_id: String,
    compose_project: String,
    compose_dir: PathBuf,
    pub proxy_plan: ProxyPlan,
}

impl RunningScenarioSpec {
    pub fn new(
        scenario_id: impl Into<String>,
        compose_project: impl Into<String>,
        compose_dir: PathBuf,
        proxy_plan: ProxyPlan,
    ) -> Self {
        Self {
            scenario_id: scenario_id.into(),
            compose_project: compose_project.into(),
            compose_dir,
            proxy_plan,
        }
    }

    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }

    pub fn compose_project(&self) -> &str {
        &self.compose_project
    }

    pub fn compose_dir(&self) -> &Path {
        &self.compose_dir
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("docker compose failed: {0}")]
    Compose(String),

    #[error("proxy setup failed: {0}")]
    Proxy(String),
}

#[cfg(test)]
static NEXT_FAKE_LOOPBACK_PORT: AtomicU16 = AtomicU16::new(20_000);

#[cfg(test)]
pub fn pick_free_loopback_port() -> Result<u16, RuntimeError> {
    Ok(NEXT_FAKE_LOOPBACK_PORT.fetch_add(1, Ordering::Relaxed))
}

#[cfg(not(test))]
pub fn pick_free_loopback_port() -> Result<u16, RuntimeError> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let listener = TcpListener::bind(addr).map_err(|err| RuntimeError::Compose(err.to_string()))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|err| RuntimeError::Compose(err.to_string()))
}

pub fn ensure_listener_available(addr: SocketAddr) -> Result<(), RuntimeError> {
    let listener = TcpListener::bind(addr).map_err(|err| RuntimeError::Compose(err.to_string()))?;
    drop(listener);
    Ok(())
}

fn validate_published_listeners(proxy_plan: &ProxyPlan) -> Result<(), RuntimeError> {
    let mut seen = BTreeSet::new();
    for listen in &proxy_plan.published_listeners {
        if !seen.insert(*listen) {
            return Err(RuntimeError::Compose(format!(
                "published listener {listen} is configured more than once"
            )));
        }
        ensure_listener_available(*listen)?;
    }
    Ok(())
}

async fn stop_proxy_task(
    proxy_tasks: &Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    scenario_id: &str,
) {
    if let Some(task) = proxy_tasks.lock().await.remove(scenario_id) {
        task.abort();
        let _ = task.await;
    }
}

fn compose_file_exists(compose_dir: &Path) -> bool {
    compose_dir.join("compose.yaml").is_file()
}

fn is_expected_exited_service(service: &ComposePsEntry) -> bool {
    let name = service.service_name();
    if !is_expected_exited_state(service.state.as_str()) {
        return false;
    }

    EXPECTED_EXITED_SERVICES.contains(&name) || name.ends_with("-egress-init")
}

fn is_expected_exited_state(state: &str) -> bool {
    let state = state.trim().to_ascii_lowercase();
    state == "exited" || state == "exited (0)"
}

fn classify_compose_services(services: &[ComposePsEntry]) -> ScenarioHealth {
    if services.is_empty() {
        return ScenarioHealth::Transitioning("docker compose reports no services".to_string());
    }

    for service in services {
        if is_expected_exited_service(service) {
            continue;
        }

        let state = service.state.to_ascii_lowercase();
        if state.starts_with("running") {
            continue;
        }
        if is_transitional_service_state(&state) {
            return ScenarioHealth::Transitioning(format!(
                "service {} is {}",
                service.service_name(),
                service.state
            ));
        }
        return ScenarioHealth::Failed(format!(
            "service {} is {}",
            service.service_name(),
            service.state
        ));
    }

    ScenarioHealth::Healthy
}

fn is_transitional_service_state(state: &str) -> bool {
    state.starts_with("created")
        || state.starts_with("starting")
        || state.starts_with("restarting")
        || state.starts_with("removing")
}

async fn run_docker_compose_up(
    compose_dir: &Path,
    compose_project: &str,
) -> Result<(), RuntimeError> {
    run_docker_compose(
        compose_dir,
        compose_project,
        &["up", "-d", "--remove-orphans"],
    )
    .await
}

async fn run_docker_compose_down(
    compose_dir: &Path,
    compose_project: &str,
    destroy_storage: bool,
) -> Result<(), RuntimeError> {
    if destroy_storage {
        run_docker_compose(
            compose_dir,
            compose_project,
            &["down", "--remove-orphans", "-v"],
        )
        .await
    } else {
        run_docker_compose(compose_dir, compose_project, &["down", "--remove-orphans"]).await
    }
}

async fn docker_compose_ps(
    compose_dir: &Path,
    compose_project: &str,
) -> Result<Vec<ComposePsEntry>, RuntimeError> {
    let output = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_dir.join("compose.yaml"))
        .args(["ps", "--all", "--format", "json"])
        .env("COMPOSE_PROJECT_NAME", compose_project)
        .current_dir(compose_dir)
        .output()
        .await
        .map_err(|err| RuntimeError::Compose(err.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(RuntimeError::Compose(format!(
            "docker compose ps failed in {} (status {}): stdout:\n{}\nstderr:\n{}",
            compose_dir.display(),
            output.status,
            stdout.trim(),
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_compose_ps_entries(stdout.trim()).map_err(|err| RuntimeError::Compose(err.to_string()))
}

async fn run_docker_compose(
    compose_dir: &Path,
    compose_project: &str,
    args: &[&str],
) -> Result<(), RuntimeError> {
    let output = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_dir.join("compose.yaml"))
        .args(args)
        .env("COMPOSE_PROJECT_NAME", compose_project)
        .current_dir(compose_dir)
        .output()
        .await
        .map_err(|err| RuntimeError::Compose(err.to_string()))?;

    if output.status.success() {
        info!(
            "docker compose {:?} succeeded for {}",
            args,
            compose_dir.display()
        );
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(RuntimeError::Compose(format!(
        "docker compose {:?} failed in {} (status {}): stdout:\n{}\nstderr:\n{}",
        args,
        compose_dir.display(),
        output.status,
        stdout.trim(),
        stderr.trim()
    )))
}

#[derive(Debug, Deserialize)]
struct ComposePsEntry {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Service", default)]
    service: String,
    #[serde(rename = "State", default)]
    state: String,
}

impl ComposePsEntry {
    fn service_name(&self) -> &str {
        if self.service.is_empty() {
            &self.name
        } else {
            &self.service
        }
    }
}

fn parse_compose_ps_entries(stdout: &str) -> Result<Vec<ComposePsEntry>, serde_json::Error> {
    if stdout.is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(entries) = serde_json::from_str::<Vec<ComposePsEntry>>(stdout) {
        return Ok(entries);
    }
    if let Ok(entry) = serde_json::from_str::<ComposePsEntry>(stdout) {
        return Ok(vec![entry]);
    }
    serde_json::Deserializer::from_str(stdout)
        .into_iter::<ComposePsEntry>()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        ComposePsEntry, ScenarioHealth, classify_compose_services, parse_compose_ps_entries,
    };

    fn service(name: &str, state: &str) -> ComposePsEntry {
        ComposePsEntry {
            name: format!("project-{name}-1"),
            service: name.to_string(),
            state: state.to_string(),
        }
    }

    #[test]
    fn compose_health_treats_empty_project_as_transitioning() {
        assert_eq!(
            classify_compose_services(&[]),
            ScenarioHealth::Transitioning("docker compose reports no services".to_string())
        );
    }

    #[test]
    fn compose_health_treats_created_service_as_transitioning() {
        assert_eq!(
            classify_compose_services(&[service("amber-otelcol", "created")]),
            ScenarioHealth::Transitioning("service amber-otelcol is created".to_string())
        );
    }

    #[test]
    fn compose_health_treats_running_services_as_healthy() {
        assert_eq!(
            classify_compose_services(&[
                service("controller", "running"),
                service("amber-init", "exited (0)"),
                service("c0-component-net-egress-init", "exited"),
            ]),
            ScenarioHealth::Healthy
        );
    }

    #[test]
    fn compose_health_treats_failed_egress_init_as_failed() {
        assert_eq!(
            classify_compose_services(&[service("c0-component-net-egress-init", "exited (1)")]),
            ScenarioHealth::Failed(
                "service c0-component-net-egress-init is exited (1)".to_string()
            )
        );
    }

    #[test]
    fn compose_health_treats_exited_primary_service_as_failed() {
        assert_eq!(
            classify_compose_services(&[service("controller", "exited (1)")]),
            ScenarioHealth::Failed("service controller is exited (1)".to_string())
        );
    }

    #[test]
    fn compose_ps_parser_handles_newline_delimited_json() {
        let stdout = concat!(
            "{\"Service\":\"controller\",\"State\":\"running\"}\n",
            "{\"Service\":\"amber-otelcol\",\"State\":\"created\"}\n"
        );
        let entries = parse_compose_ps_entries(stdout).expect("parse newline-delimited compose ps");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].service, "controller");
        assert_eq!(entries[1].state, "created");
    }
}

#[cfg(test)]
#[derive(Default, Debug)]
struct FakeRuntimeState {
    running_specs: HashMap<String, RunningScenarioSpec>,
    health_failures: HashMap<String, String>,
    fail_next_apply: HashMap<String, u32>,
    fail_next_stop: HashMap<String, u32>,
    fail_any_apply_remaining: u32,
    apply_attempt_counts: HashMap<String, u32>,
    apply_counts: HashMap<String, u32>,
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct FakeRuntimeController {
    state: Arc<Mutex<FakeRuntimeState>>,
}

#[cfg(test)]
impl FakeRuntimeController {
    pub(crate) async fn fail_next_apply_any(&self, count: u32) {
        self.state.lock().await.fail_any_apply_remaining = count;
    }

    pub(crate) async fn fail_next_stop(&self, scenario_id: &str, count: u32) {
        self.state
            .lock()
            .await
            .fail_next_stop
            .insert(scenario_id.to_string(), count);
    }

    pub(crate) async fn mark_unhealthy(&self, scenario_id: &str, message: impl Into<String>) {
        self.state
            .lock()
            .await
            .health_failures
            .insert(scenario_id.to_string(), message.into());
    }

    pub(crate) async fn apply_count(&self, scenario_id: &str) -> u32 {
        self.state
            .lock()
            .await
            .apply_counts
            .get(scenario_id)
            .copied()
            .unwrap_or_default()
    }

    pub(crate) async fn apply_attempt_count(&self, scenario_id: &str) -> u32 {
        self.state
            .lock()
            .await
            .apply_attempt_counts
            .get(scenario_id)
            .copied()
            .unwrap_or_default()
    }

    pub(crate) async fn last_spec(&self, scenario_id: &str) -> Option<RunningScenarioSpec> {
        self.state
            .lock()
            .await
            .running_specs
            .get(scenario_id)
            .cloned()
    }
}
