use std::{
    collections::BTreeMap,
    fs,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Child,
    sync::Mutex,
    time::Duration,
};

use amber_compiler::{reporter::CompiledScenario, run_plan::build_run_plan};
use amber_manifest::ExportName;
use amber_scenario_runner::{
    RunningScenario, ScenarioRunOptions, ScenarioRunner, ScenarioRunnerError, ScenarioRunnerFuture,
};
use miette::Result as MietteResult;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use tempfile::TempDir;
use tokio::{
    net::TcpStream,
    time::{Instant, sleep, timeout},
};
use url::Url;

use crate::{
    mixed_run,
    run_inputs::{
        RunInterface, collect_run_interface, missing_required_root_inputs, select_root_env,
    },
};

const EXPORT_READY_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct CliScenarioRunner {
    client: Client,
}

impl Default for CliScenarioRunner {
    fn default() -> Self {
        Self {
            client: Client::builder()
                .build()
                .expect("scenario runner HTTP client should build"),
        }
    }
}

struct CliRunningScenario {
    client: Client,
    export_urls: BTreeMap<String, Url>,
    options: ScenarioRunOptions,
    // finish(self) needs to take ownership of the temp run state while the session itself stays
    // Sync for the compiler's async pipeline.
    cleanup: Mutex<Option<ScenarioCleanup>>,
}

struct ScenarioCleanup {
    storage_root: TempDir,
    run_id: String,
    run_root: PathBuf,
    proxy_child: Option<Child>,
}

pub(crate) struct StartedRunWithProxy {
    pub(crate) receipt: mixed_run::RunReceipt,
    pub(crate) run_root: PathBuf,
    pub(crate) export_bindings: BTreeMap<String, SocketAddr>,
    pub(crate) proxy_child: Option<Child>,
}

pub(crate) async fn start_run_with_outside_proxy(
    source_plan_path: Option<&Path>,
    run_plan: &amber_compiler::run_plan::RunPlan,
    storage_root_override: Option<&Path>,
    observability: Option<&str>,
    site_launch_env: &BTreeMap<String, String>,
    slot_bindings: &BTreeMap<String, String>,
    export_bindings: BTreeMap<String, SocketAddr>,
) -> MietteResult<StartedRunWithProxy> {
    let receipt = mixed_run::run_run_plan(
        source_plan_path,
        run_plan,
        storage_root_override,
        observability,
        site_launch_env,
    )
    .await?;
    let run_root = PathBuf::from(&receipt.run_root);

    let mut proxy_child = None;
    let proxy_start_result = if slot_bindings.is_empty() && export_bindings.is_empty() {
        Ok(())
    } else {
        match mixed_run::spawn_run_outside_proxy(&run_root, slot_bindings, &export_bindings) {
            Ok(child) => {
                proxy_child = Some(child);
                mixed_run::wait_for_run_outside_proxy_ready(&run_root).await
            }
            Err(err) => Err(err),
        }
    };
    if let Err(err) = proxy_start_result {
        cleanup_failed_started_run(
            &receipt.run_id,
            &run_root,
            storage_root_override,
            &mut proxy_child,
        )
        .await;
        return Err(err);
    }

    Ok(StartedRunWithProxy {
        receipt,
        run_root,
        export_bindings,
        proxy_child,
    })
}

pub(crate) fn cleanup_temporary_run_outside_proxy(
    run_root: &Path,
    proxy_child: &mut Option<Child>,
) -> MietteResult<()> {
    if let Some(mut proxy_child) = proxy_child.take() {
        let _ = proxy_child.kill();
        let _ = proxy_child.wait();
    }
    mixed_run::clear_run_outside_proxy_state(run_root)
}

async fn cleanup_failed_started_run(
    run_id: &str,
    run_root: &Path,
    storage_root_override: Option<&Path>,
    proxy_child: &mut Option<Child>,
) {
    cleanup_failed_started_run_with(
        || cleanup_temporary_run_outside_proxy(run_root, proxy_child),
        || mixed_run::stop_run(run_id, storage_root_override),
    )
    .await;
}

async fn cleanup_failed_started_run_with<C, S, StopFuture>(cleanup: C, stop: S)
where
    C: FnOnce() -> MietteResult<()>,
    S: FnOnce() -> StopFuture,
    StopFuture: Future<Output = MietteResult<()>>,
{
    let _ = cleanup();
    let _ = stop().await;
}

fn select_launch_root_env(
    ambient_env: &BTreeMap<String, String>,
    interface: &RunInterface,
) -> Result<BTreeMap<String, String>, ScenarioRunnerError> {
    let root_env = select_root_env(ambient_env, interface);
    let missing = missing_required_root_inputs(&root_env, interface);
    if !missing.is_empty() {
        let names: Vec<String> = missing
            .iter()
            .map(|i| format!("config.{} ({})", i.path, i.env_var))
            .collect();
        return Err(ScenarioRunnerError::message(format!(
            "scenario is missing required config values - add defaults or set environment \
             variables before running: {}",
            names.join(", ")
        )));
    }
    Ok(root_env)
}

impl ScenarioRunner<CompiledScenario> for CliScenarioRunner {
    fn start<'a>(
        &'a self,
        compiled: &'a CompiledScenario,
        options: ScenarioRunOptions,
    ) -> ScenarioRunnerFuture<'a, Result<Box<dyn RunningScenario>, ScenarioRunnerError>> {
        Box::pin(async move {
            let storage_root = TempDir::new().map_err(|err| {
                ScenarioRunnerError::message(format!(
                    "failed to create temporary run storage root: {err}"
                ))
            })?;
            let run_plan = build_run_plan(compiled, None).map_err(|err| {
                ScenarioRunnerError::message(format!("failed to build run plan: {err}"))
            })?;
            let interface = collect_run_interface(&run_plan).map_err(|err| {
                ScenarioRunnerError::message(format!("failed to inspect run exports: {err}"))
            })?;
            let ambient_env: BTreeMap<String, String> = std::env::vars()
                .filter(|(k, _)| k.starts_with("AMBER_CONFIG_"))
                .collect();
            let root_env = select_launch_root_env(&ambient_env, &interface)?;

            let export_bindings = match reserve_export_bindings(&interface.exports) {
                Ok(bindings) => bindings,
                Err(err) => return Err(err),
            };
            let export_urls = match build_export_urls(&interface.exports, &export_bindings) {
                Ok(urls) => urls,
                Err(err) => return Err(err),
            };

            let mut started = start_run_with_outside_proxy(
                None,
                &run_plan,
                Some(storage_root.path()),
                None,
                &root_env,
                &BTreeMap::new(),
                export_bindings,
            )
            .await
            .map_err(|err| ScenarioRunnerError::message(err.to_string()))?;
            if let Err(err) =
                wait_for_exports_ready(&self.client, &export_urls, &options, &started.run_root)
                    .await
            {
                let _ = cleanup_temporary_run_outside_proxy(
                    &started.run_root,
                    &mut started.proxy_child,
                );
                let _ =
                    mixed_run::stop_run(&started.receipt.run_id, Some(storage_root.path())).await;
                return Err(err);
            }

            Ok(Box::new(CliRunningScenario {
                client: self.client.clone(),
                export_urls,
                options,
                cleanup: Mutex::new(Some(ScenarioCleanup {
                    storage_root,
                    run_id: started.receipt.run_id,
                    run_root: started.run_root,
                    proxy_child: started.proxy_child,
                })),
            }) as Box<dyn RunningScenario>)
        })
    }
}

impl RunningScenario for CliRunningScenario {
    fn post_json_export<'a>(
        &'a self,
        export: &'a ExportName,
        request: &'a Value,
    ) -> ScenarioRunnerFuture<'a, Result<String, ScenarioRunnerError>> {
        Box::pin(async move {
            let export_name = export.as_str();
            let url = self.export_urls.get(export_name).ok_or_else(|| {
                ScenarioRunnerError::message(format!(
                    "export `{}` is not running",
                    self.options.display_name_for(export_name)
                ))
            })?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(ScenarioRunnerError::message(format!(
                    "export `{}` uses `{}`; JSON requests require an HTTP export",
                    self.options.display_name_for(export_name),
                    url.scheme()
                )));
            }
            let response = self
                .client
                .post(url.clone())
                .json(request)
                .send()
                .await
                .map_err(|err| {
                    ScenarioRunnerError::message(format!(
                        "request to export `{}` failed: {err}",
                        self.options.display_name_for(export_name)
                    ))
                })?;
            let status = response.status();
            let body = response.text().await.map_err(|err| {
                ScenarioRunnerError::message(format!("response body could not be read: {err}"))
            })?;
            if !status.is_success() {
                return Err(ScenarioRunnerError::message(format!(
                    "{status}: {}",
                    body.trim()
                )));
            }
            Ok(body)
        })
    }

    fn finish(self: Box<Self>) -> ScenarioRunnerFuture<'static, Result<(), ScenarioRunnerError>> {
        Box::pin(async move {
            let CliRunningScenario { cleanup, .. } = *self;
            let cleanup = cleanup
                .into_inner()
                .map_err(|_| {
                    ScenarioRunnerError::message("temporary run cleanup state was poisoned")
                })?
                .ok_or_else(|| {
                    ScenarioRunnerError::message("temporary run cleanup state was missing")
                })?;
            let ScenarioCleanup {
                storage_root,
                run_id,
                run_root,
                mut proxy_child,
            } = cleanup;
            cleanup_temporary_run_outside_proxy(&run_root, &mut proxy_child)
                .map_err(|err| ScenarioRunnerError::message(err.to_string()))?;
            mixed_run::stop_run(&run_id, Some(storage_root.path()))
                .await
                .map_err(|err| ScenarioRunnerError::message(err.to_string()))
        })
    }
}

fn reserve_export_bindings(
    exports: &[crate::run_inputs::ExportSpec],
) -> Result<BTreeMap<String, SocketAddr>, ScenarioRunnerError> {
    exports
        .iter()
        .map(|export| {
            let port = mixed_run::reserve_loopback_port().map_err(|err| {
                ScenarioRunnerError::message(format!("failed to reserve export port: {err}"))
            })?;
            Ok((
                export.name.clone(),
                SocketAddr::from(([127, 0, 0, 1], port)),
            ))
        })
        .collect()
}

fn build_export_urls(
    exports: &[crate::run_inputs::ExportSpec],
    bindings: &BTreeMap<String, SocketAddr>,
) -> Result<BTreeMap<String, Url>, ScenarioRunnerError> {
    exports
        .iter()
        .map(|export| {
            let addr = bindings.get(&export.name).ok_or_else(|| {
                ScenarioRunnerError::message(format!(
                    "missing export binding for `{}`",
                    export.name
                ))
            })?;
            let raw = match export.protocol.as_str() {
                "tcp" => format!("tcp://{addr}"),
                _ => format!("http://{addr}"),
            };
            let url = Url::parse(&raw).map_err(|err| {
                ScenarioRunnerError::message(format!("invalid export url `{raw}`: {err}"))
            })?;
            Ok((export.name.clone(), url))
        })
        .collect()
}

async fn wait_for_exports_ready(
    client: &Client,
    export_urls: &BTreeMap<String, Url>,
    options: &ScenarioRunOptions,
    run_root: &Path,
) -> Result<(), ScenarioRunnerError> {
    let deadline = Instant::now() + EXPORT_READY_TIMEOUT;
    loop {
        let mut pending = Vec::new();

        for (name, url) in export_urls {
            if !export_is_ready(client, url).await {
                pending.push(options.display_name_for(name));
            }
        }

        if pending.is_empty() {
            return Ok(());
        }
        if let Some(failure) = mixed_run::startup_failure_for_run(run_root)
            .map_err(|err| ScenarioRunnerError::message(err.to_string()))?
        {
            return Err(ScenarioRunnerError::message(format_startup_error(
                &pending,
                Some(&failure),
                &collect_run_logs(run_root),
            )));
        }
        if Instant::now() >= deadline {
            return Err(ScenarioRunnerError::message(format_startup_error(
                &pending,
                None,
                &collect_run_logs(run_root),
            )));
        }

        sleep(Duration::from_millis(100)).await;
    }
}

async fn export_is_ready(client: &Client, url: &Url) -> bool {
    match url.scheme() {
        "http" | "https" => match client.get(url.clone()).send().await {
            Ok(response) => response.status() != StatusCode::BAD_GATEWAY,
            Err(_) => false,
        },
        "tcp" => {
            let Ok(addrs) = url.socket_addrs(|| None) else {
                return false;
            };
            for addr in addrs {
                if let Ok(Ok(_stream)) =
                    timeout(Duration::from_millis(100), TcpStream::connect(addr)).await
                {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

fn format_startup_error(pending: &[&str], failure: Option<&str>, logs: &[String]) -> String {
    let mut message = if let Some(failure) = failure {
        format!(
            "scenario exports failed to start: {}\n\n{}",
            pending.join(", "),
            failure
        )
    } else {
        format!(
            "scenario exports did not become ready in time: {}",
            pending.join(", "),
        )
    };
    if !logs.is_empty() {
        message.push_str("\n\nprocess output:\n");
        for line in logs {
            message.push_str("  ");
            message.push_str(line);
            message.push('\n');
        }
    }
    message
}

fn collect_run_logs(run_root: &Path) -> Vec<String> {
    let state_root = run_root.join("state");
    let Ok(entries) = fs::read_dir(&state_root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let site_root = entry.path();
        if !site_root.is_dir() {
            continue;
        }
        let Ok(raw) = fs::read_to_string(site_root.join("site.log")) else {
            continue;
        };
        for line in raw.lines() {
            if let Some(msg) = extract_log_message(line) {
                out.push(msg.to_string());
            }
        }
    }
    out
}

fn extract_log_message(line: &str) -> Option<&str> {
    // Process stderr forwarded through the tracing span
    if line.contains("amber.node.logs") && line.contains("amber_stream=\"stderr\"") {
        let msg_start = line.find("}: ")?.saturating_add(3);
        let msg_end = line[msg_start..]
            .find(" amber_stream=")
            .map(|i| msg_start + i)
            .unwrap_or(line.len());
        let msg = line[msg_start..msg_end].trim();
        if !msg.is_empty() {
            return Some(msg);
        }
    }
    // Error-level logs from the runtime helper itself
    if line.contains(" ERROR ") {
        let msg = line
            .find(" ERROR ")
            .map(|i| line[i + 7..].trim())
            .unwrap_or(line);
        if !msg.is_empty() {
            return Some(msg);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex as StdMutex};

    use super::*;
    use crate::run_inputs::RootInputSpec;

    #[test]
    fn select_launch_root_env_keeps_only_declared_root_inputs() {
        let interface = RunInterface {
            root_inputs: vec![RootInputSpec {
                path: "api_key".to_string(),
                env_var: "AMBER_CONFIG_API_KEY".to_string(),
                required: true,
                secret: true,
            }],
            ..RunInterface::default()
        };
        let env = BTreeMap::from([
            (
                "AMBER_CONFIG_API_KEY".to_string(),
                "declared-value".to_string(),
            ),
            (
                "AMBER_CONFIG_UNDECLARED".to_string(),
                "should-not-launch".to_string(),
            ),
        ]);

        let selected = select_launch_root_env(&env, &interface).expect("env should be complete");

        assert_eq!(
            selected,
            BTreeMap::from([(
                "AMBER_CONFIG_API_KEY".to_string(),
                "declared-value".to_string()
            )])
        );
    }

    #[test]
    fn select_launch_root_env_reports_missing_declared_required_input() {
        let interface = RunInterface {
            root_inputs: vec![RootInputSpec {
                path: "api_key".to_string(),
                env_var: "AMBER_CONFIG_API_KEY".to_string(),
                required: true,
                secret: true,
            }],
            ..RunInterface::default()
        };
        let env = BTreeMap::from([(
            "AMBER_CONFIG_UNDECLARED".to_string(),
            "unrelated-value".to_string(),
        )]);

        let err = select_launch_root_env(&env, &interface).expect_err("input should be missing");
        let message = err.to_string();

        assert!(
            message.contains("config.api_key (AMBER_CONFIG_API_KEY)"),
            "missing input should be named: {message}"
        );
    }

    #[tokio::test]
    async fn failed_started_run_cleanup_attempts_stop_after_cleanup_failure() {
        let calls = Arc::new(StdMutex::new(Vec::new()));
        let cleanup_calls = Arc::clone(&calls);
        let stop_calls = Arc::clone(&calls);

        cleanup_failed_started_run_with(
            move || {
                cleanup_calls.lock().expect("calls lock").push("cleanup");
                Err(miette::miette!("cleanup failed"))
            },
            move || async move {
                stop_calls.lock().expect("calls lock").push("stop");
                Ok(())
            },
        )
        .await;

        assert_eq!(
            calls.lock().expect("calls lock").as_slice(),
            ["cleanup", "stop"]
        );
    }
}
