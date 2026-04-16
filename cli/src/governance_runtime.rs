use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use amber_compiler::{
    GovernanceFuture, GovernanceRuntime, GovernanceRuntimeError, GovernanceSession,
    policy::{PolicyInput, PolicyOutput},
    reporter::CompiledScenario,
    run_plan::build_run_plan,
};
use amber_manifest::ExportName;
use reqwest::Client;
use tempfile::TempDir;
use tokio::{
    task::JoinHandle,
    time::{Instant, sleep},
};
use url::Url;

use crate::{mixed_run, run_inputs::{collect_run_interface, missing_required_root_inputs}};

pub(crate) struct CliGovernanceRuntime {
    client: Client,
}

impl Default for CliGovernanceRuntime {
    fn default() -> Self {
        Self {
            client: Client::builder()
                .build()
                .expect("governance HTTP client should build"),
        }
    }
}

struct CliGovernanceSession {
    client: Client,
    export_urls: BTreeMap<String, Url>,
    // finish(self) needs to take ownership of the temp run state while the session itself stays
    // Sync for the compiler's async pipeline.
    cleanup: Mutex<Option<GovernanceCleanup>>,
}

struct GovernanceCleanup {
    storage_root: TempDir,
    run_id: String,
    proxy_task: JoinHandle<miette::Result<()>>,
}

impl GovernanceRuntime for CliGovernanceRuntime {
    fn start<'a>(
        &'a self,
        compiled: &'a CompiledScenario,
    ) -> GovernanceFuture<'a, Result<Box<dyn GovernanceSession>, GovernanceRuntimeError>> {
        Box::pin(async move {
            let storage_root = TempDir::new().map_err(|err| {
                GovernanceRuntimeError::message(format!(
                    "failed to create governance storage root: {err}"
                ))
            })?;
            let run_plan = build_run_plan(compiled, None).map_err(|err| {
                GovernanceRuntimeError::message(format!(
                    "failed to build governance run plan: {err}"
                ))
            })?;
            let interface = collect_run_interface(&run_plan).map_err(|err| {
                GovernanceRuntimeError::message(format!(
                    "failed to inspect governance exports: {err}"
                ))
            })?;
            let ambient_env: BTreeMap<String, String> = std::env::vars()
                .filter(|(k, _)| k.starts_with("AMBER_CONFIG_"))
                .collect();
            let missing = missing_required_root_inputs(&ambient_env, &interface);
            if !missing.is_empty() {
                let names: Vec<String> = missing
                    .iter()
                    .map(|i| format!("config.{} ({})", i.path, i.env_var))
                    .collect();
                return Err(GovernanceRuntimeError::message(format!(
                    "governance policy is missing required config values - add defaults or set \
                     environment variables before running: {}",
                    names.join(", ")
                )));
            }
            let receipt = mixed_run::run_run_plan(
                None,
                &run_plan,
                Some(storage_root.path()),
                None,
                &BTreeMap::new(),
            )
            .await
            .map_err(|err| GovernanceRuntimeError::message(err.to_string()))?;
            let run_root = PathBuf::from(&receipt.run_root);

            let export_bindings = match reserve_export_bindings(&interface.exports) {
                Ok(bindings) => bindings,
                Err(err) => {
                    let _ = mixed_run::stop_run(&receipt.run_id, Some(storage_root.path())).await;
                    return Err(err);
                }
            };
            let export_urls = match build_export_urls(&interface.exports, &export_bindings) {
                Ok(urls) => urls,
                Err(err) => {
                    let _ = mixed_run::stop_run(&receipt.run_id, Some(storage_root.path())).await;
                    return Err(err);
                }
            };

            let plan_path = match mixed_run::write_run_outside_proxy_plan(
                &run_root,
                &BTreeMap::new(),
                &export_bindings,
            ) {
                Ok(path) => path,
                Err(err) => {
                    let _ = mixed_run::stop_run(&receipt.run_id, Some(storage_root.path())).await;
                    return Err(GovernanceRuntimeError::message(format!(
                        "failed to prepare governance export proxy: {err}"
                    )));
                }
            };
            let proxy_task =
                tokio::spawn(async move { mixed_run::run_outside_proxy(plan_path).await });
            if let Err(err) = mixed_run::wait_for_run_outside_proxy_ready(&run_root).await {
                proxy_task.abort();
                let _ = proxy_task.await;
                let _ = mixed_run::stop_run(&receipt.run_id, Some(storage_root.path())).await;
                return Err(GovernanceRuntimeError::message(format!(
                    "failed to expose governance exports: {err}"
                )));
            }
            if let Err(err) =
                wait_for_governance_exports_ready(&self.client, &export_urls, &run_root).await
            {
                proxy_task.abort();
                let _ = proxy_task.await;
                let _ = mixed_run::stop_run(&receipt.run_id, Some(storage_root.path())).await;
                return Err(err);
            }

            Ok(Box::new(CliGovernanceSession {
                client: self.client.clone(),
                export_urls,
                cleanup: Mutex::new(Some(GovernanceCleanup {
                    storage_root,
                    run_id: receipt.run_id,
                    proxy_task,
                })),
            }) as Box<dyn GovernanceSession>)
        })
    }
}

impl GovernanceSession for CliGovernanceSession {
    fn invoke_policy<'a>(
        &'a self,
        policy_export: &'a ExportName,
        input: &'a PolicyInput,
    ) -> GovernanceFuture<'a, Result<PolicyOutput, GovernanceRuntimeError>> {
        Box::pin(async move {
            let url = self
                .export_urls
                .get(policy_export.as_str())
                .ok_or_else(|| {
                    GovernanceRuntimeError::message(format!(
                        "governance export `{policy_export}` is not running"
                    ))
                })?;
            let response = self
                .client
                .post(url.clone())
                .json(input)
                .send()
                .await
                .map_err(|err| {
                    GovernanceRuntimeError::message(format!(
                        "request to `{policy_export}` failed: {err}"
                    ))
                })?;
            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.map_err(|err| {
                    GovernanceRuntimeError::message(format!(
                        "{status} response body could not be read: {err}"
                    ))
                })?;
                return Err(GovernanceRuntimeError::message(format!(
                    "{status}: {}",
                    body.trim()
                )));
            }
            let body = response.text().await.map_err(|err| {
                GovernanceRuntimeError::message(format!(
                    "successful response body could not be read: {err}"
                ))
            })?;
            serde_json::from_str::<PolicyOutput>(&body).map_err(|err| {
                GovernanceRuntimeError::message(format!(
                    "response body was not valid policy output JSON: {err}\n\nbody:\n{}",
                    body.trim()
                ))
            })
        })
    }

    fn finish(self: Box<Self>) -> GovernanceFuture<'static, Result<(), GovernanceRuntimeError>> {
        Box::pin(async move {
            let CliGovernanceSession { cleanup, .. } = *self;
            let cleanup = cleanup
                .into_inner()
                .map_err(|_| {
                    GovernanceRuntimeError::message("governance cleanup state was poisoned")
                })?
                .ok_or_else(|| {
                    GovernanceRuntimeError::message("governance cleanup state was missing")
                })?;
            let GovernanceCleanup {
                storage_root,
                run_id,
                proxy_task,
            } = cleanup;
            proxy_task.abort();
            match proxy_task.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    return Err(GovernanceRuntimeError::message(format!(
                        "governance export proxy failed: {err}"
                    )));
                }
                Err(err) if !err.is_cancelled() => {
                    return Err(GovernanceRuntimeError::message(format!(
                        "governance export proxy task failed: {err}"
                    )));
                }
                Err(_) => {}
            }
            mixed_run::stop_run(&run_id, Some(storage_root.path()))
                .await
                .map_err(|err| GovernanceRuntimeError::message(err.to_string()))
        })
    }
}

fn reserve_export_bindings(
    exports: &[crate::run_inputs::ExportSpec],
) -> Result<BTreeMap<String, SocketAddr>, GovernanceRuntimeError> {
    exports
        .iter()
        .map(|export| {
            let port = mixed_run::reserve_loopback_port().map_err(|err| {
                GovernanceRuntimeError::message(format!(
                    "failed to reserve governance export port: {err}"
                ))
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
) -> Result<BTreeMap<String, Url>, GovernanceRuntimeError> {
    exports
        .iter()
        .map(|export| {
            let addr = bindings.get(&export.name).ok_or_else(|| {
                GovernanceRuntimeError::message(format!(
                    "missing governance export binding for `{}`",
                    export.name
                ))
            })?;
            let raw = match export.protocol.as_str() {
                "tcp" => format!("tcp://{addr}"),
                _ => format!("http://{addr}"),
            };
            let url = Url::parse(&raw).map_err(|err| {
                GovernanceRuntimeError::message(format!(
                    "invalid governance export url `{raw}`: {err}"
                ))
            })?;
            Ok((export.name.clone(), url))
        })
        .collect()
}

async fn wait_for_governance_exports_ready(
    client: &Client,
    export_urls: &BTreeMap<String, Url>,
    run_root: &Path,
) -> Result<(), GovernanceRuntimeError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut pending = Vec::new();

        for (name, url) in export_urls {
            let ready = match client.get(url.clone()).send().await {
                Ok(response) => response.status() != reqwest::StatusCode::BAD_GATEWAY,
                Err(_) => false,
            };
            if !ready {
                pending.push(name.as_str());
            }
        }

        if pending.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            print_governance_logs(run_root);
            return Err(GovernanceRuntimeError::message(format!(
                "governance exports did not become ready in time: {}",
                pending.join(", "),
            )));
        }

        sleep(Duration::from_millis(100)).await;
    }
}

fn print_governance_logs(run_root: &Path) {
    let state_root = run_root.join("state");
    let Ok(entries) = fs::read_dir(&state_root) else {
        return;
    };
    for entry in entries.flatten() {
        let site_root = entry.path();
        if !site_root.is_dir() {
            continue;
        }
        let Ok(raw) = fs::read_to_string(site_root.join("site.log")) else {
            continue;
        };
        let stderr_lines: Vec<&str> = raw
            .lines()
            .filter(|l| l.contains("amber.node.logs") && l.contains("amber_stream=\"stderr\""))
            .filter_map(policy_log_message)
            .collect();
        if !stderr_lines.is_empty() {
            eprintln!("\npolicy process stderr:");
            for line in stderr_lines {
                eprintln!("  {line}");
            }
        }
    }
}

fn policy_log_message(line: &str) -> Option<&str> {
    let msg_start = line.find("}: ")?.saturating_add(3);
    let msg_end = line[msg_start..]
        .find(" amber_stream=")
        .map(|i| msg_start + i)
        .unwrap_or(line.len());
    let msg = line[msg_start..msg_end].trim();
    if msg.is_empty() { None } else { Some(msg) }
}
