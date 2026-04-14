use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, sync::Mutex};

use amber_compiler::{
    Governance, GovernanceFuture, GovernanceRuntime, GovernanceRuntimeError, GovernanceSession,
    policy::{PolicyInput, PolicyOutput},
    reporter::CompiledScenario,
    run_plan::{SiteKind, build_homogeneous_export_run_plan},
};
use amber_manifest::ExportName;
use amber_scenario::ScenarioIr;
use reqwest::Client;
use tempfile::TempDir;
use tokio::task::JoinHandle;
use url::Url;

use crate::{mixed_run, run_inputs::collect_run_interface};

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
        governance: &'a Governance,
    ) -> GovernanceFuture<'a, Result<Box<dyn GovernanceSession>, GovernanceRuntimeError>> {
        Box::pin(async move {
            let storage_root = TempDir::new().map_err(|err| {
                GovernanceRuntimeError::message(format!(
                    "failed to create governance storage root: {err}"
                ))
            })?;
            let compiled = CompiledScenario::from_ir(ScenarioIr::from(&governance.scenario))
                .map_err(|err| {
                    GovernanceRuntimeError::message(format!(
                        "failed to compile governance scenario: {err}"
                    ))
                })?;
            let run_plan =
                build_homogeneous_export_run_plan(&compiled, SiteKind::Direct).map_err(|err| {
                    GovernanceRuntimeError::message(format!(
                        "failed to build governance run plan: {err}"
                    ))
                })?;
            let interface = collect_run_interface(&run_plan).map_err(|err| {
                GovernanceRuntimeError::message(format!(
                    "failed to inspect governance exports: {err}"
                ))
            })?;
            let receipt = mixed_run::run_run_plan(
                None,
                &run_plan,
                Some(storage_root.path()),
                None,
                &BTreeMap::new(),
            )
            .await
            .map_err(|err| {
                GovernanceRuntimeError::message(format!(
                    "failed to start governance artifact: {err}"
                ))
            })?;
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
                        "policy `{policy_export}` returned {status} and its error body could not \
                         be read: {err}"
                    ))
                })?;
                return Err(GovernanceRuntimeError::message(format!(
                    "policy `{policy_export}` returned {status}: {}",
                    body.trim()
                )));
            }
            response.json::<PolicyOutput>().await.map_err(|err| {
                GovernanceRuntimeError::message(format!(
                    "policy `{policy_export}` returned invalid JSON: {err}"
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
                .map_err(|err| {
                    GovernanceRuntimeError::message(format!(
                        "failed to stop governance artifact: {err}"
                    ))
                })
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
