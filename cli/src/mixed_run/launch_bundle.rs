use super::*;

pub(crate) fn dry_run_run_plan(
    source_plan_path: Option<&Path>,
    run_plan: &RunPlan,
    bundle_root: &Path,
    observability: Option<&str>,
    runtime_env: &BTreeMap<String, String>,
) -> Result<PathBuf> {
    if bundle_root.exists() {
        return Err(miette::miette!(
            "launch bundle output directory `{}` already exists",
            bundle_root.display()
        ));
    }
    fs::create_dir_all(bundle_root)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create launch bundle output directory {}",
                bundle_root.display()
            )
        })?;
    let run_id = new_run_id();
    materialize_launch_bundle(
        source_plan_path,
        run_plan,
        bundle_root,
        &run_id,
        observability,
        runtime_env,
    )?;
    Ok(bundle_root.to_path_buf())
}

pub(super) fn materialize_launch_bundle(
    source_plan_path: Option<&Path>,
    run_plan: &RunPlan,
    bundle_root: &Path,
    run_id: &str,
    observability: Option<&str>,
    runtime_env: &BTreeMap<String, String>,
) -> Result<MaterializedLaunchBundle> {
    let sites_root = bundle_root.join("sites");
    let state_root = bundle_root.join("state");
    fs::create_dir_all(&sites_root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create run directory {}", sites_root.display()))?;
    fs::create_dir_all(&state_root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create state directory {}", state_root.display()))?;

    let run_plan_path = run_plan_path(bundle_root);
    write_json(&run_plan_path, run_plan)?;

    let controller_auth_token = amber_site_controller::generate_framework_auth_token(
        &run_plan.mesh_scope,
        "site-controller",
    );
    let dynamic_capability_signing_seed_b64 = amber_mesh::dynamic_caps::signing_seed_b64(
        &amber_mesh::dynamic_caps::signing_key_from_seed(
            amber_mesh::dynamic_caps::generate_dynamic_capability_signing_seed(),
        ),
    );
    let dynamic_caps_token_verify_key_b64 = amber_mesh::dynamic_caps::verify_key_b64(
        &amber_mesh::dynamic_caps::signing_key_from_seed_b64(&dynamic_capability_signing_seed_b64)
            .map_err(|err| {
                miette::miette!("site controller dynamic capability signing seed is invalid: {err}")
            })?,
    );
    let controller_endpoints = run_plan
        .sites
        .iter()
        .map(|(site_id, site_plan)| {
            let port = reserve_loopback_port()?;
            let listen_addr = host_service_bind_addr_for_consumer(site_plan.site.kind, port);
            let host = match site_plan.site.kind {
                SiteKind::Direct | SiteKind::Vm => "127.0.0.1".to_string(),
                SiteKind::Compose | SiteKind::Kubernetes => {
                    host_service_host_for_consumer(site_plan.site.kind)
                }
            };
            Ok((
                site_id.clone(),
                (listen_addr, format!("http://{host}:{port}")),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    let observability =
        materialize_observability(bundle_root, run_id, &run_plan.mesh_scope, observability)?;
    let observability_endpoint = observability
        .as_ref()
        .map(|materialized| materialized.receipt.endpoint.as_str());

    let mut sites = BTreeMap::new();
    for (site_index, (site_id, site_plan)) in run_plan.sites.iter().enumerate() {
        let artifact_dir = materialize_site_artifacts(&sites_root, site_id, site_plan)?;
        let site_state_root = state_root.join(site_id);
        let controller_state_path = site_state_root.join("site-controller-state.json");
        let controller_plan_path = site_controller_plan_path(&site_state_root);
        let (controller_listen_addr, controller_url) = controller_endpoints
            .get(site_id)
            .cloned()
            .expect("controller endpoint should exist for every site");
        let mut framework_env = BTreeMap::new();
        framework_env.insert(
            amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_URL_ENV.to_string(),
            controller_url.clone(),
        );
        framework_env.insert(
            amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_AUTH_TOKEN_ENV.to_string(),
            controller_auth_token.clone(),
        );
        framework_env.insert(
            amber_mesh::DYNAMIC_CAPS_TOKEN_VERIFY_KEY_B64_ENV.to_string(),
            dynamic_caps_token_verify_key_b64.clone(),
        );
        patch_site_artifacts(
            &artifact_dir,
            run_id,
            site_id,
            site_plan.site.kind,
            &merge_env_maps(runtime_env, &framework_env),
            observability_endpoint,
        )?;
        let launch_env = launch_env(
            run_id,
            &run_plan.mesh_scope,
            site_plan.site.kind,
            runtime_env,
            &framework_env,
            observability_endpoint,
        )?;
        let base_supervisor_plan = build_supervisor_plan(
            SupervisorPlanInput {
                run_root: bundle_root,
                run_id,
                mesh_scope: &run_plan.mesh_scope,
                site_id,
                site_plan,
                artifact_dir: &artifact_dir,
                site_state_root: &site_state_root,
                observability_endpoint,
                site_controller_plan_path: Some(controller_plan_path.as_path()),
                site_controller_url: Some(controller_url.as_str()),
            },
            launch_env.clone(),
        )?;
        let controller_state = amber_site_controller::build_site_controller_state(
            run_id,
            run_plan,
            site_id,
            site_index,
            run_plan.sites.len(),
            &dynamic_capability_signing_seed_b64,
        )?;
        amber_site_controller::write_control_state(&controller_state_path, &controller_state)?;
        let peer_controllers = controller_endpoints
            .iter()
            .filter(|(peer_site_id, _)| *peer_site_id != site_id)
            .map(|(peer_site_id, (peer_listen_addr, _peer_url))| {
                (
                    peer_site_id.clone(),
                    amber_site_controller::SiteControllerPeerPlan {
                        site_id: peer_site_id.clone(),
                        kind: run_plan
                            .sites
                            .get(peer_site_id)
                            .expect("peer site should exist in run plan")
                            .site
                            .kind,
                        // Peer controllers talk to the host-side controller process directly.
                        // The site-facing authority URL may use container-oriented hostnames such
                        // as `host.docker.internal`, which are correct for workloads inside a
                        // site but wrong for another host-side controller process.
                        authority_url: amber_site_controller::authority_url_for_listen_addr(
                            *peer_listen_addr,
                        ),
                    },
                )
            })
            .collect();
        amber_site_controller::write_site_controller_plan(
            &controller_plan_path,
            run_id,
            &run_plan.mesh_scope,
            site_id,
            site_plan.site.kind,
            controller_listen_addr,
            &controller_url,
            &site_plan.router_identity_id,
            &controller_state_path,
            bundle_root,
            &state_root,
            &site_state_root,
            &artifact_dir,
            &controller_auth_token,
            &dynamic_caps_token_verify_key_b64,
            peer_controllers,
            base_supervisor_plan.storage_root.as_deref(),
            base_supervisor_plan.runtime_root.as_deref(),
            base_supervisor_plan.router_mesh_port,
            base_supervisor_plan.compose_project.as_deref(),
            base_supervisor_plan.kubernetes_namespace.as_deref(),
            base_supervisor_plan.context.as_deref(),
            base_supervisor_plan.observability_endpoint.as_deref(),
            &launch_env,
        )?;
        write_json(
            &site_supervisor_plan_path(&site_state_root),
            &base_supervisor_plan,
        )?;
        write_json(
            &desired_links_path(&site_state_root),
            &DesiredLinkState {
                schema: DESIRED_LINKS_SCHEMA.to_string(),
                version: DESIRED_LINKS_VERSION,
                external_slots: BTreeMap::new(),
                export_peers: Vec::new(),
                external_slot_overlays: BTreeMap::new(),
                export_peer_overlays: BTreeMap::new(),
            },
        )?;
        sites.insert(
            site_id.clone(),
            MaterializedSite {
                site_plan: site_plan.clone(),
                artifact_dir,
                site_state_root,
                base_supervisor_plan,
            },
        );
    }

    let manifest = build_launch_bundle_manifest(
        run_id,
        source_plan_path,
        run_plan,
        bundle_root,
        &run_plan_path,
        observability.as_ref(),
        &sites,
    )?;
    write_json(&launch_bundle_manifest_path(bundle_root), &manifest)?;

    Ok(MaterializedLaunchBundle {
        run_plan_path,
        observability,
        sites,
    })
}

pub(super) fn build_launch_bundle_manifest(
    run_id: &str,
    source_plan_path: Option<&Path>,
    run_plan: &RunPlan,
    bundle_root: &Path,
    run_plan_path: &Path,
    observability: Option<&MaterializedObservability>,
    sites: &BTreeMap<String, MaterializedSite>,
) -> Result<LaunchBundleManifest> {
    let mut site_entries = BTreeMap::new();
    let mut site_contexts = BTreeMap::new();
    for (site_id, site) in sites {
        let mut dynamic_external_slots = run_plan
            .links
            .iter()
            .filter(|link| link.consumer_site == *site_id)
            .map(|link| link.external_slot_name.clone())
            .collect::<Vec<_>>();
        dynamic_external_slots.sort();
        dynamic_external_slots.dedup();
        let preview = match site_launch_preview(&site.base_supervisor_plan) {
            Ok(preview) => preview,
            Err(err) => SiteLaunchPreviewBundle {
                inspectability_warnings: vec![format!(
                    "failed to inspect site launch details: {err}"
                )],
                ..Default::default()
            },
        };
        site_contexts.insert(
            site_id.clone(),
            SiteStitchContext {
                kind: site.site_plan.site.kind,
                router_identity_id: site.site_plan.router_identity_id.clone(),
                router_public_key_b64: preview.router_public_key_b64.clone(),
                router_mesh_port: site.base_supervisor_plan.router_mesh_port,
            },
        );
        site_entries.insert(
            site_id.clone(),
            LaunchBundleSite {
                kind: site.site_plan.site.kind,
                router_identity_id: site.site_plan.router_identity_id.clone(),
                router_public_key_b64: preview.router_public_key_b64,
                assigned_components: site.site_plan.assigned_components.clone(),
                artifact_dir: site.artifact_dir.display().to_string(),
                site_state_root: site.site_state_root.display().to_string(),
                supervisor_plan_path: site_supervisor_plan_path(&site.site_state_root)
                    .display()
                    .to_string(),
                desired_links_path: desired_links_path(&site.site_state_root)
                    .display()
                    .to_string(),
                dynamic_external_slots,
                launch_commands: site_launch_commands(&site.base_supervisor_plan)?,
                processes: preview.processes,
                virtual_machines: preview.virtual_machines,
                inspectability_warnings: preview.inspectability_warnings,
            },
        );
    }

    let observability = observability
        .map(|observability| -> Result<LaunchBundleObservability> {
            Ok(LaunchBundleObservability {
                endpoint: observability.receipt.endpoint.clone(),
                plan_path: observability
                    .plan_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
                state_path: observability
                    .plan_path
                    .as_ref()
                    .map(|_| observability_state_path(bundle_root).display().to_string()),
                requests_log: observability.receipt.requests_log.clone(),
                events_ndjson: observability.receipt.events_ndjson.clone(),
                launch_commands: observability_launch_commands(observability)?,
            })
        })
        .transpose()?;

    Ok(LaunchBundleManifest {
        schema: LAUNCH_BUNDLE_SCHEMA.to_string(),
        version: LAUNCH_BUNDLE_VERSION,
        run_id: run_id.to_string(),
        mesh_scope: run_plan.mesh_scope.clone(),
        plan_path: run_plan_path.display().to_string(),
        source_plan_path: source_plan_path.map(|path| path.display().to_string()),
        bundle_root: bundle_root.display().to_string(),
        assignments: run_plan.assignments.clone(),
        startup_waves: run_plan.startup_waves.clone(),
        stitching: build_launch_bundle_stitching_preview(run_plan, &site_contexts)?,
        observability,
        sites: site_entries,
    })
}

pub(super) fn site_launch_preview(plan: &SiteSupervisorPlan) -> Result<SiteLaunchPreviewBundle> {
    Ok(match plan.kind {
        SiteKind::Direct => {
            let preview: DirectSiteLaunchPreview = build_direct_site_launch_preview(
                &PathBuf::from(&plan.artifact_dir).join("direct-plan.json"),
                Path::new(required_path(
                    plan.storage_root.as_deref(),
                    "direct storage root",
                )),
                Path::new(required_path(
                    plan.runtime_root.as_deref(),
                    "direct runtime root",
                )),
                plan.router_mesh_port,
            )?;
            SiteLaunchPreviewBundle {
                router_public_key_b64: preview.router_public_key_b64,
                processes: preview.processes,
                virtual_machines: Vec::new(),
                inspectability_warnings: Vec::new(),
            }
        }
        SiteKind::Vm => {
            let preview: VmSiteLaunchPreview = build_vm_site_launch_preview(
                &PathBuf::from(&plan.artifact_dir).join("vm-plan.json"),
                Path::new(required_path(
                    plan.storage_root.as_deref(),
                    "vm storage root",
                )),
                Path::new(required_path(
                    plan.runtime_root.as_deref(),
                    "vm runtime root",
                )),
                plan.router_mesh_port,
            )?;
            SiteLaunchPreviewBundle {
                router_public_key_b64: preview.router_public_key_b64,
                processes: Vec::new(),
                virtual_machines: preview.virtual_machines,
                inspectability_warnings: preview.inspectability_warnings,
            }
        }
        SiteKind::Compose | SiteKind::Kubernetes => SiteLaunchPreviewBundle::default(),
    })
}

pub(super) fn build_launch_bundle_stitching_preview(
    run_plan: &RunPlan,
    site_contexts: &BTreeMap<String, SiteStitchContext>,
) -> Result<Vec<LaunchBundleLinkPreview>> {
    run_plan
        .links
        .iter()
        .map(|link| {
            let provider = site_contexts.get(&link.provider_site).ok_or_else(|| {
                miette::miette!(
                    "launch bundle is missing provider site `{}`",
                    link.provider_site
                )
            })?;
            let consumer = site_contexts.get(&link.consumer_site).ok_or_else(|| {
                miette::miette!(
                    "launch bundle is missing consumer site `{}`",
                    link.consumer_site
                )
            })?;
            let preview_external_url = match (
                provider.router_mesh_port,
                provider.router_public_key_b64.as_deref(),
            ) {
                (Some(port), Some(peer_key_b64)) => Some(preview_external_slot_url(
                    port,
                    peer_key_b64,
                    &provider.router_identity_id,
                    link,
                    provider.kind,
                    consumer.kind,
                )?),
                _ => None,
            };
            let (resolution, unresolved_reason) = if preview_external_url.is_some() {
                (LaunchBundleLinkResolution::Exact, None)
            } else {
                let reason = match provider.kind {
                    SiteKind::Compose => {
                        "compose router host ports are assigned when Docker starts the site"
                    }
                    SiteKind::Kubernetes => {
                        "kubernetes router addresses are discovered after the port-forward sidecar \
                         starts"
                    }
                    SiteKind::Direct | SiteKind::Vm => {
                        "provider runtime identity and mesh address are materialized during launch"
                    }
                };
                (
                    LaunchBundleLinkResolution::RequiresRuntimeDiscovery,
                    Some(reason.to_string()),
                )
            };
            Ok(LaunchBundleLinkPreview {
                provider_site: link.provider_site.clone(),
                provider_kind: provider.kind,
                provider_component: link.provider_component.clone(),
                provide: link.provide.clone(),
                provider_router_identity_id: provider.router_identity_id.clone(),
                provider_router_mesh_port: provider.router_mesh_port,
                consumer_site: link.consumer_site.clone(),
                consumer_kind: consumer.kind,
                consumer_component: link.consumer_component.clone(),
                slot: link.slot.clone(),
                protocol: link.protocol,
                export_name: link.export_name.clone(),
                external_slot_name: link.external_slot_name.clone(),
                external_slot_env: amber_compiler::mesh::external_slot_env_var(
                    &link.external_slot_name,
                ),
                consumer_mesh_host: container_host_for_consumer(provider.kind, consumer.kind),
                resolution,
                preview_external_url,
                unresolved_reason,
            })
        })
        .collect()
}

pub(super) fn preview_external_slot_url(
    port: u16,
    peer_key_b64: &str,
    peer_id: &str,
    link: &RunLink,
    provider_kind: SiteKind,
    consumer_kind: SiteKind,
) -> Result<String> {
    let host = container_host_for_consumer(provider_kind, consumer_kind);
    let mut mesh_url = Url::parse(&format!("mesh://{}:{port}", host))
        .into_diagnostic()
        .wrap_err("failed to build preview mesh link url")?;
    mesh_url
        .query_pairs_mut()
        .append_pair("peer_id", peer_id)
        .append_pair("peer_key", peer_key_b64)
        .append_pair(
            "route_id",
            &router_export_route_id(&link.export_name, mesh_protocol(link.protocol)?),
        )
        .append_pair("capability", &link.export_name);
    Ok(mesh_url.to_string())
}

pub(super) fn site_launch_commands(plan: &SiteSupervisorPlan) -> Result<Vec<LaunchCommandPreview>> {
    let exe = super::amber_cli_executable()?;
    let mut commands = Vec::new();
    if let Some(plan_path) = plan.site_controller_plan_path.as_deref() {
        let controller = super::site_controller_command()?;
        let mut argv = vec![controller.executable.display().to_string()];
        argv.extend(controller.prefix_args.iter().map(|arg| (*arg).to_string()));
        argv.extend(["--plan".to_string(), plan_path.to_string()]);
        commands.push(LaunchCommandPreview {
            argv,
            env: plan.launch_env.clone(),
            current_dir: Some(plan.site_state_root.clone()),
        });
    }
    let site_commands = match plan.kind {
        SiteKind::Direct => {
            let mut argv = vec![
                exe.display().to_string(),
                "run-direct-init".to_string(),
                "--plan".to_string(),
                PathBuf::from(&plan.artifact_dir)
                    .join("direct-plan.json")
                    .display()
                    .to_string(),
                "--storage-root".to_string(),
                required_path(plan.storage_root.as_deref(), "direct storage root").to_string(),
            ];
            if let Some(runtime_root) = plan.runtime_root.as_deref() {
                argv.push("--runtime-root".to_string());
                argv.push(runtime_root.to_string());
            }
            if let Some(port) = plan.router_mesh_port {
                argv.push("--router-mesh-port".to_string());
                argv.push(port.to_string());
            }
            vec![LaunchCommandPreview {
                argv,
                env: plan.launch_env.clone(),
                current_dir: Some(plan.site_state_root.clone()),
            }]
        }
        SiteKind::Vm => {
            let mut argv = vec![
                exe.display().to_string(),
                "run-vm-init".to_string(),
                "--plan".to_string(),
                PathBuf::from(&plan.artifact_dir)
                    .join("vm-plan.json")
                    .display()
                    .to_string(),
                "--storage-root".to_string(),
                required_path(plan.storage_root.as_deref(), "vm storage root").to_string(),
            ];
            if let Some(runtime_root) = plan.runtime_root.as_deref() {
                argv.push("--runtime-root".to_string());
                argv.push(runtime_root.to_string());
            }
            if let Some(port) = plan.router_mesh_port {
                argv.push("--router-mesh-port".to_string());
                argv.push(port.to_string());
            }
            vec![LaunchCommandPreview {
                argv,
                env: plan.launch_env.clone(),
                current_dir: Some(plan.site_state_root.clone()),
            }]
        }
        SiteKind::Compose => {
            let mut argv = vec![
                "docker".to_string(),
                "compose".to_string(),
                "-f".to_string(),
                PathBuf::from(&plan.artifact_dir)
                    .join("compose.yaml")
                    .display()
                    .to_string(),
            ];
            if let Some(project_name) = plan.compose_project.as_deref() {
                argv.push("-p".to_string());
                argv.push(project_name.to_string());
            }
            argv.push("up".to_string());
            argv.push("-d".to_string());
            vec![LaunchCommandPreview {
                argv,
                env: plan.launch_env.clone(),
                current_dir: Some(plan.artifact_dir.clone()),
            }]
        }
        SiteKind::Kubernetes => {
            let mut commands = Vec::new();
            if let Some(namespace) = plan.kubernetes_namespace.as_deref() {
                let mut get_ns = kubectl_preview(plan.context.as_deref());
                get_ns.extend([
                    "get".to_string(),
                    "namespace".to_string(),
                    namespace.to_string(),
                    "-o".to_string(),
                    "json".to_string(),
                ]);
                commands.push(LaunchCommandPreview {
                    argv: get_ns,
                    env: BTreeMap::new(),
                    current_dir: None,
                });

                let mut create_ns = kubectl_preview(plan.context.as_deref());
                create_ns.extend([
                    "create".to_string(),
                    "namespace".to_string(),
                    namespace.to_string(),
                ]);
                commands.push(LaunchCommandPreview {
                    argv: create_ns,
                    env: BTreeMap::new(),
                    current_dir: None,
                });
            }

            let mut apply = kubectl_preview(plan.context.as_deref());
            apply.extend(["apply".to_string(), "-k".to_string(), ".".to_string()]);
            commands.push(LaunchCommandPreview {
                argv: apply,
                env: BTreeMap::new(),
                current_dir: Some(plan.artifact_dir.clone()),
            });

            if let (Some(namespace), Some(mesh_port), Some(control_port)) = (
                plan.kubernetes_namespace.as_deref(),
                plan.port_forward_mesh_port,
                plan.port_forward_control_port,
            ) {
                let mut port_forward = kubectl_preview(plan.context.as_deref());
                port_forward.extend([
                    "-n".to_string(),
                    namespace.to_string(),
                    "port-forward".to_string(),
                    "--address".to_string(),
                    "0.0.0.0".to_string(),
                    "deploy/amber-router".to_string(),
                    format!("{mesh_port}:24000"),
                    format!("{control_port}:24100"),
                ]);
                commands.push(LaunchCommandPreview {
                    argv: port_forward,
                    env: BTreeMap::new(),
                    current_dir: None,
                });
            }

            commands
        }
    };
    commands.extend(site_commands);
    Ok(commands)
}

pub(super) fn observability_launch_commands(
    observability: &MaterializedObservability,
) -> Result<Vec<LaunchCommandPreview>> {
    let Some(plan_path) = observability.plan_path.as_ref() else {
        return Ok(Vec::new());
    };
    let exe = super::amber_cli_executable()?;
    Ok(vec![LaunchCommandPreview {
        argv: vec![
            exe.display().to_string(),
            "run-observability-sink".to_string(),
            "--plan".to_string(),
            plan_path.display().to_string(),
        ],
        env: BTreeMap::new(),
        current_dir: Some(
            plan_path
                .parent()
                .and_then(Path::parent)
                .unwrap_or_else(|| Path::new("."))
                .display()
                .to_string(),
        ),
    }])
}

pub(super) fn kubectl_preview(context: Option<&str>) -> Vec<String> {
    let mut argv = vec!["kubectl".to_string()];
    if let Some(context) = context {
        argv.push("--context".to_string());
        argv.push(context.to_string());
    }
    argv
}

pub(super) fn materialize_observability(
    run_root: &Path,
    run_id: &str,
    mesh_scope: &str,
    observability: Option<&str>,
) -> Result<Option<MaterializedObservability>> {
    let Some(observability) = observability
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    if observability == "local" {
        let listen_port = reserve_loopback_port()?;
        let listen_addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
        let advertise_endpoint = format!("http://127.0.0.1:{listen_port}");
        let requests_log = run_root.join("observability").join("requests.log");
        let events_ndjson = run_root.join("observability").join("events.ndjson");
        let plan = ObservabilitySinkPlan {
            schema: OTLP_SINK_PLAN_SCHEMA.to_string(),
            version: OTLP_SINK_PLAN_VERSION,
            run_id: run_id.to_string(),
            mesh_scope: mesh_scope.to_string(),
            run_root: run_root.display().to_string(),
            listen_addr: listen_addr.to_string(),
            advertise_endpoint: advertise_endpoint.clone(),
            requests_log: requests_log.display().to_string(),
            events_ndjson: events_ndjson.display().to_string(),
        };
        let plan_path = observability_plan_path(run_root);
        write_json(&plan_path, &plan)?;
        return Ok(Some(MaterializedObservability {
            receipt: ObservabilityReceipt {
                endpoint: advertise_endpoint,
                sink_pid: None,
                requests_log: Some(requests_log.display().to_string()),
                events_ndjson: Some(events_ndjson.display().to_string()),
            },
            plan_path: Some(plan_path),
        }));
    }

    Ok(Some(MaterializedObservability {
        receipt: ObservabilityReceipt {
            endpoint: observability.to_string(),
            sink_pid: None,
            requests_log: None,
            events_ndjson: None,
        },
        plan_path: None,
    }))
}

pub(super) async fn start_materialized_observability(
    run_root: &Path,
    observability: Option<&MaterializedObservability>,
) -> Result<Option<ObservabilityReceipt>> {
    let Some(observability) = observability else {
        return Ok(None);
    };
    let Some(plan_path) = observability.plan_path.as_ref() else {
        return Ok(Some(observability.receipt.clone()));
    };

    let mut child = spawn_detached_child(
        run_root,
        &run_root.join("observability").join("sink.log"),
        |cmd| {
            cmd.arg("run-observability-sink")
                .arg("--plan")
                .arg(plan_path);
        },
    )?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().into_diagnostic()? {
            return Err(miette::miette!(
                "observability sink exited before becoming ready with status {status}"
            ));
        }
        if observability_state_path(run_root).is_file() {
            let mut receipt = observability.receipt.clone();
            receipt.sink_pid = Some(child.id());
            return Ok(Some(receipt));
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(miette::miette!("timed out waiting for observability sink"))
}

pub(super) fn prepare_site_launch(
    site: &MaterializedSite,
    runtime_env: &BTreeMap<String, String>,
    external_env: &BTreeMap<String, String>,
) -> Result<()> {
    let artifact_env = merge_env_maps(runtime_env, external_env);
    patch_site_artifacts(
        &site.artifact_dir,
        &site.base_supervisor_plan.run_id,
        &site.base_supervisor_plan.site_id,
        site.site_plan.site.kind,
        &artifact_env,
        site.base_supervisor_plan.observability_endpoint.as_deref(),
    )?;
    let mut supervisor_plan = site.base_supervisor_plan.clone();
    supervisor_plan.launch_env.extend(
        external_env
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    write_json(
        &site_supervisor_plan_path(&site.site_state_root),
        &supervisor_plan,
    )?;
    write_json(
        &desired_links_path(&site.site_state_root),
        &DesiredLinkState {
            schema: DESIRED_LINKS_SCHEMA.to_string(),
            version: DESIRED_LINKS_VERSION,
            external_slots: external_env
                .iter()
                .filter_map(|(env_var, url)| {
                    env_var
                        .strip_prefix("AMBER_EXTERNAL_SLOT_")
                        .map(|_| (env_var.clone(), url.clone()))
                })
                .collect(),
            export_peers: Vec::new(),
            external_slot_overlays: BTreeMap::new(),
            export_peer_overlays: BTreeMap::new(),
        },
    )
}

pub(crate) async fn run_run_plan(
    source_plan_path: Option<&Path>,
    run_plan: &RunPlan,
    storage_root_override: Option<&Path>,
    observability: Option<&str>,
    site_launch_env: &BTreeMap<String, String>,
) -> Result<RunReceipt> {
    let run_id = new_run_id();
    run_run_plan_with_id(
        source_plan_path,
        run_plan,
        storage_root_override,
        observability,
        &run_id,
        site_launch_env,
    )
    .await
}

pub(crate) async fn run_run_plan_with_id(
    source_plan_path: Option<&Path>,
    run_plan: &RunPlan,
    storage_root_override: Option<&Path>,
    observability: Option<&str>,
    run_id: &str,
    site_launch_env: &BTreeMap<String, String>,
) -> Result<RunReceipt> {
    let storage_root = mixed_run_storage_root(storage_root_override)?;
    let run_root = storage_root.join("runs").join(run_id);
    let sites_root = run_root.join("sites");
    let state_root = run_root.join("state");
    fs::create_dir_all(&sites_root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create run directory {}", sites_root.display()))?;
    fs::create_dir_all(&state_root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create state directory {}", state_root.display()))?;
    let _coordinator_lock = hold_coordinator_lock(&run_root)?;

    let launch_bundle = materialize_launch_bundle(
        source_plan_path,
        run_plan,
        &run_root,
        run_id,
        observability,
        site_launch_env,
    )?;
    let observability_receipt =
        start_materialized_observability(&run_root, launch_bundle.observability.as_ref()).await?;
    init_manager_telemetry(
        &format!("/run/{run_id}/coordinator"),
        &run_plan.mesh_scope,
        observability_receipt
            .as_ref()
            .map(|value| value.endpoint.as_str()),
    );
    emit_manager_event(
        "amber.run.starting",
        format!("starting mixed-site run {run_id}"),
        &[
            ("amber.run_id", run_id.to_string()),
            ("amber.mesh_scope", run_plan.mesh_scope.clone()),
        ],
    );

    let mut launched_by_site = BTreeMap::<String, LaunchedSite>::new();
    let mut started_site_receipts = BTreeMap::<String, SiteReceipt>::new();
    let mut supervisor_children = BTreeMap::<String, SupervisorChild>::new();
    let mut bridge_proxies = BTreeMap::<BridgeProxyKey, BridgeProxyHandle>::new();
    let test_wave_delay = test_wave_delay()?;

    let result = async {
        for wave in &run_plan.startup_waves {
            for site_id in wave {
                let site = launch_bundle
                    .sites
                    .get(site_id)
                    .ok_or_else(|| miette::miette!("launch bundle is missing site `{site_id}`"))?;
                let external_env = external_slot_env_for_site(
                    site_id,
                    site.site_plan.site.kind,
                    &run_plan.links,
                    &launched_by_site,
                )?;
                prepare_site_launch(site, site_launch_env, &external_env)?;

                let mut supervisor = spawn_site_supervisor(&site.site_state_root)?;
                let launched = wait_for_site_ready(
                    site_id,
                    &site.site_plan,
                    &site.site_state_root,
                    &mut supervisor,
                    &run_plan.mesh_scope,
                )
                .await?;

                let mut launched = launched;
                launched.receipt.supervisor_pid = supervisor.child.id();
                supervisor_children.insert(site_id.clone(), supervisor);

                register_new_site_links(
                    site_id,
                    &run_plan.links,
                    &mut launched,
                    &launched_by_site,
                    &run_root,
                    &state_root,
                    &mut bridge_proxies,
                )
                .await?;

                persist_site_state(
                    &state_root,
                    site_id,
                    &launched,
                    SiteLifecycleStatus::Running,
                    None,
                )?;
                started_site_receipts.insert(site_id.clone(), launched.receipt.clone());
                launched_by_site.insert(site_id.clone(), launched);
            }
            if let Some(delay) = test_wave_delay {
                sleep(delay).await;
            }
        }
        write_commit_marker(&run_root)?;
        emit_manager_event(
            "amber.run.committed",
            format!("committed mixed-site run {run_id}"),
            &[("amber.run_id", run_id.to_string())],
        );

        let receipt = RunReceipt {
            schema: RECEIPT_SCHEMA.to_string(),
            version: RECEIPT_VERSION,
            run_id: run_id.to_string(),
            mesh_scope: run_plan.mesh_scope.clone(),
            plan_path: launch_bundle.run_plan_path.display().to_string(),
            source_plan_path: source_plan_path.map(|path| path.display().to_string()),
            run_root: run_root.display().to_string(),
            observability: observability_receipt.clone(),
            bridge_proxies: bridge_proxies
                .values()
                .map(|proxy| BridgeProxyReceipt {
                    export_name: proxy.export_name.clone(),
                    pid: proxy.child.id(),
                    listen: proxy.listen.to_string(),
                })
                .collect(),
            sites: launched_by_site
                .into_iter()
                .map(|(site_id, launched)| (site_id, launched.receipt))
                .collect(),
        };
        write_json(&receipt_path(&run_root), &receipt)?;
        Ok(receipt)
    }
    .await;

    if result.is_err() {
        let _ = write_stop_marker(&run_root);
        for bridge in bridge_proxies.values_mut() {
            send_sigterm(bridge.child.id());
        }
        for supervisor in supervisor_children.values_mut() {
            send_sigterm(supervisor.child.id());
        }
        for bridge in bridge_proxies.values_mut() {
            let _ = wait_for_child_exit(&mut bridge.child, PROCESS_SHUTDOWN_GRACE_PERIOD).await;
        }
        for supervisor in supervisor_children.values_mut() {
            let _ = wait_for_child_exit(&mut supervisor.child, PROCESS_SHUTDOWN_GRACE_PERIOD).await;
        }
        for (site_id, receipt) in &started_site_receipts {
            let state_path = site_state_path(&state_root, site_id);
            let already_terminal = read_json::<SiteManagerState>(&state_path, "site manager state")
                .ok()
                .is_some_and(|state| {
                    matches!(
                        state.status,
                        SiteLifecycleStatus::Stopped | SiteLifecycleStatus::Failed
                    )
                });
            if already_terminal {
                continue;
            }
            let _ = stop_site_from_receipt(&run_root, site_id, receipt).await;
            let _ = write_site_state(
                &state_path,
                SiteManagerState {
                    schema: SITE_STATE_SCHEMA.to_string(),
                    version: SITE_STATE_VERSION,
                    run_id: run_id.to_string(),
                    site_id: site_id.clone(),
                    kind: receipt.kind,
                    status: SiteLifecycleStatus::Stopped,
                    artifact_dir: receipt.artifact_dir.clone(),
                    supervisor_pid: receipt.supervisor_pid,
                    process_pid: None,
                    compose_project: receipt.compose_project.clone(),
                    kubernetes_namespace: receipt.kubernetes_namespace.clone(),
                    port_forward_pid: None,
                    context: receipt.context.clone(),
                    router_control: receipt.router_control.clone(),
                    router_mesh_addr: receipt.router_mesh_addr.clone(),
                    router_identity_id: receipt.router_identity_id.clone(),
                    router_public_key_b64: receipt.router_public_key_b64.clone(),
                    site_controller_pid: receipt.site_controller_pid,
                    site_controller_url: receipt.site_controller_url.clone(),
                    last_error: Some("coordinator cleanup after failed startup".to_string()),
                },
            );
        }
        if let Some(pid) = observability_receipt
            .as_ref()
            .and_then(|value| value.sink_pid)
        {
            send_sigterm(pid);
        }
    }

    result
}

pub(crate) async fn stop_run(run_id: &str, storage_root_override: Option<&Path>) -> Result<()> {
    let storage_root = mixed_run_storage_root(storage_root_override)?;
    let run_root = storage_root.join("runs").join(run_id);
    let receipt: RunReceipt = read_json(&receipt_path(&run_root), "run receipt")?;
    let supervisor_stop_timeout = site_supervisor_stop_timeout();
    let forced_supervisor_exit_grace_period = forced_supervisor_exit_grace_period();
    write_stop_marker(&run_root)?;
    for site in receipt.sites.values() {
        send_sigterm(site.supervisor_pid);
    }

    let mut shutdown_failures = Vec::new();
    for (site_id, site) in &receipt.sites {
        let state_path = site_state_path(&run_root.join("state"), site_id);
        write_site_state(
            &state_path,
            site_state_from_receipt(&receipt, site_id, site, SiteLifecycleStatus::Stopping, None),
        )?;
        match wait_for_site_supervisor_stop(
            &state_path,
            site.supervisor_pid,
            supervisor_stop_timeout,
        )
        .await?
        {
            SiteSupervisorStopStatus::Graceful { shutdown_failed } => {
                if shutdown_failed {
                    finalize_site_stop_via_orphan_cleanup(
                        &run_root,
                        &state_path,
                        &receipt,
                        site_id,
                        site,
                        format!(
                            "site supervisor `{site_id}` reported failed shutdown; orphan cleanup \
                             completed"
                        ),
                    )
                    .await?;
                }
            }
            SiteSupervisorStopStatus::Exited => {
                finalize_site_stop_via_orphan_cleanup(
                    &run_root,
                    &state_path,
                    &receipt,
                    site_id,
                    site,
                    format!(
                        "site supervisor `{site_id}` exited before confirming stop; orphan \
                         cleanup completed"
                    ),
                )
                .await?;
            }
            SiteSupervisorStopStatus::TimedOut => {
                let message = format!(
                    "site supervisor `{site_id}` (pid {}) did not stop within {}s; forcing \
                     shutdown",
                    site.supervisor_pid,
                    supervisor_stop_timeout.as_secs()
                );
                #[cfg(unix)]
                send_sigkill(site.supervisor_pid);
                #[cfg(not(unix))]
                send_sigterm(site.supervisor_pid);

                if !wait_for_pid_exit(site.supervisor_pid, forced_supervisor_exit_grace_period)
                    .await
                {
                    shutdown_failures.push(format!(
                        "site supervisor `{site_id}` (pid {}) did not exit after forced shutdown",
                        site.supervisor_pid
                    ));
                    continue;
                }

                finalize_site_stop_via_orphan_cleanup(
                    &run_root,
                    &state_path,
                    &receipt,
                    site_id,
                    site,
                    message,
                )
                .await?;
            }
        }
    }

    if let Some(observability) = receipt.observability.as_ref()
        && let Some(pid) = observability.sink_pid
    {
        send_sigterm(pid);
    }
    if let Some(observability) = receipt.observability.as_ref()
        && let Some(pid) = observability.sink_pid
        && !wait_for_pid_exit(pid, PROCESS_SHUTDOWN_GRACE_PERIOD).await
    {
        shutdown_failures.push(format!(
            "observability sink (pid {pid}) did not stop within {}s",
            PROCESS_SHUTDOWN_GRACE_PERIOD.as_secs()
        ));
    }
    for proxy in &receipt.bridge_proxies {
        send_sigterm(proxy.pid);
    }
    for proxy in &receipt.bridge_proxies {
        if !wait_for_pid_exit(proxy.pid, PROCESS_SHUTDOWN_GRACE_PERIOD).await {
            shutdown_failures.push(format!(
                "bridge proxy `{}` (pid {}) did not stop within {}s",
                proxy.export_name,
                proxy.pid,
                PROCESS_SHUTDOWN_GRACE_PERIOD.as_secs()
            ));
        }
    }

    if !shutdown_failures.is_empty() {
        return Err(miette::miette!(
            "mixed run `{run_id}` did not stop completely:\n{}",
            shutdown_failures.join("\n")
        ));
    }

    let _ = fs::remove_file(receipt_path(&run_root));
    Ok(())
}
