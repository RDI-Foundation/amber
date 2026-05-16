use super::*;

pub(super) fn site_controller_image_reference_from_overrides(
    overrides: &BTreeMap<String, String>,
) -> String {
    overrides
        .get("site_controller")
        .map(|tag| amber_images::override_reference(&amber_images::AMBER_SITE_CONTROLLER, tag))
        .unwrap_or_else(|| amber_images::AMBER_SITE_CONTROLLER.reference.to_string())
}

pub(crate) fn site_controller_image_reference() -> Result<String> {
    let overrides =
        amber_images::parse_dev_image_tag_overrides(amber_images::INTERNAL_IMAGE_OVERRIDE_KEYS)
            .map_err(|err| miette::miette!(err))?;
    Ok(site_controller_image_reference_from_overrides(&overrides))
}

pub(crate) fn site_controller_local_router_control(kind: SiteKind, artifact_dir: &Path) -> String {
    match kind {
        SiteKind::Direct => format!(
            "unix://{}",
            direct_current_control_socket_path(artifact_dir).display()
        ),
        SiteKind::Vm => format!(
            "unix://{}",
            vm_current_control_socket_path(artifact_dir).display()
        ),
        SiteKind::Compose => "unix:///amber/control/router-control.sock".to_string(),
        SiteKind::Kubernetes => "amber-router:24100".to_string(),
    }
}

pub(crate) fn site_controller_component_port(site_plan: &RunSitePlan) -> Result<Option<u16>> {
    let scenario =
        amber_scenario::Scenario::try_from(site_plan.scenario_ir.clone()).map_err(|err| {
            miette::miette!(
                "failed to parse site scenario for router `{}`: {err}",
                site_plan.router_identity_id
            )
        })?;
    let mut controller_ports = Vec::new();
    for (_, component) in scenario.components_iter() {
        if amber_compiler::run_plan::framework_component_controller_metadata(
            component.metadata.as_ref(),
        )
        .is_none()
        {
            continue;
        }
        let port = component
            .program
            .as_ref()
            .and_then(|program| program.network())
            .and_then(|network| network.endpoints.first())
            .map(|endpoint| endpoint.port)
            .ok_or_else(|| {
                miette::miette!(
                    "synthetic framework.component controller `{}` on site `{}` is missing its \
                     endpoint",
                    component.moniker,
                    site_plan.router_identity_id
                )
            })?;
        controller_ports.push((component.moniker.clone(), port));
    }
    match controller_ports.as_slice() {
        [] => Ok(None),
        [(_, port)] => Ok(Some(*port)),
        _ => Err(miette::miette!(
            "site `{}` has multiple synthetic framework.component controllers: {}",
            site_plan.router_identity_id,
            controller_ports
                .iter()
                .map(|(moniker, _)| moniker.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

pub(crate) fn site_controller_identity_path(
    kind: SiteKind,
    artifact_dir: &Path,
    runtime_root: Option<&str>,
) -> Result<Option<String>> {
    match kind {
        SiteKind::Compose | SiteKind::Kubernetes => Ok(Some(
            amber_site_controller::SITE_CONTROLLER_MESH_IDENTITY_PATH.to_string(),
        )),
        SiteKind::Direct => {
            let Some(runtime_root) = runtime_root else {
                return Ok(None);
            };
            let direct_plan_path =
                artifact_dir.join(amber_compiler::reporter::direct::DIRECT_PLAN_FILENAME);
            let direct_plan: amber_compiler::reporter::direct::DirectPlan =
                read_json(&direct_plan_path, "direct plan")?;
            let controller = direct_plan
                .components
                .iter()
                .find(|component| {
                    matches!(
                        component.program.execution,
                        amber_compiler::reporter::direct::DirectProgramExecutionPlan::InternalSiteController
                    )
                })
                .ok_or_else(|| {
                    miette::miette!(
                        "direct site controller plan is missing its internal site controller \
                         component"
                    )
                })?;
            Ok(Some(
                Path::new(runtime_root)
                    .join(&controller.sidecar.mesh_identity_path)
                    .display()
                    .to_string(),
            ))
        }
        SiteKind::Vm => Ok(None),
    }
}

pub(crate) fn prepare_site_state_root(site_state_root: &Path, kind: SiteKind) -> Result<()> {
    fs::create_dir_all(site_state_root)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create site state directory {}",
                site_state_root.display()
            )
        })?;

    #[cfg(unix)]
    if kind == SiteKind::Compose {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = fs::metadata(site_state_root)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to read permissions for site state directory {}",
                    site_state_root.display()
                )
            })?
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(site_state_root, permissions)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to restrict compose site state directory {}",
                    site_state_root.display()
                )
            })?;
    }

    Ok(())
}

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
    let site_controller_image = site_controller_image_reference()?;

    let observability =
        materialize_observability(bundle_root, run_id, &run_plan.mesh_scope, observability)?;
    let observability_endpoint = observability
        .as_ref()
        .map(|materialized| materialized.receipt.endpoint.as_str());

    let mut sites = BTreeMap::new();
    for (site_index, (site_id, site_plan)) in run_plan.sites.iter().enumerate() {
        let artifact_dir = materialize_site_artifacts(&sites_root, site_id, site_plan)?;
        amber_site_controller::set_site_artifact_mesh_identity_seed(&artifact_dir, run_id)?;
        let site_state_root = state_root.join(site_id);
        prepare_site_state_root(&site_state_root, site_plan.site.kind)?;
        let controller = site_controller_component_port(site_plan)?.map(|controller_port| {
            let listen_addr = match site_plan.site.kind {
                SiteKind::Direct | SiteKind::Vm => {
                    host_service_bind_addr_for_consumer(site_plan.site.kind, controller_port)
                }
                SiteKind::Compose | SiteKind::Kubernetes => {
                    SocketAddr::from(([0, 0, 0, 0], controller_port))
                }
            };
            let url = match site_plan.site.kind {
                SiteKind::Direct | SiteKind::Vm => {
                    amber_site_controller::authority_url_for_listen_addr(listen_addr)
                }
                SiteKind::Compose | SiteKind::Kubernetes => format!(
                    "http://{}:{}",
                    amber_site_controller::SITE_CONTROLLER_SERVICE_NAME,
                    controller_port
                ),
            };
            MaterializedSiteController {
                state_path: site_state_root.join("site-controller-state.json"),
                plan_path: site_controller_plan_path(&site_state_root),
                listen_addr,
                url,
            }
        });
        let framework_env = BTreeMap::new();
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
                site_controller_url: controller
                    .as_ref()
                    .map(|controller| controller.url.as_str()),
            },
            launch_env.clone(),
        )?;
        if site_plan.site.kind == SiteKind::Compose
            && let Some(router_mesh_port) = base_supervisor_plan.router_mesh_port
        {
            amber_site_controller::set_compose_router_published_mesh_port(
                &artifact_dir,
                router_mesh_port,
            )?;
        }
        if let Some(controller) = &controller {
            let controller_state = amber_site_controller::build_site_controller_state(
                run_id,
                run_plan,
                site_id,
                site_index,
                run_plan.sites.len(),
            )?;
            amber_site_controller::write_control_state(&controller.state_path, &controller_state)?;
        }
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
                controller,
                base_supervisor_plan,
            },
        );
    }

    let planned_router_mesh_addrs = sites
        .iter()
        .map(|(site_id, site)| {
            Ok((
                site_id.clone(),
                planned_router_mesh_addr(&site.base_supervisor_plan)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let controller_sites = sites
        .iter()
        .filter(|(_, site)| site.controller.is_some())
        .map(|(site_id, site)| {
            (
                site_id.clone(),
                site.site_plan.router_identity_id.clone(),
                site.site_plan.site.kind,
            )
        })
        .collect::<Vec<_>>();

    for (site_id, site) in &mut sites {
        if let Some(controller) = &site.controller {
            let allowed_issuers = controller_sites
                .iter()
                .filter(|(peer_site_id, _, _)| peer_site_id != site_id)
                .map(|(_, router_identity_id, _)| router_identity_id.clone())
                .collect::<Vec<_>>();
            let route_listen_addr =
                site_controller_route_listen_addr(site.site_plan.site.kind).to_string();
            let mut peer_site_router_urls = BTreeMap::new();
            let mut peer_router_identities = BTreeMap::new();
            let mut peer_router_mesh_addrs = BTreeMap::new();
            let mut controller_routes = Vec::new();
            for (peer_site_id, peer_router_identity_id, peer_site_kind) in &controller_sites {
                if peer_site_id == site_id {
                    continue;
                }
                let route_port = reserve_loopback_port()?;
                peer_site_router_urls.insert(
                    peer_site_id.clone(),
                    amber_site_controller::site_controller_peer_router_url(
                        site.site_plan.site.kind,
                        route_port,
                    ),
                );
                peer_router_identities.insert(
                    peer_site_id.clone(),
                    planned_router_identity(run_id, &run_plan.mesh_scope, peer_router_identity_id),
                );
                let peer_router_mesh_addr = planned_router_mesh_addrs
                    .get(peer_site_id)
                    .expect("planned router mesh addr should exist for every site");
                peer_router_mesh_addrs.insert(peer_site_id.clone(), peer_router_mesh_addr.clone());
                let peer_addr = amber_site_controller::router_mesh_addr_for_consumer(
                    *peer_site_kind,
                    site.site_plan.site.kind,
                    peer_router_mesh_addr,
                )?;
                controller_routes.push(amber_site_controller::SiteControllerPeerRouterRoute {
                    site_id: peer_site_id.clone(),
                    peer_router: planned_router_identity(
                        run_id,
                        &run_plan.mesh_scope,
                        peer_router_identity_id,
                    ),
                    peer_addr,
                    listen_addr: route_listen_addr.clone(),
                    listen_port: route_port,
                });
            }

            write_json(
                &site_existing_peer_ports_path(&site.site_state_root),
                &peer_router_ports_by_identity(&peer_router_identities, &peer_router_mesh_addrs)?,
            )?;
            write_json(
                &site_existing_peer_identities_path(&site.site_state_root),
                &peer_router_identities_by_id(&peer_router_identities),
            )?;

            amber_site_controller::inject_site_controller_peer_router_routes(
                &site.artifact_dir,
                site_id,
                &allowed_issuers,
                &controller_routes,
            )?;
            let local_router_control =
                site_controller_local_router_control(site.site_plan.site.kind, &site.artifact_dir);
            let published_router_mesh_addr =
                planned_router_mesh_addrs.get(site_id).map(String::as_str);
            let compose_consumer_router_mesh_addr = published_router_mesh_addr
                .map(|addr| {
                    amber_site_controller::router_mesh_addr_for_consumer(
                        site.site_plan.site.kind,
                        SiteKind::Compose,
                        addr,
                    )
                })
                .transpose()?;
            let kubernetes_consumer_router_mesh_addr = published_router_mesh_addr
                .map(|addr| {
                    amber_site_controller::router_mesh_addr_for_consumer(
                        site.site_plan.site.kind,
                        SiteKind::Kubernetes,
                        addr,
                    )
                })
                .transpose()?;

            amber_site_controller::write_site_controller_plan(
                &controller.plan_path,
                run_id,
                &run_plan.mesh_scope,
                site_id,
                site.site_plan.site.kind,
                controller.listen_addr,
                &controller.url,
                &site.site_plan.router_identity_id,
                &peer_site_router_urls,
                &peer_router_identities,
                &peer_router_mesh_addrs,
                Some(local_router_control.as_str()),
                published_router_mesh_addr,
                compose_consumer_router_mesh_addr.as_deref(),
                kubernetes_consumer_router_mesh_addr.as_deref(),
                &controller.state_path,
                bundle_root,
                &state_root,
                &site.site_state_root,
                &site.artifact_dir,
                site_controller_identity_path(
                    site.site_plan.site.kind,
                    &site.artifact_dir,
                    site.base_supervisor_plan.runtime_root.as_deref(),
                )?
                .as_deref(),
                site.base_supervisor_plan.storage_root.as_deref(),
                site.base_supervisor_plan.runtime_root.as_deref(),
                site.base_supervisor_plan.router_mesh_port,
                site.base_supervisor_plan.compose_project.as_deref(),
                site.base_supervisor_plan.kubernetes_namespace.as_deref(),
                site.base_supervisor_plan.context.as_deref(),
                site.base_supervisor_plan.observability_endpoint.as_deref(),
                &site.base_supervisor_plan.launch_env,
            )?;
            match site.site_plan.site.kind {
                SiteKind::Compose => amber_site_controller::inject_compose_site_controller(
                    &site.artifact_dir,
                    &read_json(&controller.plan_path, "site controller plan")?,
                    &controller.plan_path,
                    site_controller_image.as_str(),
                )?,
                SiteKind::Kubernetes => amber_site_controller::inject_kubernetes_site_controller(
                    &site.artifact_dir,
                    &read_json(&controller.plan_path, "site controller plan")?,
                    site_controller_image.as_str(),
                )?,
                SiteKind::Direct | SiteKind::Vm => {}
            }
        }
        write_json(
            &site_supervisor_plan_path(&site.site_state_root),
            &site.base_supervisor_plan,
        )?;
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

fn planned_router_mesh_addr(plan: &SiteSupervisorPlan) -> Result<String> {
    match plan.kind {
        SiteKind::Direct | SiteKind::Vm | SiteKind::Compose => plan
            .router_mesh_port
            .map(|port| format!("127.0.0.1:{port}"))
            .ok_or_else(|| {
                miette::miette!("site `{}` is missing its router mesh port", plan.site_id)
            }),
        SiteKind::Kubernetes => plan
            .port_forward_mesh_port
            .map(|port| format!("127.0.0.1:{port}"))
            .ok_or_else(|| {
                miette::miette!(
                    "site `{}` is missing its kubernetes router mesh forward port",
                    plan.site_id
                )
            }),
    }
}

fn site_controller_route_listen_addr(kind: SiteKind) -> &'static str {
    match kind {
        SiteKind::Direct | SiteKind::Vm => "127.0.0.1",
        SiteKind::Compose | SiteKind::Kubernetes => "0.0.0.0",
    }
}

fn planned_router_identity(
    identity_seed: &str,
    mesh_scope: &str,
    router_identity_id: &str,
) -> amber_mesh::MeshIdentityPublic {
    amber_mesh::MeshIdentityPublic::from_identity(&amber_mesh::MeshIdentity::derive(
        router_identity_id,
        Some(mesh_scope.to_string()),
        identity_seed,
    ))
}

fn peer_router_ports_by_identity(
    peer_router_identities: &BTreeMap<String, amber_mesh::MeshIdentityPublic>,
    peer_router_mesh_addrs: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, u16>> {
    peer_router_identities
        .iter()
        .map(|(site_id, identity)| {
            let addr = peer_router_mesh_addrs.get(site_id).ok_or_else(|| {
                miette::miette!("missing planned router mesh address for peer site `{site_id}`")
            })?;
            let port = addr
                .parse::<SocketAddr>()
                .into_diagnostic()
                .wrap_err_with(|| format!("invalid planned router mesh address `{addr}`"))?
                .port();
            Ok((identity.id.clone(), port))
        })
        .collect()
}

fn peer_router_identities_by_id(
    peer_router_identities: &BTreeMap<String, amber_mesh::MeshIdentityPublic>,
) -> BTreeMap<String, amber_mesh::MeshIdentityPublic> {
    peer_router_identities
        .values()
        .cloned()
        .map(|identity| (identity.id.clone(), identity))
        .collect()
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
                inspectability_warnings: preview.inspectability_warnings,
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
        for supervisor in supervisor_children.values_mut() {
            send_sigterm(supervisor.child.id());
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
                    compose_consumer_router_mesh_addr: receipt
                        .compose_consumer_router_mesh_addr
                        .clone(),
                    kubernetes_consumer_router_mesh_addr: receipt
                        .kubernetes_consumer_router_mesh_addr
                        .clone(),
                    router_identity_id: receipt.router_identity_id.clone(),
                    router_public_key_b64: receipt.router_public_key_b64.clone(),
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

    if !shutdown_failures.is_empty() {
        return Err(miette::miette!(
            "mixed run `{run_id}` did not stop completely:\n{}",
            shutdown_failures.join("\n")
        ));
    }

    let _ = fs::remove_file(receipt_path(&run_root));
    Ok(())
}
