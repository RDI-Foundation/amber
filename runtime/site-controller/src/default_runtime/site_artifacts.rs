use super::*;

fn compose_component_mesh_peer_addr(
    artifact_root: &Path,
    component_id: &str,
    output: &MeshProvisionOutput,
    mesh_port: u16,
) -> Result<String> {
    let MeshProvisionOutput::Filesystem { dir } = output else {
        return Err(miette::miette!(
            "compose artifact {} component {} does not use filesystem mesh output",
            artifact_root.display(),
            component_id
        ));
    };
    let service_name = Path::new(dir)
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            miette::miette!(
                "compose artifact {} component {} has invalid mesh output dir {}",
                artifact_root.display(),
                component_id,
                dir
            )
        })?;
    Ok(format!("{service_name}:{mesh_port}"))
}

fn kubernetes_component_mesh_peer_addr(
    artifact_root: &Path,
    component_id: &str,
    output: &MeshProvisionOutput,
    mesh_port: u16,
) -> Result<String> {
    let MeshProvisionOutput::KubernetesSecret { name, .. } = output else {
        return Err(miette::miette!(
            "kubernetes artifact {} component {} does not use a kubernetes secret mesh output",
            artifact_root.display(),
            component_id
        ));
    };
    let service_name = name.strip_suffix("-mesh").ok_or_else(|| {
        miette::miette!(
            "kubernetes artifact {} component {} uses invalid mesh secret name {}",
            artifact_root.display(),
            component_id,
            name
        )
    })?;
    Ok(format!("{service_name}:{mesh_port}"))
}

fn build_dynamic_compose_route_overlay_payload(
    artifact_root: &Path,
    assigned_components: &[String],
    component_mesh_dirs: &BTreeMap<String, String>,
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
    routed_inputs: &[DynamicInputRouteRecord],
    existing_site_peer_identities: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<StoredRouteOverlayPayload> {
    let plan = read_embedded_compose_mesh_provision_plan(artifact_root)?;
    let assigned = assigned_components
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let kept_component_ids = plan
        .targets
        .iter()
        .filter(|target| {
            matches!(target.kind, MeshProvisionTargetKind::Component)
                && assigned.contains(target.config.identity.id.as_str())
        })
        .map(|target| target.config.identity.id.clone())
        .collect::<BTreeSet<_>>();
    let mut router_target = plan
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
        .cloned()
        .ok_or_else(|| {
            miette::miette!(
                "compose child artifact {} is missing a router mesh target",
                artifact_root.join("compose.yaml").display()
            )
        })?;
    filter_dynamic_router_target(&mut router_target, &kept_component_ids);
    let component_peer_addrs = plan
        .targets
        .iter()
        .filter(|target| matches!(target.kind, MeshProvisionTargetKind::Component))
        .map(|target| {
            Ok((
                target.config.identity.id.clone(),
                compose_component_mesh_peer_addr(
                    artifact_root,
                    &target.config.identity.id,
                    &target.output,
                    target.config.mesh_listen.port(),
                )?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    for route in &mut router_target.config.inbound {
        if let InboundTarget::MeshForward {
            peer_id, peer_addr, ..
        } = &mut route.target
            && let Some(resolved) = component_peer_addrs.get(peer_id)
        {
            *peer_addr = resolved.clone();
        }
    }

    let component_mesh_scopes = plan
        .targets
        .iter()
        .filter(|target| matches!(target.kind, MeshProvisionTargetKind::Component))
        .map(|target| {
            (
                target.config.identity.id.clone(),
                target.config.identity.mesh_scope.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut peer_identities = existing_site_peer_identities.clone();
    for (component, relative_dir) in component_mesh_dirs {
        let identity: MeshIdentitySecret = read_json(
            &artifact_root
                .join(relative_dir)
                .join(MESH_IDENTITY_FILENAME),
            "mesh identity",
        )?;
        peer_identities.insert(
            component.clone(),
            MeshIdentityPublic {
                id: identity.id.clone(),
                public_key: identity.public_key().into_diagnostic()?,
                mesh_scope: component_mesh_scopes.get(component).cloned().flatten(),
            },
        );
    }
    let peers = router_target
        .config
        .peers
        .iter()
        .map(|peer| {
            let identity = peer_identities.get(&peer.id).ok_or_else(|| {
                miette::miette!(
                    "compose child router overlay peer {} is missing a live mesh identity",
                    peer.id
                )
            })?;
            Ok(MeshPeer {
                id: identity.id.clone(),
                public_key: identity.public_key,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let allowed_issuers = overlay_issuer_sets(routed_inputs)?;
    let mut payload = StoredRouteOverlayPayload {
        peers,
        inbound_routes: router_target.config.inbound,
    };
    augment_route_overlay_payload(
        &mut payload,
        proxy_exports,
        routed_inputs,
        &component_peer_addrs,
        &peer_identities,
        Some(&allowed_issuers),
        false,
    )?;
    Ok(payload)
}

fn rewrite_compose_mesh_bind_mounts(
    artifact_root: &Path,
    mesh_dirs: &BTreeMap<String, String>,
) -> Result<()> {
    let compose_path = artifact_root.join("compose.yaml");
    let mut document = read_compose_document(&compose_path)?;
    let services = compose_services_mut(&mut document, &compose_path)?;
    for (service_name, relative_dir) in mesh_dirs {
        let service = services.get_mut(yaml_string(service_name)).ok_or_else(|| {
            miette::miette!(
                "compose file {} is missing child sidecar service {}",
                compose_path.display(),
                service_name
            )
        })?;
        let Some(service_mapping) = service.as_mapping_mut() else {
            return Err(miette::miette!(
                "compose service {} is not a mapping",
                service_name
            ));
        };
        let volumes_key = yaml_string("volumes");
        let volumes = service_mapping
            .get_mut(&volumes_key)
            .and_then(serde_yaml::Value::as_sequence_mut)
            .ok_or_else(|| {
                miette::miette!(
                    "compose child sidecar {} is missing a volumes list",
                    service_name
                )
            })?;
        let expected_prefix = format!("{service_name}-mesh:/amber/mesh");
        let replacement = serde_yaml::Value::String(format!("./{relative_dir}:/amber/mesh:ro"));
        let mut replaced = false;
        for volume in volumes.iter_mut() {
            if volume
                .as_str()
                .is_some_and(|value| value.starts_with(&expected_prefix))
            {
                *volume = replacement.clone();
                replaced = true;
            }
        }
        if !replaced {
            volumes.push(replacement);
        }
    }
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", compose_path.display()))?;
    fs::write(&compose_path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", compose_path.display()))
}

pub(super) fn load_dynamic_compose_child_metadata(
    artifact_root: &Path,
) -> Result<DynamicComposeChildMetadata> {
    read_json(
        &dynamic_compose_child_metadata_path(artifact_root),
        "dynamic compose child metadata",
    )
}

fn load_running_site_router_identity(
    plan: &SiteControllerRuntimePlan,
) -> Result<MeshIdentityPublic> {
    Ok(load_live_site_router_mesh_config(plan)?.identity)
}

fn filesystem_component_peer_identities_for_artifact(
    artifact_root: &Path,
    mesh_plan: &MeshProvisionPlan,
    artifact_kind: &str,
    compose_project: Option<&str>,
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let mut peers = BTreeMap::new();
    for target in &mesh_plan.targets {
        if !matches!(target.kind, MeshProvisionTargetKind::Component) {
            continue;
        }
        let MeshProvisionOutput::Filesystem { dir } = &target.output else {
            return Err(miette::miette!(
                "{artifact_kind} artifact {} has non-filesystem mesh output for component {}",
                artifact_root.display(),
                target.config.identity.id
            ));
        };
        let config: MeshConfigPublic = if Path::new(dir).is_absolute() {
            let compose_project = compose_project.ok_or_else(|| {
                miette::miette!(
                    "{artifact_kind} artifact {} uses absolute mesh output {} without a compose \
                     project",
                    artifact_root.display(),
                    dir
                )
            })?;
            let service_name = Path::new(dir)
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    miette::miette!(
                        "{artifact_kind} artifact {} has invalid absolute mesh output {}",
                        artifact_root.display(),
                        dir
                    )
                })?;
            read_compose_volume_mesh_config(compose_project, service_name)?
        } else {
            read_json(
                &artifact_root.join(dir).join(MESH_CONFIG_FILENAME),
                "mesh config",
            )?
        };
        peers.insert(config.identity.id.clone(), config.identity);
    }
    Ok(peers)
}

fn read_compose_volume_mesh_config(
    compose_project: &str,
    service_name: &str,
) -> Result<MeshConfigPublic> {
    let volume_name = format!("{compose_project}_{service_name}-mesh");
    let output = Command::new("docker")
        .arg("run")
        .arg("--rm")
        .arg("-v")
        .arg(format!("{volume_name}:/amber/mesh:ro"))
        .arg("busybox:1.36.1")
        .arg("cat")
        .arg(format!("/amber/mesh/{MESH_CONFIG_FILENAME}"))
        .output()
        .into_diagnostic()
        .wrap_err_with(|| {
            format!("failed to read compose mesh config from docker volume {volume_name}")
        })?;
    if !output.status.success() {
        return Err(miette::miette!(
            "failed to read compose mesh config from docker volume \
             {volume_name}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    serde_json::from_slice(&output.stdout)
        .into_diagnostic()
        .wrap_err_with(|| format!("docker volume {volume_name} returned invalid mesh config json"))
}

fn compose_peer_identities_for_artifact(
    artifact_root: &Path,
    compose_project: Option<&str>,
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let mesh_plan = if artifact_root.join("mesh-provision-plan.json").is_file() {
        read_json(
            &artifact_root.join("mesh-provision-plan.json"),
            "mesh provision plan",
        )?
    } else {
        read_embedded_compose_mesh_provision_plan(artifact_root)?
    };
    filesystem_component_peer_identities_for_artifact(
        artifact_root,
        &mesh_plan,
        "compose",
        compose_project,
    )
}

pub(super) fn local_compose_peer_identities(
    plan: &SiteControllerRuntimePlan,
    published_children: &[SiteControllerRuntimeChildRecord],
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let mut peers = BTreeMap::new();
    let router = load_running_site_router_identity(plan)?;
    peers.insert(router.id.clone(), router);
    peers.extend(compose_peer_identities_for_artifact(
        Path::new(&plan.artifact_dir),
        plan.compose_project.as_deref(),
    )?);
    for child in published_children {
        peers.extend(compose_peer_identities_for_artifact(
            Path::new(&child.artifact_root),
            plan.compose_project.as_deref(),
        )?);
    }
    Ok(peers)
}

fn kubernetes_peer_identities_for_artifact(
    plan: &SiteControllerRuntimePlan,
    artifact_root: &Path,
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let mesh_plan = read_embedded_kubernetes_mesh_provision_plan(artifact_root)?;
    let mut peers = BTreeMap::new();
    for target in &mesh_plan.targets {
        if !matches!(target.kind, MeshProvisionTargetKind::Component) {
            continue;
        }
        let MeshProvisionOutput::KubernetesSecret { name, namespace } = &target.output else {
            return Err(miette::miette!(
                "kubernetes artifact {} has non-secret mesh output for component {}",
                artifact_root.display(),
                target.config.identity.id
            ));
        };
        let config = load_kubernetes_mesh_config_public(plan, name, namespace.as_deref())?;
        peers.insert(config.identity.id.clone(), config.identity);
    }
    Ok(peers)
}

pub(super) fn local_kubernetes_peer_identities(
    plan: &SiteControllerRuntimePlan,
    published_children: &[SiteControllerRuntimeChildRecord],
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let mut peers = BTreeMap::new();
    let router = load_running_site_router_identity(plan)?;
    peers.insert(router.id.clone(), router);
    peers.extend(kubernetes_peer_identities_for_artifact(
        plan,
        Path::new(&plan.artifact_dir),
    )?);
    for child in published_children {
        peers.extend(kubernetes_peer_identities_for_artifact(
            plan,
            Path::new(&child.artifact_root),
        )?);
    }
    Ok(peers)
}

pub(crate) fn collect_live_component_runtime_metadata(
    plan: &SiteControllerRuntimePlan,
) -> Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
    let state_path = site_controller_runtime_state_path(Path::new(&plan.site_state_root));
    let published_children = if state_path.is_file() {
        let state: SiteControllerRuntimeState =
            read_json(&state_path, "site controller runtime state")?;
        state
            .children
            .values()
            .filter(|child| child.published)
            .cloned()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut components = match plan.kind {
        SiteKind::Direct => collect_direct_artifact_runtime_metadata(
            Path::new(&plan.artifact_dir),
            Path::new(plan.runtime_root.as_deref().ok_or_else(|| {
                miette::miette!("direct site `{}` is missing its runtime root", plan.site_id)
            })?),
        )?,
        SiteKind::Vm => collect_vm_artifact_runtime_metadata(
            Path::new(&plan.artifact_dir),
            Path::new(plan.runtime_root.as_deref().ok_or_else(|| {
                miette::miette!("vm site `{}` is missing its runtime root", plan.site_id)
            })?),
        )?,
        SiteKind::Compose => collect_compose_artifact_runtime_metadata(
            Path::new(&plan.artifact_dir),
            plan.compose_project.as_deref(),
        )?,
        SiteKind::Kubernetes => {
            collect_kubernetes_artifact_runtime_metadata(plan, Path::new(&plan.artifact_dir))?
        }
    };
    for child in &published_children {
        let child_components = match plan.kind {
            SiteKind::Direct => collect_direct_artifact_runtime_metadata(
                Path::new(&child.artifact_root),
                &site_controller_runtime_child_runtime_root(plan, child.child_id),
            )?,
            SiteKind::Vm => collect_vm_artifact_runtime_metadata(
                Path::new(&child.artifact_root),
                &site_controller_runtime_child_runtime_root(plan, child.child_id),
            )?,
            SiteKind::Compose => collect_compose_artifact_runtime_metadata(
                Path::new(&child.artifact_root),
                plan.compose_project.as_deref(),
            )?,
            SiteKind::Kubernetes => {
                collect_kubernetes_artifact_runtime_metadata(plan, Path::new(&child.artifact_root))?
            }
        };
        components.extend(child_components);
    }
    Ok(components)
}

pub(crate) fn load_live_site_router_mesh_config(
    plan: &SiteControllerRuntimePlan,
) -> Result<MeshConfigPublic> {
    let artifact_root = Path::new(&plan.artifact_dir);
    match plan.kind {
        SiteKind::Direct => {
            let runtime_root = Path::new(plan.runtime_root.as_deref().ok_or_else(|| {
                miette::miette!("direct site `{}` is missing its runtime root", plan.site_id)
            })?);
            let direct_plan: DirectPlan =
                read_json(&artifact_root.join("direct-plan.json"), "direct plan")?;
            let router = direct_plan.router.ok_or_else(|| {
                miette::miette!("direct site `{}` is missing its router plan", plan.site_id)
            })?;
            read_json(&runtime_root.join(&router.mesh_config_path), "mesh config")
        }
        SiteKind::Vm => {
            let runtime_root = Path::new(plan.runtime_root.as_deref().ok_or_else(|| {
                miette::miette!("vm site `{}` is missing its runtime root", plan.site_id)
            })?);
            let vm_plan: VmPlan = read_json(&artifact_root.join("vm-plan.json"), "vm plan")?;
            let router = vm_plan.router.ok_or_else(|| {
                miette::miette!("vm site `{}` is missing its router plan", plan.site_id)
            })?;
            read_json(&runtime_root.join(&router.mesh_config_path), "mesh config")
        }
        SiteKind::Compose => {
            let mesh_plan = if artifact_root.join("mesh-provision-plan.json").is_file() {
                read_json(
                    &artifact_root.join("mesh-provision-plan.json"),
                    "mesh provision plan",
                )?
            } else {
                read_embedded_compose_mesh_provision_plan(artifact_root)?
            };
            let target = mesh_plan
                .targets
                .iter()
                .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
                .ok_or_else(|| {
                    miette::miette!(
                        "compose site `{}` is missing a router mesh target",
                        plan.site_id
                    )
                })?;
            let MeshProvisionOutput::Filesystem { dir } = &target.output else {
                return Err(miette::miette!(
                    "compose site `{}` has non-filesystem mesh output for router {}",
                    plan.site_id,
                    target.config.identity.id
                ));
            };
            if Path::new(dir).is_absolute() {
                let compose_project = plan.compose_project.as_deref().ok_or_else(|| {
                    miette::miette!(
                        "compose site `{}` is missing its compose project",
                        plan.site_id
                    )
                })?;
                let service_name = Path::new(dir)
                    .file_name()
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| {
                        miette::miette!(
                            "compose site `{}` has invalid router mesh output {}",
                            plan.site_id,
                            dir
                        )
                    })?;
                read_compose_volume_mesh_config(compose_project, service_name)
            } else {
                read_json(
                    &artifact_root.join(dir).join(MESH_CONFIG_FILENAME),
                    "mesh config",
                )
            }
        }
        SiteKind::Kubernetes => {
            let mesh_plan = read_kubernetes_runtime_mesh_provision_plan(artifact_root)?;
            let target = mesh_plan
                .targets
                .iter()
                .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
                .ok_or_else(|| {
                    miette::miette!(
                        "kubernetes site `{}` is missing a router mesh target",
                        plan.site_id
                    )
                })?;
            let MeshProvisionOutput::KubernetesSecret { name, namespace } = &target.output else {
                return Err(miette::miette!(
                    "kubernetes site `{}` has non-secret mesh output for router {}",
                    plan.site_id,
                    target.config.identity.id
                ));
            };
            load_kubernetes_mesh_config_public(plan, name, namespace.as_deref())
        }
    }
}

fn collect_direct_artifact_runtime_metadata(
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
    let state: DirectRuntimeState = read_json(
        &direct_runtime_state_path(artifact_root),
        "direct runtime state",
    )?;
    let plan: DirectPlan = read_json(&artifact_root.join("direct-plan.json"), "direct plan")?;
    let mut components = BTreeMap::new();
    for component in &plan.components {
        let mesh_config: MeshConfigPublic = read_json(
            &runtime_root.join(&component.sidecar.mesh_config_path),
            "mesh config",
        )?;
        let mesh_port = state
            .component_mesh_port_by_id
            .get(&component.id)
            .copied()
            .ok_or_else(|| {
                miette::miette!(
                    "direct runtime state is missing mesh port for component {}",
                    component.moniker
                )
            })?;
        components.insert(
            component.moniker.clone(),
            LiveComponentRuntimeMetadata {
                moniker: component.moniker.clone(),
                host_mesh_addr: format!("127.0.0.1:{mesh_port}"),
                control_endpoint: Some(ControlEndpoint::Unix(
                    direct_component_control_socket_path(
                        runtime_root.join(&component.program.work_dir),
                        component.id,
                    ),
                )),
                mesh_config,
            },
        );
    }
    Ok(components)
}

fn collect_vm_artifact_runtime_metadata(
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
    let state = load_vm_runtime_state_for_artifact(artifact_root, runtime_root)?;
    let plan: VmPlan = read_json(&artifact_root.join("vm-plan.json"), "vm plan")?;
    let mut components = BTreeMap::new();
    for component in &plan.components {
        let mesh_config: MeshConfigPublic = read_json(
            &runtime_root.join(&component.mesh_config_path),
            "mesh config",
        )?;
        let mesh_port = state
            .component_mesh_port_by_id
            .get(&component.id)
            .copied()
            .ok_or_else(|| {
                miette::miette!(
                    "vm runtime state is missing mesh port for component {}",
                    component.moniker
                )
            })?;
        components.insert(
            component.moniker.clone(),
            LiveComponentRuntimeMetadata {
                moniker: component.moniker.clone(),
                host_mesh_addr: format!("127.0.0.1:{mesh_port}"),
                control_endpoint: Some(ControlEndpoint::Unix(vm_component_control_socket_path(
                    runtime_root
                        .join("work")
                        .join("sidecars")
                        .join(&component.log_name),
                    component.id,
                ))),
                mesh_config,
            },
        );
    }
    Ok(components)
}

fn direct_component_control_socket_path(work_dir: PathBuf, component_id: usize) -> PathBuf {
    amber_mesh::stable_temp_socket_path(
        "amber-direct-control",
        &format!("sidecar-{component_id}"),
        &work_dir,
    )
}

fn vm_component_control_socket_path(work_dir: PathBuf, component_id: usize) -> PathBuf {
    amber_mesh::stable_temp_socket_path(
        "amber-vm-control",
        &format!("sidecar-{component_id}"),
        &work_dir,
    )
}

fn collect_compose_artifact_runtime_metadata(
    artifact_root: &Path,
    compose_project: Option<&str>,
) -> Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
    let mesh_plan = if artifact_root.join("mesh-provision-plan.json").is_file() {
        read_json(
            &artifact_root.join("mesh-provision-plan.json"),
            "mesh provision plan",
        )?
    } else {
        read_embedded_compose_mesh_provision_plan(artifact_root)?
    };
    let mut components = BTreeMap::new();
    for target in &mesh_plan.targets {
        if !matches!(target.kind, MeshProvisionTargetKind::Component) {
            continue;
        }
        let MeshProvisionOutput::Filesystem { dir } = &target.output else {
            return Err(miette::miette!(
                "compose artifact {} has non-filesystem mesh output for component {}",
                artifact_root.display(),
                target.config.identity.id
            ));
        };
        let service_name = Path::new(dir)
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                miette::miette!(
                    "compose artifact {} has invalid mesh output {} for component {}",
                    artifact_root.display(),
                    dir,
                    target.config.identity.id
                )
            })?;
        let mesh_config = if Path::new(dir).is_absolute() {
            let compose_project = compose_project.ok_or_else(|| {
                miette::miette!(
                    "compose artifact {} requires a compose project to resolve mesh output {}",
                    artifact_root.display(),
                    dir
                )
            })?;
            read_compose_volume_mesh_config(compose_project, service_name)?
        } else {
            read_json(
                &artifact_root.join(dir).join(MESH_CONFIG_FILENAME),
                "mesh config",
            )?
        };
        components.insert(
            target.config.identity.id.clone(),
            LiveComponentRuntimeMetadata {
                moniker: target.config.identity.id.clone(),
                host_mesh_addr: compose_component_mesh_peer_addr(
                    artifact_root,
                    &target.config.identity.id,
                    &target.output,
                    mesh_config.mesh_listen.port(),
                )?,
                control_endpoint: compose_project.map(|compose_project| {
                    ControlEndpoint::VolumeSocket {
                        volume: compose_component_control_socket_volume_name(
                            compose_project,
                            service_name,
                        ),
                        socket_path: COMPONENT_CONTROL_SOCKET_PATH_IN_VOLUME.to_string(),
                    }
                }),
                mesh_config,
            },
        );
    }
    Ok(components)
}

#[cfg(test)]
mod tests {
    use amber_mesh::MeshConfigTemplate;

    use super::*;

    #[test]
    fn direct_runtime_metadata_uses_bounded_sidecar_control_socket_paths() {
        let work_dir = PathBuf::from(
            "/Users/example/Developer/amber/target/cli-test-outputs/\
             mixed-run-doc-example-detach-very-long/state/runs/run-123/state/direct_local/runtime/\
             work/components/c1-admin",
        );
        let socket = direct_component_control_socket_path(work_dir.clone(), 7);
        let rendered = socket.display().to_string();

        assert_eq!(
            socket,
            amber_mesh::stable_temp_socket_path("amber-direct-control", "sidecar-7", &work_dir)
        );
        assert!(
            rendered.len() < 104,
            "direct runtime metadata should use the hashed short socket path: {rendered}",
        );
    }

    #[test]
    fn vm_runtime_metadata_uses_bounded_sidecar_control_socket_paths() {
        let work_dir = PathBuf::from(
            "/Users/example/Developer/amber/target/cli-test-outputs/\
             linux-vm-framework_component-very-long/state/runs/run-123/state/vm_local/runtime/\
             work/sidecars/c1-worker-sidecar",
        );
        let socket = vm_component_control_socket_path(work_dir.clone(), 11);
        let rendered = socket.display().to_string();

        assert_eq!(
            socket,
            amber_mesh::stable_temp_socket_path("amber-vm-control", "sidecar-11", &work_dir)
        );
        assert!(
            rendered.len() < 104,
            "vm runtime metadata should use the hashed short socket path: {rendered}",
        );
    }

    #[test]
    fn collect_direct_runtime_metadata_uses_hashed_sidecar_control_socket_path() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let artifact_root = temp.path().join("artifact");
        let runtime_root = temp.path().join("runtime");
        fs::create_dir_all(&artifact_root).expect("artifact root should create");
        fs::create_dir_all(runtime_root.join("work/components/c1-provider"))
            .expect("runtime work dir should create");

        write_json(
            &artifact_root.join("direct-plan.json"),
            &serde_json::json!({
                "version": "3",
                "mesh_provision_plan": "mesh-provision-plan.json",
                "startup_order": [1],
                "components": [
                    {
                        "id": 1,
                        "moniker": "/provider",
                        "log_name": "provider",
                        "sidecar": {
                            "log_name": "provider-sidecar",
                            "mesh_port": 24001,
                            "mesh_config_path": "provider-mesh.json",
                            "mesh_identity_path": "provider-identity.json",
                        },
                        "program": {
                            "log_name": "provider-program",
                            "work_dir": "work/components/c1-provider",
                            "execution": {
                                "kind": "direct",
                                "entrypoint": ["/bin/true"],
                            },
                        },
                    }
                ],
                "router": {
                    "identity_id": "/site/direct/router",
                    "mesh_port": 24000,
                    "control_port": 24100,
                    "control_socket_path": "router.sock",
                    "mesh_config_path": "router-mesh.json",
                    "mesh_identity_path": "router-identity.json"
                }
            }),
        )
        .expect("direct plan should write");
        write_json(
            &direct_runtime_state_path(&artifact_root),
            &DirectRuntimeState {
                component_mesh_port_by_id: BTreeMap::from([(1, 24001)]),
                ..Default::default()
            },
        )
        .expect("direct runtime state should write");
        write_json(
            &runtime_root.join("provider-mesh.json"),
            &MeshConfigPublic {
                identity: MeshIdentityPublic {
                    id: "/provider".to_string(),
                    public_key: [3; 32],
                    mesh_scope: None,
                },
                mesh_listen: "127.0.0.1:24001".parse().expect("mesh listen"),
                control_listen: None,
                dynamic_caps_listen: None,
                control_allow: None,
                peers: Vec::new(),
                inbound: Vec::new(),
                outbound: Vec::new(),
                transport: amber_mesh::TransportConfig::NoiseIk {},
            },
        )
        .expect("provider mesh config should write");

        let metadata = collect_direct_artifact_runtime_metadata(&artifact_root, &runtime_root)
            .expect("direct metadata should load");
        let provider = metadata.get("/provider").expect("provider metadata");
        let Some(ControlEndpoint::Unix(path)) = provider.control_endpoint.as_ref() else {
            panic!("direct metadata should expose a unix control socket");
        };
        assert_eq!(
            path,
            &amber_mesh::stable_temp_socket_path(
                "amber-direct-control",
                "sidecar-1",
                &runtime_root.join("work/components/c1-provider"),
            ),
            "direct runtime metadata should use the hashed short sidecar control socket path",
        );
    }

    #[test]
    fn collect_vm_runtime_metadata_uses_hashed_sidecar_control_socket_path() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let artifact_root = temp.path().join("artifact");
        let runtime_root = temp.path().join("runtime");
        fs::create_dir_all(&artifact_root).expect("artifact root should create");
        fs::create_dir_all(runtime_root.join("work/sidecars/vm-provider"))
            .expect("runtime sidecar dir should create");

        write_json(
            &artifact_root.join("vm-plan.json"),
            &serde_json::json!({
                "version": "1",
                "mesh_provision_plan": "mesh-provision-plan.json",
                "startup_order": [1],
                "runtime_addresses": {},
                "components": [
                    {
                        "id": 1,
                        "moniker": "/provider",
                        "log_name": "vm-provider",
                        "mesh_config_path": "provider-mesh.json",
                        "mesh_identity_path": "provider-identity.json",
                        "cpus": { "kind": "literal", "value": 1 },
                        "memory_mib": { "kind": "literal", "value": 512 },
                        "base_image": { "kind": "static", "path": "/tmp/base.img" },
                        "egress": "none",
                        "storage_mounts": [],
                    }
                ]
            }),
        )
        .expect("vm plan should write");
        write_vm_runtime_state(
            &artifact_root,
            &VmRuntimeState {
                slot_ports_by_component: BTreeMap::new(),
                slot_route_ports_by_component: BTreeMap::new(),
                route_host_ports_by_component: BTreeMap::new(),
                endpoint_forwards_by_component: BTreeMap::new(),
                component_mesh_port_by_id: BTreeMap::from([(1, 24001)]),
                router_mesh_port: None,
            },
        )
        .expect("vm runtime state should write");
        write_json(
            &runtime_root.join("provider-mesh.json"),
            &MeshConfigPublic {
                identity: MeshIdentityPublic {
                    id: "/provider".to_string(),
                    public_key: [5; 32],
                    mesh_scope: None,
                },
                mesh_listen: "127.0.0.1:24001".parse().expect("mesh listen"),
                control_listen: None,
                dynamic_caps_listen: None,
                control_allow: None,
                peers: Vec::new(),
                inbound: Vec::new(),
                outbound: Vec::new(),
                transport: amber_mesh::TransportConfig::NoiseIk {},
            },
        )
        .expect("provider mesh config should write");

        let metadata = collect_vm_artifact_runtime_metadata(&artifact_root, &runtime_root)
            .expect("vm metadata should load");
        let provider = metadata.get("/provider").expect("provider metadata");
        let Some(ControlEndpoint::Unix(path)) = provider.control_endpoint.as_ref() else {
            panic!("vm metadata should expose a unix control socket");
        };
        assert_eq!(
            path,
            &amber_mesh::stable_temp_socket_path(
                "amber-vm-control",
                "sidecar-1",
                &runtime_root.join("work/sidecars/vm-provider"),
            ),
            "vm runtime metadata should use the hashed short sidecar control socket path",
        );
    }

    #[test]
    fn collect_live_component_runtime_metadata_tolerates_missing_runtime_state_file() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let artifact_root = temp.path().join("artifact");
        let runtime_root = temp.path().join("runtime");
        let site_state_root = temp.path().join("state");
        fs::create_dir_all(&artifact_root).expect("artifact root should create");
        fs::create_dir_all(&runtime_root).expect("runtime root should create");
        fs::create_dir_all(&site_state_root).expect("site state root should create");

        write_json(
            &artifact_root.join("direct-plan.json"),
            &serde_json::json!({
                "version": "3",
                "mesh_provision_plan": "mesh-provision-plan.json",
                "startup_order": [],
                "components": [],
                "router": {
                    "identity_id": "/site/direct/router",
                    "mesh_port": 24000,
                    "control_port": 24100,
                    "control_socket_path": "router.sock",
                    "mesh_config_path": "router-mesh.json",
                    "mesh_identity_path": "router-identity.json"
                }
            }),
        )
        .expect("direct plan should write");
        write_json(
            &direct_runtime_state_path(&artifact_root),
            &DirectRuntimeState::default(),
        )
        .expect("direct runtime state should write");

        let metadata = collect_live_component_runtime_metadata(&SiteControllerRuntimePlan {
            schema: "amber.run.site_controller_runtime_plan".to_string(),
            version: 1,
            run_id: "run-123".to_string(),
            mesh_scope: "amber.test".to_string(),
            run_root: temp.path().display().to_string(),
            site_id: "direct_local".to_string(),
            kind: SiteKind::Direct,
            router_identity_id: "/site/direct/router".to_string(),
            local_router_control: None,
            artifact_dir: artifact_root.display().to_string(),
            site_state_root: site_state_root.display().to_string(),
            listen_addr: "127.0.0.1:35000".parse().expect("listen addr should parse"),
            storage_root: None,
            runtime_root: Some(runtime_root.display().to_string()),
            router_mesh_port: Some(24000),
            compose_project: None,
            kubernetes_namespace: None,
            context: None,
            observability_endpoint: None,
            launch_env: BTreeMap::new(),
        })
        .expect("metadata collection should succeed without a runtime state file");

        assert!(
            metadata.is_empty(),
            "static-only sites should not require a site controller runtime state file",
        );
    }

    #[test]
    fn compose_runtime_metadata_uses_volume_root_control_socket_path() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let artifact_root = temp.path().join("artifact");
        fs::create_dir_all(artifact_root.join(".amber/mesh/provider-net"))
            .expect("mesh artifact dir should create");

        write_json(
            &artifact_root.join("mesh-provision-plan.json"),
            &MeshProvisionPlan {
                version: amber_mesh::MESH_PROVISION_PLAN_VERSION.to_string(),
                identity_seed: None,
                existing_peer_identities: Vec::new(),
                targets: vec![MeshProvisionTarget {
                    kind: MeshProvisionTargetKind::Component,
                    config: MeshConfigTemplate {
                        identity: amber_mesh::MeshIdentityTemplate {
                            id: "/provider".to_string(),
                            mesh_scope: None,
                        },
                        mesh_listen: "127.0.0.1:24001".parse().expect("mesh listen"),
                        control_listen: None,
                        dynamic_caps_listen: None,
                        control_allow: None,
                        peers: Vec::new(),
                        inbound: Vec::new(),
                        outbound: Vec::new(),
                        transport: amber_mesh::TransportConfig::NoiseIk {},
                    },
                    output: MeshProvisionOutput::Filesystem {
                        dir: ".amber/mesh/provider-net".to_string(),
                    },
                }],
            },
        )
        .expect("mesh provision plan should write");
        write_json(
            &artifact_root
                .join(".amber/mesh/provider-net")
                .join(MESH_CONFIG_FILENAME),
            &MeshConfigPublic {
                identity: MeshIdentityPublic {
                    id: "/provider".to_string(),
                    public_key: [9; 32],
                    mesh_scope: None,
                },
                mesh_listen: "127.0.0.1:24001".parse().expect("mesh listen"),
                control_listen: None,
                dynamic_caps_listen: None,
                control_allow: None,
                peers: Vec::new(),
                inbound: Vec::new(),
                outbound: Vec::new(),
                transport: amber_mesh::TransportConfig::NoiseIk {},
            },
        )
        .expect("mesh config should write");

        let components = collect_compose_artifact_runtime_metadata(&artifact_root, Some("demo"))
            .expect("compose metadata should load");
        let provider = components.get("/provider").expect("provider metadata");
        let endpoint = provider
            .control_endpoint
            .as_ref()
            .expect("compose metadata should expose a control endpoint");
        let ControlEndpoint::VolumeSocket {
            volume,
            socket_path,
        } = endpoint
        else {
            panic!("expected compose control endpoint to use a volume socket");
        };
        assert_eq!(volume, "demo_provider-net-control");
        assert_eq!(
            socket_path, "/router-control.sock",
            "compose volume sockets must use the volume-root path, not the in-container mount path",
        );
    }
}

fn collect_kubernetes_artifact_runtime_metadata(
    plan: &SiteControllerRuntimePlan,
    artifact_root: &Path,
) -> Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
    let mesh_plan = read_kubernetes_runtime_mesh_provision_plan(artifact_root)?;
    let mut components = BTreeMap::new();
    for target in &mesh_plan.targets {
        if !matches!(target.kind, MeshProvisionTargetKind::Component) {
            continue;
        }
        let MeshProvisionOutput::KubernetesSecret { name, namespace } = &target.output else {
            return Err(miette::miette!(
                "kubernetes artifact {} has non-secret mesh output for component {}",
                artifact_root.display(),
                target.config.identity.id
            ));
        };
        name.strip_suffix("-mesh").ok_or_else(|| {
            miette::miette!(
                "kubernetes artifact {} component {} uses invalid mesh secret name {}",
                artifact_root.display(),
                target.config.identity.id,
                name
            )
        })?;
        let mesh_config = load_kubernetes_mesh_config_public(plan, name, namespace.as_deref())?;
        components.insert(
            target.config.identity.id.clone(),
            LiveComponentRuntimeMetadata {
                moniker: target.config.identity.id.clone(),
                host_mesh_addr: kubernetes_component_mesh_peer_addr(
                    artifact_root,
                    &target.config.identity.id,
                    &target.output,
                    mesh_config.mesh_listen.port(),
                )?,
                control_endpoint: None,
                mesh_config,
            },
        );
    }
    Ok(components)
}

fn compose_component_control_socket_volume_name(
    compose_project: &str,
    service_name: &str,
) -> String {
    format!("{compose_project}_{service_name}-control")
}

pub(super) fn prepare_dynamic_compose_child_artifact(
    plan: &SiteControllerRuntimePlan,
    runtime_spec: &LocalChildRuntimeSpec,
    artifact_root: &Path,
    published_children: &[SiteControllerRuntimeChildRecord],
    existing_site_peer_identities: &BTreeMap<String, MeshIdentityPublic>,
    live_components: &BTreeMap<String, LiveComponentRuntimeMetadata>,
) -> Result<()> {
    project_dynamic_child_mesh_scope(artifact_root, Some(&plan.mesh_scope))?;
    let compose_path = artifact_root.join("compose.yaml");
    let mut desired_document = read_compose_document(&compose_path)?;
    let root_services =
        compose_dynamic_root_service_names(artifact_root, &runtime_spec.assigned_components)?;
    let service_closure =
        compose_service_closure(&desired_document, &compose_path, &root_services)?;
    let live_services = compose_live_service_names(plan, published_children)?;
    let mut kept_services = service_closure
        .difference(&live_services)
        .cloned()
        .collect::<BTreeSet<_>>();
    kept_services.remove(COMPOSE_PROVISIONER_SERVICE_NAME);
    if kept_services.is_empty() {
        return Err(miette::miette!(
            "compose child artifact {} does not retain any child-owned services after filtering",
            compose_path.display()
        ));
    }

    let services = compose_services_mut(&mut desired_document, &compose_path)?;
    services.retain(|name, _| {
        name.as_str()
            .is_some_and(|service_name| kept_services.contains(service_name))
    });
    for service in services.values_mut() {
        retain_compose_service_dependencies(service, &kept_services)?;
    }
    let rendered = serde_yaml::to_string(&desired_document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", compose_path.display()))?;
    fs::write(&compose_path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", compose_path.display()))?;

    let DynamicComposeMeshPlan {
        mesh_plan,
        mesh_dirs,
        component_mesh_dirs,
    } = build_dynamic_compose_mesh_plan(artifact_root, &runtime_spec.assigned_components)?;
    let mut mesh_plan = mesh_plan;
    let router_mesh_port = router_mesh_port_from_plan(
        &read_embedded_compose_mesh_provision_plan(artifact_root)?,
        "compose",
    )?;
    ensure_dynamic_proxy_export_component_routes(
        &mut mesh_plan,
        &runtime_spec.proxy_exports,
        &plan.router_identity_id,
    )?;
    rewrite_dynamic_direct_inputs(&mut mesh_plan, &runtime_spec.direct_inputs, live_components)?;
    rewrite_dynamic_routed_inputs(
        &mut mesh_plan,
        &runtime_spec.routed_inputs,
        SiteKind::Compose,
        &plan.router_identity_id,
        Some(router_mesh_port),
    )?;
    let existing_peer_identities =
        required_existing_mesh_peer_identities(&mesh_plan, existing_site_peer_identities)?;
    mesh_plan.existing_peer_identities = existing_peer_identities.values().cloned().collect();
    write_json(&artifact_root.join("mesh-provision-plan.json"), &mesh_plan)?;
    provision_mesh_filesystem_with_peer_identities(
        &mesh_plan,
        artifact_root,
        &existing_peer_identities,
    )?;
    for relative_dir in mesh_dirs.values() {
        project_existing_peer_identities_into_mesh_config(
            &artifact_root.join(relative_dir).join(MESH_CONFIG_FILENAME),
            &existing_peer_identities,
        )?;
    }
    rewrite_compose_mesh_bind_mounts(artifact_root, &mesh_dirs)?;
    let overlay_payload = build_dynamic_compose_route_overlay_payload(
        artifact_root,
        &runtime_spec.assigned_components,
        &component_mesh_dirs,
        &runtime_spec.proxy_exports,
        &runtime_spec.routed_inputs,
        existing_site_peer_identities,
    )?;
    write_json(&dynamic_route_overlay_path(artifact_root), &overlay_payload)?;
    write_embedded_compose_mesh_provision_plan(artifact_root, &mesh_plan)?;

    write_json(
        &dynamic_compose_child_metadata_path(artifact_root),
        &DynamicComposeChildMetadata {
            schema: DYNAMIC_COMPOSE_CHILD_SCHEMA.to_string(),
            version: DYNAMIC_COMPOSE_CHILD_VERSION,
            services: kept_services.iter().cloned().collect(),
            readiness_services: root_services
                .into_iter()
                .filter(|service| kept_services.contains(service))
                .collect(),
        },
    )
}

pub(super) fn read_compose_document(path: &Path) -> Result<serde_yaml::Value> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid compose file {}", path.display()))
}

pub(super) fn read_embedded_compose_mesh_provision_plan(
    artifact_root: &Path,
) -> Result<MeshProvisionPlan> {
    let path = artifact_root.join("compose.yaml");
    let document = read_compose_document(&path)?;
    let Some(root) = document.as_mapping() else {
        return Err(miette::miette!(
            "compose file {} is not a YAML mapping",
            path.display()
        ));
    };
    let configs_key = serde_yaml::Value::String("configs".to_string());
    let config_name = serde_yaml::Value::String("amber-mesh-provision-plan".to_string());
    let content_key = serde_yaml::Value::String("content".to_string());
    let content = root
        .get(&configs_key)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|configs| configs.get(&config_name))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|config| config.get(&content_key))
        .and_then(serde_yaml::Value::as_str)
        .ok_or_else(|| {
            miette::miette!(
                "compose file {} is missing configs.amber-mesh-provision-plan.content",
                path.display()
            )
        })?;
    serde_json::from_str(content).map_err(|err| {
        miette::miette!(
            "compose file {} has invalid embedded mesh provision plan: {err}",
            path.display()
        )
    })
}

fn write_embedded_compose_mesh_provision_plan(
    artifact_root: &Path,
    plan: &MeshProvisionPlan,
) -> Result<()> {
    let path = artifact_root.join("compose.yaml");
    let mut document = read_compose_document(&path)?;
    let plan_json = serde_json::to_string_pretty(plan)
        .into_diagnostic()
        .wrap_err("failed to serialize compose mesh provision plan")?;
    document
        .as_mapping_mut()
        .and_then(|root| root.get_mut(yaml_string("configs")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .and_then(|configs| configs.get_mut(yaml_string("amber-mesh-provision-plan")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| {
            miette::miette!(
                "compose file {} is missing configs.amber-mesh-provision-plan",
                path.display()
            )
        })?
        .insert(yaml_string("content"), serde_yaml::Value::String(plan_json));
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(&path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn read_embedded_kubernetes_mesh_provision_plan(artifact_root: &Path) -> Result<MeshProvisionPlan> {
    let path = artifact_root
        .join("01-configmaps")
        .join("amber-mesh-provision.yaml");
    let raw = fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let document: serde_yaml::Value =
        serde_yaml::from_str(&raw)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "invalid kubernetes mesh provision configmap {}",
                    path.display()
                )
            })?;
    let mesh_plan = document
        .as_mapping()
        .and_then(|root| root.get(yaml_string("data")))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|data| data.get(yaml_string("mesh-plan.json")))
        .and_then(serde_yaml::Value::as_str)
        .ok_or_else(|| {
            miette::miette!(
                "kubernetes mesh provision configmap {} is missing data.mesh-plan.json",
                path.display()
            )
        })?;
    serde_json::from_str(mesh_plan).map_err(|err| {
        miette::miette!(
            "kubernetes mesh provision configmap {} has invalid mesh plan: {err}",
            path.display()
        )
    })
}

fn read_kubernetes_runtime_mesh_provision_plan(artifact_root: &Path) -> Result<MeshProvisionPlan> {
    let path = artifact_root.join("mesh-provision-plan.json");
    if path.is_file() {
        return read_json(&path, "mesh provision plan");
    }
    read_embedded_kubernetes_mesh_provision_plan(artifact_root)
}

fn write_embedded_kubernetes_mesh_provision_plan(
    artifact_root: &Path,
    plan: &MeshProvisionPlan,
) -> Result<()> {
    let path = artifact_root.join(KUBERNETES_MESH_PROVISION_CONFIGMAP_PATH);
    let raw = fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "invalid kubernetes mesh provision configmap {}",
                path.display()
            )
        })?;
    let plan_json = serde_json::to_string_pretty(plan)
        .into_diagnostic()
        .wrap_err("failed to serialize kubernetes mesh provision plan")?;
    document
        .as_mapping_mut()
        .and_then(|root| root.get_mut(yaml_string("data")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| {
            miette::miette!(
                "kubernetes mesh provision configmap {} is missing a data mapping",
                path.display()
            )
        })?
        .insert(
            yaml_string("mesh-plan.json"),
            serde_yaml::Value::String(plan_json),
        );
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(&path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

#[derive(Clone, Debug)]
pub struct SiteControllerPeerRouterRoute {
    pub site_id: String,
    pub peer_router: MeshIdentityPublic,
    pub peer_addr: String,
    pub listen_addr: String,
    pub listen_port: u16,
}

pub fn inject_site_controller_peer_router_routes(
    artifact_root: &Path,
    local_site_id: &str,
    allowed_issuers: &[String],
    routes: &[SiteControllerPeerRouterRoute],
) -> Result<()> {
    let mut write_embedded = None;
    let mut plan = if artifact_root.join("mesh-provision-plan.json").is_file() {
        read_json(
            &artifact_root.join("mesh-provision-plan.json"),
            "mesh provision plan",
        )?
    } else if artifact_root.join("compose.yaml").is_file() {
        write_embedded = Some(EmbeddedMeshPlanKind::Compose);
        read_embedded_compose_mesh_provision_plan(artifact_root)?
    } else if artifact_root
        .join(KUBERNETES_MESH_PROVISION_CONFIGMAP_PATH)
        .is_file()
    {
        write_embedded = Some(EmbeddedMeshPlanKind::Kubernetes);
        read_embedded_kubernetes_mesh_provision_plan(artifact_root)?
    } else {
        return Err(miette::miette!(
            "site artifact {} is missing a mesh provision plan",
            artifact_root.display()
        ));
    };

    inject_site_controller_peer_router_routes_into_plan(
        &mut plan,
        local_site_id,
        allowed_issuers,
        routes,
    )?;

    match write_embedded {
        None => write_json(&artifact_root.join("mesh-provision-plan.json"), &plan),
        Some(EmbeddedMeshPlanKind::Compose) => {
            write_embedded_compose_mesh_provision_plan(artifact_root, &plan)
        }
        Some(EmbeddedMeshPlanKind::Kubernetes) => {
            write_embedded_kubernetes_mesh_provision_plan(artifact_root, &plan)
        }
    }
}

pub fn set_compose_router_published_mesh_port(artifact_root: &Path, host_port: u16) -> Result<()> {
    set_compose_router_published_port(artifact_root, "0.0.0.0", host_port, 24000, false)
}

pub fn add_compose_router_published_route_ports(
    artifact_root: &Path,
    route_ports: &[u16],
) -> Result<()> {
    for port in route_ports {
        set_compose_router_published_port(artifact_root, "127.0.0.1", *port, *port, true)?;
    }
    Ok(())
}

fn set_compose_router_published_port(
    artifact_root: &Path,
    host_ip: &str,
    host_port: u16,
    container_port: u16,
    append_if_missing: bool,
) -> Result<()> {
    let path = artifact_root.join("compose.yaml");
    let mut document = read_compose_document(&path)?;
    let router_ports = document
        .as_mapping_mut()
        .and_then(|root| root.get_mut(yaml_string("services")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .and_then(|services| services.get_mut(yaml_string(COMPOSE_ROUTER_SERVICE_NAME)))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .and_then(|router| router.get_mut(yaml_string("ports")))
        .and_then(serde_yaml::Value::as_sequence_mut)
        .ok_or_else(|| {
            miette::miette!(
                "compose file {} is missing services.{COMPOSE_ROUTER_SERVICE_NAME}.ports",
                path.display()
            )
        })?;
    let desired = format!("{host_ip}:{host_port}:{container_port}");
    let mut updated = false;
    for port in &mut *router_ports {
        let Some(raw) = port.as_str() else {
            continue;
        };
        if raw == desired {
            updated = true;
            continue;
        }
        if raw.ends_with(&format!("::{container_port}")) {
            *port = serde_yaml::Value::String(desired.clone());
            updated = true;
        }
    }
    if !updated && append_if_missing {
        router_ports.push(serde_yaml::Value::String(desired));
        updated = true;
    }
    if !updated {
        return Err(miette::miette!(
            "compose file {} has no router publish to rewrite for container port {container_port}",
            path.display(),
        ));
    }
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(&path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

enum EmbeddedMeshPlanKind {
    Compose,
    Kubernetes,
}

fn inject_site_controller_peer_router_routes_into_plan(
    plan: &mut MeshProvisionPlan,
    local_site_id: &str,
    allowed_issuers: &[String],
    routes: &[SiteControllerPeerRouterRoute],
) -> Result<()> {
    let router = plan
        .targets
        .iter_mut()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
        .ok_or_else(|| miette::miette!("mesh provision plan is missing a router target"))?;
    let inbound_route_id = site_controller_internal_route_id(local_site_id);
    router
        .config
        .inbound
        .retain(|route| route.route_id != inbound_route_id);
    router.config.inbound.push(InboundRoute {
        route_id: inbound_route_id,
        capability: SITE_CONTROLLER_INTERNAL_CAPABILITY.to_string(),
        capability_kind: None,
        capability_profile: None,
        protocol: MeshProtocol::Http,
        http_plugins: Vec::new(),
        target: InboundTarget::External {
            url_env: amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_URL_ENV.to_string(),
            optional: false,
        },
        allowed_issuers: allowed_issuers.to_vec(),
    });
    router
        .config
        .inbound
        .sort_by(|left, right| left.route_id.cmp(&right.route_id));
    router
        .config
        .outbound
        .retain(|route| !route.route_id.starts_with("site-controller:"));
    let mut existing_peer_identities = plan
        .existing_peer_identities
        .iter()
        .cloned()
        .map(|identity| (identity.id.clone(), identity))
        .collect::<BTreeMap<_, _>>();
    for route in routes {
        existing_peer_identities.insert(route.peer_router.id.clone(), route.peer_router.clone());
        if !router
            .config
            .peers
            .iter()
            .any(|peer| peer.id == route.peer_router.id)
        {
            router.config.peers.push(MeshPeerTemplate {
                id: route.peer_router.id.clone(),
            });
        }
        router.config.outbound.push(OutboundRoute {
            route_id: site_controller_internal_route_id(&route.site_id),
            rewrite_route_id: None,
            slot: route.site_id.clone(),
            capability_kind: None,
            capability_profile: None,
            listen_port: route.listen_port,
            listen_addr: Some(route.listen_addr.clone()),
            protocol: MeshProtocol::Http,
            http_plugins: Vec::new(),
            peer_addr: route.peer_addr.clone(),
            peer_id: route.peer_router.id.clone(),
            capability: SITE_CONTROLLER_INTERNAL_CAPABILITY.to_string(),
        });
    }
    plan.existing_peer_identities = existing_peer_identities.into_values().collect();
    router
        .config
        .outbound
        .sort_by(|left, right| left.route_id.cmp(&right.route_id));
    router
        .config
        .peers
        .sort_by(|left, right| left.id.cmp(&right.id));
    Ok(())
}

pub fn set_site_artifact_mesh_identity_seed(
    artifact_root: &Path,
    identity_seed: &str,
) -> Result<()> {
    let path = artifact_root.join("mesh-provision-plan.json");
    if path.is_file() {
        let mut plan: MeshProvisionPlan = read_json(&path, "mesh provision plan")?;
        if plan.identity_seed.as_deref() != Some(identity_seed) {
            plan.identity_seed = Some(identity_seed.to_string());
            write_json(&path, &plan)?;
        }
        return Ok(());
    }

    let compose_path = artifact_root.join("compose.yaml");
    if compose_path.is_file() {
        let mut plan = read_embedded_compose_mesh_provision_plan(artifact_root)?;
        if plan.identity_seed.as_deref() != Some(identity_seed) {
            plan.identity_seed = Some(identity_seed.to_string());
            write_embedded_compose_mesh_provision_plan(artifact_root, &plan)?;
        }
        return Ok(());
    }

    let configmap_path = artifact_root.join(KUBERNETES_MESH_PROVISION_CONFIGMAP_PATH);
    if configmap_path.is_file() {
        let mut plan = read_embedded_kubernetes_mesh_provision_plan(artifact_root)?;
        if plan.identity_seed.as_deref() != Some(identity_seed) {
            plan.identity_seed = Some(identity_seed.to_string());
            write_embedded_kubernetes_mesh_provision_plan(artifact_root, &plan)?;
        }
        return Ok(());
    }

    Err(miette::miette!(
        "site artifact {} is missing a mesh provision plan",
        artifact_root.display()
    ))
}

fn kubernetes_resource_name(document: &serde_yaml::Value) -> Option<&str> {
    document
        .as_mapping()
        .and_then(|root| root.get(yaml_string("metadata")))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|metadata| metadata.get(yaml_string("name")))
        .and_then(serde_yaml::Value::as_str)
}

fn kubernetes_dynamic_apply_resource_kept_from_contents(
    resource: &str,
    raw: &str,
    child_component_labels: &BTreeSet<String>,
) -> Result<bool> {
    if matches!(
        resource,
        KUBERNETES_MESH_PROVISION_CONFIGMAP_PATH
            | KUBERNETES_PROVISIONER_JOB_PATH
            | KUBERNETES_PROVISIONER_ROLE_PATH
            | KUBERNETES_PROVISIONER_ROLEBINDING_PATH
            | KUBERNETES_PROVISIONER_SERVICE_ACCOUNT_PATH
    ) || resource.starts_with("03-persistentvolumeclaims/")
    {
        return Ok(true);
    }

    let document: serde_yaml::Value = serde_yaml::from_str(raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid kubernetes resource {resource}"))?;
    Ok(document
        .as_mapping()
        .and_then(|root| root.get(yaml_string("metadata")))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|metadata| metadata.get(yaml_string("labels")))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|labels| labels.get(yaml_string("amber.io/component-id")))
        .and_then(serde_yaml::Value::as_str)
        .is_some_and(|component_id| child_component_labels.contains(component_id)))
}

pub(crate) fn project_kubernetes_dynamic_child_artifact_files(
    artifact_files: &BTreeMap<String, String>,
    component_ids: &[usize],
) -> Result<BTreeMap<String, String>> {
    let child_component_labels = component_ids
        .iter()
        .map(|component_id| format!("c{component_id}"))
        .collect::<BTreeSet<_>>();
    let kustomization_path = "kustomization.yaml";
    let raw = artifact_files.get(kustomization_path).ok_or_else(|| {
        miette::miette!("dynamic kubernetes artifact snapshot is missing {kustomization_path}")
    })?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid kustomization {kustomization_path}"))?;
    let root = document.as_mapping_mut().ok_or_else(|| {
        miette::miette!("kustomization {kustomization_path} is not a YAML mapping")
    })?;
    let resources = root
        .get_mut(yaml_string("resources"))
        .and_then(serde_yaml::Value::as_sequence_mut)
        .ok_or_else(|| {
            miette::miette!("kustomization {kustomization_path} is missing a resources sequence")
        })?;
    let mut projected = artifact_files
        .iter()
        .filter(|(path, _)| !path.ends_with(".yaml") && path.as_str() != kustomization_path)
        .map(|(path, contents)| (path.clone(), contents.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut kept_resources = Vec::new();
    let mut kept_resource_names = BTreeSet::new();
    for resource in resources
        .iter()
        .filter_map(serde_yaml::Value::as_str)
        .map(str::to_owned)
    {
        let raw = artifact_files
            .get(&resource)
            .ok_or_else(|| miette::miette!("dynamic kubernetes artifact is missing {resource}"))?;
        if !kubernetes_dynamic_apply_resource_kept_from_contents(
            &resource,
            raw,
            &child_component_labels,
        )? {
            continue;
        }
        let document: serde_yaml::Value = serde_yaml::from_str(raw)
            .into_diagnostic()
            .wrap_err_with(|| format!("invalid kubernetes resource {resource}"))?;
        if let Some(name) = kubernetes_resource_name(&document) {
            kept_resource_names.insert(name.to_string());
        }
        projected.insert(resource.clone(), raw.clone());
        kept_resources.push(serde_yaml::Value::String(resource));
    }
    *resources = kept_resources;

    if let Some(generators) = root
        .get_mut(yaml_string("secretGenerator"))
        .and_then(serde_yaml::Value::as_sequence_mut)
    {
        generators.retain(|generator| {
            generator
                .as_mapping()
                .and_then(|mapping| mapping.get(yaml_string("name")))
                .and_then(serde_yaml::Value::as_str)
                != Some(KUBERNETES_ROUTER_EXTERNAL_SECRET_NAME)
        });
    }

    if let Some(replacements) = root
        .get_mut(yaml_string("replacements"))
        .and_then(serde_yaml::Value::as_sequence_mut)
    {
        replacements.retain_mut(|replacement| {
            let Some(targets) = replacement
                .as_mapping_mut()
                .and_then(|mapping| mapping.get_mut(yaml_string("targets")))
                .and_then(serde_yaml::Value::as_sequence_mut)
            else {
                return false;
            };
            targets.retain(|target| {
                target
                    .as_mapping()
                    .and_then(|mapping| mapping.get(yaml_string("select")))
                    .and_then(serde_yaml::Value::as_mapping)
                    .and_then(|select| select.get(yaml_string("name")))
                    .and_then(serde_yaml::Value::as_str)
                    .is_some_and(|name| kept_resource_names.contains(name))
            });
            !targets.is_empty()
        });
    }

    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {kustomization_path}"))?;
    projected.insert(kustomization_path.to_string(), rendered);
    Ok(projected)
}

pub(super) fn project_kubernetes_dynamic_child_destroy_artifact_files(
    artifact_files: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let kustomization_path = "kustomization.yaml";
    let raw = artifact_files.get(kustomization_path).ok_or_else(|| {
        miette::miette!("dynamic kubernetes artifact snapshot is missing {kustomization_path}")
    })?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid kustomization {kustomization_path}"))?;
    let root = document.as_mapping_mut().ok_or_else(|| {
        miette::miette!("kustomization {kustomization_path} is not a YAML mapping")
    })?;
    let resources = root
        .get_mut(yaml_string("resources"))
        .and_then(serde_yaml::Value::as_sequence_mut)
        .ok_or_else(|| {
            miette::miette!("kustomization {kustomization_path} is missing a resources sequence")
        })?;
    let mut projected = artifact_files
        .iter()
        .filter(|(path, _)| !path.ends_with(".yaml") && path.as_str() != kustomization_path)
        .map(|(path, contents)| (path.clone(), contents.clone()))
        .collect::<BTreeMap<_, _>>();
    let shared_paths = [
        KUBERNETES_MESH_PROVISION_CONFIGMAP_PATH,
        KUBERNETES_PROVISIONER_ROLE_PATH,
        KUBERNETES_PROVISIONER_ROLEBINDING_PATH,
        KUBERNETES_PROVISIONER_SERVICE_ACCOUNT_PATH,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let mut kept_resources = Vec::new();
    for resource in resources
        .iter()
        .filter_map(serde_yaml::Value::as_str)
        .map(str::to_owned)
    {
        if shared_paths.contains(resource.as_str()) {
            continue;
        }
        let raw = artifact_files
            .get(&resource)
            .ok_or_else(|| miette::miette!("dynamic kubernetes artifact is missing {resource}"))?;
        projected.insert(resource.clone(), raw.clone());
        kept_resources.push(serde_yaml::Value::String(resource));
    }
    *resources = kept_resources;

    if let Some(generators) = root
        .get_mut(yaml_string("secretGenerator"))
        .and_then(serde_yaml::Value::as_sequence_mut)
    {
        generators.retain(|generator| {
            generator
                .as_mapping()
                .and_then(|mapping| mapping.get(yaml_string("name")))
                .and_then(serde_yaml::Value::as_str)
                != Some(KUBERNETES_ROUTER_EXTERNAL_SECRET_NAME)
        });
    }

    if let Some(replacements) = root
        .get_mut(yaml_string("replacements"))
        .and_then(serde_yaml::Value::as_sequence_mut)
    {
        replacements.clear();
    }

    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {kustomization_path}"))?;
    projected.insert(kustomization_path.to_string(), rendered);
    Ok(projected)
}

pub(super) fn read_artifact_snapshot(root: &Path) -> Result<BTreeMap<String, String>> {
    walk_files(root)?
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(root)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to relativize {}", path.display()))?;
            let relative = path_to_forward_slash_string(relative);
            let contents = fs::read_to_string(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read {}", path.display()))?;
            Ok((relative, contents))
        })
        .collect()
}

fn rewrite_dynamic_kubernetes_apply_bundle(
    artifact_root: &Path,
    component_ids: &[usize],
) -> Result<()> {
    let files = read_artifact_snapshot(artifact_root)?;
    let projected = project_kubernetes_dynamic_child_artifact_files(&files, component_ids)?;
    replace_artifact_snapshot(artifact_root, &projected)
}

pub(super) fn prepare_dynamic_kubernetes_child_artifact(
    plan: &SiteControllerRuntimePlan,
    runtime_spec: &LocalChildRuntimeSpec,
    artifact_root: &Path,
    existing_site_peer_identities: &BTreeMap<String, MeshIdentityPublic>,
    live_components: &BTreeMap<String, LiveComponentRuntimeMetadata>,
) -> Result<()> {
    project_dynamic_child_mesh_scope(artifact_root, Some(&plan.mesh_scope))?;
    let plan_path = artifact_root.join("mesh-provision-plan.json");
    let mesh_plan = read_embedded_kubernetes_mesh_provision_plan(artifact_root)?;
    let router_mesh_port = router_mesh_port_from_plan(&mesh_plan, "kubernetes")?;
    let assigned = runtime_spec
        .assigned_components
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut kept_component_ids = BTreeSet::new();
    let mut router_target = None;
    let mut overlay_targets = Vec::with_capacity(mesh_plan.targets.len());
    let mut provision_targets = Vec::new();
    for target in mesh_plan.targets {
        match target.kind {
            MeshProvisionTargetKind::Component => {
                if assigned.contains(target.config.identity.id.as_str()) {
                    kept_component_ids.insert(target.config.identity.id.clone());
                    provision_targets.push(target.clone());
                    overlay_targets.push(target);
                }
            }
            MeshProvisionTargetKind::Router => {
                router_target = Some(target);
            }
        }
    }

    let Some(mut router_target) = router_target else {
        return Err(miette::miette!(
            "dynamic mesh provision plan {} is missing a router target",
            plan_path.display()
        ));
    };
    filter_dynamic_router_target(&mut router_target, &kept_component_ids);
    overlay_targets.push(router_target);
    let mut overlay_plan = MeshProvisionPlan {
        version: mesh_plan.version.clone(),
        identity_seed: mesh_plan.identity_seed.clone(),
        existing_peer_identities: Vec::new(),
        targets: overlay_targets,
    };
    let overlay_existing_peer_identities =
        required_existing_mesh_peer_identities(&overlay_plan, existing_site_peer_identities)?;
    overlay_plan.existing_peer_identities =
        overlay_existing_peer_identities.values().cloned().collect();
    write_json(&plan_path, &overlay_plan)?;
    let mut provision_plan = MeshProvisionPlan {
        version: mesh_plan.version,
        identity_seed: mesh_plan.identity_seed,
        existing_peer_identities: Vec::new(),
        targets: provision_targets,
    };
    ensure_dynamic_proxy_export_component_routes(
        &mut provision_plan,
        &runtime_spec.proxy_exports,
        &plan.router_identity_id,
    )?;
    rewrite_dynamic_direct_inputs(
        &mut provision_plan,
        &runtime_spec.direct_inputs,
        live_components,
    )?;
    rewrite_dynamic_routed_inputs(
        &mut provision_plan,
        &runtime_spec.routed_inputs,
        SiteKind::Kubernetes,
        &plan.router_identity_id,
        Some(router_mesh_port),
    )?;
    let provision_existing_peer_identities =
        required_existing_mesh_peer_identities(&provision_plan, existing_site_peer_identities)?;
    provision_plan.existing_peer_identities = provision_existing_peer_identities
        .values()
        .cloned()
        .collect();
    write_embedded_kubernetes_mesh_provision_plan(artifact_root, &provision_plan)?;
    project_dynamic_kubernetes_proxy_export_resources(
        artifact_root,
        &provision_plan,
        &runtime_spec.proxy_exports,
    )?;
    rewrite_dynamic_kubernetes_apply_bundle(artifact_root, &runtime_spec.component_ids)
}

fn kubernetes_peer_addrs_for_artifact(artifact_root: &Path) -> Result<BTreeMap<String, String>> {
    let mesh_plan = read_kubernetes_runtime_mesh_provision_plan(artifact_root)?;
    mesh_plan
        .targets
        .iter()
        .filter(|target| matches!(target.kind, MeshProvisionTargetKind::Component))
        .map(|target| {
            Ok((
                target.config.identity.id.clone(),
                kubernetes_component_mesh_peer_addr(
                    artifact_root,
                    &target.config.identity.id,
                    &target.output,
                    target.config.mesh_listen.port(),
                )?,
            ))
        })
        .collect()
}

fn build_kubernetes_route_overlay_base(
    artifact_root: &Path,
    assigned_components: &[String],
    provider_peer_addrs: &BTreeMap<String, String>,
    peer_identities: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<StoredRouteOverlayPayload> {
    let mesh_plan = read_kubernetes_runtime_mesh_provision_plan(artifact_root)?;
    let kept_component_ids = assigned_components.iter().cloned().collect::<BTreeSet<_>>();
    let mut router_target = mesh_plan
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
        .cloned()
        .ok_or_else(|| {
            miette::miette!(
                "kubernetes artifact {} is missing a router mesh target",
                artifact_root.display()
            )
        })?;
    filter_dynamic_router_target(&mut router_target, &kept_component_ids);
    for route in &mut router_target.config.inbound {
        if let InboundTarget::MeshForward {
            peer_id, peer_addr, ..
        } = &mut route.target
            && let Some(resolved) = provider_peer_addrs.get(peer_id)
        {
            *peer_addr = resolved.clone();
        }
    }
    let peers = router_target
        .config
        .peers
        .iter()
        .map(|peer| {
            peer_identities.get(&peer.id).map(|identity| MeshPeer {
                id: identity.id.clone(),
                public_key: identity.public_key,
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            miette::miette!(
                "kubernetes artifact {} is missing a live mesh identity for one of its route peers",
                artifact_root.display()
            )
        })?;
    Ok(StoredRouteOverlayPayload {
        peers,
        inbound_routes: router_target.config.inbound,
    })
}

pub(super) fn write_kubernetes_live_route_overlay_payload(
    artifact_root: &Path,
    assigned_components: &[String],
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
    routed_inputs: &[DynamicInputRouteRecord],
    peer_identities: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<()> {
    let provider_peer_addrs = kubernetes_peer_addrs_for_artifact(artifact_root)?;
    let mut payload = build_kubernetes_route_overlay_base(
        artifact_root,
        assigned_components,
        &provider_peer_addrs,
        peer_identities,
    )?;
    augment_route_overlay_payload(
        &mut payload,
        proxy_exports,
        routed_inputs,
        &provider_peer_addrs,
        peer_identities,
        None,
        false,
    )?;
    write_dynamic_route_overlay_payload(artifact_root, &payload)
}

fn kubernetes_network_policy_paths_by_component_label(
    artifact_root: &Path,
) -> Result<BTreeMap<String, PathBuf>> {
    let netpol_root = artifact_root.join("05-networkpolicies");
    if !netpol_root.is_dir() {
        return Ok(BTreeMap::new());
    }
    let mut netpol_paths = BTreeMap::new();
    for path in walk_files(&netpol_root)? {
        let raw = fs::read_to_string(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read {}", path.display()))?;
        let document: serde_yaml::Value = serde_yaml::from_str(&raw)
            .into_diagnostic()
            .wrap_err_with(|| format!("invalid kubernetes network policy {}", path.display()))?;
        let Some(root) = document.as_mapping() else {
            continue;
        };
        if root
            .get(yaml_string("kind"))
            .and_then(serde_yaml::Value::as_str)
            != Some("NetworkPolicy")
        {
            continue;
        }
        let Some(component_label) = root
            .get(yaml_string("metadata"))
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|metadata| metadata.get(yaml_string("labels")))
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|labels| labels.get(yaml_string("amber.io/component-id")))
            .and_then(serde_yaml::Value::as_str)
        else {
            continue;
        };
        netpol_paths.insert(component_label.to_string(), path);
    }
    Ok(netpol_paths)
}

fn project_dynamic_kubernetes_proxy_export_resources(
    artifact_root: &Path,
    mesh_plan: &MeshProvisionPlan,
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
) -> Result<()> {
    if proxy_exports.is_empty() {
        return Ok(());
    }

    let netpol_paths = kubernetes_network_policy_paths_by_component_label(artifact_root)?;
    let exported_mesh_ports = proxy_exports
        .values()
        .map(|export| {
            let component_target = mesh_plan
                .targets
                .iter()
                .find(|target| {
                    matches!(target.kind, MeshProvisionTargetKind::Component)
                        && target.config.identity.id == export.component
                })
                .ok_or_else(|| {
                    miette::miette!(
                        "dynamic proxy export provider {} is missing from the kubernetes mesh plan",
                        export.component
                    )
                })?;
            Ok((
                format!("c{}", export.component_id),
                component_target.config.mesh_listen.port(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    for (component_label, mesh_port) in exported_mesh_ports {
        let path = netpol_paths.get(&component_label).ok_or_else(|| {
            miette::miette!(
                "dynamic proxy export provider {component_label} is missing a kubernetes network \
                 policy in {}",
                artifact_root.join("05-networkpolicies").display()
            )
        })?;
        ensure_kubernetes_network_policy_router_ingress(path, mesh_port)?;
    }

    Ok(())
}

fn ensure_kubernetes_network_policy_router_ingress(path: &Path, mesh_port: u16) -> Result<()> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid kubernetes network policy {}", path.display()))?;
    let root = document.as_mapping_mut().ok_or_else(|| {
        miette::miette!(
            "kubernetes network policy {} is not a YAML mapping",
            path.display()
        )
    })?;
    let spec = root
        .get_mut(yaml_string("spec"))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| {
            miette::miette!(
                "kubernetes network policy {} is missing a spec mapping",
                path.display()
            )
        })?;
    let ingress = spec
        .entry(yaml_string("ingress"))
        .or_insert_with(|| serde_yaml::Value::Sequence(Vec::new()))
        .as_sequence_mut()
        .ok_or_else(|| {
            miette::miette!(
                "kubernetes network policy {} has non-sequence spec.ingress",
                path.display()
            )
        })?;

    let router_peer = kubernetes_router_network_policy_peer();
    let mut matched_port_rule = false;
    let mut changed = false;
    for rule in ingress.iter_mut() {
        let Some(rule_mapping) = rule.as_mapping_mut() else {
            continue;
        };
        let matches_port = rule_mapping
            .get(yaml_string("ports"))
            .and_then(serde_yaml::Value::as_sequence)
            .is_some_and(|ports| {
                ports
                    .iter()
                    .any(|port| network_policy_port_matches(port, mesh_port))
            });
        if !matches_port {
            continue;
        }
        matched_port_rule = true;
        let Some(from) = rule_mapping
            .get_mut(yaml_string("from"))
            .and_then(serde_yaml::Value::as_sequence_mut)
        else {
            break;
        };
        if from.iter().any(network_policy_peer_is_router) {
            break;
        }
        from.push(router_peer.clone());
        changed = true;
        break;
    }

    if !matched_port_rule {
        ingress.push(serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter(
            [
                (
                    yaml_string("from"),
                    serde_yaml::Value::Sequence(vec![router_peer.clone()]),
                ),
                (
                    yaml_string("ports"),
                    serde_yaml::Value::Sequence(vec![serde_yaml::Value::Mapping(
                        serde_yaml::Mapping::from_iter([
                            (yaml_string("protocol"), yaml_string("TCP")),
                            (
                                yaml_string("port"),
                                serde_yaml::Value::Number(u64::from(mesh_port).into()),
                            ),
                        ]),
                    )]),
                ),
            ],
        )));
        changed = true;
    }

    if !changed {
        return Ok(());
    }

    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn kubernetes_router_network_policy_peer() -> serde_yaml::Value {
    serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([(
        yaml_string("podSelector"),
        serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([(
            yaml_string("matchLabels"),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([(
                yaml_string("amber.io/component"),
                yaml_string(KUBERNETES_ROUTER_COMPONENT_NAME),
            )])),
        )])),
    )]))
}

fn network_policy_port_matches(port: &serde_yaml::Value, expected_port: u16) -> bool {
    port.as_mapping()
        .and_then(|port| port.get(yaml_string("port")))
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
        })
        == Some(u64::from(expected_port))
}

fn network_policy_peer_is_router(peer: &serde_yaml::Value) -> bool {
    peer.as_mapping()
        .and_then(|peer| peer.get(yaml_string("podSelector")))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|selector| selector.get(yaml_string("matchLabels")))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|labels| labels.get(yaml_string("amber.io/component")))
        .and_then(serde_yaml::Value::as_str)
        == Some(KUBERNETES_ROUTER_COMPONENT_NAME)
}

pub(super) fn dynamic_proxy_export_kubernetes_peer_addr(
    artifact_root: &Path,
    mesh_plan: &MeshProvisionPlan,
    export: &DynamicProxyExportRecord,
) -> Result<String> {
    let component_target = mesh_plan
        .targets
        .iter()
        .find(|target| {
            matches!(target.kind, MeshProvisionTargetKind::Component)
                && target.config.identity.id == export.component
        })
        .ok_or_else(|| {
            miette::miette!(
                "dynamic proxy export provider {} is missing from the kubernetes mesh plan",
                export.component
            )
        })?;
    kubernetes_component_mesh_peer_addr(
        artifact_root,
        &export.component,
        &component_target.output,
        component_target.config.mesh_listen.port(),
    )
}

pub(super) fn project_dynamic_child_mesh_scope(
    artifact_root: &Path,
    mesh_scope: Option<&str>,
) -> Result<()> {
    let Some(mesh_scope) = mesh_scope else {
        return Ok(());
    };
    let path = artifact_root.join("mesh-provision-plan.json");
    if path.is_file() {
        let mut plan: MeshProvisionPlan = read_json(&path, "mesh provision plan")?;
        let existing_scopes = mesh_provision_plan_scopes(&plan);
        if !project_mesh_provision_plan_scope(&mut plan, mesh_scope) {
            return Ok(());
        }
        write_json(&path, &plan)?;
        return rewrite_dynamic_artifact_mesh_scope_literals(
            artifact_root,
            &existing_scopes,
            mesh_scope,
        );
    }

    let compose_path = artifact_root.join("compose.yaml");
    if compose_path.is_file() {
        let mut plan = read_embedded_compose_mesh_provision_plan(artifact_root)?;
        let existing_scopes = mesh_provision_plan_scopes(&plan);
        if !project_mesh_provision_plan_scope(&mut plan, mesh_scope) {
            return Ok(());
        }
        write_embedded_compose_mesh_provision_plan(artifact_root, &plan)?;
        return rewrite_dynamic_artifact_mesh_scope_literals(
            artifact_root,
            &existing_scopes,
            mesh_scope,
        );
    }

    let configmap_path = artifact_root.join(KUBERNETES_MESH_PROVISION_CONFIGMAP_PATH);
    if configmap_path.is_file() {
        let mut plan = read_embedded_kubernetes_mesh_provision_plan(artifact_root)?;
        let existing_scopes = mesh_provision_plan_scopes(&plan);
        if !project_mesh_provision_plan_scope(&mut plan, mesh_scope) {
            return Ok(());
        }
        write_embedded_kubernetes_mesh_provision_plan(artifact_root, &plan)?;
        return rewrite_dynamic_artifact_mesh_scope_literals(
            artifact_root,
            &existing_scopes,
            mesh_scope,
        );
    }

    Err(miette::miette!(
        "dynamic artifact {} is missing a mesh provision plan",
        artifact_root.display()
    ))
}

fn project_mesh_provision_plan_scope(plan: &mut MeshProvisionPlan, mesh_scope: &str) -> bool {
    let mut changed = false;
    for target in &mut plan.targets {
        if target.config.identity.mesh_scope.as_deref() == Some(mesh_scope) {
            continue;
        }
        target.config.identity.mesh_scope = Some(mesh_scope.to_string());
        changed = true;
    }
    changed
}

fn mesh_provision_plan_scopes(plan: &MeshProvisionPlan) -> BTreeSet<String> {
    let mut scopes = BTreeSet::new();
    for target in &plan.targets {
        if let Some(scope) = target.config.identity.mesh_scope.as_deref() {
            scopes.insert(scope.to_string());
        }
    }
    for identity in &plan.existing_peer_identities {
        if let Some(scope) = identity.mesh_scope.as_deref() {
            scopes.insert(scope.to_string());
        }
    }
    scopes
}

fn rewrite_dynamic_artifact_mesh_scope_literals(
    artifact_root: &Path,
    existing_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> Result<()> {
    let rewrite_scopes = existing_scopes
        .iter()
        .filter(|scope| scope.as_str() != mesh_scope)
        .cloned()
        .collect::<BTreeSet<_>>();
    if rewrite_scopes.is_empty() {
        return Ok(());
    }

    for path in walk_files(artifact_root)? {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("json") => rewrite_json_scope_literals(&path, &rewrite_scopes, mesh_scope)?,
            Some("yaml" | "yml") => {
                rewrite_yaml_scope_literals(&path, &rewrite_scopes, mesh_scope)?
            }
            Some("env") => rewrite_env_scope_literals(&path, &rewrite_scopes, mesh_scope)?,
            _ => {}
        }
    }
    Ok(())
}

fn rewrite_json_scope_literals(
    path: &Path,
    rewrite_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> Result<()> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut document: serde_json::Value = serde_json::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid json {}", path.display()))?;
    if !rewrite_scope_json_value(&mut document, rewrite_scopes, mesh_scope) {
        return Ok(());
    }
    let rendered = serde_json::to_string_pretty(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn rewrite_yaml_scope_literals(
    path: &Path,
    rewrite_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> Result<()> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid yaml {}", path.display()))?;
    if !rewrite_scope_yaml_value(&mut document, rewrite_scopes, mesh_scope) {
        return Ok(());
    }
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn rewrite_env_scope_literals(
    path: &Path,
    rewrite_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> Result<()> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut changed = false;
    let mut rendered = raw
        .lines()
        .map(|line| {
            let Some((name, value)) = line.split_once('=') else {
                return line.to_string();
            };
            if !rewrite_scopes.contains(value) {
                return line.to_string();
            }
            changed = true;
            format!("{name}={mesh_scope}")
        })
        .collect::<Vec<_>>()
        .join("\n");
    if !changed {
        return Ok(());
    }
    if raw.ends_with('\n') {
        rendered.push('\n');
    }
    fs::write(path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn rewrite_scope_json_value(
    value: &mut serde_json::Value,
    rewrite_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> bool {
    match value {
        serde_json::Value::String(string) => {
            rewrite_scope_string_value(string, rewrite_scopes, mesh_scope)
        }
        serde_json::Value::Array(values) => {
            let mut changed = false;
            for value in values {
                changed |= rewrite_scope_json_value(value, rewrite_scopes, mesh_scope);
            }
            changed
        }
        serde_json::Value::Object(map) => {
            let mut changed = false;
            for value in map.values_mut() {
                changed |= rewrite_scope_json_value(value, rewrite_scopes, mesh_scope);
            }
            changed
        }
        _ => false,
    }
}

fn rewrite_scope_yaml_value(
    value: &mut serde_yaml::Value,
    rewrite_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> bool {
    match value {
        serde_yaml::Value::String(string) => {
            rewrite_scope_string_value(string, rewrite_scopes, mesh_scope)
        }
        serde_yaml::Value::Sequence(values) => {
            let mut changed = false;
            for value in values {
                changed |= rewrite_scope_yaml_value(value, rewrite_scopes, mesh_scope);
            }
            changed
        }
        serde_yaml::Value::Mapping(map) => {
            let mut changed = false;
            for (_, value) in map.iter_mut() {
                changed |= rewrite_scope_yaml_value(value, rewrite_scopes, mesh_scope);
            }
            changed
        }
        _ => false,
    }
}

fn rewrite_scope_string_value(
    string: &mut String,
    rewrite_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> bool {
    if rewrite_scopes.contains(string) {
        *string = mesh_scope.to_string();
        return true;
    }
    let Some((name, value)) = string.split_once('=') else {
        return false;
    };
    if !rewrite_scopes.contains(value) {
        return false;
    }
    *string = format!("{name}={mesh_scope}");
    true
}

fn load_kubernetes_mesh_secret_payload(
    plan: &SiteControllerRuntimePlan,
    name: &str,
    namespace: Option<&str>,
) -> Result<(String, KubernetesSecretPayload)> {
    let namespace = namespace
        .or(plan.kubernetes_namespace.as_deref())
        .ok_or_else(|| {
            miette::miette!(
                "kubernetes site `{}` is missing its namespace",
                plan.site_id
            )
        })?
        .to_string();
    let output = kubectl_command(plan.context.as_deref())
        .arg("-n")
        .arg(&namespace)
        .arg("get")
        .arg("secret")
        .arg(name)
        .arg("-o")
        .arg("json")
        .output()
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to read kubernetes mesh secret {} in namespace {}",
                name, namespace
            )
        })?;
    if !output.status.success() {
        return Err(miette::miette!(
            "failed to read kubernetes mesh secret {} in namespace {}: {}",
            name,
            namespace,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let payload: KubernetesSecretPayload =
        serde_json::from_slice(&output.stdout).map_err(|err| {
            miette::miette!(
                "invalid kubernetes secret payload for {} in namespace {}: {err}",
                name,
                namespace
            )
        })?;
    Ok((namespace, payload))
}

fn decode_kubernetes_mesh_secret_json<T>(
    payload: &KubernetesSecretPayload,
    namespace: &str,
    name: &str,
    key: &str,
    description: &str,
) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let encoded = payload.data.get(key).ok_or_else(|| {
        miette::miette!(
            "kubernetes mesh secret {} in namespace {} is missing {}",
            name,
            namespace,
            key
        )
    })?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to decode kubernetes {description} {} in namespace {}",
                name, namespace
            )
        })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        miette::miette!(
            "invalid kubernetes {description} {} in namespace {}: {err}",
            name,
            namespace
        )
    })
}

pub(super) fn load_kubernetes_mesh_identity_secret(
    plan: &SiteControllerRuntimePlan,
    name: &str,
    namespace: Option<&str>,
) -> Result<MeshIdentitySecret> {
    let (namespace, payload) = load_kubernetes_mesh_secret_payload(plan, name, namespace)?;
    decode_kubernetes_mesh_secret_json(
        &payload,
        &namespace,
        name,
        MESH_IDENTITY_FILENAME,
        "mesh identity",
    )
}

fn load_kubernetes_mesh_config_public(
    plan: &SiteControllerRuntimePlan,
    name: &str,
    namespace: Option<&str>,
) -> Result<MeshConfigPublic> {
    let (namespace, payload) = load_kubernetes_mesh_secret_payload(plan, name, namespace)?;
    decode_kubernetes_mesh_secret_json(
        &payload,
        &namespace,
        name,
        MESH_CONFIG_FILENAME,
        "mesh config",
    )
}

pub(super) fn reconcile_site_proxy_metadata(
    site_artifact_root: &Path,
    site_artifact_files: &BTreeMap<String, String>,
) -> Result<()> {
    let Some(proxy_metadata) = site_artifact_files.get("amber-proxy.json") else {
        return Ok(());
    };
    let path = site_artifact_root.join("amber-proxy.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, proxy_metadata)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}
