use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde_json::json;

use super::*;

const KUBERNETES_ROUTER_NAME: &str = "amber-router";
const KUBERNETES_ROUTER_MESH_PORT: u16 = 24000;
const KUBERNETES_ROUTER_CONTROL_PORT: u16 = 24100;
const KUBERNETES_ROUTER_SERVICE_PATH: &str = "04-services/amber-router.yaml";
const KUBERNETES_ROUTER_NETPOL_PATH: &str = "05-networkpolicies/amber-router-netpol.yaml";
const KUBERNETES_CONTROLLER_NETPOL_PATH: &str =
    "05-networkpolicies/amber-site-controller-netpol.yaml";
const KUBERNETES_CONTROLLER_SEED_SECRET_PATH: &str = "01-secrets/amber-site-controller-seed.yaml";
const KUBERNETES_CONTROLLER_SEED_SECRET_PATH_PREFIX: &str = "01-secrets/amber-site-controller-seed";
const KUBERNETES_CONTROLLER_SEED_SECRET_DATA_LIMIT: usize = 64 * 1024;
const KUBERNETES_CONTROLLER_SERVICE_ACCOUNT_PATH: &str = "02-rbac/amber-site-controller-sa.yaml";
const KUBERNETES_CONTROLLER_ROLE_PATH: &str = "02-rbac/amber-site-controller-role.yaml";
const KUBERNETES_CONTROLLER_ROLE_BINDING_PATH: &str =
    "02-rbac/amber-site-controller-rolebinding.yaml";
const KUBERNETES_CONTROLLER_DEPLOYMENT_PATH: &str = "03-deployments/amber-site-controller.yaml";
const KUBERNETES_CONTROLLER_STATE_PVC_PATH: &str =
    "03-persistentvolumeclaims/amber-site-controller-state.yaml";
#[cfg(test)]
const KUBERNETES_CONTROLLER_SERVICE_PATH: &str = "04-services/amber-site-controller.yaml";
const KUBERNETES_CONTROLLER_SEED_VOLUME: &str = "controller-seed";
const KUBERNETES_CONTROLLER_STATE_VOLUME: &str = "controller-state";
const KUBERNETES_CONTROLLER_STATE_PVC_NAME: &str = "amber-site-controller-state";
const KUBERNETES_CONTROLLER_STATE_STORAGE_REQUEST: &str = "1Gi";
const KUBERNETES_CONTROLLER_SITE_ROOT: &str = "/amber/site";
const KUBERNETES_CONTROLLER_STATE_ROOT: &str = "/amber/site/state";
const KUBERNETES_CONTROLLER_ARTIFACT_ROOT: &str = "/amber/site/artifact";
const KUBERNETES_CONTROLLER_PLAN_PATH: &str = "/amber/site/state/site-controller-plan.json";
const KUBERNETES_CONTROLLER_STATE_PATH: &str = "/amber/site/state/site-controller-state.json";
const KUBERNETES_CONTROLLER_DESIRED_LINKS_PATH: &str = "/amber/site/state/desired-links.json";
const KUBERNETES_CONTROLLER_SEED_ROOT: &str = "/amber/seed";

#[derive(Clone, Debug)]
struct KubernetesControllerSeedSecret {
    path: String,
    name: String,
    items: Vec<serde_json::Value>,
    document: serde_json::Value,
}

pub fn inject_kubernetes_site_controller(
    artifact_root: &Path,
    plan: &SiteControllerPlan,
    controller_image: &str,
) -> Result<()> {
    let embedded_plan = build_embedded_kubernetes_controller_plan(plan);
    let seed_secrets =
        build_kubernetes_controller_seed_secrets(artifact_root, plan, &embedded_plan)?;
    let labels = kubernetes_controller_labels();

    for secret in &seed_secrets {
        write_yaml_artifact(artifact_root.join(&secret.path), &secret.document)?;
    }
    write_yaml_artifact(
        artifact_root.join(KUBERNETES_CONTROLLER_STATE_PVC_PATH),
        &json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": KUBERNETES_CONTROLLER_STATE_PVC_NAME,
                "labels": labels,
            },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": {
                    "requests": {
                        "storage": KUBERNETES_CONTROLLER_STATE_STORAGE_REQUEST,
                    },
                },
            },
        }),
    )?;
    write_yaml_artifact(
        artifact_root.join(KUBERNETES_CONTROLLER_SERVICE_ACCOUNT_PATH),
        &json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": SITE_CONTROLLER_SERVICE_NAME,
                "labels": labels,
            }
        }),
    )?;
    write_yaml_artifact(
        artifact_root.join(KUBERNETES_CONTROLLER_ROLE_PATH),
        &json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {
                "name": SITE_CONTROLLER_SERVICE_NAME,
                "labels": labels,
            },
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": [
                        "configmaps",
                        "persistentvolumeclaims",
                        "secrets",
                        "serviceaccounts",
                        "services"
                    ],
                    "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"],
                },
                {
                    "apiGroups": ["apps"],
                    "resources": ["deployments"],
                    "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"],
                },
                {
                    "apiGroups": ["batch"],
                    "resources": ["jobs"],
                    "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"],
                },
                {
                    "apiGroups": ["networking.k8s.io"],
                    "resources": ["networkpolicies"],
                    "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"],
                },
                {
                    "apiGroups": ["rbac.authorization.k8s.io"],
                    "resources": ["roles", "rolebindings"],
                    "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"],
                }
            ]
        }),
    )?;
    write_yaml_artifact(
        artifact_root.join(KUBERNETES_CONTROLLER_ROLE_BINDING_PATH),
        &json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {
                "name": SITE_CONTROLLER_SERVICE_NAME,
                "labels": labels,
            },
            "subjects": [{
                "kind": "ServiceAccount",
                "name": SITE_CONTROLLER_SERVICE_NAME,
            }],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": SITE_CONTROLLER_SERVICE_NAME,
            }
        }),
    )?;
    patch_kubernetes_controller_deployment(
        artifact_root.join(KUBERNETES_CONTROLLER_DEPLOYMENT_PATH),
        plan,
        controller_image,
        &seed_secrets,
    )?;
    let mut resource_paths = seed_secrets
        .iter()
        .map(|secret| secret.path.as_str())
        .collect::<Vec<_>>();
    resource_paths.extend([
        KUBERNETES_CONTROLLER_STATE_PVC_PATH,
        KUBERNETES_CONTROLLER_SERVICE_ACCOUNT_PATH,
        KUBERNETES_CONTROLLER_ROLE_PATH,
        KUBERNETES_CONTROLLER_ROLE_BINDING_PATH,
    ]);
    add_kubernetes_resource_paths(artifact_root, &resource_paths)?;
    let peer_router_route_ports = peer_router_route_ports(&embedded_plan)?;
    ensure_kubernetes_router_allows_site_controller_ingress(
        artifact_root,
        &peer_router_route_ports,
    )?;
    ensure_kubernetes_site_controller_allows_router_egress(artifact_root, &peer_router_route_ports)
}

fn upsert_named_sequence_entry(
    sequence: &mut serde_yaml::Sequence,
    name: &str,
    value: serde_yaml::Value,
) {
    if let Some(existing) = sequence.iter_mut().find(|entry| {
        entry
            .as_mapping()
            .and_then(|mapping| mapping.get(yaml_string("name")))
            .and_then(serde_yaml::Value::as_str)
            .is_some_and(|existing| existing == name)
    }) {
        *existing = value;
    } else {
        sequence.push(value);
    }
}

fn merge_kubernetes_controller_env(
    container: &mut serde_yaml::Mapping,
    plan: &SiteControllerPlan,
) -> Result<()> {
    if plan.launch_env.is_empty() {
        return Ok(());
    }
    let env = container
        .entry(yaml_string("env"))
        .or_insert_with(|| serde_yaml::Value::Sequence(Vec::new()))
        .as_sequence_mut()
        .ok_or_else(|| miette::miette!("controller deployment env must be a sequence"))?;
    for (name, value) in &plan.launch_env {
        upsert_named_sequence_entry(
            env,
            name,
            serde_yaml::to_value(json!({ "name": name, "value": value }))
                .into_diagnostic()
                .wrap_err("failed to serialize controller env entry")?,
        );
    }
    Ok(())
}

fn ensure_kubernetes_volume_mount(
    container: &mut serde_yaml::Mapping,
    name: &str,
    mount_path: &str,
    read_only: Option<bool>,
) -> Result<()> {
    let mounts = container
        .entry(yaml_string("volumeMounts"))
        .or_insert_with(|| serde_yaml::Value::Sequence(Vec::new()))
        .as_sequence_mut()
        .ok_or_else(|| miette::miette!("controller deployment volumeMounts must be a sequence"))?;
    let mut mount = json!({
        "name": name,
        "mountPath": mount_path,
    });
    if let Some(read_only) = read_only {
        mount["readOnly"] = serde_json::Value::Bool(read_only);
    }
    upsert_named_sequence_entry(
        mounts,
        name,
        serde_yaml::to_value(mount)
            .into_diagnostic()
            .wrap_err("failed to serialize controller volume mount")?,
    );
    Ok(())
}

fn patch_kubernetes_controller_deployment(
    path: PathBuf,
    plan: &SiteControllerPlan,
    controller_image: &str,
    seed_secrets: &[KubernetesControllerSeedSecret],
) -> Result<()> {
    let raw = fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut deployment: serde_yaml::Value = serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid {}", path.display()))?;
    let pod_spec = deployment
        .as_mapping_mut()
        .and_then(|root| root.get_mut(yaml_string("spec")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .and_then(|spec| spec.get_mut(yaml_string("template")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .and_then(|template| template.get_mut(yaml_string("spec")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| {
            miette::miette!(
                "controller deployment {} is missing spec.template.spec",
                path.display()
            )
        })?;
    pod_spec.insert(
        yaml_string("serviceAccountName"),
        yaml_string(SITE_CONTROLLER_SERVICE_NAME),
    );
    pod_spec.insert(
        yaml_string("automountServiceAccountToken"),
        serde_yaml::Value::Bool(true),
    );

    let init_containers = pod_spec
        .entry(yaml_string("initContainers"))
        .or_insert_with(|| serde_yaml::Value::Sequence(Vec::new()))
        .as_sequence_mut()
        .ok_or_else(|| {
            miette::miette!("controller deployment initContainers must be a sequence")
        })?;
    upsert_named_sequence_entry(
        init_containers,
        "seed-site-controller",
        serde_yaml::to_value(json!({
            "name": "seed-site-controller",
            "image": controller_image,
            "command": [
                "sh",
                "-lc",
                format!(
                    "set -eu
seed_if_missing() {{
  src=\"$1\"
  dest=\"$2\"
  if [ ! -e \"$dest\" ]; then
    cp \"$src\" \"$dest\"
  fi
}}
mkdir -p {KUBERNETES_CONTROLLER_STATE_ROOT} \
         {KUBERNETES_CONTROLLER_ARTIFACT_ROOT}
cp {KUBERNETES_CONTROLLER_SEED_ROOT}/site-controller-plan.json \
   {KUBERNETES_CONTROLLER_PLAN_PATH}
seed_if_missing {KUBERNETES_CONTROLLER_SEED_ROOT}/site-controller-state.json \
                {KUBERNETES_CONTROLLER_STATE_PATH}
seed_if_missing {KUBERNETES_CONTROLLER_SEED_ROOT}/desired-links.json \
                {KUBERNETES_CONTROLLER_DESIRED_LINKS_PATH}
if [ -d {KUBERNETES_CONTROLLER_SEED_ROOT}/artifact ]; then
  rm -rf {KUBERNETES_CONTROLLER_ARTIFACT_ROOT}
  mkdir -p {KUBERNETES_CONTROLLER_ARTIFACT_ROOT}
  cp -R {KUBERNETES_CONTROLLER_SEED_ROOT}/artifact/. \
    {KUBERNETES_CONTROLLER_ARTIFACT_ROOT}
fi
"
                )
            ],
            "volumeMounts": [
                {
                    "name": KUBERNETES_CONTROLLER_SEED_VOLUME,
                    "mountPath": KUBERNETES_CONTROLLER_SEED_ROOT,
                    "readOnly": true,
                },
                {
                    "name": KUBERNETES_CONTROLLER_STATE_VOLUME,
                    "mountPath": KUBERNETES_CONTROLLER_SITE_ROOT,
                }
            ]
        }))
        .into_diagnostic()
        .wrap_err("failed to serialize controller seed init container")?,
    );

    let containers = pod_spec
        .get_mut(yaml_string("containers"))
        .and_then(serde_yaml::Value::as_sequence_mut)
        .ok_or_else(|| {
            miette::miette!("controller deployment is missing spec.template.spec.containers")
        })?;
    let main_index = containers
        .iter()
        .position(|container| {
            container
                .as_mapping()
                .and_then(|mapping| mapping.get(yaml_string("name")))
                .and_then(serde_yaml::Value::as_str)
                .is_some_and(|name| name == "main")
        })
        .unwrap_or(0);
    let main = containers
        .get_mut(main_index)
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| miette::miette!("controller deployment has no mutable main container"))?;
    main.insert(yaml_string("image"), yaml_string(controller_image));
    merge_kubernetes_controller_env(main, plan)?;
    ensure_kubernetes_volume_mount(
        main,
        KUBERNETES_CONTROLLER_STATE_VOLUME,
        KUBERNETES_CONTROLLER_SITE_ROOT,
        None,
    )?;

    let volumes = pod_spec
        .entry(yaml_string("volumes"))
        .or_insert_with(|| serde_yaml::Value::Sequence(Vec::new()))
        .as_sequence_mut()
        .ok_or_else(|| miette::miette!("controller deployment volumes must be a sequence"))?;
    let seed_sources = seed_secrets
        .iter()
        .map(|secret| {
            json!({
                "secret": {
                    "name": secret.name.clone(),
                    "items": secret.items.clone(),
                }
            })
        })
        .collect::<Vec<_>>();
    upsert_named_sequence_entry(
        volumes,
        KUBERNETES_CONTROLLER_SEED_VOLUME,
        serde_yaml::to_value(json!({
            "name": KUBERNETES_CONTROLLER_SEED_VOLUME,
            "projected": {
                "sources": seed_sources,
            }
        }))
        .into_diagnostic()
        .wrap_err("failed to serialize controller seed volume")?,
    );
    upsert_named_sequence_entry(
        volumes,
        KUBERNETES_CONTROLLER_STATE_VOLUME,
        serde_yaml::to_value(json!({
            "name": KUBERNETES_CONTROLLER_STATE_VOLUME,
            "persistentVolumeClaim": {
                "claimName": KUBERNETES_CONTROLLER_STATE_PVC_NAME,
            }
        }))
        .into_diagnostic()
        .wrap_err("failed to serialize controller state volume")?,
    );

    write_yaml_artifact(path, &deployment)
}

fn build_embedded_kubernetes_controller_plan(plan: &SiteControllerPlan) -> SiteControllerPlan {
    let mut embedded = plan.clone();
    let port = plan.listen_addr.port();
    embedded.listen_addr = SocketAddr::from(([0, 0, 0, 0], port));
    embedded.authority_url = format!("http://{SITE_CONTROLLER_SERVICE_NAME}:{port}");
    embedded.local_router_control = Some(format!(
        "{KUBERNETES_ROUTER_NAME}:{KUBERNETES_ROUTER_CONTROL_PORT}"
    ));
    embedded.run_root = format!("{KUBERNETES_CONTROLLER_SITE_ROOT}/run");
    embedded.state_root = format!("{KUBERNETES_CONTROLLER_SITE_ROOT}/state-root");
    embedded.site_state_root = KUBERNETES_CONTROLLER_STATE_ROOT.to_string();
    embedded.artifact_dir = KUBERNETES_CONTROLLER_ARTIFACT_ROOT.to_string();
    embedded.state_path = KUBERNETES_CONTROLLER_STATE_PATH.to_string();
    embedded.context = None;
    embedded.storage_root = None;
    embedded.runtime_root = None;
    embedded.compose_project = None;
    embedded.kubernetes_namespace = plan.kubernetes_namespace.clone();
    embedded.router_mesh_port = Some(KUBERNETES_ROUTER_MESH_PORT);
    embedded
}

fn build_kubernetes_controller_seed_secrets(
    artifact_root: &Path,
    plan: &SiteControllerPlan,
    embedded_plan: &SiteControllerPlan,
) -> Result<Vec<KubernetesControllerSeedSecret>> {
    let seed_files = build_kubernetes_controller_seed_files(artifact_root, plan, embedded_plan)?;
    let mut chunks = Vec::<Vec<(String, String)>>::new();
    let mut current = Vec::<(String, String)>::new();
    let mut current_size = 0usize;
    for (path, contents) in seed_files {
        let entry_size = path.len() + contents.len();
        if !current.is_empty()
            && current_size + entry_size > KUBERNETES_CONTROLLER_SEED_SECRET_DATA_LIMIT
        {
            chunks.push(current);
            current = Vec::new();
            current_size = 0;
        }
        current.push((path, contents));
        current_size += entry_size;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, files)| render_kubernetes_controller_seed_secret(index, files))
        .collect()
}

fn build_kubernetes_controller_seed_files(
    artifact_root: &Path,
    plan: &SiteControllerPlan,
    embedded_plan: &SiteControllerPlan,
) -> Result<Vec<(String, String)>> {
    let state_json = fs::read_to_string(&plan.state_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", plan.state_path))?;
    let desired_links = super::desired_links_path(Path::new(&plan.site_state_root));
    let desired_links_json = fs::read_to_string(&desired_links)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", desired_links.display()))?;
    let embedded_plan_json = serde_json::to_string_pretty(embedded_plan)
        .into_diagnostic()
        .wrap_err("failed to serialize embedded kubernetes site controller plan")?;
    let mut files = BTreeMap::from([
        ("site-controller-plan.json".to_string(), embedded_plan_json),
        ("site-controller-state.json".to_string(), state_json),
        ("desired-links.json".to_string(), desired_links_json),
    ]);
    for path in walk_files(artifact_root)? {
        let relative = path
            .strip_prefix(artifact_root)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to relativize {}", path.display()))?;
        let relative = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let contents = fs::read_to_string(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read {}", path.display()))?;
        files.insert(format!("artifact/{relative}"), contents);
    }
    Ok(files.into_iter().collect())
}

fn render_kubernetes_controller_seed_secret(
    index: usize,
    files: Vec<(String, String)>,
) -> Result<KubernetesControllerSeedSecret> {
    let name = if index == 0 {
        format!("{SITE_CONTROLLER_SERVICE_NAME}-seed")
    } else {
        format!("{SITE_CONTROLLER_SERVICE_NAME}-seed-{index}")
    };
    let path = if index == 0 {
        KUBERNETES_CONTROLLER_SEED_SECRET_PATH.to_string()
    } else {
        format!("{KUBERNETES_CONTROLLER_SEED_SECRET_PATH_PREFIX}-{index}.yaml")
    };
    let mut string_data = serde_json::Map::new();
    let mut items = Vec::with_capacity(files.len());
    for (entry_index, (relative_path, contents)) in files.into_iter().enumerate() {
        let key = format!("seed-{entry_index:04}");
        string_data.insert(key.clone(), serde_json::Value::String(contents));
        items.push(json!({
            "key": key,
            "path": relative_path,
        }));
    }
    Ok(KubernetesControllerSeedSecret {
        path,
        name: name.clone(),
        items,
        document: json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "labels": kubernetes_controller_labels(),
            },
            "type": "Opaque",
            "stringData": string_data,
        }),
    })
}

fn add_kubernetes_resource_paths(artifact_root: &Path, paths: &[&str]) -> Result<()> {
    let kustomization_path = artifact_root.join("kustomization.yaml");
    let raw = fs::read_to_string(&kustomization_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", kustomization_path.display()))?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid {}", kustomization_path.display()))?;
    let resources = document
        .as_mapping_mut()
        .and_then(|root| root.get_mut(yaml_string("resources")))
        .and_then(serde_yaml::Value::as_sequence_mut)
        .ok_or_else(|| {
            miette::miette!(
                "kustomization {} is missing a resources sequence",
                kustomization_path.display()
            )
        })?;
    for path in paths {
        if resources
            .iter()
            .any(|value| value.as_str().is_some_and(|existing| existing == *path))
        {
            continue;
        }
        resources.push(yaml_string(path));
    }
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", kustomization_path.display()))?;
    fs::write(&kustomization_path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", kustomization_path.display()))
}

fn peer_router_route_ports(plan: &SiteControllerPlan) -> Result<BTreeSet<u16>> {
    plan.peer_site_router_urls
        .values()
        .map(|url| {
            let parsed = Url::parse(url)
                .into_diagnostic()
                .wrap_err_with(|| format!("invalid peer router url `{url}`"))?;
            parsed
                .port()
                .ok_or_else(|| miette::miette!("peer router url `{url}` is missing a route port"))
        })
        .collect()
}

fn ensure_kubernetes_router_service_ports(
    artifact_root: &Path,
    route_ports: &BTreeSet<u16>,
) -> Result<()> {
    if route_ports.is_empty() {
        return Ok(());
    }
    let path = artifact_root.join(KUBERNETES_ROUTER_SERVICE_PATH);
    let raw = fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid {}", path.display()))?;
    let ports = document
        .as_mapping_mut()
        .and_then(|root| root.get_mut(yaml_string("spec")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .and_then(|spec| spec.get_mut(yaml_string("ports")))
        .and_then(serde_yaml::Value::as_sequence_mut)
        .ok_or_else(|| {
            miette::miette!("router service {} is missing spec.ports", path.display())
        })?;
    let existing = ports
        .iter()
        .filter_map(|entry| {
            entry
                .as_mapping()
                .and_then(|mapping| mapping.get(yaml_string("port")))
                .and_then(serde_yaml::Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
        })
        .collect::<BTreeSet<_>>();
    for port in route_ports {
        if existing.contains(port) {
            continue;
        }
        ports.push(
            serde_yaml::to_value(json!({
                "name": format!("controller-route-{port}"),
                "port": port,
                "targetPort": port,
                "protocol": "TCP",
            }))
            .into_diagnostic()
            .wrap_err("failed to serialize router service route port")?,
        );
    }
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(&path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn ensure_kubernetes_router_allows_site_controller_ingress(
    artifact_root: &Path,
    route_ports: &BTreeSet<u16>,
) -> Result<()> {
    ensure_kubernetes_router_service_ports(artifact_root, route_ports)?;
    let path = artifact_root.join(KUBERNETES_ROUTER_NETPOL_PATH);
    let raw = fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid {}", path.display()))?;
    let ingress = document
        .as_mapping_mut()
        .and_then(|root| root.get_mut(yaml_string("spec")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .and_then(|spec| spec.get_mut(yaml_string("ingress")))
        .and_then(serde_yaml::Value::as_sequence_mut)
        .ok_or_else(|| {
            miette::miette!(
                "router network policy {} is missing spec.ingress",
                path.display()
            )
        })?;
    let controller_selector = kubernetes_controller_selector();
    let controller_component = controller_selector
        .get("amber.io/component")
        .expect("selector must contain component");
    let mut required_ports = BTreeSet::from([KUBERNETES_ROUTER_CONTROL_PORT]);
    required_ports.extend(route_ports.iter().copied());
    if let Some(rule) = ingress.iter_mut().find(|rule| {
        rule.as_mapping()
            .and_then(|mapping| mapping.get(yaml_string("from")))
            .and_then(serde_yaml::Value::as_sequence)
            .is_some_and(|from| {
                from.iter().any(|peer| {
                    peer.as_mapping()
                        .and_then(|mapping| mapping.get(yaml_string("podSelector")))
                        .and_then(serde_yaml::Value::as_mapping)
                        .and_then(|selector_value| selector_value.get(yaml_string("matchLabels")))
                        .and_then(serde_yaml::Value::as_mapping)
                        .is_some_and(|labels| {
                            labels.get(yaml_string("amber.io/component"))
                                == Some(&yaml_string(controller_component))
                        })
                })
            })
    }) {
        let ports = rule
            .as_mapping_mut()
            .and_then(|mapping| mapping.get_mut(yaml_string("ports")))
            .and_then(serde_yaml::Value::as_sequence_mut)
            .ok_or_else(|| {
                miette::miette!(
                    "router network policy {} controller ingress rule is missing ports",
                    path.display()
                )
            })?;
        let existing_ports = ports
            .iter()
            .filter_map(|port| {
                port.as_mapping()
                    .and_then(|entry| entry.get(yaml_string("port")))
                    .and_then(serde_yaml::Value::as_u64)
                    .and_then(|port| u16::try_from(port).ok())
            })
            .collect::<BTreeSet<_>>();
        for port in required_ports {
            if existing_ports.contains(&port) {
                continue;
            }
            ports.push(
                serde_yaml::to_value(json!({
                    "protocol": "TCP",
                    "port": port,
                }))
                .into_diagnostic()
                .wrap_err("failed to serialize site controller router ingress port")?,
            );
        }
    } else {
        ingress.push(
            serde_yaml::to_value(json!({
                "from": [{
                    "podSelector": {
                        "matchLabels": controller_selector,
                    }
                }],
                "ports": required_ports.into_iter().map(|port| json!({
                    "protocol": "TCP",
                    "port": port,
                })).collect::<Vec<_>>()
            }))
            .into_diagnostic()
            .wrap_err("failed to serialize site controller router ingress rule")?,
        );
    }
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(&path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn ensure_kubernetes_site_controller_allows_router_egress(
    artifact_root: &Path,
    route_ports: &BTreeSet<u16>,
) -> Result<()> {
    if route_ports.is_empty() {
        return Ok(());
    }
    let path = artifact_root.join(KUBERNETES_CONTROLLER_NETPOL_PATH);
    let raw = fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid {}", path.display()))?;
    let egress = document
        .as_mapping_mut()
        .and_then(|root| root.get_mut(yaml_string("spec")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .and_then(|spec| spec.get_mut(yaml_string("egress")))
        .and_then(serde_yaml::Value::as_sequence_mut)
        .ok_or_else(|| {
            miette::miette!(
                "site controller network policy {} is missing spec.egress",
                path.display()
            )
        })?;
    let router_selector = BTreeMap::from([(
        "amber.io/component".to_string(),
        KUBERNETES_ROUTER_NAME.to_string(),
    )]);
    if let Some(rule) = egress.iter_mut().find(|rule| {
        rule.as_mapping()
            .and_then(|mapping| mapping.get(yaml_string("to")))
            .and_then(serde_yaml::Value::as_sequence)
            .is_some_and(|to| {
                to.iter().any(|peer| {
                    peer.as_mapping()
                        .and_then(|mapping| mapping.get(yaml_string("podSelector")))
                        .and_then(serde_yaml::Value::as_mapping)
                        .and_then(|selector_value| selector_value.get(yaml_string("matchLabels")))
                        .and_then(serde_yaml::Value::as_mapping)
                        .is_some_and(|labels| {
                            labels.get(yaml_string("amber.io/component"))
                                == Some(&yaml_string(KUBERNETES_ROUTER_NAME))
                        })
                })
            })
    }) {
        let ports = rule
            .as_mapping_mut()
            .and_then(|mapping| mapping.get_mut(yaml_string("ports")))
            .and_then(serde_yaml::Value::as_sequence_mut)
            .ok_or_else(|| {
                miette::miette!(
                    "site controller network policy {} router egress rule is missing ports",
                    path.display()
                )
            })?;
        let existing_ports = ports
            .iter()
            .filter_map(|port| {
                port.as_mapping()
                    .and_then(|entry| entry.get(yaml_string("port")))
                    .and_then(serde_yaml::Value::as_u64)
                    .and_then(|port| u16::try_from(port).ok())
            })
            .collect::<BTreeSet<_>>();
        for port in route_ports {
            if existing_ports.contains(port) {
                continue;
            }
            ports.push(
                serde_yaml::to_value(json!({
                    "protocol": "TCP",
                    "port": port,
                }))
                .into_diagnostic()
                .wrap_err("failed to serialize site controller router egress port")?,
            );
        }
    } else {
        egress.push(
            serde_yaml::to_value(json!({
                "to": [{
                    "podSelector": {
                        "matchLabels": router_selector,
                    }
                }],
                "ports": route_ports.iter().map(|port| json!({
                    "protocol": "TCP",
                    "port": port,
                })).collect::<Vec<_>>()
            }))
            .into_diagnostic()
            .wrap_err("failed to serialize site controller router egress rule")?,
        );
    }
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(&path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn kubernetes_controller_labels() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "app.kubernetes.io/managed-by".to_string(),
            "amber".to_string(),
        ),
        (
            "amber.io/component".to_string(),
            SITE_CONTROLLER_SERVICE_NAME.to_string(),
        ),
        ("amber.io/type".to_string(), "site-controller".to_string()),
    ])
}

fn kubernetes_controller_selector() -> BTreeMap<String, String> {
    BTreeMap::from([(
        "amber.io/component".to_string(),
        SITE_CONTROLLER_SERVICE_NAME.to_string(),
    )])
}

fn write_yaml_artifact(path: PathBuf, value: &impl serde::Serialize) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        miette::miette!("artifact path {} has no parent directory", path.display())
    })?;
    fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    let rendered = serde_yaml::to_string(value)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    let mut file = fs::File::create(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", path.display()))?;
    file.write_all(rendered.as_bytes())
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};

    use amber_compiler::run_plan::SiteKind;

    use super::*;

    fn test_plan(root: &Path) -> SiteControllerPlan {
        let controller_port = 32123;
        SiteControllerPlan {
            schema: "amber.framework_component.site_controller_plan".to_string(),
            version: 1,
            run_id: "run-test".to_string(),
            mesh_scope: "scope".to_string(),
            site_id: "kind_local".to_string(),
            kind: SiteKind::Kubernetes,
            listen_addr: SocketAddr::from(([127, 0, 0, 1], controller_port)),
            authority_url: format!("http://amber-site-controller:{controller_port}"),
            router_identity_id: "/site/kind_local/router".to_string(),
            peer_site_router_urls: BTreeMap::new(),
            peer_router_identities: BTreeMap::new(),
            peer_router_mesh_addrs: BTreeMap::new(),
            local_router_control: Some("amber-router:24100".to_string()),
            published_router_mesh_addr: Some("127.0.0.1:24000".to_string()),
            compose_consumer_router_mesh_addr: Some("host.docker.internal:24000".to_string()),
            kubernetes_consumer_router_mesh_addr: Some("192.168.65.254:24000".to_string()),
            state_path: root.join("state.json").display().to_string(),
            run_root: root.join("run").display().to_string(),
            state_root: root.join("state-root").display().to_string(),
            site_state_root: root.join("site-state").display().to_string(),
            artifact_dir: root.join("artifact").display().to_string(),
            control_state_auth_token: "token".to_string(),
            controller_identity_path: None,
            storage_root: None,
            runtime_root: None,
            router_mesh_port: Some(24000),
            compose_project: None,
            kubernetes_namespace: Some("test-ns".to_string()),
            context: Some("test-context".to_string()),
            observability_endpoint: None,
            vm_endpoint_forward_ready_timeout_secs: None,
            launch_env: BTreeMap::from([(
                "AMBER_DEV_IMAGE_TAGS".to_string(),
                "router=dev-tag,helper=dev-tag".to_string(),
            )]),
        }
    }

    fn write_kubernetes_controller_fixture(artifact_root: &Path) {
        fs::create_dir_all(artifact_root.join("04-services")).expect("services dir");
        fs::create_dir_all(artifact_root.join("05-networkpolicies")).expect("netpol dir");
        fs::create_dir_all(artifact_root.join("03-deployments")).expect("deployments dir");
        fs::write(
            artifact_root.join("kustomization.yaml"),
            "resources:\n  - 03-deployments/amber-site-controller.yaml\n  - \
             04-services/amber-site-controller.yaml\n  - 04-services/amber-router.yaml\n  - \
             05-networkpolicies/amber-router-netpol.yaml\n  - \
             05-networkpolicies/amber-site-controller-netpol.yaml\n",
        )
        .expect("kustomization should write");
        fs::write(
            artifact_root.join(KUBERNETES_ROUTER_SERVICE_PATH),
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: amber-router\nspec:\n  ports:\n    \
             - name: mesh\n      port: 24000\n      targetPort: 24000\n      protocol: TCP\n",
        )
        .expect("router service should write");
        fs::write(
            artifact_root.join(KUBERNETES_ROUTER_NETPOL_PATH),
            "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: \
             amber-router-netpol\nspec:\n  ingress: []\n",
        )
        .expect("router netpol should write");
        fs::write(
            artifact_root.join(KUBERNETES_CONTROLLER_NETPOL_PATH),
            r#"
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: amber-site-controller-netpol
spec:
  egress:
  - to:
    - podSelector:
        matchLabels:
          amber.io/component: amber-router
    ports:
    - protocol: TCP
      port: 24000
    - protocol: TCP
      port: 24100
"#,
        )
        .expect("site controller netpol should write");
        fs::write(
            artifact_root.join(KUBERNETES_CONTROLLER_DEPLOYMENT_PATH),
            r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: amber-site-controller
spec:
  template:
    spec:
      containers:
        - name: main
          image: __amber_internal/site-controller
          args:
            - --plan
            - /amber/site/state/site-controller-plan.json
          env:
            - name: EXISTING_ENV
              value: kept
        - name: sidecar
          image: ghcr.io/rdi-foundation/amber-router:test
"#,
        )
        .expect("controller deployment should write");
        fs::write(
            artifact_root.join(KUBERNETES_CONTROLLER_SERVICE_PATH),
            r#"
apiVersion: v1
kind: Service
metadata:
  name: amber-site-controller
spec:
  ports:
    - name: framework-component
      port: 32123
      targetPort: 32123
      protocol: TCP
"#,
        )
        .expect("controller service should write");
    }

    fn write_controller_state(plan: &SiteControllerPlan) {
        fs::write(&plan.state_path, "{}").expect("state should write");
        fs::create_dir_all(&plan.site_state_root).expect("site state dir");
        fs::write(
            super::desired_links_path(Path::new(&plan.site_state_root)),
            "{}",
        )
        .expect("desired links should write");
    }

    fn seed_secret_paths(artifact_root: &Path) -> Vec<PathBuf> {
        let mut paths =
            walk_files(&artifact_root.join("01-secrets")).expect("seed secrets should list");
        paths.sort();
        paths
    }

    fn controller_pod_spec(deployment: &serde_yaml::Value) -> &serde_yaml::Mapping {
        deployment
            .as_mapping()
            .and_then(|root| root.get(yaml_string("spec")))
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|spec| spec.get(yaml_string("template")))
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|template| template.get(yaml_string("spec")))
            .and_then(serde_yaml::Value::as_mapping)
            .expect("controller deployment should include a pod spec")
    }

    #[test]
    fn inject_kubernetes_site_controller_propagates_launch_env() {
        let temp = tempfile::tempdir().expect("temp dir");
        let artifact_root = temp.path();
        write_kubernetes_controller_fixture(artifact_root);

        let plan = test_plan(artifact_root);
        write_controller_state(&plan);

        inject_kubernetes_site_controller(
            artifact_root,
            &plan,
            "ghcr.io/rdi-foundation/amber-site-controller:test",
        )
        .expect("kubernetes site controller injection should succeed");

        let deployment_raw =
            fs::read_to_string(artifact_root.join(KUBERNETES_CONTROLLER_DEPLOYMENT_PATH))
                .expect("controller deployment should exist");
        assert!(
            !deployment_raw.contains("artifact.tar.b64"),
            "kubernetes controller bootstrap should seed ordinary files instead of a tarball"
        );
        assert!(
            !deployment_raw.contains("base64 -d"),
            "kubernetes controller bootstrap should not decode a tarball at startup"
        );
        assert!(
            deployment_raw.contains("cp -R /amber/seed/artifact/."),
            "kubernetes controller bootstrap should copy seeded artifact files directly"
        );
        let deployment: serde_yaml::Value =
            serde_yaml::from_str(&deployment_raw).expect("deployment yaml should parse");
        let pod_spec = controller_pod_spec(&deployment);
        let containers = pod_spec
            .get(yaml_string("containers"))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("controller deployment should include containers");
        assert_eq!(
            containers.len(),
            2,
            "bootstrap should patch the rendered controller deployment instead of replacing it"
        );
        let main = containers
            .iter()
            .find(|container| {
                container
                    .as_mapping()
                    .and_then(|mapping| mapping.get(yaml_string("name")))
                    .and_then(serde_yaml::Value::as_str)
                    .is_some_and(|name| name == "main")
            })
            .and_then(serde_yaml::Value::as_mapping)
            .expect("controller deployment should keep the main container");
        let env = main
            .get(yaml_string("env"))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("controller main container should include env");
        assert!(env.iter().any(|entry| {
            entry.as_mapping().is_some_and(|mapping| {
                mapping.get(yaml_string("name")) == Some(&yaml_string("AMBER_DEV_IMAGE_TAGS"))
                    && mapping.get(yaml_string("value"))
                        == Some(&yaml_string("router=dev-tag,helper=dev-tag"))
            })
        }));
        assert!(env.iter().any(|entry| {
            entry.as_mapping().is_some_and(|mapping| {
                mapping.get(yaml_string("name")) == Some(&yaml_string("EXISTING_ENV"))
                    && mapping.get(yaml_string("value")) == Some(&yaml_string("kept"))
            })
        }));

        let volumes = pod_spec
            .get(yaml_string("volumes"))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("controller deployment should include volumes");
        let seed_volume = volumes
            .iter()
            .find(|volume| {
                volume
                    .as_mapping()
                    .and_then(|mapping| mapping.get(yaml_string("name")))
                    .and_then(serde_yaml::Value::as_str)
                    .is_some_and(|name| name == KUBERNETES_CONTROLLER_SEED_VOLUME)
            })
            .and_then(serde_yaml::Value::as_mapping)
            .expect("controller deployment should include the seed volume");
        let projected_sources = seed_volume
            .get(yaml_string("projected"))
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|projected| projected.get(yaml_string("sources")))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("controller seed volume should project secrets");
        let projected_paths = projected_sources
            .iter()
            .flat_map(|source| {
                source
                    .as_mapping()
                    .and_then(|mapping| mapping.get(yaml_string("secret")))
                    .and_then(serde_yaml::Value::as_mapping)
                    .and_then(|secret| secret.get(yaml_string("items")))
                    .and_then(serde_yaml::Value::as_sequence)
                    .into_iter()
                    .flatten()
                    .filter_map(|item| {
                        item.as_mapping()
                            .and_then(|mapping| mapping.get(yaml_string("path")))
                            .and_then(serde_yaml::Value::as_str)
                            .map(str::to_string)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert!(
            projected_paths
                .iter()
                .any(|path| path == "site-controller-plan.json")
        );
        assert!(
            projected_paths
                .iter()
                .any(|path| path == "site-controller-state.json")
        );
        assert!(
            projected_paths
                .iter()
                .any(|path| path == "desired-links.json")
        );
        assert!(
            projected_paths
                .iter()
                .any(|path| path == "artifact/kustomization.yaml")
        );
        let state_volume = volumes
            .iter()
            .find(|volume| {
                volume
                    .as_mapping()
                    .and_then(|mapping| mapping.get(yaml_string("name")))
                    .and_then(serde_yaml::Value::as_str)
                    .is_some_and(|name| name == KUBERNETES_CONTROLLER_STATE_VOLUME)
            })
            .and_then(serde_yaml::Value::as_mapping)
            .expect("controller deployment should include the state volume");
        assert_eq!(
            state_volume
                .get(yaml_string("persistentVolumeClaim"))
                .and_then(serde_yaml::Value::as_mapping)
                .and_then(|pvc| pvc.get(yaml_string("claimName")))
                .and_then(serde_yaml::Value::as_str),
            Some(KUBERNETES_CONTROLLER_STATE_PVC_NAME),
            "controller state must be backed by a PVC"
        );
        assert!(
            !state_volume.contains_key(yaml_string("emptyDir")),
            "controller state must not be backed by emptyDir"
        );
        assert!(
            seed_secret_paths(artifact_root)
                .iter()
                .any(|path| path.file_name().and_then(|name| name.to_str())
                    == Some("amber-site-controller-seed.yaml")),
            "kustomization should include the primary controller seed secret"
        );
    }

    #[test]
    fn inject_kubernetes_site_controller_chunks_seed_secrets_to_avoid_object_limits() {
        let temp = tempfile::tempdir().expect("temp dir");
        let artifact_root = temp.path();
        write_kubernetes_controller_fixture(artifact_root);
        fs::create_dir_all(artifact_root.join("seed-data")).expect("seed data dir");
        fs::write(
            artifact_root.join("seed-data/large-a.txt"),
            "a".repeat(KUBERNETES_CONTROLLER_SEED_SECRET_DATA_LIMIT / 2),
        )
        .expect("large artifact A should write");
        fs::write(
            artifact_root.join("seed-data/large-b.txt"),
            "b".repeat(KUBERNETES_CONTROLLER_SEED_SECRET_DATA_LIMIT / 2),
        )
        .expect("large artifact B should write");

        let plan = test_plan(artifact_root);
        write_controller_state(&plan);

        inject_kubernetes_site_controller(
            artifact_root,
            &plan,
            "ghcr.io/rdi-foundation/amber-site-controller:test",
        )
        .expect("kubernetes site controller injection should succeed");

        let seed_paths = seed_secret_paths(artifact_root);
        assert!(
            seed_paths.len() > 1,
            "large controller seeds should be split across multiple secrets"
        );
        for seed_path in &seed_paths {
            let raw = fs::read_to_string(seed_path).expect("seed secret should read");
            let document: serde_yaml::Value =
                serde_yaml::from_str(&raw).expect("seed secret should parse");
            let data_size = document
                .as_mapping()
                .and_then(|root| root.get(yaml_string("stringData")))
                .and_then(serde_yaml::Value::as_mapping)
                .expect("seed secret should have stringData")
                .iter()
                .map(|(key, value)| {
                    key.as_str().unwrap_or_default().len()
                        + value.as_str().unwrap_or_default().len()
                })
                .sum::<usize>();
            assert!(
                data_size <= KUBERNETES_CONTROLLER_SEED_SECRET_DATA_LIMIT,
                "seed secret {} should stay under the chunk limit",
                seed_path.display()
            );
        }

        let deployment_raw =
            fs::read_to_string(artifact_root.join(KUBERNETES_CONTROLLER_DEPLOYMENT_PATH))
                .expect("controller deployment should exist");
        let deployment: serde_yaml::Value =
            serde_yaml::from_str(&deployment_raw).expect("deployment yaml should parse");
        let pod_spec = controller_pod_spec(&deployment);
        let projected_sources = pod_spec
            .get(yaml_string("volumes"))
            .and_then(serde_yaml::Value::as_sequence)
            .and_then(|volumes| {
                volumes.iter().find(|volume| {
                    volume
                        .as_mapping()
                        .and_then(|mapping| mapping.get(yaml_string("name")))
                        .and_then(serde_yaml::Value::as_str)
                        .is_some_and(|name| name == KUBERNETES_CONTROLLER_SEED_VOLUME)
                })
            })
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|mapping| mapping.get(yaml_string("projected")))
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|projected| projected.get(yaml_string("sources")))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("controller deployment should project seed secrets");
        assert_eq!(
            projected_sources.len(),
            seed_paths.len(),
            "deployment should project every generated seed secret"
        );
    }
}
