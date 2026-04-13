use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use base64::Engine as _;
use serde_json::json;
use tar::Builder;

use super::*;

const KUBERNETES_ROUTER_NAME: &str = "amber-router";
const KUBERNETES_ROUTER_MESH_PORT: u16 = 24000;
const KUBERNETES_ROUTER_CONTROL_PORT: u16 = 24100;
const KUBERNETES_ROUTER_NETPOL_PATH: &str = "05-networkpolicies/amber-router-netpol.yaml";
const KUBERNETES_CONTROLLER_SEED_CONFIGMAP_PATH: &str =
    "01-configmaps/amber-site-controller-seed.yaml";
const KUBERNETES_CONTROLLER_SERVICE_ACCOUNT_PATH: &str = "02-rbac/amber-site-controller-sa.yaml";
const KUBERNETES_CONTROLLER_ROLE_PATH: &str = "02-rbac/amber-site-controller-role.yaml";
const KUBERNETES_CONTROLLER_ROLE_BINDING_PATH: &str =
    "02-rbac/amber-site-controller-rolebinding.yaml";
const KUBERNETES_CONTROLLER_DEPLOYMENT_PATH: &str = "03-deployments/amber-site-controller.yaml";
const KUBERNETES_CONTROLLER_SERVICE_PATH: &str = "04-services/amber-site-controller.yaml";
const KUBERNETES_CONTROLLER_SEED_VOLUME: &str = "controller-seed";
const KUBERNETES_CONTROLLER_STATE_VOLUME: &str = "controller-state";
const KUBERNETES_CONTROLLER_SITE_ROOT: &str = "/amber/site";
const KUBERNETES_CONTROLLER_STATE_ROOT: &str = "/amber/site/state";
const KUBERNETES_CONTROLLER_ARTIFACT_ROOT: &str = "/amber/site/artifact";
const KUBERNETES_CONTROLLER_PLAN_PATH: &str = "/amber/site/state/site-controller-plan.json";
const KUBERNETES_CONTROLLER_STATE_PATH: &str = "/amber/site/state/site-controller-state.json";
const KUBERNETES_CONTROLLER_DESIRED_LINKS_PATH: &str = "/amber/site/state/desired-links.json";
const KUBERNETES_CONTROLLER_SEED_ROOT: &str = "/amber/seed";

pub fn inject_kubernetes_site_controller(
    artifact_root: &Path,
    plan: &SiteControllerPlan,
    controller_image: &str,
) -> Result<()> {
    let embedded_plan = build_embedded_kubernetes_controller_plan(plan);
    let seed_configmap =
        build_kubernetes_controller_seed_configmap(artifact_root, plan, &embedded_plan)?;
    let labels = kubernetes_controller_labels();
    let selector = kubernetes_controller_selector();

    write_yaml_artifact(
        artifact_root.join(KUBERNETES_CONTROLLER_SEED_CONFIGMAP_PATH),
        &seed_configmap,
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
    write_yaml_artifact(
        artifact_root.join(KUBERNETES_CONTROLLER_DEPLOYMENT_PATH),
        &json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": SITE_CONTROLLER_SERVICE_NAME,
                "labels": labels,
            },
            "spec": {
                "replicas": 1,
                "selector": {
                    "matchLabels": selector,
                },
                "template": {
                    "metadata": {
                        "labels": labels,
                    },
                    "spec": {
                        "serviceAccountName": SITE_CONTROLLER_SERVICE_NAME,
                        "automountServiceAccountToken": true,
                        "initContainers": [{
                            "name": "seed-site-controller",
                            "image": "busybox:1.36.1",
                            "command": [
                                "sh",
                                "-lc",
                                format!(
                                    "set -eu\nmkdir -p {KUBERNETES_CONTROLLER_STATE_ROOT} \
                                     {KUBERNETES_CONTROLLER_ARTIFACT_ROOT}\ncp \
                                     {KUBERNETES_CONTROLLER_SEED_ROOT}/site-controller-plan.json \
                                     {KUBERNETES_CONTROLLER_PLAN_PATH}\ncp \
                                     {KUBERNETES_CONTROLLER_SEED_ROOT}/site-controller-state.json \
                                     {KUBERNETES_CONTROLLER_STATE_PATH}\ncp \
                                     {KUBERNETES_CONTROLLER_SEED_ROOT}/desired-links.json \
                                     {KUBERNETES_CONTROLLER_DESIRED_LINKS_PATH}\nbase64 -d \
                                     {KUBERNETES_CONTROLLER_SEED_ROOT}/artifact.tar.b64 | tar \
                                     -xf - -C {KUBERNETES_CONTROLLER_ARTIFACT_ROOT}\n"
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
                        }],
                        "containers": [{
                            "name": SITE_CONTROLLER_SERVICE_NAME,
                            "image": controller_image,
                            "command": ["--plan", KUBERNETES_CONTROLLER_PLAN_PATH],
                            "ports": [{
                                "name": "http",
                                "containerPort": SITE_CONTROLLER_PORT,
                                "protocol": "TCP",
                            }],
                            "volumeMounts": [{
                                "name": KUBERNETES_CONTROLLER_STATE_VOLUME,
                                "mountPath": KUBERNETES_CONTROLLER_SITE_ROOT,
                            }]
                        }],
                        "volumes": [
                            {
                                "name": KUBERNETES_CONTROLLER_SEED_VOLUME,
                                "configMap": {
                                    "name": format!("{SITE_CONTROLLER_SERVICE_NAME}-seed"),
                                }
                            },
                            {
                                "name": KUBERNETES_CONTROLLER_STATE_VOLUME,
                                "emptyDir": {}
                            }
                        ]
                    }
                }
            }
        }),
    )?;
    write_yaml_artifact(
        artifact_root.join(KUBERNETES_CONTROLLER_SERVICE_PATH),
        &json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": SITE_CONTROLLER_SERVICE_NAME,
                "labels": labels,
            },
            "spec": {
                "selector": selector,
                "ports": [{
                    "name": "http",
                    "port": SITE_CONTROLLER_PORT,
                    "targetPort": SITE_CONTROLLER_PORT,
                    "protocol": "TCP",
                }],
                "type": "ClusterIP",
            }
        }),
    )?;
    add_kubernetes_resource_paths(
        artifact_root,
        &[
            KUBERNETES_CONTROLLER_SEED_CONFIGMAP_PATH,
            KUBERNETES_CONTROLLER_SERVICE_ACCOUNT_PATH,
            KUBERNETES_CONTROLLER_ROLE_PATH,
            KUBERNETES_CONTROLLER_ROLE_BINDING_PATH,
            KUBERNETES_CONTROLLER_DEPLOYMENT_PATH,
            KUBERNETES_CONTROLLER_SERVICE_PATH,
        ],
    )?;
    ensure_kubernetes_router_allows_site_controller_control(artifact_root)
}

fn build_embedded_kubernetes_controller_plan(plan: &SiteControllerPlan) -> SiteControllerPlan {
    let mut embedded = plan.clone();
    embedded.listen_addr = SocketAddr::from(([0, 0, 0, 0], SITE_CONTROLLER_PORT));
    embedded.authority_url =
        format!("http://{SITE_CONTROLLER_SERVICE_NAME}:{SITE_CONTROLLER_PORT}");
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

fn build_kubernetes_controller_seed_configmap(
    artifact_root: &Path,
    plan: &SiteControllerPlan,
    embedded_plan: &SiteControllerPlan,
) -> Result<serde_json::Value> {
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
    Ok(json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": format!("{SITE_CONTROLLER_SERVICE_NAME}-seed"),
            "labels": kubernetes_controller_labels(),
        },
        "data": {
            "site-controller-plan.json": embedded_plan_json,
            "site-controller-state.json": state_json,
            "desired-links.json": desired_links_json,
            "artifact.tar.b64": tar_directory_base64(artifact_root)?,
        }
    }))
}

fn tar_directory_base64(root: &Path) -> Result<String> {
    let mut tar = Builder::new(Vec::new());
    tar.append_dir_all(".", root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to archive {}", root.display()))?;
    let bytes = tar
        .into_inner()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to finalize archive {}", root.display()))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
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

fn ensure_kubernetes_router_allows_site_controller_control(artifact_root: &Path) -> Result<()> {
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
    let exists = ingress.iter().any(|rule| {
        rule.as_mapping()
            .and_then(|mapping| mapping.get(yaml_string("ports")))
            .and_then(serde_yaml::Value::as_sequence)
            .is_some_and(|ports| {
                ports.iter().any(|port| {
                    port.as_mapping()
                        .and_then(|entry| entry.get(yaml_string("port")))
                        .and_then(serde_yaml::Value::as_i64)
                        == Some(i64::from(KUBERNETES_ROUTER_CONTROL_PORT))
                })
            })
            && rule
                .as_mapping()
                .and_then(|mapping| mapping.get(yaml_string("from")))
                .and_then(serde_yaml::Value::as_sequence)
                .is_some_and(|from| {
                    from.iter().any(|peer| {
                        peer.as_mapping()
                            .and_then(|mapping| mapping.get(yaml_string("podSelector")))
                            .and_then(serde_yaml::Value::as_mapping)
                            .and_then(|selector_value| {
                                selector_value.get(yaml_string("matchLabels"))
                            })
                            .and_then(serde_yaml::Value::as_mapping)
                            .is_some_and(|labels| {
                                labels.get(yaml_string("amber.io/component"))
                                    == Some(&yaml_string(
                                        controller_selector
                                            .get("amber.io/component")
                                            .expect("selector must contain component"),
                                    ))
                            })
                    })
                })
    });
    if !exists {
        ingress.push(
            serde_yaml::to_value(json!({
                "from": [{
                    "podSelector": {
                        "matchLabels": controller_selector,
                    }
                }],
                "ports": [{
                    "protocol": "TCP",
                    "port": KUBERNETES_ROUTER_CONTROL_PORT,
                }]
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

fn write_yaml_artifact(path: PathBuf, value: &serde_json::Value) -> Result<()> {
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
