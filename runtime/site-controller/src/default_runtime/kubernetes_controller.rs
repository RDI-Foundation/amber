use std::{
    collections::{BTreeMap, BTreeSet},
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
const KUBERNETES_ROUTER_SERVICE_PATH: &str = "04-services/amber-router.yaml";
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

fn kubernetes_env_entries(plan: &SiteControllerPlan) -> Vec<serde_json::Value> {
    plan.launch_env
        .iter()
        .map(|(name, value)| json!({ "name": name, "value": value }))
        .collect()
}

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
    let controller_env = kubernetes_env_entries(plan);

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
                            "image": controller_image,
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
                            "args": ["--plan", KUBERNETES_CONTROLLER_PLAN_PATH],
                            "env": controller_env,
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
    ensure_kubernetes_router_allows_site_controller_ingress(
        artifact_root,
        &peer_router_route_ports(&embedded_plan)?,
    )
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::SocketAddr};

    use amber_compiler::run_plan::SiteKind;

    use super::*;

    fn test_plan(root: &Path) -> SiteControllerPlan {
        SiteControllerPlan {
            schema: "amber.framework_component.site_controller_plan".to_string(),
            version: 1,
            run_id: "run-test".to_string(),
            mesh_scope: "scope".to_string(),
            site_id: "kind_local".to_string(),
            kind: SiteKind::Kubernetes,
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 4100)),
            authority_url: "http://amber-site-controller:4100".to_string(),
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
            auth_token: "token".to_string(),
            dynamic_caps_token_verify_key_b64: "verify".to_string(),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: Some(24000),
            compose_project: None,
            kubernetes_namespace: Some("test-ns".to_string()),
            context: Some("test-context".to_string()),
            observability_endpoint: None,
            launch_env: BTreeMap::from([(
                "AMBER_DEV_IMAGE_TAGS".to_string(),
                "router=dev-tag,helper=dev-tag".to_string(),
            )]),
        }
    }

    #[test]
    fn inject_kubernetes_site_controller_propagates_launch_env() {
        let temp = tempfile::tempdir().expect("temp dir");
        let artifact_root = temp.path();
        fs::create_dir_all(artifact_root.join("04-services")).expect("services dir");
        fs::create_dir_all(artifact_root.join("05-networkpolicies")).expect("netpol dir");
        fs::write(
            artifact_root.join("kustomization.yaml"),
            "resources:\n  - 04-services/amber-router.yaml\n  - \
             05-networkpolicies/amber-router-netpol.yaml\n",
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

        let plan = test_plan(artifact_root);
        fs::write(&plan.state_path, "{}").expect("state should write");
        fs::create_dir_all(&plan.site_state_root).expect("site state dir");
        fs::write(
            super::desired_links_path(Path::new(&plan.site_state_root)),
            "{}",
        )
        .expect("desired links should write");

        inject_kubernetes_site_controller(
            artifact_root,
            &plan,
            "ghcr.io/rdi-foundation/amber-site-controller:test",
        )
        .expect("kubernetes site controller injection should succeed");

        let deployment_raw =
            fs::read_to_string(artifact_root.join(KUBERNETES_CONTROLLER_DEPLOYMENT_PATH))
                .expect("controller deployment should exist");
        let deployment: serde_yaml::Value =
            serde_yaml::from_str(&deployment_raw).expect("deployment yaml should parse");
        let env = deployment
            .as_mapping()
            .and_then(|root| root.get(yaml_string("spec")))
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|spec| spec.get(yaml_string("template")))
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|template| template.get(yaml_string("spec")))
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|spec| spec.get(yaml_string("containers")))
            .and_then(serde_yaml::Value::as_sequence)
            .and_then(|containers| containers.first())
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|container| container.get(yaml_string("env")))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("controller container should include env");
        assert!(env.iter().any(|entry| {
            entry.as_mapping().is_some_and(|mapping| {
                mapping.get(yaml_string("name")) == Some(&yaml_string("AMBER_DEV_IMAGE_TAGS"))
                    && mapping.get(yaml_string("value"))
                        == Some(&yaml_string("router=dev-tag,helper=dev-tag"))
            })
        }));
    }
}
