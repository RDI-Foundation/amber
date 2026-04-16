use std::{fs, path::Path};

use serde_json::json;

use super::*;

const COMPOSE_MESH_NETWORK_NAME: &str = "amber_mesh";
const COMPOSE_PROVISIONER_SERVICE_NAME: &str = "amber-provisioner";
const COMPOSE_ROUTER_SERVICE_NAME: &str = "amber-router";
const COMPOSE_ROUTER_CONTROL_INIT_SERVICE_NAME: &str = "amber-router-control-init";
const COMPOSE_ROUTER_CONTROL_SOCKET_DIR: &str = "/amber/control";
const COMPOSE_ROUTER_CONTROL_VOLUME_NAME: &str = "amber-router-control";
const DOCKER_SOCK_PATH: &str = "/var/run/docker.sock";

fn compose_site_controller_env(plan: &SiteControllerPlan) -> serde_json::Value {
    serde_json::Value::Object(
        plan.launch_env
            .iter()
            .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
            .collect(),
    )
}

pub fn inject_compose_site_controller(
    artifact_root: &Path,
    plan: &SiteControllerPlan,
    plan_path: &Path,
    controller_image: &str,
) -> Result<()> {
    let compose_path = artifact_root.join("compose.yaml");
    let mut document = read_compose_document(&compose_path)?;
    let services = compose_services_mut(&mut document, &compose_path)?;

    let mut depends_on = serde_yaml::Mapping::new();
    for (service_name, condition) in [
        (
            COMPOSE_PROVISIONER_SERVICE_NAME,
            "service_completed_successfully",
        ),
        (
            COMPOSE_ROUTER_CONTROL_INIT_SERVICE_NAME,
            "service_completed_successfully",
        ),
        (COMPOSE_ROUTER_SERVICE_NAME, "service_started"),
    ] {
        if services.contains_key(yaml_string(service_name)) {
            depends_on.insert(
                yaml_string(service_name),
                serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([(
                    yaml_string("condition"),
                    yaml_string(condition),
                )])),
            );
        }
    }

    let networks = std::collections::BTreeMap::from([(
        COMPOSE_MESH_NETWORK_NAME.to_string(),
        serde_json::Value::Object(serde_json::Map::new()),
    )]);
    let service = json!({
        "image": controller_image,
        // The controller must be able to reach both the router-control volume and the mounted
        // run root. The router-control init service locks `/amber/control` down to `0700`, so a
        // host-derived UID/GID breaks Linux compose startup.
        "user": "0:0",
        "command": ["--plan", plan_path.display().to_string()],
        "environment": compose_site_controller_env(plan),
        "networks": networks,
        "extra_hosts": ["host.docker.internal:host-gateway"],
        "healthcheck": {
            "test": [
                "CMD-SHELL",
                "wget -qO- http://127.0.0.1:4100/healthz | grep -q '\"ok\":true'"
            ],
            "interval": "2s",
            "timeout": "2s",
            "retries": 30,
            "start_period": "1s"
        },
        "volumes": [
            format!("{}:{}", plan.run_root, plan.run_root),
            format!(
                "{COMPOSE_ROUTER_CONTROL_VOLUME_NAME}:{COMPOSE_ROUTER_CONTROL_SOCKET_DIR}"
            ),
            format!("{DOCKER_SOCK_PATH}:{DOCKER_SOCK_PATH}")
        ],
        "depends_on": depends_on,
        "restart": "unless-stopped"
    });
    services.insert(
        yaml_string(SITE_CONTROLLER_SERVICE_NAME),
        serde_yaml::to_value(service)
            .into_diagnostic()
            .wrap_err("failed to serialize compose site controller service")?,
    );

    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", compose_path.display()))?;
    fs::write(&compose_path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", compose_path.display()))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::SocketAddr};

    use amber_compiler::run_plan::SiteKind;

    use super::*;

    fn test_plan(run_root: &Path) -> SiteControllerPlan {
        SiteControllerPlan {
            schema: "amber.framework_component.site_controller_plan".to_string(),
            version: 1,
            run_id: "run-test".to_string(),
            mesh_scope: "scope".to_string(),
            site_id: "compose_local".to_string(),
            kind: SiteKind::Compose,
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 4100)),
            authority_url: "http://amber-site-controller:4100".to_string(),
            router_identity_id: "/site/compose_local/router".to_string(),
            peer_site_router_urls: BTreeMap::new(),
            peer_router_identities: BTreeMap::new(),
            peer_router_mesh_addrs: BTreeMap::new(),
            local_router_control: Some("unix:///tmp/router.sock".to_string()),
            published_router_mesh_addr: Some("127.0.0.1:24000".to_string()),
            compose_consumer_router_mesh_addr: Some("host.docker.internal:24000".to_string()),
            kubernetes_consumer_router_mesh_addr: Some("192.168.65.254:24000".to_string()),
            state_path: run_root.join("state.json").display().to_string(),
            run_root: run_root.display().to_string(),
            state_root: run_root.join("state-root").display().to_string(),
            site_state_root: run_root.join("site-state").display().to_string(),
            artifact_dir: run_root.join("artifact").display().to_string(),
            auth_token: "token".to_string(),
            dynamic_caps_token_verify_key_b64: "verify".to_string(),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: Some(24000),
            compose_project: Some("compose-project".to_string()),
            kubernetes_namespace: None,
            context: None,
            observability_endpoint: None,
            launch_env: BTreeMap::from([(
                "AMBER_DEV_IMAGE_TAGS".to_string(),
                "router=dev-tag,helper=dev-tag".to_string(),
            )]),
        }
    }

    #[test]
    fn inject_compose_site_controller_propagates_launch_env() {
        let temp = tempfile::tempdir().expect("temp dir");
        let compose_path = temp.path().join("compose.yaml");
        fs::write(
            &compose_path,
            "services:\n  amber-router:\n    image: ghcr.io/rdi-foundation/amber-router:test\n",
        )
        .expect("compose file should write");

        let plan = test_plan(temp.path());
        let plan_path = temp.path().join("site-controller-plan.json");
        fs::write(&plan_path, "{}").expect("plan file should write");

        inject_compose_site_controller(
            temp.path(),
            &plan,
            &plan_path,
            "ghcr.io/rdi-foundation/amber-site-controller:test",
        )
        .expect("compose site controller injection should succeed");

        let document = read_compose_document(&compose_path).expect("compose should parse");
        let service = document
            .as_mapping()
            .and_then(|root| root.get(yaml_string("services")))
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|services| services.get(yaml_string(SITE_CONTROLLER_SERVICE_NAME)))
            .and_then(serde_yaml::Value::as_mapping)
            .expect("site controller service should exist");
        let environment = service
            .get(yaml_string("environment"))
            .and_then(serde_yaml::Value::as_mapping)
            .expect("site controller service should include environment");
        assert_eq!(
            environment
                .get(yaml_string("AMBER_DEV_IMAGE_TAGS"))
                .and_then(serde_yaml::Value::as_str),
            Some("router=dev-tag,helper=dev-tag"),
        );
    }
}
