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
        "user": "0:0",
        "command": ["--plan", plan_path.display().to_string()],
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
