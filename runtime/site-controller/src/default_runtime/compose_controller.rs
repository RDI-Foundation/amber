use std::{fs, path::Path};

use serde_json::json;

use super::*;

const COMPOSE_PROVISIONER_SERVICE_NAME: &str = "amber-provisioner";
const COMPOSE_ROUTER_SERVICE_NAME: &str = "amber-router";
const COMPOSE_ROUTER_CONTROL_INIT_SERVICE_NAME: &str = "amber-router-control-init";
const COMPOSE_ROUTER_CONTROL_SOCKET_DIR: &str = "/amber/control";
const COMPOSE_ROUTER_CONTROL_VOLUME_NAME: &str = "amber-router-control";
const COMPOSE_ROUTER_RUNTIME_GID: &str = "65532";
const DOCKER_SOCK_PATH: &str = "/var/run/docker.sock";
const COMPOSE_CONTROLLER_PLAN_PATH: &str = "/amber/site/state/site-controller-plan.json";

fn ensure_string_sequence_contains(sequence: &mut serde_yaml::Sequence, value: &str) {
    if sequence
        .iter()
        .any(|entry| entry.as_str().is_some_and(|existing| existing == value))
    {
        return;
    }
    sequence.push(yaml_string(value));
}

fn uses_service_network_mode(service: &serde_yaml::Mapping) -> bool {
    service
        .get(yaml_string("network_mode"))
        .and_then(serde_yaml::Value::as_str)
        .is_some_and(|mode| mode.starts_with("service:"))
}

fn ensure_controller_environment(
    service: &mut serde_yaml::Mapping,
    plan: &SiteControllerPlan,
) -> Result<()> {
    if plan.launch_env.is_empty() {
        return Ok(());
    }
    match service
        .entry(yaml_string("environment"))
        .or_insert_with(|| serde_yaml::Value::Sequence(Vec::new()))
    {
        serde_yaml::Value::Sequence(sequence) => {
            for (key, value) in &plan.launch_env {
                let entry = format!("{key}={value}");
                let already_present = sequence.iter().any(|existing| {
                    existing.as_str().is_some_and(|existing| {
                        existing == entry || existing.starts_with(&format!("{key}="))
                    })
                });
                if !already_present {
                    sequence.push(yaml_string(&entry));
                }
            }
            Ok(())
        }
        serde_yaml::Value::Mapping(mapping) => {
            for (key, value) in &plan.launch_env {
                mapping.insert(yaml_string(key), yaml_string(value));
            }
            Ok(())
        }
        _ => Err(miette::miette!(
            "compose site controller service has an unsupported environment shape"
        )),
    }
}

fn ensure_controller_depends_on(
    service: &mut serde_yaml::Mapping,
    available_services: &serde_yaml::Mapping,
) -> Result<()> {
    let mut desired = serde_yaml::Mapping::new();
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
        if available_services.contains_key(yaml_string(service_name)) {
            desired.insert(
                yaml_string(service_name),
                serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([(
                    yaml_string("condition"),
                    yaml_string(condition),
                )])),
            );
        }
    }
    if desired.is_empty() {
        return Ok(());
    }

    let current = service
        .entry(yaml_string("depends_on"))
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    match current {
        serde_yaml::Value::Mapping(mapping) => {
            for (key, value) in desired {
                mapping.insert(key, value);
            }
            Ok(())
        }
        serde_yaml::Value::Sequence(sequence) => {
            let mut mapping = serde_yaml::Mapping::new();
            for value in sequence.iter() {
                let Some(name) = value.as_str() else {
                    return Err(miette::miette!(
                        "compose site controller service depends_on sequence contains a \
                         non-string entry"
                    ));
                };
                mapping.insert(
                    yaml_string(name),
                    serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([(
                        yaml_string("condition"),
                        yaml_string("service_started"),
                    )])),
                );
            }
            for (key, value) in desired {
                mapping.insert(key, value);
            }
            *current = serde_yaml::Value::Mapping(mapping);
            Ok(())
        }
        _ => Err(miette::miette!(
            "compose site controller service has an unsupported depends_on shape"
        )),
    }
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
    let available_services = services.clone();
    let service = services
        .get_mut(yaml_string(SITE_CONTROLLER_SERVICE_NAME))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| {
            miette::miette!(
                "compose file {} is missing services.{SITE_CONTROLLER_SERVICE_NAME}",
                compose_path.display()
            )
        })?;

    service.insert(yaml_string("image"), yaml_string(controller_image));
    service.insert(yaml_string("user"), yaml_string("0:0"));
    service.insert(
        yaml_string("group_add"),
        serde_yaml::Value::Sequence(vec![yaml_string(COMPOSE_ROUTER_RUNTIME_GID)]),
    );
    service.insert(
        yaml_string("healthcheck"),
        serde_yaml::to_value(json!({
            "test": [
                "CMD-SHELL",
                format!(
                    "wget -qO- http://127.0.0.1:{}/healthz | grep -q '\"ok\":true'",
                    plan.listen_addr.port()
                )
            ],
            "interval": "2s",
            "timeout": "2s",
            "retries": 30,
            "start_period": "1s"
        }))
        .into_diagnostic()
        .wrap_err("failed to serialize compose site controller healthcheck")?,
    );
    service.insert(yaml_string("restart"), yaml_string("unless-stopped"));

    if uses_service_network_mode(service) {
        service.remove(yaml_string("extra_hosts"));
    } else {
        let extra_hosts = service
            .entry(yaml_string("extra_hosts"))
            .or_insert_with(|| serde_yaml::Value::Sequence(Vec::new()))
            .as_sequence_mut()
            .ok_or_else(|| {
                miette::miette!(
                    "compose site controller service has a non-sequence extra_hosts field"
                )
            })?;
        ensure_string_sequence_contains(extra_hosts, "host.docker.internal:host-gateway");
    }

    let volumes = service
        .entry(yaml_string("volumes"))
        .or_insert_with(|| serde_yaml::Value::Sequence(Vec::new()))
        .as_sequence_mut()
        .ok_or_else(|| {
            miette::miette!("compose site controller service has a non-sequence volumes field")
        })?;
    for volume in [
        format!("{}:{}", plan.run_root, plan.run_root),
        format!("{}:{COMPOSE_CONTROLLER_PLAN_PATH}", plan_path.display()),
        format!("{COMPOSE_ROUTER_CONTROL_VOLUME_NAME}:{COMPOSE_ROUTER_CONTROL_SOCKET_DIR}"),
        format!("{DOCKER_SOCK_PATH}:{DOCKER_SOCK_PATH}"),
    ] {
        ensure_string_sequence_contains(volumes, &volume);
    }

    ensure_controller_environment(service, plan)?;
    ensure_controller_depends_on(service, &available_services)?;

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
            control_state_auth_token: "token".to_string(),
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
    fn inject_compose_site_controller_keeps_service_network_mode_compatible() {
        let temp = tempfile::tempdir().expect("temp dir");
        let compose_path = temp.path().join("compose.yaml");
        fs::write(
            &compose_path,
            "services:
  amber-site-controller:
    image: __amber_internal/site-controller
    network_mode: service:amber-site-controller-net
    extra_hosts:
      - host.docker.internal:host-gateway
",
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
        assert_eq!(
            service
                .get(yaml_string("network_mode"))
                .and_then(serde_yaml::Value::as_str),
            Some("service:amber-site-controller-net"),
            "late bootstrap must preserve the lowered sidecar sharing topology",
        );
        assert!(
            service.get(yaml_string("extra_hosts")).is_none(),
            "late bootstrap must not add host mappings to service-networked controller workloads",
        );
    }

    #[test]
    fn inject_compose_site_controller_propagates_launch_env() {
        let temp = tempfile::tempdir().expect("temp dir");
        let compose_path = temp.path().join("compose.yaml");
        fs::write(
            &compose_path,
            "services:\n  amber-router:\n    image: ghcr.io/rdi-foundation/amber-router:test\n  amber-site-controller:\n    image: __amber_internal/site-controller\n    environment:\n      - AMBER_DYNAMIC_CAPS_API_URL=http://127.0.0.1:19000\n",
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
            .and_then(serde_yaml::Value::as_sequence)
            .expect("site controller service should include environment entries");
        assert!(
            environment
                .iter()
                .any(|value| value.as_str().is_some_and(|value| {
                    value == "AMBER_DEV_IMAGE_TAGS=router=dev-tag,helper=dev-tag"
                })),
            "launch env should be merged into the existing environment list: {service:?}"
        );
        assert!(
            environment
                .iter()
                .any(|value| value.as_str().is_some_and(|value| {
                    value == "AMBER_DYNAMIC_CAPS_API_URL=http://127.0.0.1:19000"
                })),
            "existing controller program env must be preserved: {service:?}"
        );
        let volumes = service
            .get(yaml_string("volumes"))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("site controller service should include volumes");
        assert!(
            volumes.iter().any(|value| value
                .as_str()
                .is_some_and(|value| { value == format!("{}:{}", plan.run_root, plan.run_root) })),
            "compose controller bootstrap should mount the run root into the existing service: \
             {service:?}"
        );
    }
}
