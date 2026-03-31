use super::*;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a reachable Docker daemon via DOCKER_HOST, ~/.docker/run/docker.sock, or \
            /var/run/docker.sock"]
async fn docker_daemon_e2e_enforces_scoping_and_policy() {
    let Some(docker_sock) = docker_socket_for_ignored_e2e() else {
        eprintln!("skipping docker daemon e2e: no docker unix socket found");
        return;
    };

    if UnixStream::connect(&docker_sock).await.is_err() {
        eprintln!(
            "skipping docker daemon e2e: docker socket exists but is not reachable at {}",
            docker_sock.display()
        );
        return;
    }

    let ping = send_docker_request(&docker_sock, Method::GET, "/_ping", None).await;
    if ping.status != StatusCode::OK {
        eprintln!(
            "skipping docker daemon e2e: /_ping returned {} with body {}",
            ping.status,
            String::from_utf8_lossy(&ping.body)
        );
        return;
    }

    let suffix = unique_test_suffix();
    let compose_project = format!("amber-gw-e2e-project-{suffix}");
    let component = format!("amber-gw-e2e-component-{suffix}");
    let foreign_component = format!("amber-gw-e2e-foreign-{suffix}");
    let owned_network = format!("amber-gw-owned-net-{suffix}");
    let foreign_network = format!("amber-gw-foreign-net-{suffix}");
    let owned_volume = format!("amber-gw-owned-vol-{suffix}");
    let foreign_volume = format!("amber-gw-foreign-vol-{suffix}");

    let listen = reserve_loopback_socket_addr();
    let config = DockerGatewayConfig {
        listen,
        docker_sock: docker_sock.clone(),
        compose_project: compose_project.clone(),
        callers: vec![CallerConfig {
            host: "127.0.0.1".to_string(),
            port: None,
            component: component.clone(),
            compose_service: component.clone(),
        }],
    };

    let gateway_task = tokio::spawn(async move {
        if let Err(err) = run(config).await {
            panic!("gateway run failed in e2e test: {err}");
        }
    });
    wait_until_gateway_listens(listen, &gateway_task).await;

    send_docker_request(
        &docker_sock,
        Method::POST,
        "/networks/create",
        Some(serde_json::json!({
            "Name": foreign_network.as_str(),
            "Labels": {
                AMBER_PROJECT_LABEL: compose_project.as_str(),
                AMBER_COMPONENT_LABEL: foreign_component.as_str()
            }
        })),
    )
    .await;

    send_docker_request(
        &docker_sock,
        Method::POST,
        "/volumes/create",
        Some(serde_json::json!({
            "Name": foreign_volume.as_str(),
            "Labels": {
                AMBER_PROJECT_LABEL: compose_project.as_str(),
                AMBER_COMPONENT_LABEL: foreign_component.as_str()
            }
        })),
    )
    .await;

    let create_network = send_gateway_request(
        listen,
        Method::POST,
        "/networks/create",
        &[("content-type", "application/json")],
        serde_json::json!({
            "Name": owned_network.as_str(),
            "Labels": {
                AMBER_COMPONENT_LABEL: "attacker",
                AMBER_PROJECT_LABEL: "attacker-project",
                "user.label": "kept"
            }
        })
        .to_string()
        .as_bytes(),
    )
    .await;
    assert_eq!(
        create_network.status,
        StatusCode::CREATED,
        "network create failed via gateway: {}",
        String::from_utf8_lossy(&create_network.body)
    );

    let create_volume = send_gateway_request(
        listen,
        Method::POST,
        "/volumes/create",
        &[("content-type", "application/json")],
        serde_json::json!({
            "Name": owned_volume.as_str(),
            "Labels": {
                AMBER_COMPONENT_LABEL: "attacker",
                AMBER_PROJECT_LABEL: "attacker-project"
            }
        })
        .to_string()
        .as_bytes(),
    )
    .await;
    assert_eq!(
        create_volume.status,
        StatusCode::CREATED,
        "volume create failed via gateway: {}",
        String::from_utf8_lossy(&create_volume.body)
    );

    let owned_network_meta = send_docker_request(
        &docker_sock,
        Method::GET,
        &format!("/networks/{owned_network}"),
        None,
    )
    .await;
    assert_eq!(owned_network_meta.status, StatusCode::OK);
    let owned_network_value: serde_json::Value =
        serde_json::from_slice(&owned_network_meta.body).expect("owned network inspect json");
    let owned_network_labels = owned_network_value
        .get("Labels")
        .and_then(|value| value.as_object())
        .expect("owned network labels");
    assert_eq!(
        owned_network_labels
            .get(AMBER_COMPONENT_LABEL)
            .and_then(|value| value.as_str()),
        Some(component.as_str())
    );
    assert_eq!(
        owned_network_labels
            .get(AMBER_PROJECT_LABEL)
            .and_then(|value| value.as_str()),
        Some(compose_project.as_str())
    );
    assert_eq!(
        owned_network_labels
            .get("user.label")
            .and_then(|value| value.as_str()),
        Some("kept")
    );

    let owned_volume_meta = send_docker_request(
        &docker_sock,
        Method::GET,
        &format!("/volumes/{owned_volume}"),
        None,
    )
    .await;
    assert_eq!(owned_volume_meta.status, StatusCode::OK);
    let owned_volume_value: serde_json::Value =
        serde_json::from_slice(&owned_volume_meta.body).expect("owned volume inspect json");
    let owned_volume_labels = owned_volume_value
        .get("Labels")
        .and_then(|value| value.as_object())
        .expect("owned volume labels");
    assert_eq!(
        owned_volume_labels
            .get(AMBER_COMPONENT_LABEL)
            .and_then(|value| value.as_str()),
        Some(component.as_str())
    );
    assert_eq!(
        owned_volume_labels
            .get(AMBER_PROJECT_LABEL)
            .and_then(|value| value.as_str()),
        Some(compose_project.as_str())
    );

    let deny_network = send_gateway_request(
        listen,
        Method::GET,
        &format!("/networks/{foreign_network}"),
        &[],
        &[],
    )
    .await;
    assert_eq!(deny_network.status, StatusCode::FORBIDDEN);

    let deny_volume = send_gateway_request(
        listen,
        Method::GET,
        &format!("/volumes/{foreign_volume}"),
        &[],
        &[],
    )
    .await;
    assert_eq!(deny_volume.status, StatusCode::FORBIDDEN);

    let list_networks = send_gateway_request(listen, Method::GET, "/networks", &[], &[]).await;
    assert_eq!(list_networks.status, StatusCode::OK);
    let networks_value: serde_json::Value =
        serde_json::from_slice(&list_networks.body).expect("list networks json");
    let network_names: HashSet<String> = networks_value
        .as_array()
        .expect("networks list array")
        .iter()
        .filter_map(|entry| {
            entry
                .get("Name")
                .and_then(|name| name.as_str())
                .map(str::to_string)
        })
        .collect();
    assert!(network_names.contains(&owned_network));
    assert!(!network_names.contains(&foreign_network));

    let list_volumes = send_gateway_request(listen, Method::GET, "/volumes", &[], &[]).await;
    assert_eq!(list_volumes.status, StatusCode::OK);
    let volumes_value: serde_json::Value =
        serde_json::from_slice(&list_volumes.body).expect("list volumes json");
    let volume_names: HashSet<String> = volumes_value
        .get("Volumes")
        .and_then(|volumes| volumes.as_array())
        .map(|volumes| {
            volumes
                .iter()
                .filter_map(|entry| {
                    entry
                        .get("Name")
                        .and_then(|name| name.as_str())
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();
    assert!(volume_names.contains(&owned_volume));
    assert!(!volume_names.contains(&foreign_volume));

    let blocked_connect = send_gateway_request(
        listen,
        Method::POST,
        &format!("/networks/{owned_network}/connect"),
        &[("content-type", "application/json")],
        br#"{"Container":"dummy"}"#,
    )
    .await;
    assert_eq!(blocked_connect.status, StatusCode::FORBIDDEN);

    // Image pull: resolve a known image, then pull it through the gateway.
    if let Some(image) = docker_image_for_ignored_e2e(&docker_sock).await {
        let (from_image, tag) = image.rsplit_once(':').unwrap_or((image.as_str(), "latest"));

        let pull_result = send_gateway_request(
            listen,
            Method::POST,
            &format!("/images/create?fromImage={from_image}&tag={tag}"),
            &[],
            &[],
        )
        .await;
        assert!(
            pull_result.status.is_success(),
            "image pull via gateway failed: {} {}",
            pull_result.status,
            String::from_utf8_lossy(&pull_result.body)
        );

        // Verify the pulled image is inspectable through the gateway.
        let inspect = send_gateway_request(
            listen,
            Method::GET,
            &format!("/images/{image}/json"),
            &[],
            &[],
        )
        .await;
        assert_eq!(
            inspect.status,
            StatusCode::OK,
            "image inspect after pull failed: {}",
            String::from_utf8_lossy(&inspect.body)
        );
    }

    // Image import should still be blocked.
    let blocked_import = send_gateway_request(
        listen,
        Method::POST,
        "/images/create?fromSrc=-",
        &[("content-type", "application/x-tar")],
        &[],
    )
    .await;
    assert_eq!(blocked_import.status, StatusCode::FORBIDDEN);

    // Bare image create (no query params) should be blocked.
    let blocked_bare = send_gateway_request(listen, Method::POST, "/images/create", &[], &[]).await;
    assert_eq!(blocked_bare.status, StatusCode::FORBIDDEN);

    gateway_task.abort();
    docker_delete_network_best_effort(&docker_sock, &owned_network).await;
    docker_delete_network_best_effort(&docker_sock, &foreign_network).await;
    docker_delete_volume_best_effort(&docker_sock, &owned_volume).await;
    docker_delete_volume_best_effort(&docker_sock, &foreign_volume).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a reachable Docker daemon via DOCKER_HOST, ~/.docker/run/docker.sock, or \
            /var/run/docker.sock"]
async fn docker_daemon_e2e_enforces_multicaller_container_exec_and_upgrade() {
    let Some(docker_sock) = docker_socket_for_ignored_e2e() else {
        eprintln!("skipping docker daemon e2e: no docker unix socket found");
        return;
    };

    if UnixStream::connect(&docker_sock).await.is_err() {
        eprintln!(
            "skipping docker daemon e2e: docker socket exists but is not reachable at {}",
            docker_sock.display()
        );
        return;
    }

    let ping = send_docker_request(&docker_sock, Method::GET, "/_ping", None).await;
    if ping.status != StatusCode::OK {
        eprintln!(
            "skipping docker daemon e2e: /_ping returned {} with body {}",
            ping.status,
            String::from_utf8_lossy(&ping.body)
        );
        return;
    }

    let Some(image) = docker_image_for_ignored_e2e(&docker_sock).await else {
        return;
    };

    let suffix = unique_test_suffix();
    let compose_project = format!("amber-gw-e2e-project-{suffix}");
    let component_a = format!("amber-gw-e2e-component-a-{suffix}");
    let component_b = format!("amber-gw-e2e-component-b-{suffix}");
    let owned_network_a = format!("amber-gw-owned-net-a-{suffix}");
    let owned_network_b = format!("amber-gw-owned-net-b-{suffix}");
    let owned_container_a = format!("amber-gw-owned-container-a-{suffix}");

    let (caller_a_socket, caller_a_port) = reserve_bound_loopback_socket();
    let (caller_b_socket, caller_b_port) = reserve_bound_loopback_socket();

    let listen = reserve_loopback_socket_addr();
    let config = DockerGatewayConfig {
        listen,
        docker_sock: docker_sock.clone(),
        compose_project: compose_project.clone(),
        callers: vec![
            CallerConfig {
                host: "127.0.0.1".to_string(),
                port: Some(caller_a_port),
                component: component_a.clone(),
                compose_service: component_a.clone(),
            },
            CallerConfig {
                host: "127.0.0.1".to_string(),
                port: Some(caller_b_port),
                component: component_b.clone(),
                compose_service: component_b.clone(),
            },
        ],
    };

    let gateway_task = tokio::spawn(async move {
        if let Err(err) = run(config).await {
            panic!("gateway run failed in multicaller e2e test: {err}");
        }
    });
    wait_until_gateway_listens(listen, &gateway_task).await;

    let mut caller_a = GatewayClient::connect_from_socket(caller_a_socket, listen).await;
    let mut caller_b = GatewayClient::connect_from_socket(caller_b_socket, listen).await;

    let create_network_a = caller_a
        .request(
            Method::POST,
            "/networks/create",
            &[("content-type", "application/json")],
            serde_json::json!({
                "Name": owned_network_a.as_str(),
            })
            .to_string()
            .as_bytes(),
        )
        .await;
    assert_eq!(
        create_network_a.status,
        StatusCode::CREATED,
        "network A create failed via gateway: {}",
        String::from_utf8_lossy(&create_network_a.body)
    );

    let create_network_b = caller_b
        .request(
            Method::POST,
            "/networks/create",
            &[("content-type", "application/json")],
            serde_json::json!({
                "Name": owned_network_b.as_str(),
            })
            .to_string()
            .as_bytes(),
        )
        .await;
    assert_eq!(
        create_network_b.status,
        StatusCode::CREATED,
        "network B create failed via gateway: {}",
        String::from_utf8_lossy(&create_network_b.body)
    );

    let cross_network_a_denied = caller_b
        .request(
            Method::GET,
            &format!("/networks/{owned_network_a}"),
            &[],
            &[],
        )
        .await;
    assert_eq!(cross_network_a_denied.status, StatusCode::FORBIDDEN);

    let cross_network_b_denied = caller_a
        .request(
            Method::GET,
            &format!("/networks/{owned_network_b}"),
            &[],
            &[],
        )
        .await;
    assert_eq!(cross_network_b_denied.status, StatusCode::FORBIDDEN);

    let create_container_a = caller_a
        .request(
            Method::POST,
            &format!("/containers/create?name={owned_container_a}"),
            &[("content-type", "application/json")],
            serde_json::json!({
                "Image": image.as_str(),
                "Cmd": ["sleep", "60"],
                "HostConfig": {
                    "NetworkMode": owned_network_a.as_str()
                }
            })
            .to_string()
            .as_bytes(),
        )
        .await;
    assert_eq!(
        create_container_a.status,
        StatusCode::CREATED,
        "container create failed via gateway: {}",
        String::from_utf8_lossy(&create_container_a.body)
    );

    let start_container_a = caller_a
        .request(
            Method::POST,
            &format!("/containers/{owned_container_a}/start"),
            &[],
            &[],
        )
        .await;
    assert!(
        matches!(
            start_container_a.status,
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
        ),
        "container start via gateway failed: {} body={}",
        start_container_a.status,
        String::from_utf8_lossy(&start_container_a.body)
    );

    let inspect_container_denied = caller_b
        .request(
            Method::GET,
            &format!("/containers/{owned_container_a}/json"),
            &[],
            &[],
        )
        .await;
    assert_eq!(inspect_container_denied.status, StatusCode::FORBIDDEN);

    let start_container_denied = caller_b
        .request(
            Method::POST,
            &format!("/containers/{owned_container_a}/start"),
            &[],
            &[],
        )
        .await;
    assert_eq!(start_container_denied.status, StatusCode::FORBIDDEN);

    let list_containers_a = caller_a
        .request(Method::GET, "/containers/json?all=1", &[], &[])
        .await;
    assert_eq!(list_containers_a.status, StatusCode::OK);
    let names_a = parse_container_names(&list_containers_a.body);
    assert!(names_a.contains(&owned_container_a));

    let list_containers_b = caller_b
        .request(Method::GET, "/containers/json?all=1", &[], &[])
        .await;
    assert_eq!(list_containers_b.status, StatusCode::OK);
    let names_b = parse_container_names(&list_containers_b.body);
    assert!(!names_b.contains(&owned_container_a));

    let create_exec_a = caller_a
        .request(
            Method::POST,
            &format!("/containers/{owned_container_a}/exec"),
            &[("content-type", "application/json")],
            serde_json::json!({
                "Cmd": ["echo", "gateway-upgrade"],
                "AttachStdout": true,
                "AttachStderr": true
            })
            .to_string()
            .as_bytes(),
        )
        .await;
    assert_eq!(
        create_exec_a.status,
        StatusCode::CREATED,
        "exec create via gateway failed: {}",
        String::from_utf8_lossy(&create_exec_a.body)
    );
    let exec_id = response_json_id(&create_exec_a.body);

    let denied_exec_start = caller_b
        .request(
            Method::POST,
            &format!("/exec/{exec_id}/start"),
            &[("content-type", "application/json")],
            br#"{"Detach":false,"Tty":false}"#,
        )
        .await;
    assert_eq!(denied_exec_start.status, StatusCode::FORBIDDEN);

    let allowed_exec_start = caller_a
        .request_with_upgrade(
            Method::POST,
            &format!("/exec/{exec_id}/start"),
            &[
                ("content-type", "application/json"),
                ("connection", "Upgrade"),
                ("upgrade", "tcp"),
            ],
            br#"{"Detach":false,"Tty":false}"#,
        )
        .await;
    assert!(
        matches!(
            allowed_exec_start.status,
            StatusCode::OK | StatusCode::SWITCHING_PROTOCOLS
        ),
        "exec start via gateway failed: {} body={}",
        allowed_exec_start.status,
        String::from_utf8_lossy(&allowed_exec_start.body)
    );
    assert!(
        String::from_utf8_lossy(&allowed_exec_start.body).contains("gateway-upgrade"),
        "exec output did not contain expected marker, body={}",
        String::from_utf8_lossy(&allowed_exec_start.body)
    );

    gateway_task.abort();
    docker_delete_container_best_effort(&docker_sock, &owned_container_a).await;
    docker_delete_network_best_effort(&docker_sock, &owned_network_a).await;
    docker_delete_network_best_effort(&docker_sock, &owned_network_b).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a reachable Docker daemon via DOCKER_HOST, ~/.docker/run/docker.sock, or \
            /var/run/docker.sock"]
async fn docker_daemon_e2e_container_create_without_network_mode() {
    let Some(docker_sock) = docker_socket_for_ignored_e2e() else {
        eprintln!("skipping docker daemon e2e: no docker unix socket found");
        return;
    };

    if UnixStream::connect(&docker_sock).await.is_err() {
        eprintln!(
            "skipping docker daemon e2e: docker socket exists but is not reachable at {}",
            docker_sock.display()
        );
        return;
    }

    let ping = send_docker_request(&docker_sock, Method::GET, "/_ping", None).await;
    if ping.status != StatusCode::OK {
        eprintln!(
            "skipping docker daemon e2e: /_ping returned {} with body {}",
            ping.status,
            String::from_utf8_lossy(&ping.body)
        );
        return;
    }

    let Some(image) = docker_image_for_ignored_e2e(&docker_sock).await else {
        return;
    };

    let suffix = unique_test_suffix();
    let compose_project = format!("amber-gw-e2e-netmode-{suffix}");
    let component = format!("amber-gw-e2e-netmode-comp-{suffix}");
    let container_name = format!("amber-gw-e2e-netmode-ctr-{suffix}");

    let listen = reserve_loopback_socket_addr();
    let config = DockerGatewayConfig {
        listen,
        docker_sock: docker_sock.clone(),
        compose_project: compose_project.clone(),
        callers: vec![CallerConfig {
            host: "127.0.0.1".to_string(),
            port: None,
            component: component.clone(),
            compose_service: component.clone(),
        }],
    };

    let gateway_task = tokio::spawn(async move {
        if let Err(err) = run(config).await {
            panic!("gateway run failed in network-mode e2e test: {err}");
        }
    });
    wait_until_gateway_listens(listen, &gateway_task).await;

    // Docker CLI v27+ sends EndpointsConfig:{"default":{}} when no
    // --network flag is given. The gateway should skip builtin names.
    let create = send_gateway_request(
        listen,
        Method::POST,
        &format!("/containers/create?name={container_name}"),
        &[("content-type", "application/json")],
        serde_json::json!({
            "Image": image.as_str(),
            "Cmd": ["true"],
            "HostConfig": {
                "NetworkMode": "default"
            },
            "NetworkingConfig": {
                "EndpointsConfig": {
                    "default": {}
                }
            }
        })
        .to_string()
        .as_bytes(),
    )
    .await;
    assert_eq!(
        create.status,
        StatusCode::CREATED,
        "container create via gateway failed: {}",
        String::from_utf8_lossy(&create.body)
    );

    // Verify the container exists and has correct labels.
    let inspect = send_gateway_request(
        listen,
        Method::GET,
        &format!("/containers/{container_name}/json"),
        &[],
        &[],
    )
    .await;
    assert_eq!(
        inspect.status,
        StatusCode::OK,
        "container inspect failed: {}",
        String::from_utf8_lossy(&inspect.body)
    );
    let inspect_value: serde_json::Value =
        serde_json::from_slice(&inspect.body).expect("inspect json");
    let labels = inspect_value
        .pointer("/Config/Labels")
        .and_then(|v| v.as_object())
        .expect("container labels");
    assert_eq!(
        labels
            .get(COMPOSE_PROJECT_LABEL)
            .and_then(|value| value.as_str()),
        Some(compose_project.as_str())
    );
    assert_eq!(
        labels
            .get(AMBER_COMPONENT_LABEL)
            .and_then(|value| value.as_str()),
        Some(component.as_str())
    );

    gateway_task.abort();
    docker_delete_container_best_effort(&docker_sock, &container_name).await;
}
