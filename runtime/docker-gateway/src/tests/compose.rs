use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn compose_in_compose_setup_injects_scoped_labels() {
    let gateway = GatewayHarness::start(vec![default_caller()]).await;
    gateway.enqueue_json(
        Method::POST,
        "/networks/create",
        StatusCode::CREATED,
        serde_json::json!({"Id":"inner-net"}),
    );
    gateway.enqueue_json(
        Method::POST,
        "/volumes/create",
        StatusCode::CREATED,
        serde_json::json!({"Name":"inner-vol"}),
    );
    gateway.enqueue_json(
        Method::POST,
        "/containers/create",
        StatusCode::CREATED,
        serde_json::json!({"Id":"inner-workload"}),
    );

    let create_network = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/networks/create",
        &[("content-type", "application/json")],
        br#"{
                "Name":"inner-net",
                "Labels":{
                    "com.docker.compose.project":"inner-project",
                    "com.docker.compose.network":"default"
                }
            }"#,
    )
    .await;
    assert_eq!(create_network.status, StatusCode::CREATED);

    let create_volume = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/volumes/create",
        &[("content-type", "application/json")],
        br#"{
                "Name":"inner-vol",
                "Labels":{
                    "com.docker.compose.project":"inner-project",
                    "com.docker.compose.volume":"cache"
                }
            }"#,
    )
    .await;
    assert_eq!(create_volume.status, StatusCode::CREATED);

    let create_container = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/containers/create?name=inner-workload-1",
        &[("content-type", "application/json")],
        br#"{
                "Image":"busybox",
                "Labels":{
                    "com.docker.compose.project":"inner-project",
                    "com.docker.compose.service":"workload"
                }
            }"#,
    )
    .await;
    assert_eq!(create_container.status, StatusCode::CREATED);

    let requests = gateway.requests();
    let network_create = requests
        .iter()
        .find(|req| req.method == Method::POST && req.path == "/networks/create")
        .expect("network create should be forwarded");
    let network_body: serde_json::Value =
        serde_json::from_slice(&network_create.body).expect("network create body json");
    let network_labels = network_body
        .get("Labels")
        .and_then(|value| value.as_object())
        .expect("network labels object");
    assert_eq!(
        network_labels
            .get(COMPOSE_PROJECT_LABEL)
            .and_then(|value| value.as_str()),
        Some(TEST_PROJECT)
    );
    assert_eq!(
        network_labels
            .get(AMBER_COMPONENT_LABEL)
            .and_then(|value| value.as_str()),
        Some(TEST_COMPONENT)
    );
    assert_eq!(
        network_labels
            .get(AMBER_PROJECT_LABEL)
            .and_then(|value| value.as_str()),
        Some(TEST_PROJECT)
    );

    let volume_create = requests
        .iter()
        .find(|req| req.method == Method::POST && req.path == "/volumes/create")
        .expect("volume create should be forwarded");
    let volume_body: serde_json::Value =
        serde_json::from_slice(&volume_create.body).expect("volume create body json");
    let volume_labels = volume_body
        .get("Labels")
        .and_then(|value| value.as_object())
        .expect("volume labels object");
    assert_eq!(
        volume_labels
            .get(COMPOSE_PROJECT_LABEL)
            .and_then(|value| value.as_str()),
        Some(TEST_PROJECT)
    );
    assert_eq!(
        volume_labels
            .get(AMBER_COMPONENT_LABEL)
            .and_then(|value| value.as_str()),
        Some(TEST_COMPONENT)
    );
    assert_eq!(
        volume_labels
            .get(AMBER_PROJECT_LABEL)
            .and_then(|value| value.as_str()),
        Some(TEST_PROJECT)
    );

    let container_create = requests
        .iter()
        .find(|req| req.method == Method::POST && req.path == "/containers/create")
        .expect("container create should be forwarded");
    let container_body: serde_json::Value =
        serde_json::from_slice(&container_create.body).expect("container create body json");
    let container_labels = container_body
        .get("Labels")
        .and_then(|value| value.as_object())
        .expect("container labels object");
    assert_eq!(
        container_labels
            .get(COMPOSE_PROJECT_LABEL)
            .and_then(|value| value.as_str()),
        Some(TEST_PROJECT)
    );
    assert_eq!(
        container_labels
            .get(AMBER_COMPONENT_LABEL)
            .and_then(|value| value.as_str()),
        Some(TEST_COMPONENT)
    );
    assert_eq!(
        container_labels
            .get(AMBER_PROJECT_LABEL)
            .and_then(|value| value.as_str()),
        Some(TEST_PROJECT)
    );
    assert_eq!(
        container_labels
            .get(COMPOSE_SERVICE_LABEL)
            .and_then(|value| value.as_str()),
        Some("workload")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn compose_in_compose_teardown_allows_owned_resource_removal() {
    let gateway = GatewayHarness::start(vec![default_caller()]).await;
    gateway.enqueue_json(
        Method::GET,
        "/containers/inner-workload/json",
        StatusCode::OK,
        container_labels(TEST_COMPONENT, TEST_PROJECT),
    );
    gateway.enqueue_empty(
        Method::POST,
        "/containers/inner-workload/stop",
        StatusCode::OK,
    );
    gateway.enqueue_json(
        Method::GET,
        "/containers/inner-workload/json",
        StatusCode::OK,
        container_labels(TEST_COMPONENT, TEST_PROJECT),
    );
    gateway.enqueue_empty(
        Method::DELETE,
        "/containers/inner-workload",
        StatusCode::NO_CONTENT,
    );
    gateway.enqueue_json(
        Method::GET,
        "/networks/inner-net",
        StatusCode::OK,
        resource_labels(TEST_COMPONENT, TEST_PROJECT),
    );
    gateway.enqueue_empty(
        Method::DELETE,
        "/networks/inner-net",
        StatusCode::NO_CONTENT,
    );
    gateway.enqueue_json(
        Method::GET,
        "/volumes/inner-vol",
        StatusCode::OK,
        resource_labels(TEST_COMPONENT, TEST_PROJECT),
    );
    gateway.enqueue_empty(Method::DELETE, "/volumes/inner-vol", StatusCode::NO_CONTENT);

    let stop_container = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/containers/inner-workload/stop?t=1",
        &[],
        &[],
    )
    .await;
    assert_eq!(stop_container.status, StatusCode::OK);

    let remove_container = send_gateway_request(
        gateway.addr,
        Method::DELETE,
        "/containers/inner-workload?v=1",
        &[],
        &[],
    )
    .await;
    assert_eq!(remove_container.status, StatusCode::NO_CONTENT);

    let remove_network = send_gateway_request(
        gateway.addr,
        Method::DELETE,
        "/networks/inner-net",
        &[],
        &[],
    )
    .await;
    assert_eq!(remove_network.status, StatusCode::NO_CONTENT);

    let remove_volume = send_gateway_request(
        gateway.addr,
        Method::DELETE,
        "/volumes/inner-vol?force=1",
        &[],
        &[],
    )
    .await;
    assert_eq!(remove_volume.status, StatusCode::NO_CONTENT);

    let requests = gateway.requests();
    let container_auth_count = requests
        .iter()
        .filter(|req| req.method == Method::GET && req.path == "/containers/inner-workload/json")
        .count();
    assert_eq!(container_auth_count, 2);
    assert!(
        requests
            .iter()
            .any(|req| req.method == Method::POST && req.path == "/containers/inner-workload/stop")
    );
    assert!(
        requests
            .iter()
            .any(|req| req.method == Method::DELETE && req.path == "/containers/inner-workload")
    );
    assert!(
        requests
            .iter()
            .any(|req| req.method == Method::GET && req.path == "/networks/inner-net")
    );
    assert!(
        requests
            .iter()
            .any(|req| req.method == Method::DELETE && req.path == "/networks/inner-net")
    );
    assert!(
        requests
            .iter()
            .any(|req| req.method == Method::GET && req.path == "/volumes/inner-vol")
    );
    assert!(
        requests
            .iter()
            .any(|req| req.method == Method::DELETE && req.path == "/volumes/inner-vol")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn compose_in_compose_remove_orphans_rewrites_project_filters() {
    let gateway = GatewayHarness::start(vec![default_caller()]).await;
    gateway.enqueue_json(
        Method::GET,
        "/containers/json",
        StatusCode::OK,
        serde_json::json!([]),
    );
    gateway.enqueue_json(
        Method::GET,
        "/networks",
        StatusCode::OK,
        serde_json::json!([]),
    );
    gateway.enqueue_json(
        Method::GET,
        "/volumes",
        StatusCode::OK,
        serde_json::json!({"Volumes":[]}),
    );

    let inner_project = "inner-project";
    let container_query = build_label_filter_query(
        &[
            format!("{COMPOSE_PROJECT_LABEL}={inner_project}"),
            "com.docker.compose.oneoff=False".to_string(),
        ],
        true,
    );
    let network_query =
        build_label_filter_query(&[format!("{COMPOSE_PROJECT_LABEL}={inner_project}")], false);
    let volume_query =
        build_label_filter_query(&[format!("{COMPOSE_PROJECT_LABEL}={inner_project}")], false);

    let list_containers = send_gateway_request(
        gateway.addr,
        Method::GET,
        &format!("/containers/json?{container_query}"),
        &[],
        &[],
    )
    .await;
    assert_eq!(list_containers.status, StatusCode::OK);

    let list_networks = send_gateway_request(
        gateway.addr,
        Method::GET,
        &format!("/networks?{network_query}"),
        &[],
        &[],
    )
    .await;
    assert_eq!(list_networks.status, StatusCode::OK);

    let list_volumes = send_gateway_request(
        gateway.addr,
        Method::GET,
        &format!("/volumes?{volume_query}"),
        &[],
        &[],
    )
    .await;
    assert_eq!(list_volumes.status, StatusCode::OK);

    let requests = gateway.requests();
    let containers_req = requests
        .iter()
        .find(|req| req.method == Method::GET && req.path == "/containers/json")
        .expect("containers list should be forwarded");
    assert!(
        containers_req.path_and_query.contains("all=1"),
        "compose --remove-orphans should preserve all=1 on container listing"
    );
    let container_filters = decode_filters(containers_req);
    let container_labels = labels_as_set(&container_filters);
    assert!(container_labels.contains("com.docker.compose.oneoff=False"));
    assert!(container_labels.contains(&format!("{COMPOSE_PROJECT_LABEL}={TEST_PROJECT}")));
    assert!(!container_labels.contains(&format!("{COMPOSE_PROJECT_LABEL}={inner_project}")));
    assert!(container_labels.contains(&format!("{AMBER_COMPONENT_LABEL}={TEST_COMPONENT}")));
    assert!(container_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));

    let networks_req = requests
        .iter()
        .find(|req| req.method == Method::GET && req.path == "/networks")
        .expect("networks list should be forwarded");
    let network_filters = decode_filters(networks_req);
    let network_labels = labels_as_set(&network_filters);
    assert!(network_labels.contains(&format!("{COMPOSE_PROJECT_LABEL}={TEST_PROJECT}")));
    assert!(!network_labels.contains(&format!("{COMPOSE_PROJECT_LABEL}={inner_project}")));
    assert!(network_labels.contains(&format!("{AMBER_COMPONENT_LABEL}={TEST_COMPONENT}")));
    assert!(network_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));

    let volumes_req = requests
        .iter()
        .find(|req| req.method == Method::GET && req.path == "/volumes")
        .expect("volumes list should be forwarded");
    let volume_filters = decode_filters(volumes_req);
    let volume_labels = labels_as_set(&volume_filters);
    assert!(volume_labels.contains(&format!("{COMPOSE_PROJECT_LABEL}={TEST_PROJECT}")));
    assert!(!volume_labels.contains(&format!("{COMPOSE_PROJECT_LABEL}={inner_project}")));
    assert!(volume_labels.contains(&format!("{AMBER_COMPONENT_LABEL}={TEST_COMPONENT}")));
    assert!(volume_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_cleanup_removes_owned_resources() {
    let docker = MockDocker::start().await;
    let state = State::new(DockerGatewayConfig {
        listen: "127.0.0.1:23750".parse().expect("valid listen addr"),
        docker_sock: docker.socket_path.clone(),
        compose_project: TEST_PROJECT.to_string(),
        callers: vec![default_caller()],
    });

    docker.enqueue_json(
        Method::GET,
        "/containers/json",
        StatusCode::OK,
        serde_json::json!([
            {"Id":"container-a"},
            {"Id":"container-b"},
        ]),
    );
    docker.enqueue_empty(
        Method::DELETE,
        "/containers/container-a",
        StatusCode::NO_CONTENT,
    );
    docker.enqueue_empty(
        Method::DELETE,
        "/containers/container-b",
        StatusCode::NO_CONTENT,
    );
    docker.enqueue_json(
        Method::GET,
        "/networks",
        StatusCode::OK,
        serde_json::json!([
            {"Id":"network-a"},
        ]),
    );
    docker.enqueue_empty(
        Method::DELETE,
        "/networks/network-a",
        StatusCode::NO_CONTENT,
    );
    docker.enqueue_json(
        Method::GET,
        "/volumes",
        StatusCode::OK,
        serde_json::json!({
            "Volumes": [
                {"Name":"volume-a"},
            ]
        }),
    );
    docker.enqueue_empty(Method::DELETE, "/volumes/volume-a", StatusCode::NO_CONTENT);

    state.cleanup_created_resources_inner().await;

    let requests = docker.requests();

    let container_list = requests
        .iter()
        .find(|req| req.method == Method::GET && req.path == "/containers/json")
        .expect("containers list request");
    assert!(
        container_list.path_and_query.contains("all=1"),
        "containers cleanup should request all containers"
    );
    let container_filters = decode_filters(container_list);
    let container_labels = labels_as_set(&container_filters);
    assert!(container_labels.contains(AMBER_COMPONENT_LABEL));
    assert!(container_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));

    let network_list = requests
        .iter()
        .find(|req| req.method == Method::GET && req.path == "/networks")
        .expect("networks list request");
    let network_filters = decode_filters(network_list);
    let network_labels = labels_as_set(&network_filters);
    assert!(network_labels.contains(AMBER_COMPONENT_LABEL));
    assert!(network_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));

    let volume_list = requests
        .iter()
        .find(|req| req.method == Method::GET && req.path == "/volumes")
        .expect("volumes list request");
    let volume_filters = decode_filters(volume_list);
    let volume_labels = labels_as_set(&volume_filters);
    assert!(volume_labels.contains(AMBER_COMPONENT_LABEL));
    assert!(volume_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));

    let deleted_containers: HashSet<&str> = requests
        .iter()
        .filter(|req| req.method == Method::DELETE && req.path.starts_with("/containers/"))
        .map(|req| req.path.as_str())
        .collect();
    assert!(deleted_containers.contains("/containers/container-a"));
    assert!(deleted_containers.contains("/containers/container-b"));

    assert!(
        requests
            .iter()
            .any(|req| req.method == Method::DELETE && req.path == "/networks/network-a")
    );
    assert!(
        requests
            .iter()
            .any(|req| req.method == Method::DELETE && req.path == "/volumes/volume-a")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn versioned_paths_preserve_version_for_authorization_and_forwarding() {
    let gateway = GatewayHarness::start(vec![default_caller()]).await;
    gateway.enqueue_json(
        Method::GET,
        "/v1.41/containers/workload/json",
        StatusCode::OK,
        container_labels(TEST_COMPONENT, TEST_PROJECT),
    );
    gateway.enqueue_empty(
        Method::POST,
        "/v1.41/containers/workload/start",
        StatusCode::NO_CONTENT,
    );

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/v1.41/containers/workload/start",
        &[],
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);

    let requests = gateway.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/v1.41/containers/workload/json");
    assert_eq!(requests[1].path, "/v1.41/containers/workload/start");
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_start_uses_cached_exec_to_container_mapping() {
    let gateway = GatewayHarness::start(vec![default_caller()]).await;
    gateway.enqueue_json(
        Method::GET,
        "/containers/workload/json",
        StatusCode::OK,
        container_labels(TEST_COMPONENT, TEST_PROJECT),
    );
    gateway.enqueue_json(
        Method::POST,
        "/containers/workload/exec",
        StatusCode::CREATED,
        serde_json::json!({"Id":"exec-1"}),
    );
    gateway.enqueue_json(
        Method::GET,
        "/containers/workload/json",
        StatusCode::OK,
        container_labels(TEST_COMPONENT, TEST_PROJECT),
    );
    gateway.enqueue_json(
        Method::POST,
        "/exec/exec-1/start",
        StatusCode::OK,
        serde_json::json!({"ok":true}),
    );

    let create_exec = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/containers/workload/exec",
        &[("content-type", "application/json")],
        br#"{"Cmd":["echo","hi"]}"#,
    )
    .await;
    assert_eq!(create_exec.status, StatusCode::CREATED);

    let start_exec = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/exec/exec-1/start",
        &[("content-type", "application/json")],
        br#"{"Detach":false}"#,
    )
    .await;
    assert_eq!(start_exec.status, StatusCode::OK);

    let requests = gateway.requests();
    let paths: HashSet<&str> = requests.iter().map(|req| req.path.as_str()).collect();
    assert!(paths.contains("/containers/workload/json"));
    assert!(paths.contains("/containers/workload/exec"));
    assert!(paths.contains("/exec/exec-1/start"));
    assert!(!paths.contains("/exec/exec-1/json"));
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_start_falls_back_to_exec_inspect_when_cache_is_missing() {
    let gateway = GatewayHarness::start(vec![default_caller()]).await;
    gateway.enqueue_json(
        Method::GET,
        "/exec/exec-2/json",
        StatusCode::OK,
        serde_json::json!({"ContainerID":"workload"}),
    );
    gateway.enqueue_json(
        Method::GET,
        "/containers/workload/json",
        StatusCode::OK,
        container_labels(TEST_COMPONENT, TEST_PROJECT),
    );
    gateway.enqueue_json(
        Method::POST,
        "/exec/exec-2/start",
        StatusCode::OK,
        serde_json::json!({"ok":true}),
    );

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/exec/exec-2/start",
        &[("content-type", "application/json")],
        br#"{"Detach":false}"#,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    let requests = gateway.requests();
    let paths: Vec<&str> = requests.iter().map(|req| req.path.as_str()).collect();
    assert!(paths.contains(&"/exec/exec-2/json"));
    assert!(paths.contains(&"/containers/workload/json"));
    assert!(paths.contains(&"/exec/exec-2/start"));
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_start_denies_access_when_exec_belongs_to_foreign_container() {
    let gateway = GatewayHarness::start(vec![default_caller()]).await;
    gateway.enqueue_json(
        Method::GET,
        "/exec/exec-9/json",
        StatusCode::OK,
        serde_json::json!({"ContainerID":"foreign"}),
    );
    gateway.enqueue_json(
        Method::GET,
        "/containers/foreign/json",
        StatusCode::OK,
        container_labels("other-component", TEST_PROJECT),
    );

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/exec/exec-9/start",
        &[("content-type", "application/json")],
        br#"{"Detach":false}"#,
    )
    .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(response_message(&response.body).contains("not authorized for this container"));

    let requests = gateway.requests();
    let paths: HashSet<&str> = requests.iter().map(|req| req.path.as_str()).collect();
    assert!(paths.contains("/exec/exec-9/json"));
    assert!(paths.contains("/containers/foreign/json"));
    assert!(!paths.contains("/exec/exec-9/start"));
}
