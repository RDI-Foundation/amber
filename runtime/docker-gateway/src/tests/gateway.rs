use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn mesh_peer_identity_labels_created_resources() {
    let gateway = GatewayHarness::start("/component-b").await;
    gateway.enqueue_json(
        Method::POST,
        "/containers/create",
        StatusCode::CREATED,
        serde_json::json!({"Id":"new-container"}),
    );

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/containers/create",
        &[("content-type", "application/json")],
        br#"{"Image":"busybox"}"#,
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED);

    let requests = gateway.requests();
    let create_req = requests
        .iter()
        .find(|req| req.method == Method::POST && req.path == "/containers/create")
        .expect("create should be forwarded");
    let forwarded: serde_json::Value =
        serde_json::from_slice(&create_req.body).expect("forwarded body json");
    let labels = forwarded
        .get("Labels")
        .and_then(|value| value.as_object())
        .expect("forwarded labels object");
    assert_eq!(
        labels.get(AMBER_COMPONENT_LABEL).and_then(|v| v.as_str()),
        Some("/component-b")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn default_deny_blocks_unapproved_endpoints() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;

    let response = send_gateway_request(gateway.addr, Method::GET, "/images/json", &[], &[]).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(response_message(&response.body).contains("not allowed by gateway policy"));
    assert!(gateway.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn allows_image_inspect_endpoint_for_prebuilt_workflows() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::GET,
        "/images/busybox:latest/json",
        StatusCode::OK,
        serde_json::json!({"Id":"sha256:abc"}),
    );

    let response = send_gateway_request(
        gateway.addr,
        Method::GET,
        "/images/busybox:latest/json",
        &[],
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    let requests = gateway.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::GET);
    assert_eq!(requests[0].path, "/images/busybox:latest/json");
}

#[tokio::test(flavor = "multi_thread")]
async fn allows_image_inspect_endpoint_for_registry_qualified_names() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::GET,
        "/images/ghcr.io/org/app:latest/json",
        StatusCode::OK,
        serde_json::json!({"Id":"sha256:def"}),
    );

    let response = send_gateway_request(
        gateway.addr,
        Method::GET,
        "/images/ghcr.io/org/app:latest/json",
        &[],
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    let requests = gateway.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::GET);
    assert_eq!(requests[0].path, "/images/ghcr.io/org/app:latest/json");
}

#[tokio::test(flavor = "multi_thread")]
async fn allows_image_pull_with_from_image() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::POST,
        "/images/create",
        StatusCode::OK,
        serde_json::json!({"status":"Pulling from library/nginx"}),
    );

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/images/create?fromImage=nginx&tag=latest",
        &[],
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    let requests = gateway.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::POST);
    assert_eq!(requests[0].path, "/images/create");
    assert_eq!(
        requests[0].path_and_query,
        "/images/create?fromImage=nginx&tag=latest"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn allows_image_pull_without_explicit_tag() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::POST,
        "/images/create",
        StatusCode::OK,
        serde_json::json!({"status":"Pulling from library/alpine"}),
    );

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/images/create?fromImage=alpine",
        &[],
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    let requests = gateway.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::POST);
    assert_eq!(
        requests[0].path_and_query,
        "/images/create?fromImage=alpine"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn allows_image_pull_with_registry_qualified_name() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::POST,
        "/images/create",
        StatusCode::OK,
        serde_json::json!({"status":"Pulling from ghcr.io/org/app"}),
    );

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/images/create?fromImage=ghcr.io/org/app&tag=v1.2",
        &[],
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    let requests = gateway.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].path_and_query,
        "/images/create?fromImage=ghcr.io/org/app&tag=v1.2"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn blocks_image_import_with_from_src() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/images/create?fromSrc=-",
        &[("content-type", "application/x-tar")],
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(response_message(&response.body).contains("only image pull"));
    assert!(gateway.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn blocks_image_create_with_no_query_params() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;

    let response =
        send_gateway_request(gateway.addr, Method::POST, "/images/create", &[], &[]).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(response_message(&response.body).contains("only image pull"));
    assert!(gateway.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn blocks_image_create_with_both_from_image_and_from_src() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/images/create?fromImage=nginx&fromSrc=-",
        &[],
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(gateway.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn allows_image_pull_with_version_prefix() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::POST,
        "/v1.45/images/create",
        StatusCode::OK,
        serde_json::json!({"status":"Pulling from library/nginx"}),
    );

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/v1.45/images/create?fromImage=nginx&tag=latest",
        &[],
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    let requests = gateway.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::POST);
}

#[tokio::test(flavor = "multi_thread")]
async fn allows_info_endpoint() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::GET,
        "/info",
        StatusCode::OK,
        serde_json::json!({"ServerVersion":"27.0"}),
    );

    let response = send_gateway_request(gateway.addr, Method::GET, "/info", &[], &[]).await;
    assert_eq!(response.status, StatusCode::OK);

    let requests = gateway.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::GET);
    assert_eq!(requests[0].path, "/info");
}

#[tokio::test(flavor = "multi_thread")]
async fn blocks_network_connect_and_disconnect() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;

    let connect = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/networks/app-net/connect",
        &[],
        br#"{"Container":"abc"}"#,
    )
    .await;
    assert_eq!(connect.status, StatusCode::FORBIDDEN);

    let disconnect = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/networks/app-net/disconnect",
        &[],
        br#"{"Container":"abc"}"#,
    )
    .await;
    assert_eq!(disconnect.status, StatusCode::FORBIDDEN);

    assert!(gateway.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_injects_owner_labels_and_normalizes_compose_project() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::POST,
        "/containers/create",
        StatusCode::CREATED,
        serde_json::json!({"Id":"new-container"}),
    );

    let body = serde_json::json!({
        "Image": "busybox",
        "Labels": {
            AMBER_COMPONENT_LABEL: "attacker",
            AMBER_PROJECT_LABEL: "other-project",
            COMPOSE_PROJECT_LABEL: "compose-project",
            COMPOSE_SERVICE_LABEL: "other-service",
            "user.label": "kept"
        }
    });

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/containers/create",
        &[("content-type", "application/json")],
        body.to_string().as_bytes(),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED);

    let requests = gateway.requests();
    let create_req = requests
        .iter()
        .find(|req| req.method == Method::POST && req.path == "/containers/create")
        .expect("create should be forwarded");
    let forwarded: serde_json::Value =
        serde_json::from_slice(&create_req.body).expect("forwarded body json");
    let labels = forwarded
        .get("Labels")
        .and_then(|value| value.as_object())
        .expect("forwarded labels object");
    assert_eq!(
        labels.get(AMBER_COMPONENT_LABEL).and_then(|v| v.as_str()),
        Some(TEST_COMPONENT)
    );
    assert_eq!(
        labels.get(AMBER_PROJECT_LABEL).and_then(|v| v.as_str()),
        Some(TEST_PROJECT)
    );
    assert_eq!(
        labels.get(COMPOSE_SERVICE_LABEL).and_then(|v| v.as_str()),
        Some("other-service")
    );
    assert_eq!(
        labels.get(COMPOSE_PROJECT_LABEL).and_then(|v| v.as_str()),
        Some(TEST_PROJECT)
    );
    assert_eq!(
        labels.get("user.label").and_then(|v| v.as_str()),
        Some("kept")
    );

    assert!(
        !requests
            .iter()
            .any(|req| req.method == Method::GET && req.path == "/containers/json"),
        "container create should not query compose config hash"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn create_allows_endpoints_config_with_builtin_default_network() {
    // Docker CLI v27+ sends EndpointsConfig:{"default":{}} when no
    // --network flag is given. Builtin names should be skipped, just
    // like add_network_mode_reference does for NetworkMode.
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::POST,
        "/containers/create",
        StatusCode::CREATED,
        serde_json::json!({"Id":"new-container"}),
    );

    let body = serde_json::json!({
        "Image": "busybox",
        "HostConfig": {
            "NetworkMode": "default"
        },
        "NetworkingConfig": {
            "EndpointsConfig": {
                "default": {}
            }
        }
    });

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/containers/create",
        &[("content-type", "application/json")],
        body.to_string().as_bytes(),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED);

    let requests = gateway.requests();
    assert!(
        !requests
            .iter()
            .any(|req| req.method == Method::GET && req.path == "/networks/default"),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn create_rejects_foreign_network_in_endpoints_config() {
    // User-defined networks in EndpointsConfig must still be authorized.
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::GET,
        "/networks/custom-net",
        StatusCode::OK,
        resource_labels("other-component", TEST_PROJECT),
    );

    let body = serde_json::json!({
        "Image": "busybox",
        "HostConfig": {
            "NetworkMode": "custom-net"
        },
        "NetworkingConfig": {
            "EndpointsConfig": {
                "custom-net": {}
            }
        }
    });

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/containers/create",
        &[("content-type", "application/json")],
        body.to_string().as_bytes(),
    )
    .await;
    // custom-net is owned by a different component, so this should be denied
    assert_eq!(response.status, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_rejects_foreign_network_reference() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::GET,
        "/networks/shared-net",
        StatusCode::OK,
        resource_labels("other-component", TEST_PROJECT),
    );

    let body = serde_json::json!({
        "Image": "busybox",
        "HostConfig": {
            "NetworkMode": "shared-net"
        }
    });

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/containers/create",
        &[("content-type", "application/json")],
        body.to_string().as_bytes(),
    )
    .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(response_message(&response.body).contains("not authorized for this network"));

    let requests = gateway.requests();
    let paths: HashSet<&str> = requests.iter().map(|req| req.path.as_str()).collect();
    assert!(paths.contains("/networks/shared-net"));
    assert!(!paths.contains("/containers/create"));
}

#[tokio::test(flavor = "multi_thread")]
async fn create_rejects_foreign_named_volume_bind() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::GET,
        "/volumes/shared-volume",
        StatusCode::OK,
        resource_labels("other-component", TEST_PROJECT),
    );

    let body = serde_json::json!({
        "Image": "busybox",
        "HostConfig": {
            "Binds": ["shared-volume:/data"]
        }
    });

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/containers/create",
        &[("content-type", "application/json")],
        body.to_string().as_bytes(),
    )
    .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(response_message(&response.body).contains("not authorized for this volume"));

    let requests = gateway.requests();
    let paths: HashSet<&str> = requests.iter().map(|req| req.path.as_str()).collect();
    assert!(paths.contains("/volumes/shared-volume"));
    assert!(!paths.contains("/containers/create"));
}

#[tokio::test(flavor = "multi_thread")]
async fn create_allows_owned_resource_references() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::GET,
        "/containers/base/json",
        StatusCode::OK,
        container_labels(TEST_COMPONENT, TEST_PROJECT),
    );
    gateway.enqueue_json(
        Method::GET,
        "/networks/app-net",
        StatusCode::OK,
        resource_labels(TEST_COMPONENT, TEST_PROJECT),
    );
    gateway.enqueue_json(
        Method::GET,
        "/networks/side-net",
        StatusCode::OK,
        resource_labels(TEST_COMPONENT, TEST_PROJECT),
    );
    gateway.enqueue_json(
        Method::GET,
        "/volumes/shared-vol",
        StatusCode::OK,
        resource_labels(TEST_COMPONENT, TEST_PROJECT),
    );
    gateway.enqueue_json(
        Method::POST,
        "/containers/create",
        StatusCode::CREATED,
        serde_json::json!({"Id":"ok"}),
    );

    let body = serde_json::json!({
        "Image": "busybox",
        "HostConfig": {
            "NetworkMode": "app-net",
            "Binds": ["shared-vol:/data"],
            "VolumesFrom": ["base:ro"],
            "Links": ["base:alias"],
            "PidMode": "container:base",
            "IpcMode": "container:base"
        },
        "NetworkingConfig": {
            "EndpointsConfig": {
                "side-net": {}
            }
        }
    });

    let response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/containers/create",
        &[("content-type", "application/json")],
        body.to_string().as_bytes(),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED);

    let requests = gateway.requests();
    let paths: HashSet<&str> = requests.iter().map(|req| req.path.as_str()).collect();
    assert!(paths.contains("/containers/base/json"));
    assert!(paths.contains("/networks/app-net"));
    assert!(paths.contains("/networks/side-net"));
    assert!(paths.contains("/volumes/shared-vol"));
    assert!(paths.contains("/containers/create"));
}

#[tokio::test(flavor = "multi_thread")]
async fn list_and_prune_endpoints_force_required_label_filters() {
    let gateway = GatewayHarness::start(TEST_COMPONENT).await;
    gateway.enqueue_json(
        Method::GET,
        "/containers/json",
        StatusCode::OK,
        serde_json::json!([]),
    );
    gateway.enqueue_json(
        Method::POST,
        "/volumes/prune",
        StatusCode::OK,
        serde_json::json!({"VolumesDeleted":[]}),
    );

    let containers_response = send_gateway_request(
        gateway.addr,
        Method::GET,
        "/containers/json?filters=%7B%22label%22%3A%5B%22existing%3Dlabel%22%5D%7D",
        &[],
        &[],
    )
    .await;
    assert_eq!(containers_response.status, StatusCode::OK);

    let prune_response = send_gateway_request(
        gateway.addr,
        Method::POST,
        "/volumes/prune?filters=%7B%22label%22%3A%7B%22existing%3Dlabel%22%3Atrue%7D%7D",
        &[],
        &[],
    )
    .await;
    assert_eq!(prune_response.status, StatusCode::OK);

    let requests = gateway.requests();
    let containers_req = requests
        .iter()
        .find(|req| req.method == Method::GET && req.path == "/containers/json")
        .expect("containers list should be forwarded");
    let containers_filters = decode_filters(containers_req);
    let container_labels = labels_as_set(&containers_filters);
    assert!(container_labels.contains("existing=label"));
    assert!(container_labels.contains(&format!("{AMBER_COMPONENT_LABEL}={TEST_COMPONENT}")));
    assert!(container_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));

    let prune_req = requests
        .iter()
        .find(|req| req.method == Method::POST && req.path == "/volumes/prune")
        .expect("volumes prune should be forwarded");
    let prune_filters = decode_filters(prune_req);
    let prune_labels = labels_as_set(&prune_filters);
    assert!(prune_labels.contains("existing=label"));
    assert!(prune_labels.contains(&format!("{AMBER_COMPONENT_LABEL}={TEST_COMPONENT}")));
    assert!(prune_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));
}
