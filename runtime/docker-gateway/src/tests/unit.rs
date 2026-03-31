use super::*;

#[test]
fn split_version_and_segments_parses_version_prefix() {
    let (version, segments) = split_version_and_segments("/v1.41/containers/json");
    assert_eq!(version.as_deref(), Some("/v1.41"));
    assert_eq!(segments, vec!["containers", "json"]);
}

#[test]
fn split_version_and_segments_handles_unversioned() {
    let (version, segments) = split_version_and_segments("/containers/json");
    assert!(version.is_none());
    assert_eq!(segments, vec!["containers", "json"]);
}

#[test]
fn inject_labels_adds_missing_labels() {
    let body = Bytes::from(r#"{"Image":"busybox"}"#);
    let labels = vec![("com.example.owner".to_string(), "alice".to_string())];
    let out = inject_labels_into_create_body(body, &labels).expect("inject labels");
    let parsed: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
    let labels = parsed
        .get("Labels")
        .and_then(|value| value.as_object())
        .expect("labels object");
    assert_eq!(
        labels.get("com.example.owner").and_then(|v| v.as_str()),
        Some("alice")
    );
}

#[test]
fn add_label_filters_to_uri_merges_filters() {
    let uri: Uri = "/containers/json?filters=%7B%22label%22%3A%5B%22a%3Db%22%5D%7D"
        .parse()
        .expect("uri");
    let required = vec!["c=d".to_string()];
    let out = add_label_filters_to_uri(&uri, &required).expect("filters");
    let query = out.query().expect("query");
    assert!(query.contains("filters="));
}

#[test]
fn add_label_filters_to_uri_accepts_object_labels() {
    let uri: Uri = "/containers/json?filters=%7B%22label%22%3A%7B%22a%3Db%22%3Atrue%2C%22c%3Dd%22%\
                    3Afalse%7D%7D"
        .parse()
        .expect("uri");
    let required = vec!["c=d".to_string()];
    let out = add_label_filters_to_uri(&uri, &required).expect("filters");
    let query = out.query().expect("query");
    let parsed_query: HashMap<String, String> =
        serde_urlencoded::from_str(query).expect("query should decode");
    let filters = parsed_query.get("filters").expect("filters");
    let parsed_filters: serde_json::Value = serde_json::from_str(filters).expect("json");
    let labels = parsed_filters
        .get("label")
        .and_then(|value| value.as_object())
        .expect("labels object");
    assert_eq!(
        labels.get("a=b").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        labels.get("c=d").and_then(|value| value.as_bool()),
        Some(true)
    );
}

#[test]
fn add_label_filters_to_uri_uses_object_labels_with_name_filter() {
    let uri: Uri = "/networks?filters=%7B%22name%22%3A%7B%22example_net%22%3Atrue%7D%2C%22label%\
                    22%3A%7B%22existing%3Dlabel%22%3Atrue%7D%7D"
        .parse()
        .expect("uri");
    let required = vec!["amber.component=/green".to_string()];
    let out = add_label_filters_to_uri(&uri, &required).expect("filters");
    let query = out.query().expect("query");
    let parsed_query: HashMap<String, String> =
        serde_urlencoded::from_str(query).expect("query should decode");
    let filters = parsed_query.get("filters").expect("filters");
    let parsed_filters: serde_json::Value = serde_json::from_str(filters).expect("json");

    assert!(
        parsed_filters
            .get("name")
            .and_then(|value| value.as_object())
            .is_some()
    );

    let labels = parsed_filters
        .get("label")
        .and_then(|value| value.as_object())
        .expect("labels object");
    assert_eq!(
        labels
            .get("existing=label")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        labels
            .get("amber.component=/green")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
}

#[test]
fn add_label_filters_to_uri_rewrites_compose_project_filter() {
    let uri: Uri = "/containers/json?filters=%7B%22label%22%3A%5B%22com.docker.compose.project%\
                    3Dinner-project%22%2C%22com.docker.compose.service%3Dlangchain%22%5D%7D"
        .parse()
        .expect("uri");
    let required = vec![
        "amber.component=/green".to_string(),
        "amber.project=outer-project".to_string(),
        "com.docker.compose.project=outer-project".to_string(),
    ];

    let out = add_label_filters_to_uri(&uri, &required).expect("filters");
    let query = out.query().expect("query");
    let parsed_query: HashMap<String, String> =
        serde_urlencoded::from_str(query).expect("query should decode");
    let filters = parsed_query.get("filters").expect("filters");
    let parsed_filters: serde_json::Value = serde_json::from_str(filters).expect("json");
    let labels = parsed_filters
        .get("label")
        .and_then(|value| value.as_object())
        .expect("labels object");

    assert!(labels.contains_key("com.docker.compose.service=langchain"));
    assert!(labels.contains_key("com.docker.compose.project=outer-project"));
    assert!(!labels.contains_key("com.docker.compose.project=inner-project"));
}

#[test]
fn add_label_filters_to_uri_rejects_invalid_filters_json() {
    let uri: Uri = "/containers/json?filters=%7Bnot-json".parse().expect("uri");
    let required = vec!["amber.component=/green".to_string()];
    let err = add_label_filters_to_uri(&uri, &required).expect_err("expected invalid filters");
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn add_label_filters_to_uri_rejects_non_object_filters() {
    let uri: Uri = "/containers/json?filters=%5B%22a%3Db%22%5D"
        .parse()
        .expect("uri");
    let required = vec!["amber.component=/green".to_string()];
    let err = add_label_filters_to_uri(&uri, &required).expect_err("expected invalid filters");
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn add_label_filters_to_uri_rejects_non_boolean_label_values() {
    let uri: Uri = "/containers/json?filters=%7B%22label%22%3A%7B%22a%3Db%22%3A%22yes%22%7D%7D"
        .parse()
        .expect("uri");
    let required = vec!["amber.component=/green".to_string()];
    let err = add_label_filters_to_uri(&uri, &required).expect_err("expected invalid labels");
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn parse_container_create_references_extracts_resources() {
    let body = br#"{
            "HostConfig": {
                "NetworkMode": "app-net",
                "Binds": ["shared-vol:/data", "/tmp:/tmp", ".:/workspace"],
                "Mounts": [
                    {"Type": "volume", "Source": "db-vol"},
                    {"Type": "bind", "Source": "/host"}
                ],
                "VolumesFrom": ["base-container:ro"],
                "Links": ["linked-container:alias"],
                "PidMode": "container:pid-target",
                "IpcMode": "container:ipc-target"
            },
            "NetworkingConfig": {
                "EndpointsConfig": {
                    "side-net": {}
                }
            }
        }"#;
    let refs = parse_container_create_references(body).expect("refs");
    assert!(refs.networks.contains("app-net"));
    assert!(refs.networks.contains("side-net"));
    assert!(refs.volumes.contains("shared-vol"));
    assert!(refs.volumes.contains("db-vol"));
    assert!(refs.containers.contains("base-container"));
    assert!(refs.containers.contains("linked-container"));
    assert!(refs.containers.contains("pid-target"));
    assert!(refs.containers.contains("ipc-target"));
}

#[test]
fn validate_rejects_empty_caller_host() {
    let config = DockerGatewayConfig {
        listen: "127.0.0.1:23750".parse().expect("valid listen addr"),
        docker_sock: PathBuf::from("/tmp/docker.sock"),
        compose_project: TEST_PROJECT.to_string(),
        callers: vec![CallerConfig {
            host: "   ".to_string(),
            port: None,
            component: TEST_COMPONENT.to_string(),
            compose_service: TEST_COMPONENT.to_string(),
        }],
    };

    let err = DockerGatewayConfig::validate(config).expect_err("empty host should fail");
    assert!(
        err.to_string().contains("caller host must not be empty"),
        "{err}"
    );
}

#[test]
fn validate_rejects_empty_caller_component() {
    let config = DockerGatewayConfig {
        listen: "127.0.0.1:23750".parse().expect("valid listen addr"),
        docker_sock: PathBuf::from("/tmp/docker.sock"),
        compose_project: TEST_PROJECT.to_string(),
        callers: vec![CallerConfig {
            host: "localhost".to_string(),
            port: None,
            component: "   ".to_string(),
            compose_service: TEST_COMPONENT.to_string(),
        }],
    };

    let err = DockerGatewayConfig::validate(config).expect_err("empty component should fail");
    assert!(
        err.to_string()
            .contains("caller component must not be empty"),
        "{err}"
    );
}
