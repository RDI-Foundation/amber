use std::time::Duration;

use base64::Engine as _;

use super::*;

fn test_mesh_config() -> MeshConfig {
    MeshConfig {
        identity: MeshIdentity::generate("router", Some("test-scope".to_string())),
        mesh_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        control_listen: None,
        control_allow: None,
        peers: Vec::new(),
        inbound: Vec::new(),
        outbound: Vec::new(),
        transport: amber_mesh::TransportConfig::NoiseIk {},
    }
}

fn test_peer(id: &str) -> MeshPeer {
    let identity = MeshIdentity::generate(id, Some("test-scope".to_string()));
    MeshPeer {
        id: id.to_string(),
        public_key: identity.public_key,
    }
}

fn inbound_route(
    route_id: &str,
    capability: &str,
    protocol: MeshProtocol,
    target: InboundTarget,
    allowed_issuers: &[&str],
) -> InboundRoute {
    InboundRoute {
        route_id: route_id.to_string(),
        capability: capability.to_string(),
        capability_kind: None,
        capability_profile: None,
        protocol,
        http_plugins: Vec::new(),
        target,
        allowed_issuers: allowed_issuers.iter().map(ToString::to_string).collect(),
    }
}

fn test_http_exchange_labels() -> HttpExchangeLabels {
    HttpExchangeLabels {
        kind: HttpEdgeKind::ExternalSlot,
        emit_telemetry: true,
        slot: Some(Arc::<str>::from("matrix")),
        capability: Arc::<str>::from("matrix"),
        capability_kind: Some(Arc::<str>::from("http")),
        capability_profile: None,
        source_component: Some(Arc::<str>::from("/bot")),
        source_endpoint: Arc::<str>::from("matrix"),
        destination_component: None,
        destination_endpoint: Arc::<str>::from("matrix"),
    }
}

fn empty_box_body() -> BoxBody {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

async fn response_text(response: Response<Incoming>) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .expect("response body should collect")
            .to_bytes()
            .to_vec(),
    )
    .expect("response body should be utf-8")
}

async fn spawn_test_mesh_http_server(
    router_identity: &MeshIdentity,
    connection_count: Arc<std::sync::atomic::AtomicUsize>,
) -> (String, tokio::task::JoinHandle<()>) {
    let peer_identity = MeshIdentity::generate("proxy", Some("test-scope".to_string()));
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("mesh server should bind");
    let addr = listener
        .local_addr()
        .expect("listener should have local addr");
    let server_config = MeshConfig {
        identity: peer_identity.clone(),
        peers: vec![MeshPeer {
            id: router_identity.id.clone(),
            public_key: router_identity.public_key,
        }],
        ..test_mesh_config()
    };
    let trust = Arc::new(TrustBundle::new(&server_config).expect("mesh server trust"));
    let noise_keys = noise_keys_for_identity(&server_config.identity).expect("noise keys");

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("mesh peer should accept");
        connection_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let mut session = accept_noise(stream, &noise_keys, trust.as_ref())
            .await
            .expect("mesh peer should accept noise");
        let open = session.recv_open().await.expect("open frame");
        assert_eq!(open.capability, "matrix");

        let (local, remote) = duplex(64 * 1024);
        let bridge = tokio::spawn(async move { proxy_noise_to_plain(&mut session, local).await });
        let service = service_fn(|req: Request<Incoming>| async move {
            assert_eq!(req.uri().path(), "/_matrix/client/v3/sync");
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(
                        Full::new(Bytes::from_static(b"mesh ok"))
                            .map_err(|never| match never {})
                            .boxed(),
                    )
                    .expect("mesh response should build"),
            )
        });
        http1::Builder::new()
            .serve_connection(TokioIo::new(remote), service)
            .await
            .expect("mesh http server should complete");
        bridge
            .await
            .expect("mesh bridge task should complete")
            .expect("mesh bridge should succeed");
    });

    let peer_key = base64::engine::general_purpose::STANDARD.encode(peer_identity.public_key);
    let mut mesh_url =
        Url::parse(&format!("mesh://127.0.0.1:{}", addr.port())).expect("mesh url should parse");
    mesh_url
        .query_pairs_mut()
        .append_pair("peer_id", &peer_identity.id)
        .append_pair("peer_key", &peer_key);
    (mesh_url.to_string(), server_task)
}

#[test]
fn build_inbound_routes_rejects_duplicate_route_id() {
    let config = MeshConfig {
        inbound: vec![
            inbound_route(
                "dup",
                "shared-a",
                MeshProtocol::Http,
                InboundTarget::Local { port: 7001 },
                &["peer-a"],
            ),
            inbound_route(
                "dup",
                "shared-b",
                MeshProtocol::Http,
                InboundTarget::Local { port: 7002 },
                &["peer-b"],
            ),
        ],
        ..test_mesh_config()
    };

    let err = build_inbound_routes(&config).expect_err("duplicate route id should fail");
    match err {
        RouterError::InvalidConfig(message) => {
            assert!(message.contains("duplicate inbound route_id dup"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_inbound_routes_rejects_http_plugins_on_non_http_route() {
    let config = MeshConfig {
        inbound: vec![InboundRoute {
            route_id: "bad-route".to_string(),
            capability: "cap".to_string(),
            capability_kind: None,
            capability_profile: None,
            protocol: MeshProtocol::Tcp,
            http_plugins: vec![HttpRoutePlugin::A2a],
            target: InboundTarget::Local { port: 7001 },
            allowed_issuers: vec!["peer-a".to_string()],
        }],
        ..test_mesh_config()
    };

    let err =
        build_inbound_routes(&config).expect_err("non-http route with http plugin should fail");
    match err {
        RouterError::InvalidConfig(message) => {
            assert!(message.contains("has http plugins but uses tcp protocol"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_inbound_routes_rejects_http_plugins_on_non_local_target() {
    let config = MeshConfig {
        inbound: vec![InboundRoute {
            route_id: "bad-route".to_string(),
            capability: "cap".to_string(),
            capability_kind: None,
            capability_profile: None,
            protocol: MeshProtocol::Http,
            http_plugins: vec![HttpRoutePlugin::A2a],
            target: InboundTarget::External {
                url_env: "TEST_URL".to_string(),
                optional: false,
            },
            allowed_issuers: vec!["peer-a".to_string()],
        }],
        ..test_mesh_config()
    };

    let err =
        build_inbound_routes(&config).expect_err("non-local target with http plugin should fail");
    match err {
        RouterError::InvalidConfig(message) => {
            assert!(message.contains("has http plugins but target is not local"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn validate_outbound_routes_rejects_http_plugins_on_non_http_route() {
    let config = MeshConfig {
        outbound: vec![OutboundRoute {
            route_id: "bad-route".to_string(),
            slot: "slot".to_string(),
            capability_kind: None,
            capability_profile: None,
            listen_port: 20000,
            listen_addr: None,
            protocol: MeshProtocol::Tcp,
            http_plugins: vec![HttpRoutePlugin::A2a],
            peer_addr: "127.0.0.1:30000".to_string(),
            peer_id: "peer-a".to_string(),
            capability: "cap".to_string(),
        }],
        ..test_mesh_config()
    };

    let err = validate_outbound_routes(&config)
        .expect_err("non-http outbound route with http plugin should fail");
    match err {
        RouterError::InvalidConfig(message) => {
            assert!(message.contains("has http plugins but uses tcp protocol"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn join_paths_handles_root() {
    assert_eq!(join_paths("/", "/foo"), "/foo");
    assert_eq!(join_paths("", "/foo"), "/foo");
    assert_eq!(join_paths("/", "/"), "/");
}

#[test]
fn join_paths_preserves_base_prefix() {
    assert_eq!(join_paths("/v1", "/chat"), "/v1/chat");
    assert_eq!(join_paths("/v1/", "/chat"), "/v1/chat");
    assert_eq!(join_paths("/v1", "/"), "/v1");
}

#[test]
fn join_url_copies_request_query_when_base_has_none() {
    let base = Url::parse("http://example.com/v1").expect("base url");
    let uri: Uri = "/chat?model=gpt".parse().expect("request uri");
    let out = join_url(&base, &uri);
    assert_eq!(out.as_str(), "http://example.com/v1/chat?model=gpt");
}

#[test]
fn join_url_preserves_base_query_over_request_query() {
    let base = Url::parse("http://example.com/v1?token=abc").expect("base url");
    let uri: Uri = "/chat?model=gpt".parse().expect("request uri");
    let out = join_url(&base, &uri);
    assert_eq!(out.as_str(), "http://example.com/v1/chat?token=abc");
}

#[test]
fn join_url_preserves_empty_base_query() {
    let base = Url::parse("http://example.com/v1?").expect("base url");
    let uri: Uri = "/chat?model=gpt".parse().expect("request uri");
    let out = join_url(&base, &uri);
    assert_eq!(out.path(), "/v1/chat");
    assert_eq!(out.query(), Some(""));
}

#[tokio::test]
async fn insert_peer_allows_idempotent_same_key() {
    let trust = TrustBundle::new(&test_mesh_config()).expect("trust bundle");
    let peer = test_peer("dynamic-peer");
    trust.insert_peer(&peer).await.expect("first insert");
    trust.insert_peer(&peer).await.expect("second insert");
}

#[tokio::test]
async fn insert_peer_rejects_existing_id_with_different_key() {
    let trust = TrustBundle::new(&test_mesh_config()).expect("trust bundle");
    let first = test_peer("dynamic-peer");
    let second = test_peer("dynamic-peer");
    trust.insert_peer(&first).await.expect("first insert");
    let err = trust
        .insert_peer(&second)
        .await
        .expect_err("second insert should fail");
    match err {
        RouterError::Auth(message) => {
            assert!(message.contains("different key"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test]
async fn insert_peer_rejects_key_reused_by_different_id() {
    let trust = TrustBundle::new(&test_mesh_config()).expect("trust bundle");
    let identity = MeshIdentity::generate("first-peer", Some("test-scope".to_string()));
    let first = MeshPeer {
        id: "first-peer".to_string(),
        public_key: identity.public_key,
    };
    let second = MeshPeer {
        id: "second-peer".to_string(),
        public_key: identity.public_key,
    };
    trust.insert_peer(&first).await.expect("first insert");
    let err = trust
        .insert_peer(&second)
        .await
        .expect_err("second insert should fail");
    match err {
        RouterError::Auth(message) => {
            assert!(message.contains("peer key already registered for first-peer"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test]
async fn run_surfaces_outbound_listener_bind_failure() {
    let occupied = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind occupied listener");
    let occupied_addr = occupied
        .local_addr()
        .expect("read occupied listener address");

    let mut config = test_mesh_config();
    config.outbound.push(amber_mesh::OutboundRoute {
        route_id: "route".to_string(),
        slot: "test-outbound".to_string(),
        capability_kind: None,
        capability_profile: None,
        listen_port: occupied_addr.port(),
        listen_addr: Some("127.0.0.1".to_string()),
        protocol: MeshProtocol::Tcp,
        http_plugins: Vec::new(),
        peer_addr: "127.0.0.1:65535".to_string(),
        peer_id: "peer".to_string(),
        capability: "capability".to_string(),
    });

    let err = tokio::time::timeout(Duration::from_secs(2), run(config))
        .await
        .expect("run should return when a listener fails to bind")
        .expect_err("run should fail when outbound listener port is occupied");

    match err {
        RouterError::BindFailed { addr, .. } => assert_eq!(addr, occupied_addr),
        other => panic!("expected bind failure, got {other}"),
    }
}

#[tokio::test]
async fn run_with_prebound_outbound_listener_proxies_http_requests() {
    let reserved = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("reserved listener should bind");
    let reserved_addr = reserved.local_addr().expect("reserved listener addr");
    reserved
        .set_nonblocking(true)
        .expect("reserved listener should be non-blocking");
    let reserved =
        TcpListener::from_std(reserved).expect("reserved listener should convert to tokio");

    let mut config = test_mesh_config();
    let connection_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (mesh_url, mesh_server_task) =
        spawn_test_mesh_http_server(&config.identity, connection_count.clone()).await;
    let mesh = parse_mesh_external(&mesh_url).expect("mesh url should parse");
    config.peers.push(MeshPeer {
        id: mesh.peer_id.clone(),
        public_key: mesh.peer_key,
    });
    config.outbound.push(OutboundRoute {
        route_id: "route".to_string(),
        slot: "matrix".to_string(),
        capability_kind: Some("http".to_string()),
        capability_profile: None,
        listen_port: reserved_addr.port(),
        listen_addr: Some("127.0.0.1".to_string()),
        protocol: MeshProtocol::Http,
        http_plugins: Vec::new(),
        peer_addr: mesh.peer_addr,
        peer_id: mesh.peer_id,
        capability: "matrix".to_string(),
    });

    let mut listeners = PreboundListeners::default();
    listeners.insert_outbound("route", reserved);
    let router_task = tokio::spawn(async move { run_with_listeners(config, listeners).await });

    let stream = tokio::net::TcpStream::connect(reserved_addr)
        .await
        .expect("client should connect to prebound listener");
    let (mut sender, conn) = client_http1::handshake(TokioIo::new(stream))
        .await
        .expect("client handshake should succeed");
    let client_task = tokio::spawn(async move {
        conn.await.expect("client connection should complete");
    });

    let response = sender
        .send_request(
            Request::builder()
                .uri("/_matrix/client/v3/sync")
                .header(header::HOST, "tuwunel.test")
                .body(empty_box_body())
                .expect("request should build"),
        )
        .await
        .expect("response should arrive through prebound listener");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_text(response).await, "mesh ok");
    assert_eq!(
        connection_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "prebound outbound listener should still proxy through the mesh peer"
    );

    drop(sender);
    let _ = client_task.await;
    router_task.abort();
    let _ = router_task.await;
    let _ = mesh_server_task.await;
}

#[tokio::test]
async fn prebound_listeners_preserve_duplicates_for_the_same_route_id() {
    let first = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("first listener should bind");
    let second = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("second listener should bind");
    let first_addr = first.local_addr().expect("first listener addr");
    let second_addr = second.local_addr().expect("second listener addr");
    first
        .set_nonblocking(true)
        .expect("first listener should be non-blocking");
    second
        .set_nonblocking(true)
        .expect("second listener should be non-blocking");

    let mut listeners = PreboundListeners::default();
    listeners.insert_outbound(
        "route",
        TcpListener::from_std(first).expect("first listener should convert to tokio"),
    );
    listeners.insert_outbound(
        "route",
        TcpListener::from_std(second).expect("second listener should convert to tokio"),
    );

    let first = listeners
        .take_outbound("route")
        .expect("first duplicate listener should be available");
    let second = listeners
        .take_outbound("route")
        .expect("second duplicate listener should be available");
    assert_eq!(
        first.local_addr().expect("first listener local addr"),
        first_addr
    );
    assert_eq!(
        second.local_addr().expect("second listener local addr"),
        second_addr
    );
    assert!(
        listeners.take_outbound("route").is_none(),
        "all duplicate listeners should be drained in insertion order"
    );
}

#[test]
fn resolve_inbound_route_isolated_by_peer_identity() {
    let config = MeshConfig {
        inbound: vec![
            inbound_route(
                "route-a",
                "shared",
                MeshProtocol::Http,
                InboundTarget::Local { port: 7001 },
                &["peer-a"],
            ),
            inbound_route(
                "route-b",
                "shared",
                MeshProtocol::Http,
                InboundTarget::Local { port: 7002 },
                &["peer-b"],
            ),
        ],
        ..test_mesh_config()
    };
    let inbound_routes = build_inbound_routes(&config).expect("build inbound routes");
    let open = OpenFrame {
        route_id: "route-a".to_string(),
        capability: "shared".to_string(),
        protocol: MeshProtocol::Http,
        slot: None,
        capability_kind: None,
        capability_profile: None,
    };
    let dynamic_overlays = HashMap::new();

    let a = resolve_inbound_route(
        &inbound_routes,
        &dynamic_overlays,
        &open,
        "peer-a",
        &HashMap::new(),
    )
    .expect("peer-a route should resolve");
    let denied = resolve_inbound_route(
        &inbound_routes,
        &dynamic_overlays,
        &open,
        "peer-b",
        &HashMap::new(),
    )
    .expect_err("peer-c should not be allowed");

    match &a.target {
        InboundTarget::Local { port } => assert_eq!(*port, 7001),
        _ => panic!("peer-a should resolve to local route"),
    }
    match denied {
        RouterError::Auth(message) => {
            assert_eq!(message, "peer peer-b not allowed for route route-a")
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn resolve_inbound_route_rejects_route_id_spoof() {
    let config = MeshConfig {
        inbound: vec![
            inbound_route(
                "route-a",
                "shared",
                MeshProtocol::Http,
                InboundTarget::Local { port: 7001 },
                &["peer-a"],
            ),
            inbound_route(
                "route-b",
                "shared",
                MeshProtocol::Http,
                InboundTarget::Local { port: 7002 },
                &["peer-b"],
            ),
        ],
        ..test_mesh_config()
    };
    let inbound_routes = build_inbound_routes(&config).expect("build inbound routes");
    let spoofed = OpenFrame {
        route_id: "route-b".to_string(),
        capability: "shared".to_string(),
        protocol: MeshProtocol::Http,
        slot: None,
        capability_kind: None,
        capability_profile: None,
    };
    let denied = resolve_inbound_route(
        &inbound_routes,
        &HashMap::new(),
        &spoofed,
        "peer-a",
        &HashMap::new(),
    )
    .expect_err("peer-a should not be able to use peer-b route id");
    match denied {
        RouterError::Auth(message) => {
            assert_eq!(message, "peer peer-a not allowed for route route-b")
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn resolve_inbound_route_dynamic_issuers_apply_only_to_exports() {
    let config = MeshConfig {
        inbound: vec![
            inbound_route(
                "external-route",
                "shared",
                MeshProtocol::Http,
                InboundTarget::External {
                    url_env: "SHARED_URL".to_string(),
                    optional: false,
                },
                &["consumer"],
            ),
            inbound_route(
                "export-route",
                "shared",
                MeshProtocol::Http,
                InboundTarget::MeshForward {
                    peer_addr: "127.0.0.1:1234".to_string(),
                    peer_id: "provider".to_string(),
                    route_id: "provider-route".to_string(),
                    capability: "upstream".to_string(),
                },
                &["router"],
            ),
        ],
        ..test_mesh_config()
    };
    let inbound_routes = build_inbound_routes(&config).expect("build inbound routes");
    let open = OpenFrame {
        route_id: "export-route".to_string(),
        capability: "shared".to_string(),
        protocol: MeshProtocol::Http,
        slot: None,
        capability_kind: None,
        capability_profile: None,
    };
    let dynamic_overlays = HashMap::new();
    let dynamic = HashSet::from([String::from("dynamic-peer")]);
    let issuers = HashMap::from([(String::from("export-route"), dynamic.clone())]);

    let dynamic_route = resolve_inbound_route(
        &inbound_routes,
        &dynamic_overlays,
        &open,
        "dynamic-peer",
        &issuers,
    )
    .expect("dynamic issuer should resolve");
    let denied = resolve_inbound_route(
        &inbound_routes,
        &dynamic_overlays,
        &open,
        "consumer",
        &HashMap::new(),
    )
    .expect_err("consumer should not be authorized for export route");

    assert!(
        matches!(&dynamic_route.target, InboundTarget::MeshForward { .. }),
        "dynamic issuers must only authorize mesh-forward exports"
    );
    match denied {
        RouterError::Auth(message) => {
            assert_eq!(message, "peer consumer not allowed for route export-route")
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test]
async fn register_export_peer_succeeds_when_export_key_collides_with_external_slot() {
    let mut config = test_mesh_config();
    config.inbound = vec![
        inbound_route(
            "export-route",
            "shared",
            MeshProtocol::Http,
            InboundTarget::MeshForward {
                peer_addr: "127.0.0.1:1234".to_string(),
                peer_id: "provider".to_string(),
                route_id: "provider-route".to_string(),
                capability: "upstream".to_string(),
            },
            &[config.identity.id.as_str()],
        ),
        inbound_route(
            "external-route",
            "shared",
            MeshProtocol::Http,
            InboundTarget::External {
                url_env: "SHARED_URL".to_string(),
                optional: false,
            },
            &["consumer"],
        ),
    ];
    let inbound_routes = build_inbound_routes(&config).expect("build inbound routes");
    let trust = TrustBundle::new(&config).expect("trust");
    let dynamic_route_overlays: DynamicRouteOverlays = Arc::new(RwLock::new(HashMap::new()));
    let dynamic_issuers: DynamicIssuers = Arc::new(RwLock::new(HashMap::new()));
    let peer = test_peer("dynamic-peer");
    let payload = ControlExportPeer {
        peer_id: peer.id.clone(),
        peer_key: base64::engine::general_purpose::STANDARD.encode(peer.public_key),
        protocol: "http".to_string(),
    };

    register_export_peer(
        "shared",
        payload,
        &trust,
        &inbound_routes,
        &dynamic_route_overlays,
        &dynamic_issuers,
        &config.identity.id,
    )
    .await
    .expect("export registration should succeed");

    let issuers = dynamic_issuers.read().await;
    assert!(
        issuers
            .get("export-route")
            .is_some_and(|ids| ids.contains("dynamic-peer")),
        "dynamic issuer should be registered under the export key"
    );
}

#[tokio::test]
async fn unregister_export_peer_removes_only_requested_dynamic_issuer() {
    let mut config = test_mesh_config();
    config.inbound = vec![inbound_route(
        "export-route",
        "shared",
        MeshProtocol::Http,
        InboundTarget::MeshForward {
            peer_addr: "127.0.0.1:1234".to_string(),
            peer_id: "provider".to_string(),
            route_id: "provider-route".to_string(),
            capability: "upstream".to_string(),
        },
        &[config.identity.id.as_str()],
    )];
    let inbound_routes = build_inbound_routes(&config).expect("build inbound routes");
    let trust = TrustBundle::new(&config).expect("trust");
    let dynamic_route_overlays: DynamicRouteOverlays = Arc::new(RwLock::new(HashMap::new()));
    let dynamic_issuers: DynamicIssuers = Arc::new(RwLock::new(HashMap::new()));
    let peer_a = test_peer("dynamic-peer-a");
    let peer_b = test_peer("dynamic-peer-b");

    for peer in [&peer_a, &peer_b] {
        register_export_peer(
            "shared",
            ControlExportPeer {
                peer_id: peer.id.clone(),
                peer_key: base64::engine::general_purpose::STANDARD.encode(peer.public_key),
                protocol: "http".to_string(),
            },
            &trust,
            &inbound_routes,
            &dynamic_route_overlays,
            &dynamic_issuers,
            &config.identity.id,
        )
        .await
        .expect("export registration should succeed");
    }

    unregister_export_peer(
        "shared",
        ControlExportPeer {
            peer_id: peer_a.id.clone(),
            peer_key: String::new(),
            protocol: "http".to_string(),
        },
        &inbound_routes,
        &dynamic_route_overlays,
        &dynamic_issuers,
    )
    .await
    .expect("export unregister should succeed");

    let issuers = dynamic_issuers.read().await;
    let route_issuers = issuers
        .get("export-route")
        .expect("remaining issuer set should exist");
    assert!(
        !route_issuers.contains(&peer_a.id),
        "requested issuer should be removed"
    );
    assert!(
        route_issuers.contains(&peer_b.id),
        "unrelated issuer should remain"
    );
}

#[test]
fn extract_json_rpc_from_text_extracts_method_and_id() {
    let rpc = extract_json_rpc_from_text(r#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#);
    assert_eq!(rpc.method.as_deref(), Some("tools/list"));
    assert_eq!(rpc.id.as_deref(), Some("7"));
    assert_eq!(rpc.is_notification, Some(false));
    assert_eq!(rpc.error_code, None);
}

#[test]
fn extract_json_rpc_from_text_extracts_batch_first_rpc_entry() {
    let rpc = extract_json_rpc_from_text(
        r#"[{"jsonrpc":"2.0","id":"a","method":"foo"},{"jsonrpc":"2.0","id":"b","method":"bar"}]"#,
    );
    assert_eq!(rpc.method.as_deref(), Some("foo"));
    assert_eq!(rpc.id.as_deref(), Some("a"));
}

#[test]
fn parse_sse_events_parses_framed_messages() {
    let events = parse_sse_events(
        "id: 1\nevent: message\ndata: \
         {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}\n\n:comment\ndata: plain\n\n",
    );
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].id.as_deref(), Some("1"));
    assert_eq!(events[0].event.as_deref(), Some("message"));
    assert_eq!(
        events[0].data,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#
    );
    assert_eq!(events[1].event, None);
    assert_eq!(events[1].id, None);
    assert_eq!(events[1].data, "plain");
}

#[test]
fn inbound_labels_fall_back_to_open_frame_metadata() {
    let route = InboundRoute {
        route_id: "route".to_string(),
        capability: "cap".to_string(),
        capability_kind: None,
        capability_profile: None,
        protocol: MeshProtocol::Http,
        http_plugins: Vec::new(),
        target: InboundTarget::Local { port: 7000 },
        allowed_issuers: vec!["peer".to_string()],
    };
    let open = OpenFrame {
        route_id: "route".to_string(),
        capability: "cap".to_string(),
        protocol: MeshProtocol::Http,
        slot: Some("slot".to_string()),
        capability_kind: Some("mcp".to_string()),
        capability_profile: Some("v1".to_string()),
    };

    let labels = HttpExchangeLabels::inbound_from_route(
        Arc::<str>::from("/provider"),
        Arc::<str>::from("/consumer"),
        &route,
        &open,
    );
    assert_eq!(labels.slot.as_deref(), Some("slot"));
    assert_eq!(labels.capability_kind.as_deref(), Some("mcp"));
    assert_eq!(labels.capability_profile.as_deref(), Some("v1"));
}

#[test]
fn inbound_export_delivery_to_provider_is_not_observed_twice() {
    let route = InboundRoute {
        route_id: "component:/server:api:http".to_string(),
        capability: "api".to_string(),
        capability_kind: Some("mcp".to_string()),
        capability_profile: Some("debug-jsonrpc".to_string()),
        protocol: MeshProtocol::Http,
        http_plugins: Vec::new(),
        target: InboundTarget::Local { port: 9000 },
        allowed_issuers: vec!["/router".to_string()],
    };
    let open = OpenFrame {
        route_id: "router:export:public:http".to_string(),
        capability: "public".to_string(),
        protocol: MeshProtocol::Http,
        slot: Some("public".to_string()),
        capability_kind: Some("mcp".to_string()),
        capability_profile: Some("debug-jsonrpc".to_string()),
    };

    let labels = HttpExchangeLabels::inbound_from_route(
        Arc::<str>::from("/server"),
        Arc::<str>::from("/router"),
        &route,
        &open,
    );

    assert_eq!(labels.kind, HttpEdgeKind::Export);
    assert!(!labels.emit_telemetry);
    assert_eq!(labels.source_endpoint.as_ref(), "public");
    assert_eq!(labels.destination_component.as_deref(), Some("/server"));
}

#[test]
fn inbound_export_labels_treat_router_slot_only_metadata_as_export() {
    let route = InboundRoute {
        route_id: "component:/server:api:http".to_string(),
        capability: "api".to_string(),
        capability_kind: Some("mcp".to_string()),
        capability_profile: Some("debug-jsonrpc".to_string()),
        protocol: MeshProtocol::Http,
        http_plugins: Vec::new(),
        target: InboundTarget::Local { port: 9000 },
        allowed_issuers: vec!["/router".to_string()],
    };
    let open = OpenFrame {
        route_id: "router:export:public:http".to_string(),
        capability: "public".to_string(),
        protocol: MeshProtocol::Http,
        slot: Some("public".to_string()),
        capability_kind: Some("mcp".to_string()),
        capability_profile: Some("debug-jsonrpc".to_string()),
    };

    let labels = HttpExchangeLabels::inbound_from_route(
        Arc::<str>::from("/server"),
        Arc::<str>::from("/router"),
        &route,
        &open,
    );

    assert_eq!(labels.kind, HttpEdgeKind::Export);
    assert!(!labels.emit_telemetry);
    assert_eq!(labels.source_endpoint.as_ref(), "public");
    assert_eq!(labels.destination_component.as_deref(), Some("/server"));
}

#[test]
fn external_slot_destination_ref_is_user_facing() {
    let route = OutboundRoute {
        route_id: "router:external:ext_api:http".to_string(),
        slot: "ext_api".to_string(),
        capability_kind: Some("http".to_string()),
        capability_profile: Some("debug-external".to_string()),
        listen_port: 20000,
        listen_addr: None,
        protocol: MeshProtocol::Http,
        peer_addr: "router:24000".to_string(),
        peer_id: "/router".to_string(),
        capability: "ext_api".to_string(),
        http_plugins: Vec::new(),
    };

    let labels = HttpExchangeLabels::outbound_from_route(Arc::<str>::from("/client"), &route);
    assert_eq!(destination_ref_for(&labels), "external.ext_api");
    assert_eq!(
        edge_ref_for(
            RewriteFlow::Outbound,
            &labels,
            "/client.ext_api",
            "external.ext_api"
        ),
        "/client.ext_api -> external.ext_api"
    );
}

#[test]
fn export_messages_use_user_facing_component_story() {
    let route = InboundRoute {
        route_id: "router:export:public:http".to_string(),
        capability: "public".to_string(),
        capability_kind: Some("mcp".to_string()),
        capability_profile: Some("debug-jsonrpc".to_string()),
        protocol: MeshProtocol::Http,
        http_plugins: Vec::new(),
        target: InboundTarget::MeshForward {
            peer_addr: "server:23000".to_string(),
            peer_id: "/server".to_string(),
            route_id: "component:/server:api:http".to_string(),
            capability: "api".to_string(),
        },
        allowed_issuers: vec!["/router".to_string()],
    };
    let open = OpenFrame {
        route_id: "router:export:public:http".to_string(),
        capability: "public".to_string(),
        protocol: MeshProtocol::Http,
        slot: Some("public".to_string()),
        capability_kind: Some("mcp".to_string()),
        capability_profile: Some("debug-jsonrpc".to_string()),
    };
    let labels = HttpExchangeLabels::inbound_from_route(
        Arc::<str>::from("/router"),
        Arc::<str>::from("/proxy/example"),
        &route,
        &open,
    );
    let telemetry = HttpExchangeTelemetryContext::new(RewriteFlow::Inbound, &labels);

    assert_eq!(
        exchange_message(
            &telemetry,
            HttpLifecyclePart::Request,
            &ProtocolSummary::default(),
        ),
        "request received from public by /server"
    );
}

#[test]
fn rewrite_flow_maps_to_expected_otel_kind() {
    assert_eq!(RewriteFlow::Inbound.otel_kind(), "server");
    assert_eq!(RewriteFlow::Outbound.otel_kind(), "client");
}

#[test]
fn otel_status_code_for_http_marks_server_errors() {
    assert_eq!(otel_status_code_for_http(StatusCode::OK), "ok");
    assert_eq!(otel_status_code_for_http(StatusCode::NOT_FOUND), "ok");
    assert_eq!(
        otel_status_code_for_http(StatusCode::INTERNAL_SERVER_ERROR),
        "error"
    );
}

#[test]
fn resolve_http_external_target_with_override_returns_service_unavailable_when_missing() {
    let target = ExternalTarget {
        name: "matrix".to_string(),
        url_env: "MATRIX_URL".to_string(),
        optional: false,
        url_override: None,
    };

    let response = resolve_http_external_target_with_override(
        &target,
        None,
        &Uri::from_static("/_matrix/client/v3/sync"),
    )
    .expect_err("missing external slot should fail");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn resolve_http_external_target_with_override_joins_http_targets_per_request() {
    let target = ExternalTarget {
        name: "matrix".to_string(),
        url_env: "MATRIX_URL".to_string(),
        optional: false,
        url_override: None,
    };

    let resolved = resolve_http_external_target_with_override(
        &target,
        Some("http://8.8.8.8:6167/base"),
        &Uri::from_static("/_matrix/client/v3/sync?timeout=30000"),
    )
    .expect("http target should resolve");

    let ResolvedHttpExternalTarget::Http(url) = resolved else {
        panic!("expected direct http target");
    };
    assert_eq!(
        url.as_str(),
        "http://8.8.8.8:6167/base/_matrix/client/v3/sync?timeout=30000"
    );
}

#[test]
fn resolve_http_external_target_with_override_rejects_loopback_ip_literals() {
    let target = ExternalTarget {
        name: "matrix".to_string(),
        url_env: "MATRIX_URL".to_string(),
        optional: false,
        url_override: None,
    };

    let response = resolve_http_external_target_with_override(
        &target,
        Some("http://127.0.0.1:6167/base"),
        &Uri::from_static("/_matrix/client/v3/sync"),
    )
    .expect_err("loopback target should be rejected");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[test]
fn resolve_http_external_target_with_override_accepts_framework_loopback_ip_literals() {
    let target = ExternalTarget {
        name: "component".to_string(),
        url_env: amber_mesh::FRAMEWORK_COMPONENT_CCS_URL_ENV.to_string(),
        optional: false,
        url_override: None,
    };

    let resolved = resolve_http_external_target_with_override(
        &target,
        Some("http://127.0.0.1:6167/base"),
        &Uri::from_static("/v1/children"),
    )
    .expect("framework target should resolve");

    let ResolvedHttpExternalTarget::Http(url) = resolved else {
        panic!("expected direct http target");
    };
    assert_eq!(url.as_str(), "http://127.0.0.1:6167/base/v1/children");
}

#[test]
fn resolve_http_external_target_with_override_accepts_private_ip_literals() {
    let target = ExternalTarget {
        name: "matrix".to_string(),
        url_env: "MATRIX_URL".to_string(),
        optional: false,
        url_override: None,
    };

    let resolved = resolve_http_external_target_with_override(
        &target,
        Some("http://10.0.0.8:6167/base"),
        &Uri::from_static("/_matrix/client/v3/sync"),
    )
    .expect("private target should resolve");

    let ResolvedHttpExternalTarget::Http(url) = resolved else {
        panic!("expected direct http target");
    };
    assert_eq!(
        url.as_str(),
        "http://10.0.0.8:6167/base/_matrix/client/v3/sync"
    );
}

#[test]
fn resolve_http_external_target_with_override_preserves_mesh_targets() {
    let peer_key = base64::engine::general_purpose::STANDARD.encode([251u8; 32]);
    assert!(
        peer_key.contains('+'),
        "regression test requires a base64 peer key with '+'"
    );
    let mut mesh_url =
        Url::parse("mesh://host.docker.internal:61662").expect("mesh url should parse");
    mesh_url
        .query_pairs_mut()
        .append_pair("peer_id", "/proxy")
        .append_pair("peer_key", &peer_key);
    let mesh_url = mesh_url.to_string();
    let target = ExternalTarget {
        name: "matrix".to_string(),
        url_env: "MATRIX_URL".to_string(),
        optional: false,
        url_override: None,
    };

    let resolved = resolve_http_external_target_with_override(
        &target,
        Some(mesh_url.as_str()),
        &Uri::from_static("/_matrix/client/v3/sync"),
    )
    .expect("mesh target should resolve");

    let ResolvedHttpExternalTarget::Mesh { target_url, mesh } = resolved else {
        panic!("expected mesh target");
    };
    assert_eq!(target_url, mesh_url);
    assert_eq!(mesh.peer_addr, "host.docker.internal:61662");
    assert_eq!(mesh.peer_id, "/proxy");
    assert_eq!(mesh.route_id, None);
    assert_eq!(mesh.capability, None);
}

#[test]
fn resolve_http_external_target_with_override_preserves_explicit_mesh_route() {
    let peer_key = base64::engine::general_purpose::STANDARD.encode([251u8; 32]);
    let mut mesh_url = Url::parse("mesh://127.0.0.1:61662").expect("mesh url should parse");
    mesh_url
        .query_pairs_mut()
        .append_pair("peer_id", "/site/provider/router")
        .append_pair("peer_key", &peer_key)
        .append_pair("route_id", "router:export:public:http")
        .append_pair("capability", "public");
    let mesh_url = mesh_url.to_string();
    let target = ExternalTarget {
        name: "public".to_string(),
        url_env: "PUBLIC_URL".to_string(),
        optional: false,
        url_override: None,
    };

    let resolved = resolve_http_external_target_with_override(
        &target,
        Some(mesh_url.as_str()),
        &Uri::from_static("/"),
    )
    .expect("mesh target should resolve");

    let ResolvedHttpExternalTarget::Mesh { mesh, .. } = resolved else {
        panic!("expected mesh target");
    };
    assert_eq!(mesh.peer_addr, "127.0.0.1:61662");
    assert_eq!(mesh.peer_id, "/site/provider/router");
    assert_eq!(mesh.route_id.as_deref(), Some("router:export:public:http"));
    assert_eq!(mesh.capability.as_deref(), Some("public"));
}

#[tokio::test]
async fn resolve_http_external_target_reads_live_overrides() {
    let external_overrides: ExternalOverrides = Arc::new(RwLock::new(HashMap::new()));
    let (client, vetted_external_addrs) = build_client();
    let state = HttpProxyState {
        client,
        target: ExternalTarget {
            name: "matrix".to_string(),
            url_env: "MATRIX_URL".to_string(),
            optional: false,
            url_override: None,
        },
        labels: test_http_exchange_labels(),
        config: Arc::new(test_mesh_config()),
        external_overrides: external_overrides.clone(),
        vetted_external_addrs,
        mesh_upstream: Arc::new(Mutex::new(None)),
        route_id: None,
        peer_id: None,
    };
    let uri = Uri::from_static("/_matrix/client/v3/sync");

    let first = resolve_http_external_target(&state, &uri)
        .await
        .expect_err("unconfigured external slot should fail");
    assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);

    external_overrides
        .write()
        .await
        .insert("matrix".to_string(), "http://8.8.8.8:6167".to_string());

    let second = resolve_http_external_target(&state, &uri)
        .await
        .expect("new override should be visible");
    let ResolvedHttpExternalTarget::Http(url) = second else {
        panic!("expected direct http target after override registration");
    };
    assert_eq!(url.as_str(), "http://8.8.8.8:6167/_matrix/client/v3/sync");
}

#[tokio::test]
async fn resolve_http_external_target_rejects_localhost_overrides() {
    let external_overrides: ExternalOverrides = Arc::new(RwLock::new(HashMap::new()));
    let (client, vetted_external_addrs) = build_client();
    let state = HttpProxyState {
        client,
        target: ExternalTarget {
            name: "matrix".to_string(),
            url_env: "MATRIX_URL".to_string(),
            optional: false,
            url_override: None,
        },
        labels: test_http_exchange_labels(),
        config: Arc::new(test_mesh_config()),
        external_overrides: external_overrides.clone(),
        vetted_external_addrs,
        mesh_upstream: Arc::new(Mutex::new(None)),
        route_id: None,
        peer_id: None,
    };
    let uri = Uri::from_static("/_matrix/client/v3/sync");

    external_overrides
        .write()
        .await
        .insert("matrix".to_string(), "http://localhost:6167".to_string());

    let response = resolve_http_external_target(&state, &uri)
        .await
        .expect_err("localhost override should be rejected");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn resolve_external_host_rejects_loopback_ip_literals() {
    let err = resolve_external_host("127.0.0.1", 6167)
        .await
        .expect_err("loopback target should be rejected");
    assert!(
        err.contains("disallowed address"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn resolve_external_host_with_policy_accepts_loopback_for_framework_targets() {
    let resolved = resolve_external_host_with_policy("127.0.0.1", 6167, true)
        .await
        .expect("framework target should allow loopback");
    assert_eq!(resolved, vec![SocketAddr::from(([127, 0, 0, 1], 6167))]);
}

#[tokio::test]
async fn resolve_external_host_accepts_private_ip_literals() {
    let resolved = resolve_external_host("10.0.0.8", 6167)
        .await
        .expect("private target should resolve");
    assert_eq!(resolved, vec![SocketAddr::from(([10, 0, 0, 8], 6167))]);
}

#[tokio::test]
async fn external_http_resolver_prefers_pinned_addresses() {
    let resolver = ExternalHttpResolver {
        vetted_external_addrs: Arc::new(RwLock::new(HashMap::from([(
            "example.com".to_string(),
            vec![SocketAddr::from(([203, 0, 113, 10], 0))],
        )]))),
        fallback: GaiResolver::new(),
    };
    let mut resolver = resolver;
    let addrs = resolver
        .call(
            "example.com"
                .parse::<Name>()
                .expect("resolver name should parse"),
        )
        .await
        .expect("pinned address should resolve")
        .collect::<Vec<_>>();
    assert_eq!(addrs, vec![SocketAddr::from(([203, 0, 113, 10], 0))]);
}

#[tokio::test]
async fn late_mesh_slot_registration_succeeds_on_same_http_connection() {
    let config = Arc::new(test_mesh_config());
    let external_overrides: ExternalOverrides = Arc::new(RwLock::new(HashMap::new()));
    let connection_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (mesh_url, mesh_server_task) =
        spawn_test_mesh_http_server(&config.identity, connection_count.clone()).await;
    let (client, vetted_external_addrs) = build_client();
    let state = HttpProxyState {
        client,
        target: ExternalTarget {
            name: "matrix".to_string(),
            url_env: "MATRIX_URL".to_string(),
            optional: false,
            url_override: None,
        },
        labels: test_http_exchange_labels(),
        config: config.clone(),
        external_overrides: external_overrides.clone(),
        vetted_external_addrs,
        mesh_upstream: Arc::new(Mutex::new(None)),
        route_id: None,
        peer_id: None,
    };
    let (client_side, server_side) = duplex(64 * 1024);
    let proxy_state = state.clone();
    let proxy_task = tokio::spawn(async move {
        let service = service_fn(move |req: Request<Incoming>| {
            let state = proxy_state.clone();
            async move { Ok::<_, std::convert::Infallible>(proxy_http_request(state, req).await) }
        });
        http1::Builder::new()
            .serve_connection(TokioIo::new(server_side), service)
            .await
            .expect("proxy http server should complete");
    });
    let (mut sender, conn) = client_http1::handshake(TokioIo::new(client_side))
        .await
        .expect("client handshake should succeed");
    let client_task = tokio::spawn(async move {
        conn.await.expect("client connection should complete");
    });

    let first = sender
        .send_request(
            Request::builder()
                .uri("/_matrix/client/v3/sync")
                .header(header::HOST, "tuwunel.test")
                .body(empty_box_body())
                .expect("first request should build"),
        )
        .await
        .expect("first response should arrive");
    assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response_text(first).await,
        "external slot matrix is not configured"
    );

    external_overrides
        .write()
        .await
        .insert("matrix".to_string(), mesh_url);

    let second = sender
        .send_request(
            Request::builder()
                .uri("/_matrix/client/v3/sync")
                .header(header::HOST, "tuwunel.test")
                .body(empty_box_body())
                .expect("second request should build"),
        )
        .await
        .expect("second response should arrive");
    let second_status = second.status();
    let second_body = response_text(second).await;
    assert_eq!(
        second_status,
        StatusCode::OK,
        "second response body: {second_body}"
    );
    assert_eq!(second_body, "mesh ok");

    let third = sender
        .send_request(
            Request::builder()
                .uri("/_matrix/client/v3/sync")
                .header(header::HOST, "tuwunel.test")
                .body(empty_box_body())
                .expect("third request should build"),
        )
        .await
        .expect("third response should arrive");
    let third_status = third.status();
    let third_body = response_text(third).await;
    assert_eq!(
        third_status,
        StatusCode::OK,
        "third response body: {third_body}"
    );
    assert_eq!(third_body, "mesh ok");
    assert_eq!(
        connection_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "mesh upstream should be reused once registered"
    );

    drop(sender);
    drop(state);
    let _ = client_task.await;
    let _ = proxy_task.await;
    let _ = mesh_server_task.await;
}
