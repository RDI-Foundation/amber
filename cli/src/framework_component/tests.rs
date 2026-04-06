    use std::fs;

    use amber_compiler::run_plan::build_run_plan;
    use amber_mesh::component_protocol::BindingInput;
    use tempfile::TempDir;
    use url::Url;

    use super::*;

    fn write_file(path: &Path, contents: &str) {
        fs::write(path, contents).expect("test fixture should write");
    }

    fn file_url(path: &Path) -> String {
        Url::from_file_path(path)
            .expect("test path should convert to file URL")
            .to_string()
    }

    async fn compile_control_state_with_placement(
        root_path: &Path,
        placement: Option<&PlacementFile>,
    ) -> FrameworkControlState {
        let compiler = Compiler::new(Resolver::new(), DigestStore::default());
        let output = compiler
            .compile(
                ManifestRef::from_url(
                    Url::from_file_path(root_path).expect("root path should convert to URL"),
                ),
                CompileOptions::default(),
            )
            .await
            .expect("fixture should compile");
        let compiled = CompiledScenario::from_compile_output(&output)
            .expect("fixture should materialize compiled scenario");
        let run_plan =
            build_run_plan(&compiled, placement).expect("fixture should produce run plan");
        build_control_state("test-run", &run_plan).expect("fixture should build control state")
    }

    async fn compile_control_state(root_path: &Path) -> FrameworkControlState {
        compile_control_state_with_placement(root_path, None).await
    }

    async fn compile_control_state_from_ir(
        scenario_ir: ScenarioIr,
        placement: Option<&PlacementFile>,
    ) -> FrameworkControlState {
        let compiled = CompiledScenario::from_ir(scenario_ir).expect("fixture should load from ir");
        let run_plan =
            build_run_plan(&compiled, placement).expect("fixture should produce replay run plan");
        build_control_state("test-run", &run_plan).expect("fixture should build replay state")
    }

    #[derive(Deserialize)]
    struct SnapshotPlacementFixture {
        offered_sites: BTreeMap<String, SiteDefinition>,
        defaults: PlacementDefaults,
        #[serde(default)]
        assignments: BTreeMap<String, String>,
    }

    fn placement_from_snapshot(snapshot: &SnapshotResponse) -> PlacementFile {
        let placement: SnapshotPlacementFixture =
            serde_json::from_value(snapshot.placement.clone()).expect("snapshot placement");
        PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: placement.offered_sites,
            defaults: placement.defaults,
            components: placement.assignments,
        }
    }

    async fn compile_control_state_from_snapshot(
        snapshot: &SnapshotResponse,
    ) -> FrameworkControlState {
        let scenario_ir: ScenarioIr =
            serde_json::from_value(snapshot.scenario.clone()).expect("snapshot scenario");
        let placement = placement_from_snapshot(snapshot);
        compile_control_state_from_ir(scenario_ir, Some(&placement)).await
    }

    #[tokio::test]
    async fn same_site_dynamic_child_output_bindings_reuse_provider_component_routes() {
        let dir = TempDir::new().expect("temp dir");
        let required_path = dir.path().join("required.json5");
        let consumer_path = dir.path().join("consumer.json5");
        let root_path = dir.path().join("root.json5");
        write_file(
            &required_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "python:3.13-alpine",
                entrypoint: ["python3", "-c", "print('required')"],
                network: {
                  endpoints: [{ name: "http", port: 8080, protocol: "http" }]
                }
              },
              provides: {
                http: { kind: "http", endpoint: "http" }
              },
              exports: {
                http: "http"
              }
            }
            "#,
        );
        write_file(
            &consumer_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                required_api: { kind: "http" }
              },
              program: {
                image: "python:3.13-alpine",
                entrypoint: ["python3", "-c", "print('consumer')"],
                network: {
                  endpoints: [{ name: "http", port: 8081, protocol: "http" }]
                }
              },
              provides: {
                http: { kind: "http", endpoint: "http" }
              },
              exports: {
                http: "http"
              }
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r##"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  program: {{
                    image: "python:3.13-alpine",
                    entrypoint: ["python3", "-c", "print('root')"]
                  }},
                  child_templates: {{
                    required: {{
                      manifest: "{required}"
                    }},
                    consumer: {{
                      manifest: "{consumer}"
                    }}
                  }}
                }}
                "##,
                required = file_url(&required_path),
                consumer = file_url(&consumer_path),
            ),
        );
        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([(
                "compose_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Compose,
                    context: None,
                },
            )]),
            defaults: PlacementDefaults {
                image: Some("compose_local".to_string()),
                ..PlacementDefaults::default()
            },
            components: BTreeMap::new(),
        };
        let state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;
        let app = test_control_state_app(&dir, state, state_path);
        let actuators = install_success_site_actuator(&app).await;

        execute_create_child(
            &app,
            root_authority,
            CreateChildRequest {
                template: "required".to_string(),
                name: "required".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
        )
        .await
        .expect("required child should create");
        execute_create_child(
            &app,
            root_authority,
            CreateChildRequest {
                template: "consumer".to_string(),
                name: "consumer".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::from([(
                    "required_api".to_string(),
                    BindingInput {
                        selector: Some("children.required.exports.http".to_string()),
                        handle: None,
                    },
                )]),
            },
        )
        .await
        .expect("consumer child should create");

        let state = app.control_state.lock().await.clone();
        let consumer = state
            .live_children
            .iter()
            .find(|child| child.name == "consumer")
            .expect("consumer child should be recorded");
        for site_plan in &consumer.site_plans {
            assert_eq!(site_plan.routed_inputs.len(), 1);
            assert_eq!(site_plan.routed_inputs[0].component, "/consumer");
            assert_eq!(site_plan.routed_inputs[0].slot, "required_api");
            assert_eq!(site_plan.routed_inputs[0].provider_component, "/required");
            assert_eq!(site_plan.routed_inputs[0].protocol, "http");
            assert_eq!(site_plan.routed_inputs[0].capability_kind, "http");
            assert_eq!(
                site_plan.routed_inputs[0].target,
                DynamicInputRouteTarget::ComponentProvide {
                    provide: "http".to_string()
                },
                "same-site child exports should reuse the provider component route instead of \
                 inventing a synthetic dynamic-export hop",
            );
        }

        for actuator in actuators {
            actuator.abort();
        }
    }

    #[tokio::test]
    async fn same_site_static_child_export_bindings_reuse_provider_component_routes() {
        let dir = TempDir::new().expect("temp dir");
        let provider_path = dir.path().join("provider.json5");
        let consumer_path = dir.path().join("consumer.json5");
        let root_path = dir.path().join("root.json5");
        write_file(
            &provider_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "python:3.13-alpine",
                entrypoint: ["python3", "-c", "print('provider')"],
                network: {
                  endpoints: [{ name: "http", port: 8080, protocol: "http" }]
                }
              },
              provides: {
                http: { kind: "http", endpoint: "http" }
              },
              exports: {
                http: "http"
              }
            }
            "#,
        );
        write_file(
            &consumer_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                upstream: { kind: "http" }
              },
              program: {
                image: "python:3.13-alpine",
                entrypoint: ["python3", "-c", "print('consumer')"],
                network: {
                  endpoints: [{ name: "http", port: 8081, protocol: "http" }]
                }
              },
              provides: {
                http: { kind: "http", endpoint: "http" }
              },
              exports: {
                http: "http"
              }
            }
            "#,
        );
        write_json(
            &root_path,
            &json!({
                "manifest_version": "0.3.0",
                "slots": {
                    "realm": { "kind": "component", "optional": true }
                },
                "components": {
                    "provider": file_url(&provider_path)
                },
                "child_templates": {
                    "consumer": {
                        "manifest": file_url(&consumer_path)
                    }
                },
                "exports": {
                    "provider_http": "#provider.http"
                }
            }),
        )
        .expect("root manifest should write");
        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([(
                "compose_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Compose,
                    context: None,
                },
            )]),
            defaults: PlacementDefaults {
                image: Some("compose_local".to_string()),
                ..PlacementDefaults::default()
            },
            components: BTreeMap::new(),
        };
        let state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;
        let app = test_control_state_app(&dir, state, state_path);
        let actuators = install_success_site_actuator(&app).await;

        execute_create_child(
            &app,
            root_authority,
            CreateChildRequest {
                template: "consumer".to_string(),
                name: "consumer".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::from([(
                    "upstream".to_string(),
                    BindingInput {
                        selector: Some("children.provider.exports.http".to_string()),
                        handle: None,
                    },
                )]),
            },
        )
        .await
        .expect("consumer child should create");

        let state = app.control_state.lock().await.clone();
        let consumer = state
            .live_children
            .iter()
            .find(|child| child.name == "consumer")
            .expect("consumer child should be recorded");
        for site_plan in &consumer.site_plans {
            assert_eq!(site_plan.routed_inputs.len(), 1);
            assert_eq!(site_plan.routed_inputs[0].component, "/consumer");
            assert_eq!(site_plan.routed_inputs[0].slot, "upstream");
            assert_eq!(site_plan.routed_inputs[0].provider_component, "/provider");
            assert_eq!(site_plan.routed_inputs[0].protocol, "http");
            assert_eq!(site_plan.routed_inputs[0].capability_kind, "http");
            assert_eq!(
                site_plan.routed_inputs[0].target,
                DynamicInputRouteTarget::ComponentProvide {
                    provide: "http".to_string()
                },
                "same-site static child exports should reuse the provider component route",
            );
        }

        for actuator in actuators {
            actuator.abort();
        }
    }

    #[test]
    fn framework_ccs_addressing_matches_site_runtime_topology() {
        assert_eq!(
            ccs_listen_addr_for_site(SiteKind::Direct, 41000),
            SocketAddr::from(([127, 0, 0, 1], 41000))
        );
        assert_eq!(
            ccs_url_for_site(SiteKind::Direct, 41000),
            "http://127.0.0.1:41000"
        );
        assert_eq!(
            ccs_listen_addr_for_site(SiteKind::Vm, 42000),
            SocketAddr::from(([127, 0, 0, 1], 42000))
        );
        assert_eq!(
            ccs_url_for_site(SiteKind::Vm, 42000),
            "http://127.0.0.1:42000"
        );
        assert_eq!(
            ccs_listen_addr_for_site(SiteKind::Compose, 43000),
            SocketAddr::from(([0, 0, 0, 0], 43000))
        );
        assert_eq!(
            ccs_url_for_site(SiteKind::Compose, 43000),
            "http://host.docker.internal:43000"
        );
        assert_eq!(
            ccs_listen_addr_for_site(SiteKind::Kubernetes, 44000),
            SocketAddr::from(([0, 0, 0, 0], 44000))
        );
        assert_eq!(
            ccs_url_for_site(SiteKind::Kubernetes, 44000),
            format!(
                "http://{}:44000",
                host_service_host_for_consumer(SiteKind::Kubernetes)
            )
        );
    }

    async fn compile_empty_control_state() -> (TempDir, FrameworkControlState, PathBuf) {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        write_file(
            &root_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: { path: "/bin/echo", args: ["root"] },
            }
            "#,
        );
        let state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        (dir, state, state_path)
    }

    async fn compile_exact_template_control_state() -> (TempDir, FrameworkControlState, PathBuf) {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let child_path = dir.path().join("child.json5");
        write_file(
            &child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["child"],
                network: { endpoints: [{ name: "out", port: 8080, protocol: "http" }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
                child = file_url(&child_path),
            ),
        );
        let state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        (dir, state, state_path)
    }

    fn empty_live_child(
        authority_realm_id: usize,
        name: &str,
        child_id: u64,
        state: ChildState,
    ) -> LiveChildRecord {
        LiveChildRecord {
            child_id,
            authority_realm_id,
            name: name.to_string(),
            state,
            template_name: Some("worker".to_string()),
            selected_manifest_catalog_key: None,
            fragment: None,
            assignments: BTreeMap::new(),
            site_plans: Vec::new(),
            overlay_ids: Vec::new(),
            overlays: Vec::new(),
            outputs: BTreeMap::new(),
        }
    }

    fn pending_create(tx_id: u64, child: LiveChildRecord) -> PendingCreateRecord {
        PendingCreateRecord { tx_id, child }
    }

    fn pending_destroy(tx_id: u64, child: LiveChildRecord) -> PendingDestroyRecord {
        PendingDestroyRecord { tx_id, child }
    }

    fn test_control_state_app(
        dir: &TempDir,
        state: FrameworkControlState,
        state_path: PathBuf,
    ) -> ControlStateApp {
        let run_root = dir.path().join("run");
        let state_root = dir.path().join("state");
        fs::create_dir_all(&run_root).expect("run root should exist");
        fs::create_dir_all(&state_root).expect("state root should exist");
        ControlStateApp {
            control_state: Arc::new(Mutex::new(state)),
            client: ReqwestClient::new(),
            state_path,
            run_root,
            state_root,
            mesh_scope: Arc::<str>::from("test-mesh"),
            control_state_auth_token: Arc::<str>::from("test-control-state-auth"),
            authority_locks: Arc::new(Mutex::new(BTreeMap::new())),
            bridge_proxies: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    async fn install_success_site_actuator(
        app: &ControlStateApp,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let offered_sites = {
            let state = app.control_state.lock().await;
            state
                .placement
                .offered_sites
                .iter()
                .map(|(site_id, site)| (site_id.clone(), site.kind))
                .collect::<Vec<_>>()
        };
        let mut handles = Vec::with_capacity(offered_sites.len());
        for (site_id, site_kind) in offered_sites {
            let site_state_root = Path::new(&app.state_root).join(&site_id);
            fs::create_dir_all(&site_state_root).expect("site state root should exist");
            let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .expect("actuator listener");
            let listen_addr = listener.local_addr().expect("actuator addr");
            write_json(
                &site_state_root.join("site-actuator-plan.json"),
                &SiteActuatorPlan {
                    schema: "amber.run.site_actuator_plan".to_string(),
                    version: 1,
                    run_id: "test-run".to_string(),
                    mesh_scope: "test-mesh".to_string(),
                    run_root: app.run_root.display().to_string(),
                    site_id: site_id.clone(),
                    kind: site_kind,
                    router_identity_id: format!("/site/{site_id}/router"),
                    artifact_dir: site_state_root.join("artifact").display().to_string(),
                    site_state_root: site_state_root.display().to_string(),
                    listen_addr,
                    storage_root: None,
                    runtime_root: None,
                    router_mesh_port: None,
                    compose_project: None,
                    kubernetes_namespace: None,
                    context: None,
                    observability_endpoint: None,
                    launch_env: BTreeMap::new(),
                },
            )
            .expect("site actuator plan should write");
            let app = Router::new()
                .route(
                    "/v1/children/{child_id}/prepare",
                    post(|| async { StatusCode::NO_CONTENT }),
                )
                .route(
                    "/v1/children/{child_id}/rollback",
                    post(|| async { StatusCode::NO_CONTENT }),
                )
                .route(
                    "/v1/children/{child_id}/publish",
                    post(|| async { StatusCode::NO_CONTENT }),
                )
                .route(
                    "/v1/children/{child_id}/destroy",
                    post(|| async { StatusCode::NO_CONTENT }),
                );
            handles.push(tokio::spawn(async move {
                axum::serve(listener, app)
                    .await
                    .expect("site actuator should serve");
            }));
        }
        handles
    }

    async fn install_failing_rollback_site_actuator(
        app: &ControlStateApp,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let offered_sites = {
            let state = app.control_state.lock().await;
            state
                .placement
                .offered_sites
                .iter()
                .map(|(site_id, site)| (site_id.clone(), site.kind))
                .collect::<Vec<_>>()
        };
        let mut handles = Vec::with_capacity(offered_sites.len());
        for (site_id, site_kind) in offered_sites {
            let site_state_root = Path::new(&app.state_root).join(&site_id);
            fs::create_dir_all(&site_state_root).expect("site state root should exist");
            let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .expect("actuator listener");
            let listen_addr = listener.local_addr().expect("actuator addr");
            write_json(
                &site_state_root.join("site-actuator-plan.json"),
                &SiteActuatorPlan {
                    schema: "amber.run.site_actuator_plan".to_string(),
                    version: 1,
                    run_id: "test-run".to_string(),
                    mesh_scope: "test-mesh".to_string(),
                    run_root: app.run_root.display().to_string(),
                    site_id: site_id.clone(),
                    kind: site_kind,
                    router_identity_id: format!("/site/{site_id}/router"),
                    artifact_dir: site_state_root.join("artifact").display().to_string(),
                    site_state_root: site_state_root.display().to_string(),
                    listen_addr,
                    storage_root: None,
                    runtime_root: None,
                    router_mesh_port: None,
                    compose_project: None,
                    kubernetes_namespace: None,
                    context: None,
                    observability_endpoint: None,
                    launch_env: BTreeMap::new(),
                },
            )
            .expect("site actuator plan should write");
            let app = Router::new()
                .route(
                    "/v1/children/{child_id}/prepare",
                    post(|| async { StatusCode::NO_CONTENT }),
                )
                .route(
                    "/v1/children/{child_id}/rollback",
                    post(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
                )
                .route(
                    "/v1/children/{child_id}/publish",
                    post(|| async { StatusCode::NO_CONTENT }),
                )
                .route(
                    "/v1/children/{child_id}/destroy",
                    post(|| async { StatusCode::NO_CONTENT }),
                );
            handles.push(tokio::spawn(async move {
                axum::serve(listener, app)
                    .await
                    .expect("site actuator should serve");
            }));
        }
        handles
    }

    async fn install_barrier_destroy_site_actuator(
        app: &ControlStateApp,
    ) -> (
        Vec<tokio::task::JoinHandle<()>>,
        tokio::sync::mpsc::UnboundedReceiver<String>,
        Arc<tokio::sync::Barrier>,
    ) {
        let offered_sites = {
            let state = app.control_state.lock().await;
            state
                .placement
                .offered_sites
                .iter()
                .map(|(site_id, site)| (site_id.clone(), site.kind))
                .collect::<Vec<_>>()
        };
        let barrier = Arc::new(tokio::sync::Barrier::new(offered_sites.len() + 1));
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut handles = Vec::with_capacity(offered_sites.len());
        for (site_id, site_kind) in offered_sites {
            let site_state_root = Path::new(&app.state_root).join(&site_id);
            fs::create_dir_all(&site_state_root).expect("site state root should exist");
            let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .expect("actuator listener");
            let listen_addr = listener.local_addr().expect("actuator addr");
            write_json(
                &site_state_root.join("site-actuator-plan.json"),
                &SiteActuatorPlan {
                    schema: "amber.run.site_actuator_plan".to_string(),
                    version: 1,
                    run_id: "test-run".to_string(),
                    mesh_scope: "test-mesh".to_string(),
                    run_root: app.run_root.display().to_string(),
                    site_id: site_id.clone(),
                    kind: site_kind,
                    router_identity_id: format!("/site/{site_id}/router"),
                    artifact_dir: site_state_root.join("artifact").display().to_string(),
                    site_state_root: site_state_root.display().to_string(),
                    listen_addr,
                    storage_root: None,
                    runtime_root: None,
                    router_mesh_port: None,
                    compose_project: None,
                    kubernetes_namespace: None,
                    context: None,
                    observability_endpoint: None,
                    launch_env: BTreeMap::new(),
                },
            )
            .expect("site actuator plan should write");
            let start_tx = tx.clone();
            let destroy_barrier = barrier.clone();
            let site_id_for_destroy = site_id.clone();
            let app = Router::new()
                .route(
                    "/v1/children/{child_id}/prepare",
                    post(|| async { StatusCode::NO_CONTENT }),
                )
                .route(
                    "/v1/children/{child_id}/publish",
                    post(|| async { StatusCode::NO_CONTENT }),
                )
                .route(
                    "/v1/children/{child_id}/destroy",
                    post(move || {
                        let start_tx = start_tx.clone();
                        let destroy_barrier = destroy_barrier.clone();
                        let site_id = site_id_for_destroy.clone();
                        async move {
                            start_tx
                                .send(site_id)
                                .expect("destroy start notification should send");
                            destroy_barrier.wait().await;
                            StatusCode::NO_CONTENT
                        }
                    }),
                );
            handles.push(tokio::spawn(async move {
                axum::serve(listener, app)
                    .await
                    .expect("site actuator should serve");
            }));
        }
        (handles, rx, barrier)
    }

    async fn install_barrier_publish_site_actuator(
        app: &ControlStateApp,
    ) -> (
        Vec<tokio::task::JoinHandle<()>>,
        tokio::sync::mpsc::UnboundedReceiver<String>,
        Arc<tokio::sync::Barrier>,
    ) {
        let offered_sites = {
            let state = app.control_state.lock().await;
            state
                .placement
                .offered_sites
                .iter()
                .map(|(site_id, site)| (site_id.clone(), site.kind))
                .collect::<Vec<_>>()
        };
        let barrier = Arc::new(tokio::sync::Barrier::new(offered_sites.len() + 1));
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut handles = Vec::with_capacity(offered_sites.len());
        for (site_id, site_kind) in offered_sites {
            let site_state_root = Path::new(&app.state_root).join(&site_id);
            fs::create_dir_all(&site_state_root).expect("site state root should exist");
            let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .expect("actuator listener");
            let listen_addr = listener.local_addr().expect("actuator addr");
            write_json(
                &site_state_root.join("site-actuator-plan.json"),
                &SiteActuatorPlan {
                    schema: "amber.run.site_actuator_plan".to_string(),
                    version: 1,
                    run_id: "test-run".to_string(),
                    mesh_scope: "test-mesh".to_string(),
                    run_root: app.run_root.display().to_string(),
                    site_id: site_id.clone(),
                    kind: site_kind,
                    router_identity_id: format!("/site/{site_id}/router"),
                    artifact_dir: site_state_root.join("artifact").display().to_string(),
                    site_state_root: site_state_root.display().to_string(),
                    listen_addr,
                    storage_root: None,
                    runtime_root: None,
                    router_mesh_port: None,
                    compose_project: None,
                    kubernetes_namespace: None,
                    context: None,
                    observability_endpoint: None,
                    launch_env: BTreeMap::new(),
                },
            )
            .expect("site actuator plan should write");
            let start_tx = tx.clone();
            let publish_barrier = barrier.clone();
            let site_id_for_publish = site_id.clone();
            let app = Router::new()
                .route(
                    "/v1/children/{child_id}/prepare",
                    post(|| async { StatusCode::NO_CONTENT }),
                )
                .route(
                    "/v1/children/{child_id}/publish",
                    post(move || {
                        let start_tx = start_tx.clone();
                        let publish_barrier = publish_barrier.clone();
                        let site_id = site_id_for_publish.clone();
                        async move {
                            start_tx
                                .send(site_id)
                                .expect("publish start notification should send");
                            publish_barrier.wait().await;
                            StatusCode::NO_CONTENT
                        }
                    }),
                )
                .route(
                    "/v1/children/{child_id}/destroy",
                    post(|| async { StatusCode::NO_CONTENT }),
                );
            handles.push(tokio::spawn(async move {
                axum::serve(listener, app)
                    .await
                    .expect("site actuator should serve");
            }));
        }
        (handles, rx, barrier)
    }

    #[tokio::test]
    async fn create_snapshot_and_destroy_exact_child() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let child_path = dir.path().join("child.json5");
        write_file(
            &child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["child"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    ctl: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
                child = file_url(&child_path),
            ),
        );

        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([
                (
                    "direct_a".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Direct,
                        context: None,
                    },
                ),
                (
                    "direct_b".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Direct,
                        context: None,
                    },
                ),
            ]),
            defaults: PlacementDefaults {
                path: Some("direct_a".to_string()),
                ..PlacementDefaults::default()
            },
            components: BTreeMap::from([("/job-b".to_string(), "direct_b".to_string())]),
        };

        let mut state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;

        let response = create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job-1".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("create should succeed");

        assert_eq!(response.child.selector, "children.job-1");
        assert!(
            state
                .live_children
                .iter()
                .any(|child| child.name == "job-1")
        );

        let snapshot_response =
            snapshot(&state, state.base_scenario.root).expect("snapshot should succeed");
        let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
            .expect("snapshot scenario should decode");
        assert!(
            scenario_ir
                .components
                .iter()
                .any(|component| component.moniker == "/job-1"),
            "snapshot should contain the created child root"
        );

        destroy_child(&mut state, root_authority, "job-1", &state_path)
            .await
            .expect("destroy should succeed");
        assert!(
            state.live_children.is_empty(),
            "destroy should remove the live child record"
        );
        let snapshot_response =
            snapshot(&state, state.base_scenario.root).expect("snapshot should succeed");
        let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
            .expect("snapshot scenario should decode");
        assert!(
            !scenario_ir
                .components
                .iter()
                .any(|component| component.moniker == "/job-1"),
            "destroyed child should be absent from snapshots"
        );
    }

    #[tokio::test]
    async fn open_template_selection_uses_requested_catalog_key() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let alpha_path = dir.path().join("alpha.json5");
        let beta_path = dir.path().join("beta.json5");
        write_file(
            &alpha_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["alpha"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &beta_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["beta"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    ctl: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{
                      allowed_manifests: ["{alpha}", "{beta}"]
                    }}
                  }},
                }}
                "#,
                alpha = file_url(&alpha_path),
                beta = file_url(&beta_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let beta_key = file_url(&beta_path);
        let root_authority = state.base_scenario.root;

        create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job-open".to_string(),
                manifest: Some(
                    amber_mesh::component_protocol::CreateChildManifestSelection {
                        catalog_key: beta_key.clone(),
                    },
                ),
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("open-template create should succeed");

        assert_eq!(
            state.live_children[0]
                .selected_manifest_catalog_key
                .as_deref(),
            Some(beta_key.as_str())
        );
        let snapshot_response =
            snapshot(&state, state.base_scenario.root).expect("snapshot should succeed");
        let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
            .expect("snapshot scenario should decode");
        let child = scenario_ir
            .components
            .iter()
            .find(|component| component.moniker == "/job-open")
            .expect("snapshot should contain the created child");
        let rendered_program =
            serde_json::to_string(&child.program).expect("program should encode");
        assert!(
            rendered_program.contains("beta"),
            "snapshot should contain the selected manifest, got {rendered_program}"
        );
    }

    #[tokio::test]
    async fn open_template_replay_uses_frozen_manifest_catalog_after_source_mutation() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let alpha_path = dir.path().join("alpha.json5");
        let beta_path = dir.path().join("beta.json5");
        write_file(
            &alpha_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["alpha-original"],
                network: { endpoints: [{ name: "out", port: 8081 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &beta_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["beta-original"],
                network: { endpoints: [{ name: "out", port: 8082 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{
                      allowed_manifests: ["{alpha}", "{beta}"]
                    }}
                  }},
                }}
                "#,
                alpha = file_url(&alpha_path),
                beta = file_url(&beta_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;
        let beta_key = file_url(&beta_path);

        write_file(
            &beta_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["beta-mutated-on-disk"],
                network: { endpoints: [{ name: "out", port: 8082 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        fs::remove_file(&alpha_path).expect("alpha source should be removable after compile");

        create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job-open".to_string(),
                manifest: Some(
                    amber_mesh::component_protocol::CreateChildManifestSelection {
                        catalog_key: beta_key.clone(),
                    },
                ),
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("open-template create should use the frozen catalog");

        let snapshot_response =
            snapshot(&state, root_authority).expect("snapshot should succeed after create");
        let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario.clone())
            .expect("snapshot scenario should decode");
        let created_child = scenario_ir
            .components
            .iter()
            .find(|component| component.moniker == "/job-open")
            .expect("snapshot should contain the created child");
        let created_program =
            serde_json::to_string(&created_child.program).expect("program should encode");
        assert!(
            created_program.contains("beta-original"),
            "snapshot should preserve the frozen selected manifest, got {created_program}"
        );
        assert!(
            !created_program.contains("beta-mutated-on-disk"),
            "snapshot must not reread the current disk manifest, got {created_program}"
        );

        fs::remove_file(&beta_path).expect("beta source should be removable before replay");

        let mut replayed = compile_control_state_from_snapshot(&snapshot_response).await;
        let replay_state_path = dir.path().join("replay-control-state.json");
        write_control_state(&replay_state_path, &replayed).expect("replay state should write");
        let replay_root_authority = replayed.base_scenario.root;

        create_child(
            &mut replayed,
            replay_root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job-replay".to_string(),
                manifest: Some(
                    amber_mesh::component_protocol::CreateChildManifestSelection {
                        catalog_key: file_url(&alpha_path),
                    },
                ),
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &replay_state_path,
        )
        .await
        .expect("replayed snapshot should preserve future dynamic create affordances");

        let replay_snapshot =
            snapshot(&replayed, replay_root_authority).expect("replay snapshot should succeed");
        let replay_ir: ScenarioIr = serde_json::from_value(replay_snapshot.scenario)
            .expect("replay scenario should decode");
        let replay_child = replay_ir
            .components
            .iter()
            .find(|component| component.moniker == "/job-replay")
            .expect("replay should contain the newly created child");
        let replay_program =
            serde_json::to_string(&replay_child.program).expect("program should encode");
        assert!(
            replay_program.contains("alpha-original"),
            "replay should still use the frozen manifest content, got {replay_program}"
        );
        assert!(
            !replay_program.contains("beta-mutated-on-disk"),
            "replay must not fall back to mutated on-disk content, got {replay_program}"
        );
    }

    #[tokio::test]
    async fn dynamic_framework_bindings_refresh_capability_instances_and_preserve_origin_realm() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let parent_path = dir.path().join("parent.json5");
        let worker_path = dir.path().join("worker.json5");
        let root_worker_path = dir.path().join("root-worker.json5");
        write_file(
            &worker_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                realm: { kind: "component", optional: true }
              },
              program: {
                path: "/bin/echo",
                args: ["worker", "${slots.realm.url}"],
                network: { endpoints: [{ name: "http", port: 8080 }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &root_worker_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["root-worker"],
                network: { endpoints: [{ name: "http", port: 8082 }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &parent_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  program: {{
                    path: "/bin/echo",
                    args: ["parent", "${{slots.realm.url}}"],
                    network: {{ endpoints: [{{ name: "http", port: 8081 }}] }}
                  }},
                  provides: {{ http: {{ kind: "http", endpoint: "http" }} }},
                  exports: {{ http: "provides.http" }},
                  child_templates: {{
                    worker: {{
                      manifest: "{worker}",
                      bindings: {{
                        realm: "slots.realm"
                      }}
                    }}
                  }},
                }}
                "#,
                worker = file_url(&worker_path),
            ),
        );
        write_file(
            &root_path,
            &format!(
                r##"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    root_worker: {{
                      manifest: "{root_worker}"
                    }}
                  }},
                  components: {{
                    parent: "{parent}"
                  }},
                  bindings: [
                    {{ to: "#parent.realm", from: "framework.component" }}
                  ],
                  exports: {{
                    parent_http: "#parent.http"
                  }},
                }}
                "##,
                root_worker = file_url(&root_worker_path),
                parent = file_url(&parent_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let base = Scenario::try_from(state.base_scenario.clone()).expect("base scenario");
        let parent_id = base
            .components_iter()
            .find(|(_, component)| component.moniker.as_str() == "/parent")
            .map(|(id, _)| id.0)
            .expect("parent component should exist");
        let static_parent_record = state
            .capability_instances
            .values()
            .find(|record| record.recipient_component_moniker == "/parent")
            .cloned()
            .expect("static parent should have a realm capability instance");
        assert_eq!(static_parent_record.authority_realm_moniker, "/");

        create_child(
            &mut state,
            parent_id,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "delegate".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("delegate child should be created");

        let dynamic_record = state
            .capability_instances
            .values()
            .find(|record| record.recipient_component_moniker == "/parent/delegate")
            .cloned()
            .expect("dynamic child should receive its own realm capability instance");
        let root_authority = state.base_scenario.root;
        assert_eq!(dynamic_record.authority_realm_id, root_authority);
        assert_eq!(dynamic_record.authority_realm_moniker, "/");
        let authorized = authorize_capability_instance(
            &state,
            &dynamic_record.cap_instance_id,
            "/parent/delegate",
        )
        .expect("dynamic child capability instance should authorize for its own peer");
        let delegated_authority_realm_id = authorized.authority_realm_id;
        assert_eq!(delegated_authority_realm_id, root_authority);

        create_child(
            &mut state,
            delegated_authority_realm_id,
            CreateChildRequest {
                template: "root_worker".to_string(),
                name: "sibling".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("forwarded realm authority should create a sibling in the parent realm");

        let live_scenario = live_scenario_ir(&state).expect("live scenario should materialize");
        let live = Scenario::try_from(live_scenario).expect("live scenario should decode");
        assert!(
            live.components_iter()
                .any(|(_, component)| component.moniker.as_str() == "/parent/delegate"),
            "delegate should live under the parent realm"
        );
        assert!(
            live.components_iter()
                .any(|(_, component)| component.moniker.as_str() == "/sibling"),
            "forwarded realm capability should create in the origin realm, not under the caller"
        );

        destroy_child(&mut state, parent_id, "delegate", &state_path)
            .await
            .expect("destroy should succeed");
        assert!(
            !state
                .capability_instances
                .values()
                .any(|record| record.recipient_component_moniker == "/parent/delegate"),
            "destroy should revoke dynamic capability instances owned by the removed child"
        );
    }

    #[tokio::test]
    async fn capability_instance_auth_and_snapshot_scope_are_enforced() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let parent_path = dir.path().join("parent.json5");
        write_file(
            &parent_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                realm: { kind: "component", optional: true }
              },
              program: {
                path: "/bin/echo",
                args: ["parent", "${slots.realm.url}"],
                network: { endpoints: [{ name: "http", port: 8081 }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r##"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  components: {{
                    parent: "{parent}"
                  }},
                  bindings: [
                    {{ to: "#parent.realm", from: "framework.component" }}
                  ],
                  exports: {{
                    parent_http: "#parent.http"
                  }},
                }}
                "##,
                parent = file_url(&parent_path),
            ),
        );

        let state = compile_control_state(&root_path).await;
        let base = Scenario::try_from(state.base_scenario.clone()).expect("base scenario");
        let parent_id = base
            .components_iter()
            .find(|(_, component)| component.moniker.as_str() == "/parent")
            .map(|(id, _)| id.0)
            .expect("parent component should exist");
        let record = state
            .capability_instances
            .values()
            .find(|record| record.recipient_component_moniker == "/parent")
            .expect("parent should have a realm capability instance");

        let wrong_peer = authorize_capability_instance(&state, &record.cap_instance_id, "/root")
            .expect_err("peer mismatch should be rejected");
        assert_eq!(wrong_peer.code, ProtocolErrorCode::Unauthorized);

        let unknown = authorize_capability_instance(&state, "cap.missing", "/parent")
            .expect_err("unknown capability instance should be rejected");
        assert_eq!(unknown.code, ProtocolErrorCode::Unauthorized);

        let snapshot_err = snapshot(&state, parent_id)
            .expect_err("non-root authority should not be able to snapshot");
        assert_eq!(snapshot_err.code, ProtocolErrorCode::ScopeNotAllowed);
    }

    #[tokio::test]
    async fn destroy_and_recreate_same_child_name_gets_a_new_capability_instance_id() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let parent_path = dir.path().join("parent.json5");
        let worker_path = dir.path().join("worker.json5");
        write_file(
            &worker_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                realm: { kind: "component", optional: true }
              },
              program: {
                path: "/bin/echo",
                args: ["worker", "${slots.realm.url}"],
                network: { endpoints: [{ name: "http", port: 8080 }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &parent_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  program: {{
                    path: "/bin/echo",
                    args: ["parent", "${{slots.realm.url}}"],
                    network: {{ endpoints: [{{ name: "http", port: 8081 }}] }}
                  }},
                  provides: {{ http: {{ kind: "http", endpoint: "http" }} }},
                  exports: {{ http: "provides.http" }},
                  child_templates: {{
                    worker: {{
                      manifest: "{worker}",
                      bindings: {{
                        realm: "slots.realm"
                      }}
                    }}
                  }},
                }}
                "#,
                worker = file_url(&worker_path),
            ),
        );
        write_file(
            &root_path,
            &format!(
                r##"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  components: {{
                    parent: "{parent}"
                  }},
                  bindings: [
                    {{ to: "#parent.realm", from: "framework.component" }}
                  ],
                }}
                "##,
                parent = file_url(&parent_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let base = Scenario::try_from(state.base_scenario.clone()).expect("base scenario");
        let parent_id = base
            .components_iter()
            .find(|(_, component)| component.moniker.as_str() == "/parent")
            .map(|(id, _)| id.0)
            .expect("parent component should exist");

        create_child(
            &mut state,
            parent_id,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "delegate".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("first delegate create should succeed");
        let first_cap_instance_id = state
            .capability_instances
            .values()
            .find(|record| record.recipient_component_moniker == "/parent/delegate")
            .map(|record| record.cap_instance_id.clone())
            .expect("first delegate capability instance should exist");

        destroy_child(&mut state, parent_id, "delegate", &state_path)
            .await
            .expect("destroy should succeed");
        assert!(
            !state
                .capability_instances
                .values()
                .any(|record| record.recipient_component_moniker == "/parent/delegate"),
            "destroy should revoke the first child lifetime's capability instance",
        );

        create_child(
            &mut state,
            parent_id,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "delegate".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("second delegate create should succeed");
        let second_cap_instance_id = state
            .capability_instances
            .values()
            .find(|record| record.recipient_component_moniker == "/parent/delegate")
            .map(|record| record.cap_instance_id.clone())
            .expect("second delegate capability instance should exist");

        assert_ne!(
            first_cap_instance_id, second_cap_instance_id,
            "recreating the same child name must mint a new framework capability instance id",
        );
    }

    #[test]
    fn framework_auth_header_must_match_expected_token() {
        let mut headers = HeaderMap::new();
        let missing = authorize_framework_auth_header(&headers, "expected")
            .expect_err("missing auth header should be rejected");
        assert_eq!(missing.0.code, ProtocolErrorCode::Unauthorized);

        headers.insert(
            FRAMEWORK_AUTH_HEADER,
            "wrong".parse().expect("header should parse"),
        );
        let wrong = authorize_framework_auth_header(&headers, "expected")
            .expect_err("mismatched auth header should be rejected");
        assert_eq!(wrong.0.code, ProtocolErrorCode::Unauthorized);

        headers.insert(
            FRAMEWORK_AUTH_HEADER,
            "expected".parse().expect("header should parse"),
        );
        authorize_framework_auth_header(&headers, "expected")
            .expect("matching auth header should succeed");
    }

    #[tokio::test]
    async fn dynamic_authority_templates_are_listed_and_created_from_live_realm() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let worker_path = dir.path().join("worker.json5");
        let admin_path = dir.path().join("admin.json5");
        let nested_path = dir.path().join("nested.json5");

        write_file(
            &admin_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                realm: { kind: "component", optional: true }
              },
              program: {
                path: "/bin/echo",
                args: ["admin", "${slots.realm.url}"],
                network: { endpoints: [{ name: "http", port: 8081, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &nested_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["nested"],
                network: { endpoints: [{ name: "http", port: 8082, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &worker_path,
            &format!(
                r##"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm_cap: {{ kind: "component", optional: true }}
                  }},
                  program: {{
                    path: "/bin/echo",
                    args: ["worker"],
                    network: {{ endpoints: [{{ name: "http", port: 8080, protocol: "http" }}] }}
                  }},
                  provides: {{ http: {{ kind: "http", endpoint: "http" }} }},
                  exports: {{ http: "provides.http" }},
                  components: {{
                    admin: "{admin}"
                  }},
                  child_templates: {{
                    nested: {{ manifest: "{nested}" }}
                  }},
                  bindings: [
                    {{ to: "#admin.realm", from: "framework.component" }}
                  ],
                }}
                "##,
                admin = file_url(&admin_path),
                nested = file_url(&nested_path),
            ),
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{worker}" }}
                  }},
                }}
                "#,
                worker = file_url(&worker_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;

        create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "delegate".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("delegate child should be created");

        let delegated_realm = state
            .capability_instances
            .values()
            .find(|record| record.recipient_component_moniker == "/delegate/admin")
            .cloned()
            .expect("dynamic admin should receive a framework capability instance");
        assert_eq!(
            delegated_realm.authority_realm_moniker, "/delegate",
            "delegated capability should originate from the dynamic child realm",
        );

        let listed = list_templates(&state, delegated_realm.authority_realm_id)
            .expect("dynamic realm templates should be available");
        assert_eq!(
            listed
                .templates
                .iter()
                .map(|template| template.name.as_str())
                .collect::<Vec<_>>(),
            vec!["nested"],
        );
        let described = describe_template(&state, delegated_realm.authority_realm_id, "nested")
            .expect("dynamic realm template description should use the live realm");
        assert_eq!(described.name, "nested");

        create_child(
            &mut state,
            delegated_realm.authority_realm_id,
            CreateChildRequest {
                template: "nested".to_string(),
                name: "inner".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("dynamic delegated authority should create inside the live child realm");

        let live = decode_live_scenario(&state).expect("live scenario should decode");
        assert!(
            live.components_iter()
                .any(|(_, component)| component.moniker.as_str() == "/delegate/inner"),
            "nested child should be created under the dynamic authority realm",
        );
        assert!(
            !live
                .components_iter()
                .any(|(_, component)| component.moniker.as_str() == "/inner"),
            "delegated dynamic authority must not fall back to the base realm",
        );
    }

    #[test]
    fn shared_cross_site_link_is_retained_while_another_child_still_needs_it() {
        let link = RunLink {
            provider_site: "provider".to_string(),
            consumer_site: "consumer".to_string(),
            provider_component: "/provider".to_string(),
            provide: "api".to_string(),
            consumer_component: "/consumer-a".to_string(),
            slot: "api".to_string(),
            weak: false,
            protocol: NetworkProtocol::Http,
            export_name: "amber_export_shared".to_string(),
            external_slot_name: "amber_link_shared".to_string(),
        };
        let mut first = empty_live_child(0, "a", 1, ChildState::Live);
        first.overlays = vec![DynamicOverlayRecord {
            overlay_id: "a".to_string(),
            site_id: "consumer".to_string(),
            action: DynamicOverlayAction::ExternalSlot { link: link.clone() },
        }];
        let mut second = empty_live_child(0, "b", 2, ChildState::Live);
        second.overlays = vec![DynamicOverlayRecord {
            overlay_id: "b".to_string(),
            site_id: "consumer".to_string(),
            action: DynamicOverlayAction::ExternalSlot { link: link.clone() },
        }];
        let state = FrameworkControlState {
            schema: CONTROL_STATE_SCHEMA.to_string(),
            version: CONTROL_STATE_VERSION,
            run_id: "test".to_string(),
            base_scenario: ScenarioIr {
                schema: amber_scenario::SCENARIO_IR_SCHEMA.to_string(),
                version: amber_scenario::SCENARIO_IR_VERSION,
                root: 0,
                components: Vec::new(),
                bindings: Vec::new(),
                exports: Vec::new(),
                manifest_catalog: BTreeMap::new(),
            },
            placement: FrozenPlacementState {
                offered_sites: BTreeMap::new(),
                defaults: PlacementDefaults::default(),
                standby_sites: Vec::new(),
                initial_active_sites: Vec::new(),
                dynamic_enabled_sites: Vec::new(),
                control_only_sites: Vec::new(),
                active_site_capabilities: BTreeMap::new(),
                placement_components: BTreeMap::new(),
                assignments: BTreeMap::new(),
            },
            generation: 0,
            next_child_id: 2,
            next_tx_id: 0,
            next_component_id: 0,
            capability_instances: BTreeMap::new(),
            journal: Vec::new(),
            live_children: vec![first, second],
            pending_creates: Vec::new(),
            pending_destroys: Vec::new(),
        };

        assert!(
            link_still_required(&state, 1, &link),
            "retracting one child must keep a shared cross-site link in place for the survivor",
        );
        assert!(
            !link_still_required(
                &state,
                2,
                &RunLink {
                    consumer_component: "/different".to_string(),
                    ..link
                }
            ),
            "different links should not be retained accidentally",
        );
    }

    #[tokio::test]
    async fn create_rejects_duplicate_names_and_destroy_is_idempotent() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let child_path = dir.path().join("child.json5");
        write_file(
            &child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["child"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
                child = file_url(&child_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;

        create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("first create should succeed");

        let duplicate = create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect_err("duplicate child name should be rejected");
        assert_eq!(duplicate.code, ProtocolErrorCode::NameConflict);

        destroy_child(&mut state, root_authority, "job", &state_path)
            .await
            .expect("first destroy should succeed");
        destroy_child(&mut state, root_authority, "job", &state_path)
            .await
            .expect("destroy should be idempotent once the child is gone");
        assert!(
            state.live_children.is_empty(),
            "destroy should remove the child"
        );
    }

    #[tokio::test]
    async fn max_live_children_is_scoped_per_template() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        write_file(
            &root_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: { path: "/bin/echo", args: ["root"] },
              slots: {
                realm: { kind: "component", optional: true }
              }
            }
            "#,
        );

        let mut state = compile_control_state(&root_path).await;
        let root_authority = state.base_scenario.root;
        let mut alpha_child = empty_live_child(root_authority, "job-a", 1, ChildState::Live);
        alpha_child.template_name = Some("alpha".to_string());
        state.live_children = vec![alpha_child];

        let template = ChildTemplate {
            frozen: false,
            manifest: Some("file:///templates/worker.json5".to_string()),
            allowed_manifests: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
            slot_decls: BTreeMap::new(),
            visible_exports: None,
            limits: Some(amber_scenario::ChildTemplateLimits {
                max_live_children: Some(1),
                name_pattern: None,
            }),
            possible_backends: Vec::new(),
        };

        validate_template_limits(&state, root_authority, "beta", "job-c", &template)
            .expect("beta should still have capacity when only alpha is full");

        let err = validate_template_limits(&state, root_authority, "alpha", "job-c", &template)
            .expect_err("second alpha child should hit the per-template limit");
        assert_eq!(err.code, ProtocolErrorCode::NameConflict);
        assert!(
            err.message.contains("template `alpha`"),
            "error should name the saturated template, got: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn snapshot_is_stable_across_dynamic_create_order() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let child_path = dir.path().join("child.json5");
        write_file(
            &child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["child"],
                network: { endpoints: [{ name: "out", port: 8080, protocol: "http" }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
                child = file_url(&child_path),
            ),
        );
        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([
                (
                    "direct_a".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Direct,
                        context: None,
                    },
                ),
                (
                    "direct_b".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Direct,
                        context: None,
                    },
                ),
            ]),
            defaults: PlacementDefaults {
                path: Some("direct_a".to_string()),
                ..PlacementDefaults::default()
            },
            components: BTreeMap::from([
                ("/job-a".to_string(), "direct_a".to_string()),
                ("/job-b".to_string(), "direct_b".to_string()),
            ]),
        };
        let mut state_a = compile_control_state_with_placement(&root_path, Some(&placement)).await;
        let mut state_b = compile_control_state_with_placement(&root_path, Some(&placement)).await;
        let state_path_a = dir.path().join("control-state-a.json");
        let state_path_b = dir.path().join("control-state-b.json");
        write_control_state(&state_path_a, &state_a).expect("state A should write");
        write_control_state(&state_path_b, &state_b).expect("state B should write");
        let root_authority = state_a.base_scenario.root;

        for (state, state_path, names) in [
            (&mut state_a, &state_path_a, ["job-a", "job-b"]),
            (&mut state_b, &state_path_b, ["job-b", "job-a"]),
        ] {
            for name in names {
                create_child(
                    state,
                    root_authority,
                    CreateChildRequest {
                        template: "worker".to_string(),
                        name: name.to_string(),
                        manifest: None,
                        config: BTreeMap::new(),
                        bindings: BTreeMap::new(),
                    },
                    state_path,
                )
                .await
                .unwrap_or_else(|err| panic!("create {name} should succeed: {err:?}"));
            }
        }

        let snapshot_a = snapshot(&state_a, root_authority).expect("snapshot A should succeed");
        let snapshot_b = snapshot(&state_b, root_authority).expect("snapshot B should succeed");
        assert_eq!(
            snapshot_a.scenario, snapshot_b.scenario,
            "snapshot scenario should be normalized independent of create order",
        );
        assert_eq!(
            snapshot_a.placement, snapshot_b.placement,
            "snapshot placement should be normalized independent of create order",
        );
    }

    #[tokio::test]
    async fn create_rejects_unoffered_backend_without_committing_child_state() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let direct_child_path = dir.path().join("child-direct.json5");
        let compose_child_path = dir.path().join("child-compose.json5");
        write_file(
            &direct_child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["direct-only"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &compose_child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{
                      allowed_manifests: ["{compose_child}", "{direct_child}"]
                    }}
                  }},
                }}
                "#,
                compose_child = file_url(&compose_child_path),
                direct_child = file_url(&direct_child_path),
            ),
        );
        let compiler = Compiler::new(Resolver::new(), DigestStore::default());
        let output = compiler
            .compile(
                ManifestRef::from_url(
                    Url::from_file_path(&root_path).expect("root path should convert to URL"),
                ),
                CompileOptions::default(),
            )
            .await
            .expect("fixture should compile");
        let compiled = CompiledScenario::from_compile_output(&output)
            .expect("fixture should materialize compiled scenario");
        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([(
                "compose_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Compose,
                    context: None,
                },
            )]),
            defaults: PlacementDefaults {
                image: Some("compose_local".to_string()),
                ..PlacementDefaults::default()
            },
            components: BTreeMap::new(),
        };
        let err = build_run_plan(&compiled, Some(&placement))
            .expect_err("run planning should reject future direct children without a direct site");
        let message = err.to_string();
        assert!(
            message.contains("program.path"),
            "placement failure should point operators at the missing future direct site, got \
             {message}"
        );
    }

    #[tokio::test]
    async fn concurrent_same_name_creates_serialize_to_one_live_child() {
        let (dir, state, state_path) = compile_exact_template_control_state().await;
        let root_authority = state.base_scenario.root;
        let app = test_control_state_app(&dir, state, state_path);
        let actuators = install_success_site_actuator(&app).await;
        let request = CreateChildRequest {
            template: "worker".to_string(),
            name: "job".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        };

        let (left, right) = tokio::join!(
            execute_create_child(&app, root_authority, request.clone()),
            execute_create_child(&app, root_authority, request),
        );
        let results = [left, right];
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "exactly one racing create should succeed",
        );
        assert_eq!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .filter(|err| err.0.code == ProtocolErrorCode::NameConflict)
                .count(),
            1,
            "exactly one racing create should fail with name_conflict",
        );

        let state = app.control_state.lock().await.clone();
        assert_eq!(
            state.live_children.len(),
            1,
            "only one child should be committed"
        );
        assert_eq!(state.live_children[0].name, "job");
        let snapshot_response =
            snapshot(&state, root_authority).expect("snapshot should succeed after the race");
        let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
            .expect("snapshot scenario should decode");
        assert_eq!(
            scenario_ir
                .components
                .iter()
                .filter(|component| component.moniker == "/job")
                .count(),
            1,
            "snapshot should remain clean after the same-name race",
        );
        for actuator in actuators {
            actuator.abort();
        }
    }

    #[tokio::test]
    async fn destroy_retracted_tears_down_sites_concurrently() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        write_file(
            &root_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/sh",
                args: ["-c", "sleep 1"]
              }
            }
            "#,
        );

        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([
                (
                    "compose_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Compose,
                        context: None,
                    },
                ),
                (
                    "direct_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Direct,
                        context: None,
                    },
                ),
            ]),
            defaults: PlacementDefaults {
                path: Some("direct_local".to_string()),
                image: Some("compose_local".to_string()),
                ..PlacementDefaults::default()
            },
            components: BTreeMap::new(),
        };

        let state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;
        let app = test_control_state_app(&dir, state, state_path);
        let (actuators, mut destroy_starts, barrier) =
            install_barrier_destroy_site_actuator(&app).await;
        {
            let mut state = app.control_state.lock().await;
            state.pending_destroys.push(pending_destroy(
                1,
                LiveChildRecord {
                    child_id: 7,
                    authority_realm_id: root_authority,
                    name: "job-compose".to_string(),
                    state: ChildState::DestroyRetracted,
                    template_name: Some("fixture".to_string()),
                    selected_manifest_catalog_key: None,
                    fragment: None,
                    assignments: BTreeMap::new(),
                    site_plans: vec![
                        DynamicSitePlanRecord {
                            site_id: "compose_local".to_string(),
                            kind: SiteKind::Compose,
                            router_identity_id: "/site/compose_local/router".to_string(),
                            component_ids: Vec::new(),
                            assigned_components: Vec::new(),
                            artifact_files: BTreeMap::new(),
                            desired_artifact_files: BTreeMap::new(),
                            proxy_exports: BTreeMap::new(),
                            routed_inputs: Vec::new(),
                        },
                        DynamicSitePlanRecord {
                            site_id: "direct_local".to_string(),
                            kind: SiteKind::Direct,
                            router_identity_id: "/site/direct_local/router".to_string(),
                            component_ids: Vec::new(),
                            assigned_components: Vec::new(),
                            artifact_files: BTreeMap::new(),
                            desired_artifact_files: BTreeMap::new(),
                            proxy_exports: BTreeMap::new(),
                            routed_inputs: Vec::new(),
                        },
                    ],
                    overlay_ids: Vec::new(),
                    overlays: Vec::new(),
                    outputs: BTreeMap::new(),
                },
            ));
        }

        let destroy = tokio::spawn({
            let app = app.clone();
            async move { continue_destroy_retracted(&app, 7).await }
        });

        let first = tokio::time::timeout(Duration::from_secs(5), destroy_starts.recv())
            .await
            .expect("first destroy should start in time")
            .expect("first destroy notification should arrive");
        let second = tokio::time::timeout(Duration::from_secs(5), destroy_starts.recv())
            .await
            .expect("second destroy should start in time")
            .expect("second destroy notification should arrive");
        assert_ne!(
            first, second,
            "destroy should reach both site actuators before either completes"
        );

        barrier.wait().await;
        destroy
            .await
            .expect("destroy task should join")
            .expect("destroy should succeed");

        let recovered = app.control_state.lock().await.clone();
        assert!(
            recovered.live_children.is_empty(),
            "successful destroy should remove the child after concurrent site teardown",
        );
        for actuator in actuators {
            actuator.abort();
        }
    }

    #[tokio::test]
    async fn create_committed_hidden_publishes_independent_sites_concurrently() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        write_file(
            &root_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/sh",
                args: ["-c", "sleep 1"]
              }
            }
            "#,
        );

        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([
                (
                    "compose_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Compose,
                        context: None,
                    },
                ),
                (
                    "direct_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Direct,
                        context: None,
                    },
                ),
            ]),
            defaults: PlacementDefaults {
                path: Some("direct_local".to_string()),
                image: Some("compose_local".to_string()),
                ..PlacementDefaults::default()
            },
            components: BTreeMap::new(),
        };

        let state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;
        let app = test_control_state_app(&dir, state, state_path);
        let (actuators, mut publish_starts, barrier) =
            install_barrier_publish_site_actuator(&app).await;
        {
            let mut state = app.control_state.lock().await;
            state.pending_creates.push(pending_create(
                1,
                LiveChildRecord {
                    child_id: 7,
                    authority_realm_id: root_authority,
                    name: "job-compose".to_string(),
                    state: ChildState::CreateCommittedHidden,
                    template_name: Some("fixture".to_string()),
                    selected_manifest_catalog_key: None,
                    fragment: None,
                    assignments: BTreeMap::new(),
                    site_plans: vec![
                        DynamicSitePlanRecord {
                            site_id: "compose_local".to_string(),
                            kind: SiteKind::Compose,
                            router_identity_id: "/site/compose_local/router".to_string(),
                            component_ids: Vec::new(),
                            assigned_components: Vec::new(),
                            artifact_files: BTreeMap::new(),
                            desired_artifact_files: BTreeMap::new(),
                            proxy_exports: BTreeMap::new(),
                            routed_inputs: Vec::new(),
                        },
                        DynamicSitePlanRecord {
                            site_id: "direct_local".to_string(),
                            kind: SiteKind::Direct,
                            router_identity_id: "/site/direct_local/router".to_string(),
                            component_ids: Vec::new(),
                            assigned_components: Vec::new(),
                            artifact_files: BTreeMap::new(),
                            desired_artifact_files: BTreeMap::new(),
                            proxy_exports: BTreeMap::new(),
                            routed_inputs: Vec::new(),
                        },
                    ],
                    overlay_ids: Vec::new(),
                    overlays: Vec::new(),
                    outputs: BTreeMap::new(),
                },
            ));
        }

        let publish = tokio::spawn({
            let app = app.clone();
            async move { continue_create_committed_hidden(&app, 7).await }
        });

        let first = tokio::time::timeout(Duration::from_secs(5), publish_starts.recv())
            .await
            .expect("first publish should start in time")
            .expect("first publish notification should arrive");
        let second = tokio::time::timeout(Duration::from_secs(5), publish_starts.recv())
            .await
            .expect("second publish should start in time")
            .expect("second publish notification should arrive");
        assert_ne!(
            first, second,
            "create should reach both independent site actuators before either completes"
        );

        barrier.wait().await;
        publish
            .await
            .expect("publish task should join")
            .expect("publish should succeed");

        let recovered = app.control_state.lock().await.clone();
        let child = recovered
            .live_children
            .iter()
            .find(|child| child.child_id == 7)
            .expect("child should remain present");
        assert_eq!(
            child.state,
            ChildState::Live,
            "successful concurrent site publication should promote the child to live",
        );
        for actuator in actuators {
            actuator.abort();
        }
    }

    #[tokio::test]
    async fn concurrent_distinct_creates_commit_both_children() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let child_path = dir.path().join("child.json5");
        write_file(
            &child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
                child = file_url(&child_path),
            ),
        );
        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([(
                "compose_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Compose,
                    context: None,
                },
            )]),
            defaults: PlacementDefaults {
                image: Some("compose_local".to_string()),
                ..PlacementDefaults::default()
            },
            components: BTreeMap::new(),
        };
        let state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;
        let app = test_control_state_app(&dir, state, state_path);
        let actuators = install_success_site_actuator(&app).await;

        let (left, right) = tokio::join!(
            execute_create_child(
                &app,
                root_authority,
                CreateChildRequest {
                    template: "worker".to_string(),
                    name: "job-a".to_string(),
                    manifest: None,
                    config: BTreeMap::new(),
                    bindings: BTreeMap::new(),
                },
            ),
            execute_create_child(
                &app,
                root_authority,
                CreateChildRequest {
                    template: "worker".to_string(),
                    name: "job-b".to_string(),
                    manifest: None,
                    config: BTreeMap::new(),
                    bindings: BTreeMap::new(),
                },
            ),
        );
        left.expect("first distinct create should succeed");
        right.expect("second distinct create should succeed");

        let state = app.control_state.lock().await.clone();
        assert_eq!(
            state.live_children.len(),
            2,
            "both children should be committed"
        );
        assert_eq!(
            state
                .live_children
                .iter()
                .map(|child| child.name.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["job-a", "job-b"]),
        );
        let snapshot_response =
            snapshot(&state, root_authority).expect("snapshot should succeed after both creates");
        let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
            .expect("snapshot scenario should decode");
        assert!(
            scenario_ir
                .components
                .iter()
                .any(|component| component.moniker == "/job-a"),
            "snapshot should contain the first child",
        );
        assert!(
            scenario_ir
                .components
                .iter()
                .any(|component| component.moniker == "/job-b"),
            "snapshot should contain the second child",
        );
        for actuator in actuators {
            actuator.abort();
        }
    }

    #[tokio::test]
    async fn prepare_child_record_uses_frozen_dynamic_placement_assignments() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let child_path = dir.path().join("child.json5");
        write_file(
            &child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
                child = file_url(&child_path),
            ),
        );

        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([
                (
                    "compose_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Compose,
                        context: None,
                    },
                ),
                (
                    "kind_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Kubernetes,
                        context: None,
                    },
                ),
            ]),
            defaults: PlacementDefaults {
                image: Some("compose_local".to_string()),
                ..PlacementDefaults::default()
            },
            components: BTreeMap::from([("/job".to_string(), "kind_local".to_string())]),
        };

        let mut state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
        let root_authority = state.base_scenario.root;
        let child = prepare_child_record(
            &mut state,
            root_authority,
            &CreateChildRequest {
                template: "worker".to_string(),
                name: "job".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
        )
        .await
        .expect("child should plan successfully");

        assert_eq!(
            child.assignments.get("/job").map(String::as_str),
            Some("kind_local"),
            "dynamic create must honor frozen placement entries for future child monikers",
        );
    }

    #[tokio::test]
    async fn prepare_child_record_preserves_cross_backend_matrix_assignments() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let child_path = dir.path().join("child-compose.json5");
        let child_root_path = dir.path().join("child-compose-root.json5");
        let direct_helper_path = dir.path().join("direct-helper.json5");
        let kind_helper_path = dir.path().join("kind-helper.json5");
        let vm_helper_path = dir.path().join("vm-helper.json5");
        let vm_helper_root_path = dir.path().join("vm-helper-root.json5");

        write_file(
            &direct_helper_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/sh",
                args: ["-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &kind_helper_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &vm_helper_root_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                vm: {
                  image: "/tmp/base.img",
                  cpus: 1,
                  memory_mib: 256,
                  cloud_init: {
                    user_data: "IyBjbG91ZC1jb25maWcK"
                  },
                  network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
                }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &vm_helper_path,
            &format!(
                r##"
                {{
                  manifest_version: "0.3.0",
                  components: {{
                    root: "{vm_helper_root}"
                  }},
                  exports: {{
                    http: "#root.http"
                  }}
                }}
                "##,
                vm_helper_root = file_url(&vm_helper_root_path),
            ),
        );
        write_file(
            &child_root_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                direct: { kind: "http" },
                kind: { kind: "http" },
                vm: { kind: "http" }
              },
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                env: {
                  DIRECT_URL: "${slots.direct.url}",
                  KIND_URL: "${slots.kind.url}",
                  VM_URL: "${slots.vm.url}"
                },
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &child_path,
            &format!(
                r##"
                {{
                  manifest_version: "0.3.0",
                  components: {{
                    direct_helper: "{direct_helper}",
                    kind_helper: "{kind_helper}",
                    root: "{child_root}",
                    vm_helper: "{vm_helper}"
                  }},
                  bindings: [
                    {{ from: "#kind_helper.http", to: "#root.kind" }},
                    {{ from: "#direct_helper.http", to: "#root.direct" }},
                    {{ from: "#vm_helper.http", to: "#root.vm" }}
                  ],
                  exports: {{
                    direct_http: "#direct_helper.http",
                    http: "#root.http",
                    kind_http: "#kind_helper.http",
                    vm_http: "#vm_helper.http"
                  }}
                }}
                "##,
                direct_helper = file_url(&direct_helper_path),
                kind_helper = file_url(&kind_helper_path),
                child_root = file_url(&child_root_path),
                vm_helper = file_url(&vm_helper_path),
            ),
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    child_compose: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
                child = file_url(&child_path),
            ),
        );

        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([
                (
                    "compose_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Compose,
                        context: None,
                    },
                ),
                (
                    "direct_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Direct,
                        context: None,
                    },
                ),
                (
                    "kind_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Kubernetes,
                        context: None,
                    },
                ),
                (
                    "vm_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Vm,
                        context: None,
                    },
                ),
            ]),
            defaults: PlacementDefaults {
                image: Some("compose_local".to_string()),
                path: Some("direct_local".to_string()),
                vm: Some("vm_local".to_string()),
            },
            components: BTreeMap::from([
                ("/job-compose/root".to_string(), "compose_local".to_string()),
                (
                    "/job-compose/kind_helper".to_string(),
                    "kind_local".to_string(),
                ),
                (
                    "/job-compose/direct_helper".to_string(),
                    "direct_local".to_string(),
                ),
                ("/job-compose/vm_helper".to_string(), "vm_local".to_string()),
            ]),
        };

        let mut state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
        let root_authority = state.base_scenario.root;
        let child = prepare_child_record(
            &mut state,
            root_authority,
            &CreateChildRequest {
                template: "child_compose".to_string(),
                name: "job-compose".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
        )
        .await
        .expect("matrix child should plan successfully");

        assert_eq!(
            child
                .assignments
                .get("/job-compose/root")
                .map(String::as_str),
            Some("compose_local"),
        );
        assert_eq!(
            child
                .assignments
                .get("/job-compose/kind_helper")
                .map(String::as_str),
            Some("kind_local"),
        );
        assert_eq!(
            child
                .assignments
                .get("/job-compose/direct_helper")
                .map(String::as_str),
            Some("direct_local"),
        );
        assert_eq!(
            child
                .assignments
                .get("/job-compose/vm_helper/root")
                .map(String::as_str),
            Some("vm_local"),
        );
        assert_eq!(
            child
                .site_plans
                .iter()
                .map(|site_plan| site_plan.site_id.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["compose_local", "direct_local", "kind_local", "vm_local"]),
            "cross-backend child planning should retain all expected site slices",
        );
        let proxy_exports_by_site = child
            .site_plans
            .iter()
            .map(|site_plan| {
                (
                    site_plan.site_id.as_str(),
                    site_plan
                        .proxy_exports
                        .keys()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            proxy_exports_by_site.get("compose_local"),
            Some(&BTreeSet::from(["http"])),
            "compose site should own the dynamic child root export",
        );
        for (site_id, public_export) in [
            ("kind_local", "kind_http"),
            ("direct_local", "direct_http"),
            ("vm_local", "vm_http"),
        ] {
            let exports = proxy_exports_by_site
                .get(site_id)
                .unwrap_or_else(|| panic!("missing proxy export set for {site_id}"));
            assert!(
                exports.contains(public_export),
                "{site_id} should keep its public helper export",
            );
            assert!(
                exports.iter().any(|name| name.starts_with("amber_export_")),
                "{site_id} should also publish its internal routed link export",
            );
        }
        assert!(
            child
                .site_plans
                .iter()
                .all(|site_plan| site_plan.routed_inputs.is_empty()),
            "bindings that stay inside the created fragment must remain intra-fragment wiring, \
             not site-router routed inputs",
        );
    }

    #[tokio::test]
    async fn describe_template_exposes_dynamic_child_exports_as_binding_candidates() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let producer_path = dir.path().join("producer.json5");
        let consumer_path = dir.path().join("consumer.json5");
        write_file(
            &producer_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["producer"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &consumer_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                upstream: { kind: "http" }
              },
              program: {
                path: "/bin/echo",
                args: ["consumer", "${slots.upstream.url}"]
              },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    producer: {{ manifest: "{producer}" }},
                    consumer: {{ manifest: "{consumer}" }}
                  }},
                }}
                "#,
                producer = file_url(&producer_path),
                consumer = file_url(&consumer_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;

        create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "producer".to_string(),
                name: "source".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("producer child should be created");

        let description =
            describe_template(&state, root_authority, "consumer").expect("template should exist");
        let upstream = description
            .bindings
            .get("upstream")
            .expect("consumer should expose the upstream binding");
        assert_eq!(upstream.state, InputState::Open);
        assert!(
            upstream
                .candidates
                .iter()
                .any(|candidate| candidate == "children.source.exports.out"),
            "dynamic child exports should enter the authority realm bindable source set"
        );
    }

    #[tokio::test]
    async fn describe_template_exposes_static_child_exports_as_binding_candidates() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let provider_path = dir.path().join("provider.json5");
        let consumer_path = dir.path().join("consumer.json5");
        write_file(
            &provider_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["provider"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &consumer_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                upstream: { kind: "http" }
              },
              program: {
                path: "/bin/echo",
                args: ["consumer", "${slots.upstream.url}"]
              },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  components: {{
                    provider: "{provider}"
                  }},
                  child_templates: {{
                    consumer: {{ manifest: "{consumer}" }}
                  }},
                }}
                "#,
                provider = file_url(&provider_path),
                consumer = file_url(&consumer_path),
            ),
        );

        let state = compile_control_state(&root_path).await;
        let description = describe_template(&state, state.base_scenario.root, "consumer")
            .expect("template should exist");
        let upstream = description
            .bindings
            .get("upstream")
            .expect("consumer should expose the upstream binding");
        assert_eq!(upstream.state, InputState::Open);
        assert!(
            upstream
                .candidates
                .iter()
                .any(|candidate| candidate == "children.provider.exports.out"),
            "static child exports should enter the authority realm bindable source set"
        );
    }

    #[tokio::test]
    async fn root_external_bindable_sources_are_listed_and_weak() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let worker_path = dir.path().join("worker.json5");
        write_file(
            &worker_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                catalog_api: { kind: "http" }
              },
              program: {
                path: "/bin/echo",
                args: ["worker", "${slots.catalog_api.url}"]
              }
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }},
                    catalog_api: {{ kind: "http" }}
                  }},
                  program: {{
                    path: "/bin/echo",
                    args: ["root"]
                  }},
                  child_templates: {{
                    worker: {{
                      manifest: "{worker}"
                    }}
                  }}
                }}
                "#,
                worker = file_url(&worker_path),
            ),
        );

        let state = compile_control_state(&root_path).await;
        let scenario = Scenario::try_from(state.base_scenario.clone()).expect("base scenario");
        let candidates =
            bindable_source_candidates(&scenario, &state.base_scenario, &state, scenario.root)
                .expect("candidates");
        let external = candidates
            .iter()
            .find(|candidate| candidate.selector == "external.catalog_api")
            .expect("root external source should be listed");
        assert_eq!(external.sources.len(), 1);
        assert!(
            external.sources[0].weak,
            "root external bindable sources must remain weak because they depend on the external \
             site"
        );
    }

    #[tokio::test]
    async fn open_template_rejects_manifest_outside_frozen_allowed_set() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let alpha_path = dir.path().join("alpha.json5");
        let beta_path = dir.path().join("beta.json5");
        let gamma_path = dir.path().join("gamma.json5");
        for (path, label) in [
            (&alpha_path, "alpha"),
            (&beta_path, "beta"),
            (&gamma_path, "gamma"),
        ] {
            write_file(
                path,
                &format!(
                    r#"
                    {{
                      manifest_version: "0.3.0",
                      program: {{ path: "/bin/echo", args: ["{label}"] }},
                    }}
                    "#
                ),
            );
        }
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{
                      allowed_manifests: ["{alpha}", "{beta}"]
                    }}
                  }},
                }}
                "#,
                alpha = file_url(&alpha_path),
                beta = file_url(&beta_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;

        let err = create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job".to_string(),
                manifest: Some(
                    amber_mesh::component_protocol::CreateChildManifestSelection {
                        catalog_key: file_url(&gamma_path),
                    },
                ),
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect_err("unexpected manifest selection should be rejected");
        assert_eq!(err.code, ProtocolErrorCode::ManifestNotAllowed);
    }

    #[tokio::test]
    async fn execute_create_child_write_failure_rolls_back_authoritative_state() {
        let (dir, state, _) = compile_exact_template_control_state().await;
        let bad_state_path = dir.path().join("control-state-dir");
        fs::create_dir_all(&bad_state_path).expect("bad state path should exist as a directory");
        let root_authority = state.base_scenario.root;
        let app = test_control_state_app(&dir, state, bad_state_path);

        let err = execute_create_child(
            &app,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
        )
        .await
        .expect_err("create should fail when control-state writes fail");
        assert_eq!(err.0.code, ProtocolErrorCode::ControlStateUnavailable);

        let recovered = app.control_state.lock().await.clone();
        assert!(
            recovered.live_children.is_empty(),
            "failed create must not leave an in-memory child record behind"
        );
        assert!(
            recovered.journal.is_empty(),
            "failed create must not append durable journal entries in memory"
        );
    }

    #[tokio::test]
    async fn execute_destroy_child_write_failure_preserves_live_state() {
        let (dir, mut state, state_path) = compile_exact_template_control_state().await;
        let root_authority = state.base_scenario.root;
        create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("setup create should succeed");

        let bad_state_path = dir.path().join("control-state-dir");
        fs::create_dir_all(&bad_state_path).expect("bad state path should exist as a directory");
        let app = test_control_state_app(&dir, state, bad_state_path);

        let err = execute_destroy_child(&app, root_authority, "job")
            .await
            .expect_err("destroy should fail when control-state writes fail");
        assert_eq!(err.0.code, ProtocolErrorCode::ControlStateUnavailable);

        let recovered = app.control_state.lock().await.clone();
        let live_child = recovered
            .live_children
            .iter()
            .find(|child| child.name == "job")
            .expect("failed destroy must keep the live child present");
        assert_eq!(live_child.state, ChildState::Live);
    }

    #[tokio::test]
    async fn execute_destroy_child_resumes_pending_destroy_transactions() {
        let (dir, mut state, state_path) = compile_empty_control_state().await;
        let root_authority = state.base_scenario.root;
        state.pending_destroys.push(pending_destroy(
            1,
            empty_live_child(root_authority, "doomed", 1, ChildState::DestroyRequested),
        ));
        write_control_state(&state_path, &state).expect("state should write");
        let app = test_control_state_app(&dir, state, state_path);

        execute_destroy_child(&app, root_authority, "doomed")
            .await
            .expect("destroy should resume the pending transaction");

        let recovered = app.control_state.lock().await.clone();
        assert!(
            recovered.pending_destroys.is_empty(),
            "resumed destroy should consume pending destroy state"
        );
        let states = recovered
            .journal
            .iter()
            .map(|entry| entry.state)
            .collect::<Vec<_>>();
        assert!(
            states.contains(&ChildState::DestroyRetracted),
            "resumed destroy should continue the existing transaction"
        );
        assert_eq!(states.last().copied(), Some(ChildState::DestroyCommitted));
    }

    #[tokio::test]
    async fn describe_template_rejects_unfrozen_template_contracts() {
        let (_, mut state, _) = compile_exact_template_control_state().await;
        let root_authority = state.base_scenario.root;
        let root_component = state
            .base_scenario
            .components
            .iter_mut()
            .find(|component| component.id == root_authority)
            .expect("root component should exist");
        let template = root_component
            .child_templates
            .get_mut("worker")
            .expect("worker template should exist");
        template.frozen = false;
        template.visible_exports = None;
        template.slot_decls.clear();

        let err = describe_template(&state, root_authority, "worker")
            .expect_err("framework.component should reject unfrozen template contracts");
        assert_eq!(err.code, ProtocolErrorCode::ControlStateUnavailable);
        assert!(
            err.message.contains("recompile with the current compiler"),
            "error should direct the operator toward recompilation, got: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn recover_control_state_aborts_create_requested_children() {
        let (dir, mut state, state_path) = compile_empty_control_state().await;
        let root_authority = state.base_scenario.root;
        state.pending_creates.push(pending_create(
            1,
            empty_live_child(root_authority, "requested", 1, ChildState::CreateRequested),
        ));
        write_control_state(&state_path, &state).expect("state should write");
        let app = test_control_state_app(&dir, state, state_path);

        recover_control_state(&app)
            .await
            .expect("recovery should succeed");

        let recovered = app.control_state.lock().await.clone();
        assert!(
            recovered.live_children.is_empty(),
            "create_requested recovery should discard the stale child"
        );
        assert!(
            recovered.pending_creates.is_empty(),
            "create_requested recovery should clear pending create state"
        );
        assert_eq!(
            recovered.journal.last().map(|entry| entry.state),
            Some(ChildState::CreateAborted)
        );
    }

    #[tokio::test]
    async fn recover_control_state_aborts_create_prepared_children() {
        let (dir, mut state, state_path) = compile_empty_control_state().await;
        let root_authority = state.base_scenario.root;
        state.pending_creates.push(pending_create(
            1,
            empty_live_child(root_authority, "prepared", 1, ChildState::CreatePrepared),
        ));
        write_control_state(&state_path, &state).expect("state should write");
        let app = test_control_state_app(&dir, state, state_path);

        recover_control_state(&app)
            .await
            .expect("recovery should succeed");

        let recovered = app.control_state.lock().await.clone();
        assert!(
            recovered.live_children.is_empty(),
            "create_prepared recovery should remove the child"
        );
        assert!(
            recovered.pending_creates.is_empty(),
            "create_prepared recovery should clear pending create state"
        );
        assert_eq!(
            recovered.journal.last().map(|entry| entry.state),
            Some(ChildState::CreateAborted)
        );
    }

    #[tokio::test]
    async fn recover_control_state_surfaces_create_prepared_rollback_failures() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        write_file(
            &root_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: { path: "/bin/echo", args: ["root"] },
            }
            "#,
        );
        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([(
                "direct_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            )]),
            defaults: PlacementDefaults {
                path: Some("direct_local".to_string()),
                ..PlacementDefaults::default()
            },
            components: BTreeMap::new(),
        };
        let mut state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
        let state_path = dir.path().join("control-state.json");
        let root_authority = state.base_scenario.root;
        let app = test_control_state_app(&dir, state.clone(), state_path.clone());
        let actuators = install_failing_rollback_site_actuator(&app).await;
        state.pending_creates.push(pending_create(
            1,
            LiveChildRecord {
                child_id: 1,
                authority_realm_id: root_authority,
                name: "prepared".to_string(),
                state: ChildState::CreatePrepared,
                template_name: Some("worker".to_string()),
                selected_manifest_catalog_key: None,
                fragment: None,
                assignments: BTreeMap::new(),
                site_plans: vec![DynamicSitePlanRecord {
                    site_id: "direct_local".to_string(),
                    kind: SiteKind::Direct,
                    router_identity_id: "/site/direct_local/router".to_string(),
                    component_ids: Vec::new(),
                    assigned_components: Vec::new(),
                    artifact_files: BTreeMap::new(),
                    desired_artifact_files: BTreeMap::new(),
                    proxy_exports: BTreeMap::new(),
                    routed_inputs: Vec::new(),
                }],
                overlay_ids: Vec::new(),
                overlays: Vec::new(),
                outputs: BTreeMap::new(),
            },
        ));
        write_control_state(&state_path, &state).expect("state should write");
        *app.control_state.lock().await = state;

        let err = recover_control_state(&app)
            .await
            .expect_err("recovery should fail when prepared rollback fails");
        let message = err.to_string();
        assert!(
            message.contains("failed to rollback prepared child `prepared`"),
            "error should identify the blocked transaction, got: {message}"
        );

        let recovered = app.control_state.lock().await.clone();
        assert_eq!(
            recovered.pending_creates.len(),
            1,
            "failed recovery must retain the prepared child transaction"
        );
        assert!(
            recovered.journal.is_empty(),
            "failed rollback must not pretend the child was aborted"
        );
        for actuator in actuators {
            actuator.abort();
        }
    }

    #[tokio::test]
    async fn recover_control_state_promotes_create_committed_hidden_children_to_live() {
        let (dir, mut state, state_path) = compile_empty_control_state().await;
        let root_authority = state.base_scenario.root;
        state.pending_creates.push(pending_create(
            1,
            empty_live_child(
                root_authority,
                "hidden",
                1,
                ChildState::CreateCommittedHidden,
            ),
        ));
        write_control_state(&state_path, &state).expect("state should write");
        let app = test_control_state_app(&dir, state, state_path);

        recover_control_state(&app)
            .await
            .expect("recovery should succeed");

        let recovered = app.control_state.lock().await.clone();
        assert_eq!(
            recovered
                .live_children
                .iter()
                .find(|child| child.name == "hidden")
                .map(|child| child.state),
            Some(ChildState::Live)
        );
        assert!(
            recovered.pending_creates.is_empty(),
            "create_committed_hidden recovery should consume pending create state"
        );
        assert_eq!(
            recovered.journal.last().map(|entry| entry.state),
            Some(ChildState::Live)
        );
    }

    #[tokio::test]
    async fn recover_control_state_completes_destroy_requested_children() {
        let (dir, mut state, state_path) = compile_empty_control_state().await;
        let root_authority = state.base_scenario.root;
        state.pending_destroys.push(pending_destroy(
            1,
            empty_live_child(root_authority, "doomed", 1, ChildState::DestroyRequested),
        ));
        write_control_state(&state_path, &state).expect("state should write");
        let app = test_control_state_app(&dir, state, state_path);

        recover_control_state(&app)
            .await
            .expect("recovery should succeed");

        let recovered = app.control_state.lock().await.clone();
        assert!(
            recovered.live_children.is_empty(),
            "destroy_requested recovery should commit the removal"
        );
        assert!(
            recovered.pending_destroys.is_empty(),
            "destroy_requested recovery should clear pending destroy state"
        );
        let states = recovered
            .journal
            .iter()
            .map(|entry| entry.state)
            .collect::<Vec<_>>();
        assert!(
            states.contains(&ChildState::DestroyRetracted),
            "recovery should retract bindings before commit"
        );
        assert_eq!(states.last().copied(), Some(ChildState::DestroyCommitted));
    }

    #[tokio::test]
    async fn recover_control_state_completes_destroy_retracted_children() {
        let (dir, mut state, state_path) = compile_empty_control_state().await;
        let root_authority = state.base_scenario.root;
        state.pending_destroys.push(pending_destroy(
            1,
            empty_live_child(root_authority, "retracted", 1, ChildState::DestroyRetracted),
        ));
        write_control_state(&state_path, &state).expect("state should write");
        let app = test_control_state_app(&dir, state, state_path);

        recover_control_state(&app)
            .await
            .expect("recovery should succeed");

        let recovered = app.control_state.lock().await.clone();
        assert!(
            recovered.live_children.is_empty(),
            "destroy_retracted recovery should commit the removal"
        );
        assert!(
            recovered.pending_destroys.is_empty(),
            "destroy_retracted recovery should clear pending destroy state"
        );
        assert_eq!(
            recovered.journal.last().map(|entry| entry.state),
            Some(ChildState::DestroyCommitted)
        );
    }
