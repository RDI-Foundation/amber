use super::*;

#[test]
fn compose_artifact_emits_env_sample_and_readme() {
    let program = lower_test_program(
        0,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["sh", "-lc", "sleep infinity"],
            "env": {}
        }),
    );

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: Some(program),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };
    let output = compile_output(Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root)],
        bindings: Vec::new(),
        exports: Vec::new(),
    });

    let artifact = render_compose(&output).expect("compose render should succeed");

    assert!(artifact.files.contains_key(Path::new("env.example")));
    assert!(artifact.files.contains_key(Path::new("compose.yaml")));
    let readme = artifact
        .files
        .get(Path::new("README.md"))
        .expect("compose readme should be present");
    assert!(readme.contains("README.md"), "{readme}");
    assert!(readme.contains("docker compose up -d"), "{readme}");
}

#[test]
fn compose_emits_storage_volume_mounts() {
    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: Some(lower_test_program(
            0,
            json!({
                "image": "busybox:1.36.1",
                "entrypoint": ["sh", "-lc", "sleep infinity"],
                "mounts": [
                    { "path": "/var/lib/app", "from": "resources.state" }
                ]
            }),
        )),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        resources: BTreeMap::from([("state".to_string(), storage_resource_decl(None))]),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root)],
        bindings: Vec::new(),
        exports: Vec::new(),
    };

    let artifact = render_compose(&compile_output(scenario)).expect("compose render ok");
    let compose = parse_compose(&artifact);
    let volume_name = super::compose_storage_volume_name(&StorageIdentity {
        owner: ComponentId(0),
        owner_moniker: "/".to_string(),
        resource: "state".to_string(),
    });
    assert!(
        compose.volumes.contains_key(&volume_name),
        "compose should declare a named volume for storage mounts"
    );
    let app_service = service(&compose, "c0-component");
    assert!(
        app_service
            .volumes
            .iter()
            .any(|mount| mount == &format!("{volume_name}:/var/lib/app")),
        "app service should mount the generated storage volume: {:?}",
        app_service.volumes
    );
}

#[test]
fn compose_storage_volume_names_include_identity_hash() {
    let root_identity = StorageIdentity {
        owner: ComponentId(0),
        owner_moniker: "/".to_string(),
        resource: "state".to_string(),
    };
    let child_identity = StorageIdentity {
        owner: ComponentId(1),
        owner_moniker: "/root".to_string(),
        resource: "state".to_string(),
    };

    let root_name = super::compose_storage_volume_name(&root_identity);
    let child_name = super::compose_storage_volume_name(&child_identity);

    assert_ne!(root_name, child_name);
    assert!(root_name.starts_with("amber-storage-root-state-"));
    assert!(child_name.starts_with("amber-storage-root-state-"));
}

#[test]
fn compose_emits_otelcol_agent_and_wires_router_otel_env() {
    let program = lower_test_program(
        0,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["sh", "-lc", "sleep infinity"],
            "env": {}
        }),
    );

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: Some(program),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };
    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root)],
        bindings: Vec::new(),
        exports: Vec::new(),
    };

    let output = compile_output(scenario);
    let yaml = render_compose(&output).expect("compose render should succeed");
    let compose = parse_compose(&yaml);

    assert!(
        compose.services.contains_key(super::OTELCOL_SERVICE_NAME),
        "{yaml}"
    );
    assert!(
        compose.configs.contains_key(super::OTELCOL_CONFIG_NAME),
        "{yaml}"
    );

    let otelcol = service(&compose, super::OTELCOL_SERVICE_NAME);
    assert!(
        otelcol.networks.contains_key(super::MESH_NETWORK_NAME),
        "{yaml}"
    );
    assert!(
        otelcol.networks.contains_key(super::BOUNDARY_NETWORK_NAME),
        "{yaml}"
    );
    assert!(
        otelcol
            .extra_hosts
            .iter()
            .any(|entry| entry == super::HOST_GATEWAY_ENTRY),
        "{yaml}"
    );
    assert_eq!(
        env_value(otelcol, super::SCENARIO_RUN_ID_ENV).as_deref(),
        Some("${COMPOSE_PROJECT_NAME:-default}"),
        "{yaml}"
    );
    assert_eq!(
        env_value(otelcol, super::OTELCOL_UPSTREAM_ENV).as_deref(),
        Some("${AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT:-http://host.docker.internal:18890}"),
        "{yaml}"
    );
    assert!(
        otelcol
            .configs
            .iter()
            .any(|mount| mount.source == super::OTELCOL_CONFIG_NAME
                && mount.target.as_deref() == Some(super::OTELCOL_CONFIG_PATH)),
        "{yaml}"
    );
    assert!(
        otelcol
            .volumes
            .iter()
            .any(|mount| mount.contains(super::DOCKER_CONTAINER_LOGS_DIR)),
        "{yaml}"
    );

    let otelcol_config = &compose
        .configs
        .get(super::OTELCOL_CONFIG_NAME)
        .expect("otelcol config missing")
        .content;
    assert!(otelcol_config.contains("endpoint: 0.0.0.0:4317"));
    assert!(otelcol_config.contains("endpoint: 0.0.0.0:4318"));
    assert!(otelcol_config.contains(
        "receivers:
  otlp:"
    ));
    assert!(otelcol_config.contains("traces:"));
    assert!(otelcol_config.contains("logs/otlp:"));
    assert!(otelcol_config.contains("logs/program:"));
    assert!(otelcol_config.contains("metrics:"));
    assert!(otelcol_config.contains("telemetry:"));
    assert!(otelcol_config.contains("level: warn"));
    assert!(otelcol_config.contains("resource/amber"));
    assert!(otelcol_config.contains("value: $${env:AMBER_SCENARIO_RUN_ID}"));
    assert!(otelcol_config.contains("endpoint: $${env:AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT}"));
    assert!(otelcol_config.contains("filelog/docker"));
    assert!(otelcol_config.contains(super::DOCKER_CONTAINER_LOGS_DIR));
    assert!(otelcol_config.contains("transform/program_logs"));
    assert!(otelcol_config.contains("set(scope.name, \"amber.program\")"));
    assert!(
        otelcol_config
            .contains(r#"IsMatch(log.body, "(?i)\\b(error|failed|exception|fatal|panic)\\b")"#)
    );
    assert!(otelcol_config.contains(r#"IsMatch(log.body, "(?i)\\b(warn|warning)\\b")"#));
    assert!(
        otelcol_config.contains(
            "set(log.severity_number, SEVERITY_NUMBER_INFO) where log.severity_number == 0"
        )
    );
    assert!(otelcol_config.contains(
        "set(log.severity_number, SEVERITY_NUMBER_WARN) where log.severity_number == 0 and \
         log.attributes[\"amber_stream\"] == \"stderr\""
    ));

    let sidecar = service(&compose, "c0-component-net");
    let egress_init = service(&compose, "c0-component-net-egress-init");
    assert!(
        compose
            .networks
            .get(super::MESH_NETWORK_NAME)
            .is_some_and(|network| network.internal),
        "{yaml}"
    );
    assert!(
        compose
            .networks
            .get("amber_egress_c0-component-net")
            .is_some_and(|network| !network.internal),
        "{yaml}"
    );
    assert!(
        sidecar
            .networks
            .contains_key("amber_egress_c0-component-net"),
        "{yaml}"
    );
    assert!(
        !sidecar.networks.contains_key(super::BOUNDARY_NETWORK_NAME),
        "{yaml}"
    );
    assert_eq!(
        egress_init.network_mode.as_deref(),
        Some("service:c0-component-net"),
        "{yaml}"
    );
    assert_eq!(egress_init.user.as_deref(), Some("0:0"), "{yaml}");
    assert!(
        egress_init.cap_add.iter().any(|cap| cap == "NET_ADMIN"),
        "{yaml}"
    );
    assert_eq!(egress_init.restart.as_deref(), Some("no"), "{yaml}");
    assert_depends_on(egress_init, "c0-component-net", "service_started");
    assert!(egress_init.read_only != Some(true), "{yaml}");
    assert_eq!(
        env_value(sidecar, "OTEL_TRACES_SAMPLER").as_deref(),
        Some("always_on"),
        "{yaml}"
    );
    assert_eq!(
        env_value(sidecar, "OTEL_EXPORTER_OTLP_PROTOCOL").as_deref(),
        Some("http/protobuf"),
        "{yaml}"
    );
    assert_eq!(
        env_value(sidecar, "OTEL_EXPORTER_OTLP_ENDPOINT").as_deref(),
        Some("http://amber-otelcol:4318"),
        "{yaml}"
    );
    assert!(env_value(sidecar, "AMBER_LOG_FORMAT").is_none(), "{yaml}");

    let program = service(&compose, "c0-component");
    assert_depends_on(
        program,
        "c0-component-net-egress-init",
        "service_completed_successfully",
    );
    assert_eq!(
        env_value(program, "OTEL_TRACES_SAMPLER").as_deref(),
        Some("always_on"),
        "{yaml}"
    );
    assert_eq!(
        env_value(program, "OTEL_EXPORTER_OTLP_PROTOCOL").as_deref(),
        Some("http/protobuf"),
        "{yaml}"
    );
    assert_eq!(
        env_value(program, "OTEL_EXPORTER_OTLP_ENDPOINT").as_deref(),
        Some("http://amber-otelcol:4318"),
        "{yaml}"
    );
    assert_eq!(
        env_value(program, "AMBER_COMPONENT_MONIKER").as_deref(),
        Some("/"),
        "{yaml}"
    );
    assert!(env_value(program, "AMBER_LOG_FORMAT").is_none(), "{yaml}");
    let logging = program
        .logging
        .as_ref()
        .expect("program logging configured");
    assert_eq!(logging.driver, "json-file", "{yaml}");
    assert_eq!(
        logging.options.get("labels").map(String::as_str),
        Some(super::LOG_LABEL_LIST),
        "{yaml}"
    );
    assert_eq!(
        program
            .labels
            .get(super::LOG_LABEL_MONIKER)
            .map(String::as_str),
        Some("/"),
        "{yaml}"
    );
    assert_eq!(
        program
            .labels
            .get(super::LOG_LABEL_SERVICE_NAME)
            .map(String::as_str),
        Some("amber.${COMPOSE_PROJECT_NAME:-default}.root"),
        "{yaml}"
    );
}

pub(super) fn provision_plan(compose: &super::DockerComposeFile) -> MeshProvisionPlan {
    let raw = &compose
        .configs
        .get(super::PROVISIONER_PLAN_CONFIG_NAME)
        .expect("mesh provision plan config missing")
        .content;
    serde_json::from_str(raw).expect("parse mesh provision plan")
}

fn target_for_service<'a>(plan: &'a MeshProvisionPlan, service: &str) -> &'a MeshProvisionTarget {
    let suffix = format!("/{service}");
    plan.targets
        .iter()
        .find(|target| match &target.output {
            MeshProvisionOutput::Filesystem { dir } => dir.ends_with(&suffix),
            MeshProvisionOutput::KubernetesSecret { .. } => false,
        })
        .unwrap_or_else(|| panic!("mesh provision target missing for {service}"))
}

#[test]
fn control_socket_volume_name_uses_compose_project() {
    let volume_expr = super::compose_control_socket_volume_expr();
    assert_eq!(
        volume_expr,
        "${COMPOSE_PROJECT_NAME:-default}_amber-router-control"
    );
}

#[test]
fn docker_compose_emits_gateway_for_framework_docker_binding() {
    let program = lower_test_program(
        0,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["sh", "-lc", "sleep infinity"],
            "env": {
                "DOCKER_HOST": "${slots.docker.url}",
            },
        }),
    );
    let slot_docker: SlotDecl = serde_json::from_value(json!({ "kind": "docker" })).unwrap();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: Some(program),
        slots: BTreeMap::from([("docker".to_string(), slot_docker)]),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };
    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root)],
        bindings: vec![BindingEdge {
            from: BindingFrom::Framework(FrameworkCapabilityName::try_from("docker").unwrap()),
            to: SlotRef {
                component: ComponentId(0),
                name: "docker".to_string(),
            },
            weak: false,
        }],
        exports: Vec::new(),
    };

    let output = compile_output_with_docker_feature(scenario);
    let yaml = render_compose(&output).expect("compose render should succeed");
    let compose = parse_compose(&yaml);
    assert!(
        !compose.services.contains_key("amber-router"),
        "framework-only scenarios should not emit a scenario router service"
    );
    assert!(
        !compose.services.contains_key("amber-docker-router"),
        "framework routing should not emit a bespoke docker router service"
    );
    assert!(
        !compose.services.contains_key("amber-docker-gateway"),
        "framework routing should not emit a bespoke docker gateway service"
    );

    let (gateway_name, gateway) = injected_docker_gateway_service(&compose);
    let expected_network_mode = format!("service:{gateway_name}-net");
    assert_eq!(
        gateway.network_mode.as_deref(),
        Some(expected_network_mode.as_str()),
    );
    assert_internal_service_rootfs_hardened(gateway, yaml.as_ref());

    let gateway_config = env_value(gateway, super::DOCKER_GATEWAY_CONFIG_ENV)
        .expect("gateway config env should be present");
    let gateway_config_json: Value =
        serde_json::from_str(&gateway_config).expect("gateway config should parse");
    let callers = gateway_config_json["callers"]
        .as_array()
        .expect("callers should be an array");
    assert_eq!(callers.len(), 1);
    assert_eq!(callers[0]["host"], "127.0.0.1");
    let gateway_component = callers[0]["component"]
        .as_str()
        .expect("gateway caller component should be a string");
    assert!(
        gateway_component.starts_with("/__amber_internal_framework_docker_gateway"),
        "unexpected injected gateway component moniker: {gateway_component}"
    );
    assert_eq!(callers[0]["compose_service"], gateway_name);

    let program_service = service(&compose, "c0-component");
    assert_depends_on(program_service, gateway_name, "service_started");
    assert_eq!(
        env_value(program_service, "DOCKER_HOST").as_deref(),
        Some("tcp://127.0.0.1:20000"),
    );
}

#[test]
fn docker_compose_emits_framework_docker_mount_proxy_wiring() {
    let program = lower_test_program(
        0,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["sh", "-lc", "sleep infinity"],
            "mounts": [
                { "path": "/var/run/docker.sock", "from": "framework.docker" },
            ],
        }),
    );

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: Some(program),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };
    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root)],
        bindings: Vec::new(),
        exports: Vec::new(),
    };

    let output = compile_output_with_docker_feature(scenario);
    let yaml = render_compose(&output).expect("compose render should succeed");
    let compose = parse_compose(&yaml);
    assert!(
        !compose.services.contains_key("amber-router"),
        "framework-only scenarios should not emit a scenario router service"
    );
    assert!(
        !compose.services.contains_key("amber-docker-router"),
        "framework routing should not emit a bespoke docker router service"
    );
    assert!(
        !compose.services.contains_key("amber-docker-gateway"),
        "framework routing should not emit a bespoke docker gateway service"
    );

    let (gateway_name, gateway) = injected_docker_gateway_service(&compose);
    let expected_network_mode = format!("service:{gateway_name}-net");
    assert_eq!(
        gateway.network_mode.as_deref(),
        Some(expected_network_mode.as_str()),
    );

    let program_service = service(&compose, "c0-component");
    let entrypoint = program_service
        .entrypoint
        .as_ref()
        .expect("framework mount should force helper entrypoint");
    assert_eq!(
        entrypoint,
        &vec![super::HELPER_BIN_PATH.to_string(), "run".to_string()]
    );
    assert_depends_on(
        program_service,
        super::HELPER_INIT_SERVICE,
        "service_completed_successfully",
    );
    assert_internal_service_rootfs_hardened(
        service(&compose, super::HELPER_INIT_SERVICE),
        yaml.as_ref(),
    );
    assert_depends_on(program_service, gateway_name, "service_started");

    let mount_proxy_b64 = env_value(program_service, super::DOCKER_MOUNT_PROXY_SPEC_ENV)
        .expect("docker mount proxy env should be present");
    let mount_proxy_json = base64::engine::general_purpose::STANDARD
        .decode(mount_proxy_b64.as_bytes())
        .expect("mount proxy env should be valid base64");
    let mount_specs: Value =
        serde_json::from_slice(&mount_proxy_json).expect("mount proxy payload should be JSON");
    let mount_specs = mount_specs
        .as_array()
        .expect("mount proxy payload should be an array");
    assert_eq!(mount_specs.len(), 1);
    assert_eq!(mount_specs[0]["path"], "/var/run/docker.sock");
    assert_eq!(mount_specs[0]["tcp_host"], "127.0.0.1");
    assert_eq!(mount_specs[0]["tcp_port"], 20000);
}

#[test]
fn compose_emits_sidecars_and_programs_and_slot_urls() {
    let server_program = lower_test_program(
        1,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["server"],
            "env": {},
            "network": {
                "endpoints": [
                    { "name": "api", "port": 8080, "protocol": "http" }
                ]
            }
        }),
    );

    let client_program = lower_test_program(
        2,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["client"],
            "env": {
                "URL": "${slots.api.url}"
            }
        }),
    );

    let slot_http: SlotDecl = serde_json::from_value(json!({ "kind": "http" })).unwrap();
    let provide_http: ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "api" })).unwrap();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: vec![ComponentId(2), ComponentId(1)],
    };

    let server = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(server_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("api".to_string(), provide_http)]),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    let client = Component {
        id: ComponentId(2),
        parent: Some(ComponentId(0)),
        moniker: moniker("/client"),
        digest: digest(2),
        config: None,
        config_schema: None,
        program: Some(client_program),
        slots: BTreeMap::from([("api".to_string(), slot_http)]),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root), Some(server), Some(client)],
        bindings: vec![BindingEdge {
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(1),
                name: "api".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(2),
                name: "api".to_string(),
            },
            weak: false,
        }],
        exports: vec![],
    };

    let output = compile_output(scenario);
    let yaml = render_compose(&output).expect("compose render ok");
    let compose = parse_compose(&yaml);
    let images = internal_images();
    let plan = provision_plan(&compose);

    let provisioner = service(&compose, "amber-provisioner");
    assert_eq!(
        env_value(provisioner, "AMBER_MESH_PROVISION_PLAN_PATH").as_deref(),
        Some(super::PROVISIONER_PLAN_PATH),
        "{yaml}"
    );
    assert!(
        env_value(provisioner, "AMBER_MESH_PROVISION_PLAN_B64").is_none(),
        "{yaml}"
    );
    assert!(
        provisioner.configs.iter().any(|mount| {
            mount.source == super::PROVISIONER_PLAN_CONFIG_NAME
                && mount.target.as_deref() == Some(super::PROVISIONER_PLAN_PATH)
        }),
        "{yaml}"
    );
    assert!(
        compose
            .configs
            .contains_key(super::PROVISIONER_PLAN_CONFIG_NAME),
        "{yaml}"
    );

    // Service names should be injective and include sidecars.
    assert!(compose.services.contains_key("c1-server-net"), "{yaml}");
    assert!(compose.services.contains_key("c1-server"), "{yaml}");
    assert!(compose.services.contains_key("c2-client-net"), "{yaml}");
    assert!(compose.services.contains_key("c2-client"), "{yaml}");

    for name in [
        "amber-provisioner",
        "amber-otelcol",
        "c1-server-net",
        "c1-server",
        "c2-client-net",
        "c2-client",
    ] {
        assert_service_hardened(service(&compose, name), yaml.as_ref());
    }
    for name in ["c1-server-net", "c2-client-net"] {
        assert_internal_service_rootfs_hardened(service(&compose, name), yaml.as_ref());
    }

    // Program uses sidecar netns.
    assert_eq!(
        service(&compose, "c2-client").network_mode.as_deref(),
        Some("service:c2-client-net")
    );

    // Sidecar image should be the router binary.
    assert_eq!(service(&compose, "c1-server-net").image, images.router);

    // Compose should not pin static IPs or subnets.
    assert!(!yaml.contains("ipv4_address:"), "{yaml}");
    assert!(!yaml.contains("ipam:"), "{yaml}");

    // Server sidecar config should expose the provide on the program port.
    let server_target = target_for_service(&plan, "c1-server-net");
    let inbound = server_target
        .config
        .inbound
        .iter()
        .find(|route| route.capability == "api")
        .expect("server inbound route missing");
    assert_eq!(inbound.allowed_issuers.len(), 1);

    // Client sidecar config should listen on the local slot port.
    let client_target = target_for_service(&plan, "c2-client-net");
    let outbound = client_target
        .config
        .outbound
        .iter()
        .find(|route| route.slot == "api")
        .expect("client outbound route missing");
    assert_eq!(outbound.listen_port, 20000);

    // Slot URL should be rendered with local proxy port base (20000).
    assert_eq!(
        env_value(service(&compose, "c2-client"), "URL").as_deref(),
        Some("http://127.0.0.1:20000")
    );
}

#[test]
fn compose_emits_minimal_peer_keys() {
    let server1_program = lower_test_program(
        1,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["server1"],
            "network": {
                "endpoints": [
                    { "name": "api1", "port": 8080, "protocol": "http" }
                ]
            }
        }),
    );

    let server2_program = lower_test_program(
        2,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["server2"],
            "network": {
                "endpoints": [
                    { "name": "api2", "port": 8081, "protocol": "http" }
                ]
            }
        }),
    );

    let client_program = lower_test_program(
        3,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["client"],
            "env": {
                "URL": "${slots.api1.url}"
            }
        }),
    );

    let slot_http: SlotDecl = serde_json::from_value(json!({ "kind": "http" })).unwrap();
    let provide_api1: ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "api1" })).unwrap();
    let provide_api2: ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "api2" })).unwrap();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: vec![ComponentId(1), ComponentId(2), ComponentId(3)],
    };

    let server1 = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server1"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(server1_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("api1".to_string(), provide_api1)]),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    let server2 = Component {
        id: ComponentId(2),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server2"),
        digest: digest(2),
        config: None,
        config_schema: None,
        program: Some(server2_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("api2".to_string(), provide_api2)]),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    let client = Component {
        id: ComponentId(3),
        parent: Some(ComponentId(0)),
        moniker: moniker("/client"),
        digest: digest(3),
        config: None,
        config_schema: None,
        program: Some(client_program),
        slots: BTreeMap::from([("api1".to_string(), slot_http)]),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root), Some(server1), Some(server2), Some(client)],
        bindings: vec![BindingEdge {
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(1),
                name: "api1".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(3),
                name: "api1".to_string(),
            },
            weak: false,
        }],
        exports: vec![],
    };

    let output = compile_output(scenario);
    let yaml = render_compose(&output).expect("compose render should succeed");
    let compose = parse_compose(&yaml);
    let plan = provision_plan(&compose);

    let server1_target = target_for_service(&plan, "c1-server1-net");
    let server2_target = target_for_service(&plan, "c2-server2-net");
    let client_target = target_for_service(&plan, "c3-client-net");

    let server1_peers: BTreeSet<String> = server1_target
        .config
        .peers
        .iter()
        .map(|peer| peer.id.clone())
        .collect();
    let server2_peers: BTreeSet<String> = server2_target
        .config
        .peers
        .iter()
        .map(|peer| peer.id.clone())
        .collect();
    let client_peers: BTreeSet<String> = client_target
        .config
        .peers
        .iter()
        .map(|peer| peer.id.clone())
        .collect();

    let expected_server1: BTreeSet<String> = ["/client".to_string()].into_iter().collect();
    let expected_client: BTreeSet<String> = ["/server1".to_string()].into_iter().collect();

    assert_eq!(server1_peers, expected_server1);
    assert!(server2_peers.is_empty());
    assert_eq!(client_peers, expected_client);
}

#[test]
fn compose_emits_named_volumes_for_storage_mounts() {
    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: Some(lower_test_program(
            0,
            json!({
                "image": "busybox:1.36.1",
                "entrypoint": ["sh", "-lc", "sleep 3600"],
                "mounts": [
                    { "path": "/var/lib/app", "from": "resources.state" }
                ]
            }),
        )),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        resources: BTreeMap::from([("state".to_string(), storage_resource_decl(None))]),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root)],
        bindings: Vec::new(),
        exports: Vec::new(),
    };

    let artifact =
        render_compose(&compile_output(scenario)).expect("compose render should succeed");
    let compose = parse_compose(&artifact);
    let volume_name = super::compose_storage_volume_name(&StorageIdentity {
        owner: ComponentId(0),
        owner_moniker: "/".to_string(),
        resource: "state".to_string(),
    });

    assert!(
        compose.volumes.contains_key(&volume_name),
        "expected named storage volume in compose file:\n{}",
        artifact.compose_yaml()
    );

    let app_service = service(&compose, "c0-component");
    assert!(
        app_service
            .volumes
            .iter()
            .any(|mount| mount == &format!("{volume_name}:/var/lib/app")),
        "expected storage mount on app service:\n{}",
        artifact.compose_yaml()
    );
}

#[test]
fn compose_escapes_entrypoint_dollars() {
    let program = lower_test_program(
        0,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["sh", "-lc", "echo $API_URL"]
        }),
    );

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: Some(program),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root)],
        bindings: vec![],
        exports: vec![],
    };

    let output = compile_output(scenario);
    let yaml = render_compose(&output).expect("compose render ok");
    let compose = parse_compose(&yaml);

    let service = compose
        .services
        .values()
        .find(|svc| svc.image == "alpine:3.20")
        .expect("program service should exist");
    let entrypoint = service
        .entrypoint
        .as_ref()
        .expect("entrypoint should exist");
    assert!(entrypoint.iter().any(|arg| arg == "echo $$API_URL"));
}

#[test]
fn compose_emits_export_metadata_and_labels() {
    let server_program = lower_test_program(
        1,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["server"],
            "env": {},
            "network": {
                "endpoints": [
                    { "name": "api", "port": 8080, "protocol": "http" }
                ]
            }
        }),
    );

    let provide_http: ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "api" })).unwrap();
    let provide_decl = provide_http.decl.clone();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: vec![ComponentId(1)],
    };

    let server = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(server_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("api".to_string(), provide_http)]),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root), Some(server)],
        bindings: vec![],
        exports: vec![ScenarioExport {
            name: "public".to_string(),
            capability: provide_decl,
            from: ProvideRef {
                component: ComponentId(1),
                name: "api".to_string(),
            },
        }],
    };

    let output = compile_output(scenario);
    let yaml = render_compose(&output).expect("compose render ok");
    let compose = parse_compose(&yaml);

    let exports = compose
        .x_amber
        .as_ref()
        .expect("x-amber should be present")
        .exports
        .get("public")
        .expect("public export should exist");
    assert_eq!(exports.component, "/server");
    assert_eq!(exports.provide, "api");
    assert_eq!(exports.protocol, "http");
    assert_eq!(exports.router_mesh_port, 24000);
    let router_meta = compose
        .x_amber
        .as_ref()
        .expect("x-amber should be present")
        .router
        .as_ref()
        .expect("router metadata missing");
    assert_eq!(router_meta.mesh_port, 24000);
    assert_eq!(router_meta.control_port, 24100);
    let control_socket = router_meta
        .control_socket
        .as_deref()
        .expect("router control socket missing");
    assert_eq!(control_socket, "/router-control.sock");
    let control_volume = router_meta
        .control_socket_volume
        .as_deref()
        .expect("router control socket volume missing");
    assert_eq!(
        control_volume,
        "${COMPOSE_PROJECT_NAME:-default}_amber-router-control"
    );

    let router_service = service(&compose, "amber-router");
    assert!(router_service.ports.iter().any(|p| p == "127.0.0.1::24000"));
    assert!(
        router_service
            .ports
            .iter()
            .all(|p| p != "127.0.0.1:24100:24100")
    );
    assert!(router_service.environment.as_ref().is_some());
    assert_eq!(
        env_value(router_service, "AMBER_ROUTER_CONTROL_SOCKET_PATH").as_deref(),
        Some("/amber/control/router-control.sock")
    );
    assert!(
        router_service
            .volumes
            .iter()
            .any(|v| v == "amber-router-control:/amber/control")
    );
    assert_depends_on(
        router_service,
        "amber-router-control-init",
        "service_completed_successfully",
    );
    let control_init_service = service(&compose, "amber-router-control-init");
    assert_eq!(control_init_service.user.as_deref(), Some("0:0"));
    assert!(
        control_init_service
            .volumes
            .iter()
            .any(|v| v == "amber-router-control:/amber/control")
    );
    let labels_json = router_service
        .labels
        .get("amber.exports")
        .expect("router export labels missing");
    let labels_value: serde_json::Value =
        serde_json::from_str(labels_json).expect("labels should be json");
    assert_eq!(labels_value["public"]["router_mesh_port"], 24000);
}

#[test]
fn compose_routes_external_slots_through_router() {
    let client_program = lower_test_program(
        1,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["client"],
            "env": {
                "API_URL": "${slots.api.url}"
            }
        }),
    );

    let slot_http: SlotDecl = serde_json::from_value(json!({ "kind": "http" })).unwrap();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::from([("api".to_string(), slot_http.clone())]),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: vec![ComponentId(1)],
    };

    let client = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/client"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(client_program),
        slots: BTreeMap::from([("api".to_string(), slot_http)]),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root), Some(client)],
        bindings: vec![BindingEdge {
            from: BindingFrom::External(SlotRef {
                component: ComponentId(0),
                name: "api".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(1),
                name: "api".to_string(),
            },
            weak: true,
        }],
        exports: Vec::new(),
    };

    let output = compile_output(scenario);
    let yaml = render_compose(&output).expect("compose render ok");
    let compose = parse_compose(&yaml);

    assert!(compose.services.contains_key("amber-router"));
    let router_service = service(&compose, "amber-router");
    assert!(env_value(router_service, "AMBER_EXTERNAL_SLOT_API_URL").is_some());
    assert_eq!(
        router_service.user.as_deref(),
        Some("65532:65532"),
        "{yaml}"
    );
    assert_internal_service_rootfs_hardened(router_service, yaml.as_ref());
    assert!(
        router_service.ports.is_empty(),
        "slot-only scenarios should not publish the router mesh port on the host"
    );
    assert!(
        router_service
            .networks
            .contains_key(super::MESH_NETWORK_NAME)
    );
    assert!(
        router_service
            .networks
            .contains_key(super::BOUNDARY_NETWORK_NAME)
    );
    assert!(
        router_service
            .extra_hosts
            .iter()
            .any(|entry| entry == "host.docker.internal:host-gateway")
    );
    assert!(
        compose
            .services
            .values()
            .any(|svc| { env_value(svc, "API_URL").as_deref() == Some("http://127.0.0.1:20000") })
    );
    let external_meta = compose
        .x_amber
        .as_ref()
        .expect("x-amber should be present")
        .external_slots
        .get("api")
        .expect("external slot metadata missing");
    assert_eq!(external_meta.kind, CapabilityKind::Http);
    assert_eq!(external_meta.url_env, "AMBER_EXTERNAL_SLOT_API_URL");

    let plan = provision_plan(&compose);
    let router_target = target_for_service(&plan, "amber-router");
    assert_eq!(router_target.config.control_allow, None);
    assert!(router_target.config.outbound.is_empty());
    let inbound = router_target
        .config
        .inbound
        .iter()
        .find(|route| route.capability == "api")
        .expect("router external route missing");
    match &inbound.target {
        amber_mesh::InboundTarget::External { url_env, .. } => {
            assert_eq!(url_env, "AMBER_EXTERNAL_SLOT_API_URL");
        }
        other => panic!("unexpected router target: {other:?}"),
    }
}
