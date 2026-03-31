use super::*;

#[test]
fn kubernetes_namespace_and_metadata_digest_follow_scenario_ir() {
    let dir = tempdir().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    fs::write(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          components: { child: "./child.json5" }
        }
        "#,
    )
    .expect("write root manifest");

    let compile_namespace_and_digest = |child_contents: &str| {
        fs::write(&child_path, child_contents).expect("write child manifest");
        let compiler = Compiler::new(Resolver::new(), DigestStore::default());
        let opts = CompileOptions {
            optimize: OptimizeOptions { dce: false },
            ..Default::default()
        };
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let output = rt
            .block_on(compiler.compile(ManifestRef::from_url(file_url(&root_path)), opts))
            .expect("compile scenario");

        let artifact = render_artifact(&output);

        let kustomization = artifact
            .files
            .get(&PathBuf::from("kustomization.yaml"))
            .expect("kustomization");
        let kust_doc: serde_yaml::Value =
            serde_yaml::from_str(kustomization).expect("parse kustomization");
        let namespace = kust_doc["namespace"]
            .as_str()
            .expect("kustomization namespace")
            .to_string();

        let metadata_yaml = artifact
            .files
            .get(&PathBuf::from("01-configmaps/amber-metadata.yaml"))
            .expect("metadata configmap");
        let meta_doc: serde_yaml::Value =
            serde_yaml::from_str(metadata_yaml).expect("parse metadata yaml");
        let scenario_json = meta_doc["data"]["scenario.json"]
            .as_str()
            .expect("scenario.json in metadata");
        let scenario_json: serde_json::Value =
            serde_json::from_str(scenario_json).expect("parse scenario.json");
        let digest = scenario_json["digest"]
            .as_str()
            .expect("scenario digest")
            .to_string();

        (namespace, digest)
    };

    let child_a = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 3600"]
          }
        }
        "#;
    let child_b = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 1200"]
          }
        }
        "#;

    let (namespace_a, digest_a) = compile_namespace_and_digest(child_a);
    let (namespace_b, digest_b) = compile_namespace_and_digest(child_b);

    assert_ne!(
        namespace_a, namespace_b,
        "namespace should change when scenario IR changes"
    );
    assert_ne!(
        digest_a, digest_b,
        "metadata digest should change when scenario IR changes"
    );
}

#[test]
fn kubernetes_emits_router_for_external_slots() {
    let dir = tempdir().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let client_path = dir.path().join("client.json5");

    fs::write(
        &root_path,
        r##"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
          components: { client: "./client.json5" },
          bindings: [
            { to: "#client.api", from: "self.api", weak: true }
          ]
        }
        "##,
    )
    .expect("write root manifest");

    fs::write(
        &client_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "client",
            entrypoint: ["client"],
            env: { API_URL: "${slots.api.url}" }
          },
          slots: { api: { kind: "http" } }
        }
        "#,
    )
    .expect("write client manifest");

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions {
        optimize: OptimizeOptions { dce: false },
        ..Default::default()
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&root_path)), opts))
        .expect("compile scenario");

    let artifact = render_artifact(&output);

    let router_deploy = artifact
        .files
        .get(&PathBuf::from("03-deployments/amber-router.yaml"))
        .expect("router deployment");
    assert!(
        router_deploy.contains("AMBER_ROUTER_CONFIG_PATH"),
        "{router_deploy}"
    );
    assert!(
        router_deploy.contains("AMBER_ROUTER_IDENTITY_PATH"),
        "{router_deploy}"
    );
    assert!(
        router_deploy.contains("amber-router-external"),
        "{router_deploy}"
    );

    let router_service = artifact
        .files
        .get(&PathBuf::from("04-services/amber-router.yaml"))
        .expect("router service");
    assert!(router_service.contains("port: 24000"), "{router_service}");

    let router_env = artifact
        .files
        .get(&PathBuf::from(super::DEFAULT_EXTERNAL_ENV_FILE))
        .expect("router env template");
    assert!(
        router_env.contains("AMBER_EXTERNAL_SLOT_API_URL="),
        "{router_env}"
    );

    let kustomization = artifact
        .files
        .get(&PathBuf::from("kustomization.yaml"))
        .expect("kustomization");
    let kust_doc: serde_yaml::Value =
        serde_yaml::from_str(kustomization).expect("parse kustomization");
    let resources = kust_doc["resources"]
        .as_sequence()
        .expect("kustomization resources list");
    let contains_env = resources
        .iter()
        .any(|item| item.as_str() == Some(super::DEFAULT_EXTERNAL_ENV_FILE));
    assert!(!contains_env, "{kustomization}");
    let contains_proxy = resources
        .iter()
        .any(|item| item.as_str() == Some(super::PROXY_METADATA_FILENAME));
    assert!(!contains_proxy, "{kustomization}");
    let contains_readme = resources
        .iter()
        .any(|item| item.as_str() == Some("README.md"));
    assert!(!contains_readme, "{kustomization}");

    let proxy_json = artifact
        .files
        .get(&PathBuf::from(super::PROXY_METADATA_FILENAME))
        .expect("proxy metadata file");
    let proxy_meta: serde_json::Value =
        serde_json::from_str(proxy_json).expect("parse proxy metadata json");
    assert_eq!(proxy_meta["version"], super::PROXY_METADATA_VERSION);
    assert_eq!(proxy_meta["router"]["mesh_port"], 24000);
    assert_eq!(proxy_meta["router"]["control_port"], 24100);
    assert_eq!(proxy_meta["external_slots"]["api"]["kind"], "http");
    let readme = artifact
        .files
        .get(&PathBuf::from("README.md"))
        .expect("generated readme");
    assert!(readme.contains("kubectl apply -k ."), "{readme}");
    assert!(readme.contains("amber proxy ."), "{readme}");

    let role_yaml = artifact
        .files
        .get(&PathBuf::from("02-rbac/amber-provisioner-role.yaml"))
        .expect("provisioner role");
    let role_doc: serde_yaml::Value = serde_yaml::from_str(role_yaml).expect("parse role yaml");
    let rules = role_doc["rules"].as_sequence().expect("role rules");
    let has_create_rule = rules.iter().any(|rule| {
        let verbs = rule["verbs"].as_sequence().expect("rule verbs");
        verbs.iter().any(|v| v.as_str() == Some("create"))
            && rule["resourceNames"].is_null()
            && rule["resources"]
                .as_sequence()
                .expect("rule resources")
                .iter()
                .any(|r| r.as_str() == Some("secrets"))
    });
    assert!(has_create_rule, "{role_yaml}");
    let has_named_get_update_rule = rules.iter().any(|rule| {
        let verbs = rule["verbs"].as_sequence().expect("rule verbs");
        let has_get = verbs.iter().any(|v| v.as_str() == Some("get"));
        let has_update = verbs.iter().any(|v| v.as_str() == Some("update"));
        has_get
            && has_update
            && !rule["resourceNames"].is_null()
            && rule["resources"]
                .as_sequence()
                .expect("rule resources")
                .iter()
                .any(|r| r.as_str() == Some("secrets"))
    });
    assert!(has_named_get_update_rule, "{role_yaml}");

    let metadata_yaml = artifact
        .files
        .get(&PathBuf::from("01-configmaps/amber-metadata.yaml"))
        .expect("metadata configmap");
    let meta_doc: serde_yaml::Value =
        serde_yaml::from_str(metadata_yaml).expect("parse metadata yaml");
    let scenario_json = meta_doc["data"]["scenario.json"]
        .as_str()
        .expect("scenario.json in metadata");
    let scenario_json: serde_json::Value =
        serde_json::from_str(scenario_json).expect("parse scenario.json");
    assert_eq!(
        scenario_json["external_slots"]["api"]["required"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        scenario_json["external_slots"]["api"]["kind"],
        serde_json::Value::String("http".to_string())
    );
}

#[test]
fn kubernetes_storage_mounts_emit_pvc_and_recreate_deployment() {
    let fixture_dir = tempdir().expect("fixture dir");
    let scenario_path = write_kubernetes_counter_storage_fixture(fixture_dir.path(), "v1");
    let artifact = compile_fixture(&scenario_path);

    assert!(
        !artifact
            .files
            .contains_key(&PathBuf::from("00-namespace.yaml")),
        "runtime artifact should not embed a Namespace object"
    );

    let claim_name = storage_claim_name_for_prefix(&artifact, "storage-component-state-")
        .expect("storage pvc claim name");

    let pvc_yaml = artifact
        .files
        .get(&PathBuf::from(format!(
            "03-persistentvolumeclaims/{claim_name}.yaml"
        )))
        .expect("pvc yaml");
    assert!(
        pvc_yaml.contains("kind: PersistentVolumeClaim"),
        "{pvc_yaml}"
    );
    assert!(pvc_yaml.contains("ReadWriteOnce"), "{pvc_yaml}");
    assert!(pvc_yaml.contains("storage: 1Gi"), "{pvc_yaml}");

    let deployment_yaml = artifact
        .files
        .get(&PathBuf::from("03-deployments/c0-component.yaml"))
        .expect("deployment yaml");
    assert!(
        deployment_yaml.contains("kind: Deployment"),
        "{deployment_yaml}"
    );
    assert!(
        deployment_yaml.contains("type: Recreate"),
        "{deployment_yaml}"
    );
    assert!(
        deployment_yaml.contains(&format!("claimName: {claim_name}")),
        "{deployment_yaml}"
    );
    assert!(
        deployment_yaml.contains("mountPath: /var/lib/app"),
        "{deployment_yaml}"
    );
    assert!(
        !deployment_yaml.contains("\n  namespace:"),
        "{deployment_yaml}"
    );

    let provision_plan_yaml = artifact
        .files
        .get(&PathBuf::from("01-configmaps/amber-mesh-provision.yaml"))
        .expect("mesh provision configmap");
    let provision_plan_doc: serde_yaml::Value =
        serde_yaml::from_str(provision_plan_yaml).expect("parse mesh provision yaml");
    let plan_json = provision_plan_doc["data"]["mesh-plan.json"]
        .as_str()
        .expect("mesh plan json");
    let plan_doc: serde_json::Value =
        serde_json::from_str(plan_json).expect("parse mesh plan json");
    assert_eq!(
        plan_doc["targets"][0]["output"]["namespace"],
        serde_json::Value::Null
    );
    assert_eq!(
        plan_doc["targets"][1]["output"]["namespace"],
        serde_json::Value::Null
    );
    assert_eq!(
        plan_doc["targets"][1]["config"]["inbound"][0]["target"]["peer_addr"],
        serde_json::Value::String("c0-component:23000".to_string())
    );

    let readme = artifact
        .files
        .get(&PathBuf::from("README.md"))
        .expect("generated readme");
    assert!(
        readme.contains("Open `kustomization.yaml` and choose the namespace"),
        "{readme}"
    );
    assert!(
        readme.contains("If you want this scenario's storage to persist across redeploys"),
        "{readme}"
    );
    assert!(
        readme.contains("kubectl -n YOUR_NAMESPACE delete pvc --all"),
        "{readme}"
    );
}

#[test]
fn kubernetes_storage_claim_names_include_identity_hash() {
    let upper = StorageIdentity {
        owner: ComponentId(0),
        owner_moniker: "/Component".to_string(),
        resource: "state".to_string(),
    };
    let lower = StorageIdentity {
        owner: ComponentId(1),
        owner_moniker: "/component".to_string(),
        resource: "state".to_string(),
    };

    let upper_name = super::storage_claim_name(&upper);
    let lower_name = super::storage_claim_name(&lower);

    assert_ne!(upper_name, lower_name);
    assert!(upper_name.starts_with("storage-component-state-"));
    assert!(lower_name.starts_with("storage-component-state-"));
    assert!(upper_name.len() <= 63);
    assert!(lower_name.len() <= 63);
}

#[test]
fn kubernetes_emits_deployment_and_pvc_for_storage_mounts() {
    let fixture_dir = tempdir().expect("create fixture temp dir");
    let scenario_path =
        write_kubernetes_storage_fixture(fixture_dir.path(), "version-v1", "persisted-v1");

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions {
        optimize: OptimizeOptions { dce: false },
        ..Default::default()
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&scenario_path)), opts))
        .expect("compile kubernetes storage scenario");

    let artifact = render_artifact(&output);

    assert!(
        !artifact
            .files
            .contains_key(&PathBuf::from("00-namespace.yaml")),
        "runtime output should not include a Namespace resource"
    );

    let claim_name = storage_claim_name_for_prefix(&artifact, "storage-component-state-")
        .expect("storage pvc claim name");

    let pvc = artifact
        .files
        .get(&PathBuf::from(format!(
            "03-persistentvolumeclaims/{claim_name}.yaml"
        )))
        .expect("persistentvolumeclaim manifest");
    assert!(pvc.contains("kind: PersistentVolumeClaim"), "{pvc}");
    assert!(pvc.contains("ReadWriteOnce"), "{pvc}");
    assert!(pvc.contains("storage: 1Gi"), "{pvc}");

    let deployment = artifact
        .files
        .get(&PathBuf::from("03-deployments/c0-component.yaml"))
        .expect("deployment manifest");
    assert!(deployment.contains("kind: Deployment"), "{deployment}");
    assert!(deployment.contains("type: Recreate"), "{deployment}");
    assert!(
        deployment.contains(&format!("claimName: {claim_name}")),
        "{deployment}"
    );
    assert!(
        deployment.contains("mountPath: /var/lib/app"),
        "{deployment}"
    );
    assert!(
        artifact
            .files
            .contains_key(&PathBuf::from("03-deployments/c0-component.yaml")),
        "storage-backed components should still render as deployments"
    );
}

#[test]
fn kubernetes_mesh_workloads_wait_for_fresh_mesh_config() {
    let fixture_dir = tempdir().expect("fixture dir");
    let scenario_path = write_kubernetes_counter_storage_fixture(fixture_dir.path(), "v1");
    let artifact = compile_fixture(&scenario_path);

    let component_deployment = artifact
        .files
        .get(&PathBuf::from("03-deployments/c0-component.yaml"))
        .expect("component deployment yaml");
    assert!(
        component_deployment.contains("name: wait-mesh-config"),
        "{component_deployment}"
    );
    assert!(
        component_deployment.contains("/amber/mesh/mesh-config.json"),
        "{component_deployment}"
    );
    assert_internal_container_runtime_hardening(component_deployment);

    let router_deployment = artifact
        .files
        .get(&PathBuf::from("03-deployments/amber-router.yaml"))
        .expect("router deployment yaml");
    assert!(
        router_deployment.contains("name: wait-mesh-config"),
        "{router_deployment}"
    );
    assert!(
        router_deployment.contains("/amber/mesh/mesh-config.json"),
        "{router_deployment}"
    );
    assert_internal_container_runtime_hardening(router_deployment);
}

#[test]
fn helper_image_precreates_mesh_mount_dir_for_read_only_init_container() {
    let dockerfile = fs::read_to_string(workspace_root().join("docker/amber-helper/Dockerfile"))
        .expect("read helper Dockerfile");
    assert!(
        dockerfile.contains("/out/amber/mesh"),
        "helper image must create /amber/mesh for the read-only wait-mesh-config init \
         container\n{dockerfile}"
    );
}

#[test]
fn kubernetes_emits_default_container_security_contexts() {
    let fixture_dir = tempdir().expect("fixture dir");
    let scenario_path = write_kubernetes_smoke_fixture(fixture_dir.path());
    let artifact = compile_fixture(&scenario_path);

    let component_deployment = artifact
        .files
        .iter()
        .find_map(|(path, content)| {
            let path = path.to_str()?;
            (path.starts_with("03-deployments/")
                && path.ends_with(".yaml")
                && !path.ends_with("amber-router.yaml"))
            .then_some(content)
        })
        .expect("component deployment yaml");
    assert_default_container_security_context(component_deployment);
    assert_internal_container_runtime_hardening(component_deployment);

    let router_deployment = artifact
        .files
        .get(&PathBuf::from("03-deployments/amber-router.yaml"))
        .expect("router deployment yaml");
    assert_default_container_security_context(router_deployment);
    assert_internal_container_runtime_hardening(router_deployment);

    let provisioner_job = artifact
        .files
        .get(&PathBuf::from("02-rbac/amber-provisioner-job.yaml"))
        .expect("provisioner job yaml");
    assert_default_container_security_context(provisioner_job);
    assert_internal_container_runtime_hardening(provisioner_job);

    let otelcol_daemonset = artifact
        .files
        .get(&PathBuf::from("03-daemonsets/amber-otelcol.yaml"))
        .expect("otelcol daemonset yaml");
    assert_default_container_security_context(otelcol_daemonset);
}

#[test]
fn kubernetes_emits_otelcol_and_wires_otel_env() {
    let dir = tempdir().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let worker_path = dir.path().join("worker.json5");

    fs::write(
        &root_path,
        r##"
        {
          manifest_version: "0.1.0",
          components: { worker: "./worker.json5" }
        }
        "##,
    )
    .expect("write root manifest");

    fs::write(
        &worker_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "echo hello && sleep 3600"]
          }
        }
        "#,
    )
    .expect("write worker manifest");

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions {
        optimize: OptimizeOptions { dce: false },
        ..Default::default()
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&root_path)), opts))
        .expect("compile scenario");

    let artifact = render_artifact(&output);

    let otelcol_config = artifact
        .files
        .get(&PathBuf::from("01-configmaps/amber-otelcol-config.yaml"))
        .expect("otelcol config");
    assert!(
        otelcol_config.contains("endpoint: 0.0.0.0:4317"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains("endpoint: 0.0.0.0:4318"),
        "{otelcol_config}"
    );
    assert!(otelcol_config.contains("service:"), "{otelcol_config}");
    assert!(otelcol_config.contains("telemetry:"), "{otelcol_config}");
    assert!(otelcol_config.contains("level: warn"), "{otelcol_config}");
    assert!(otelcol_config.contains("traces:"), "{otelcol_config}");
    assert!(otelcol_config.contains("logs/otlp:"), "{otelcol_config}");
    assert!(otelcol_config.contains("logs/program:"), "{otelcol_config}");
    assert!(otelcol_config.contains("metrics:"), "{otelcol_config}");
    assert!(
        otelcol_config.contains("resource/amber"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains("${env:AMBER_SCENARIO_RUN_ID}"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains("filelog/kubernetes"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains("/var/log/containers"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains("transform/program_logs"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains("set(scope.name, \"amber.program\")"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config
            .contains("set(log.attributes[\"amber_stream\"], log.attributes[\"log.iostream\"])"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains(
            "set(log.severity_number, SEVERITY_NUMBER_INFO) where log.severity_number == 0"
        ),
        "{otelcol_config}"
    );

    let otelcol_daemonset = artifact
        .files
        .get(&PathBuf::from("03-daemonsets/amber-otelcol.yaml"))
        .expect("otelcol daemonset");
    assert!(
        otelcol_daemonset.contains("AMBER_SCENARIO_RUN_ID"),
        "{otelcol_daemonset}"
    );
    assert!(
        otelcol_daemonset.contains("AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT"),
        "{otelcol_daemonset}"
    );
    assert!(
        otelcol_daemonset.contains("serviceAccountName: amber-otelcol"),
        "{otelcol_daemonset}"
    );
    assert!(
        otelcol_daemonset.contains("/var/log/containers"),
        "{otelcol_daemonset}"
    );
    assert!(
        otelcol_daemonset.contains("/var/log/pods"),
        "{otelcol_daemonset}"
    );

    let otelcol_service = artifact
        .files
        .get(&PathBuf::from("04-services/amber-otelcol.yaml"))
        .expect("otelcol service");
    assert!(otelcol_service.contains("port: 4317"), "{otelcol_service}");
    assert!(otelcol_service.contains("port: 4318"), "{otelcol_service}");

    let component_deploy = artifact
        .files
        .iter()
        .find_map(|(path, content)| {
            let path = path.to_string_lossy();
            (path.starts_with("03-deployments/") && path.ends_with("worker.yaml"))
                .then_some(content)
        })
        .expect("worker deployment");
    assert!(
        component_deploy.contains("OTEL_EXPORTER_OTLP_ENDPOINT"),
        "{component_deploy}"
    );
    assert!(
        component_deploy.contains("http://amber-otelcol:4318"),
        "{component_deploy}"
    );
    assert!(
        component_deploy.contains("AMBER_COMPONENT_MONIKER"),
        "{component_deploy}"
    );
    assert!(
        !component_deploy.contains("AMBER_LOG_FORMAT"),
        "{component_deploy}"
    );
    assert!(
        component_deploy.contains("resource.opentelemetry.io/service.name"),
        "{component_deploy}"
    );
    assert!(
        component_deploy.contains("amber.io/component-moniker"),
        "{component_deploy}"
    );
}
