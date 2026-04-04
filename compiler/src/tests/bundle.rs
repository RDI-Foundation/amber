use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compile_is_spawnable_on_multithread_runtime() {
    let dir = tmp_dir("scenario-compile-send");
    let root_path = dir.path().join("root.json5");

    write_file(&root_path, r#"{ manifest_version: "0.1.0" }"#);
    let root_ref = manifest_ref_for_path(&root_path);

    let compiler = Arc::new(default_compiler());

    let handle = tokio::spawn({
        let compiler = Arc::clone(&compiler);
        async move { compiler.compile(root_ref, CompileOptions::default()).await }
    });

    let compilation = handle.await.unwrap().unwrap();
    assert_eq!(compilation.scenario.components.len(), 1);
}

#[tokio::test]
async fn bundle_compile_matches_direct_ir() {
    let dir = tmp_dir("bundle-match");
    let root_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("examples")
        .join("tau2")
        .join("scenario.json5")
        .canonicalize()
        .unwrap();

    let root_ref = manifest_ref_for_path(&root_path);
    let compiler = default_compiler();
    let opts = CompileOptions::default();

    let tree = compiler
        .resolve_tree(root_ref.clone(), opts.resolve)
        .await
        .unwrap();
    let direct = compiler
        .compile_from_tree(tree.clone(), opts.optimize)
        .unwrap();
    let direct_ir = ScenarioIrReporter
        .emit(&compiled_scenario(&direct))
        .unwrap();

    let bundle_dir = dir.path().join("bundle");
    BundleBuilder::build(&tree, compiler.store(), &bundle_dir).unwrap();

    let bundle = BundleLoader::from_root(&bundle_dir)
        .unwrap()
        .load()
        .await
        .unwrap();
    let bundle_compiler =
        Compiler::new(bundle.resolver, DigestStore::default()).with_registry(bundle.registry);
    let bundled = bundle_compiler
        .compile(bundle.root, CompileOptions::default())
        .await
        .unwrap();
    let bundled_ir = ScenarioIrReporter
        .emit(&compiled_scenario(&bundled))
        .unwrap();

    assert_eq!(direct_ir, bundled_ir);
}

#[tokio::test]
async fn bundle_compile_avoids_http_requests() {
    let child_manifest = r#"
        {
          manifest_version: "0.1.0",
          program: { image: "child", entrypoint: ["child"] },
        }
        "#
    .to_string();
    let (url, server) = spawn_redirecting_manifest_server(child_manifest);

    let dir = tmp_dir("bundle-http");
    let root_path = dir.path().join("root.json5");
    write_file(
        &root_path,
        &format!(
            r#"
            {{
              manifest_version: "0.1.0",
              components: {{ child: "{url}" }},
            }}
            "#
        ),
    );

    let root_ref = manifest_ref_for_path(&root_path);
    let compiler = default_compiler();
    let tree = compiler
        .resolve_tree(root_ref.clone(), CompileOptions::default().resolve)
        .await
        .unwrap();

    let bundle_dir = dir.path().join("bundle");
    BundleBuilder::build(&tree, compiler.store(), &bundle_dir).unwrap();
    server.join().unwrap();

    let bundle = BundleLoader::from_root(&bundle_dir)
        .unwrap()
        .load()
        .await
        .unwrap();
    let bundle_compiler =
        Compiler::new(bundle.resolver, DigestStore::default()).with_registry(bundle.registry);
    bundle_compiler
        .compile(bundle.root, CompileOptions::default())
        .await
        .unwrap();
}

#[tokio::test]
async fn bundle_compile_supports_relative_refs_with_digest_pins() {
    let dir = tmp_dir("bundle-relative");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    let child_contents = r#"
        {
          manifest_version: "0.1.0",
          program: { image: "child", entrypoint: ["child"] },
        }
        "#;
    write_file(&child_path, child_contents);

    let child_digest = child_contents.parse::<Manifest>().unwrap().digest();
    let root_contents = format!(
        r#"
        {{
          manifest_version: "0.1.0",
          components: {{
            child: {{ url: "./child.json5", digest: "{child_digest}" }},
          }},
        }}
        "#
    );
    write_file(&root_path, &root_contents);

    let root_digest = root_contents.parse::<Manifest>().unwrap().digest();
    let root_ref = ManifestRef::new(file_url(&root_path), Some(root_digest));
    let compiler = default_compiler();
    let tree = compiler
        .resolve_tree(root_ref, CompileOptions::default().resolve)
        .await
        .unwrap();

    let bundle_dir = dir.path().join("bundle");
    BundleBuilder::build(&tree, compiler.store(), &bundle_dir).unwrap();

    let bundle = BundleLoader::from_root(&bundle_dir)
        .unwrap()
        .load()
        .await
        .unwrap();
    let bundle_compiler =
        Compiler::new(bundle.resolver, DigestStore::default()).with_registry(bundle.registry);
    bundle_compiler
        .compile(bundle.root, CompileOptions::default())
        .await
        .unwrap();
}

#[tokio::test]
async fn bundle_compile_registers_environment_resolvers() {
    let dir = tmp_dir("bundle-env");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          environments: {
            counting: { resolvers: ["count"] },
          },
          components: {
            child: { manifest: "count://child", environment: "counting" },
          },
        }
        "#,
    );

    let backend = Arc::new(CountingBackend::new());
    let mut registry = ResolverRegistry::new();
    registry.insert("count", RemoteResolver::new(["count"], backend.clone()));

    let compiler = default_compiler().with_registry(registry);
    let tree = compiler
        .resolve_tree(
            manifest_ref_for_path(&root_path),
            CompileOptions::default().resolve,
        )
        .await
        .unwrap();

    let bundle_dir = dir.path().join("bundle");
    BundleBuilder::build(&tree, compiler.store(), &bundle_dir).unwrap();
    let calls_after_bundle = backend.call_count();

    let bundle = BundleLoader::from_root(&bundle_dir)
        .unwrap()
        .load()
        .await
        .unwrap();
    let bundle_compiler =
        Compiler::new(bundle.resolver, DigestStore::default()).with_registry(bundle.registry);
    bundle_compiler
        .compile(bundle.root, CompileOptions::default())
        .await
        .unwrap();

    assert_eq!(backend.call_count(), calls_after_bundle);
}

#[tokio::test]
async fn bundle_loader_auto_detects_dir_and_index() {
    let dir = tmp_dir("bundle-detect");
    let root_path = dir.path().join("root.json5");

    write_file(&root_path, r#"{ manifest_version: "0.1.0" }"#);

    let root_ref = manifest_ref_for_path(&root_path);
    let compiler = default_compiler();
    let tree = compiler
        .resolve_tree(root_ref.clone(), CompileOptions::default().resolve)
        .await
        .unwrap();

    let bundle_dir = dir.path().join("bundle");
    BundleBuilder::build(&tree, compiler.store(), &bundle_dir).unwrap();

    let bundle_from_dir = BundleLoader::from_path(&bundle_dir)
        .unwrap()
        .expect("bundle dir should be detected");
    let load_from_dir = bundle_from_dir.load().await.unwrap();
    assert_eq!(
        load_from_dir.root.url.as_url().unwrap(),
        root_ref.url.as_url().unwrap()
    );

    let bundle_index_path = bundle_dir.join(BUNDLE_INDEX_NAME);
    let bundle_from_index = BundleLoader::from_path(&bundle_index_path)
        .unwrap()
        .expect("bundle index should be detected");
    let load_from_index = bundle_from_index.load().await.unwrap();
    assert_eq!(
        load_from_index.root.url.as_url().unwrap(),
        root_ref.url.as_url().unwrap()
    );
}

#[test]
fn bundle_loader_from_path_rejects_unsupported_schema() {
    let dir = tmp_dir("bundle-invalid-schema");
    let index_path = dir.path().join(BUNDLE_INDEX_NAME);
    let index = serde_json::json!({
        "schema": "other.bundle",
        "version": BUNDLE_VERSION,
        "root_url": "file:///bundle/root.json5",
        "requests": []
    });
    fs::write(&index_path, serde_json::to_vec(&index).unwrap()).unwrap();

    let err = match BundleLoader::from_path(&index_path) {
        Ok(_) => panic!("unsupported schema should fail"),
        Err(err) => err,
    };
    match err {
        crate::bundle::Error::InvalidSchema { schema, expected } => {
            assert_eq!(schema, "other.bundle");
            assert_eq!(expected, BUNDLE_SCHEMA);
        }
        other => panic!("expected InvalidSchema, got {other:?}"),
    }
}

#[test]
fn bundle_loader_from_path_rejects_unsupported_version() {
    let dir = tmp_dir("bundle-invalid-version");
    let index_path = dir.path().join(BUNDLE_INDEX_NAME);
    let index = serde_json::json!({
        "schema": BUNDLE_SCHEMA,
        "version": BUNDLE_VERSION + 1,
        "root_url": "file:///bundle/root.json5",
        "requests": []
    });
    fs::write(&index_path, serde_json::to_vec(&index).unwrap()).unwrap();

    let err = match BundleLoader::from_path(&index_path) {
        Ok(_) => panic!("unsupported version should fail"),
        Err(err) => err,
    };
    match err {
        crate::bundle::Error::InvalidVersion { version, expected } => {
            assert_eq!(version, BUNDLE_VERSION + 1);
            assert_eq!(expected, BUNDLE_VERSION);
        }
        other => panic!("expected InvalidVersion, got {other:?}"),
    }
}

#[test]
fn compile_from_tree_handles_malformed_program_image_from_builder() {
    let manifest = Manifest::builder()
        .program(amber_manifest::Program::image(
            amber_manifest::ProgramImage::builder()
                .image("${config.image")
                .entrypoint(amber_manifest::ProgramEntrypoint(vec![
                    "run"
                        .parse::<amber_manifest::InterpolatedString>()
                        .unwrap()
                        .into(),
                ]))
                .common(amber_manifest::ProgramCommon::default())
                .build(),
        ))
        .build()
        .unwrap();
    let digest = manifest.digest();
    let url = Url::parse("file:///virtual/root.json5").unwrap();
    let root_ref = ManifestRef::from_url(url.clone());
    let store = DigestStore::default();
    store.put(digest, Arc::new(manifest));

    let tree = ResolvedTree {
        root: ResolvedNode {
            name: String::new(),
            declared_ref: root_ref,
            digest,
            resolved_url: url,
            observed_url: None,
            config: None,
            children: BTreeMap::new(),
            child_templates: BTreeMap::new(),
        },
    };

    let compiler = Compiler::new(Resolver::new(), store);
    let out = compiler
        .compile_from_tree(tree, standard_compile_options().optimize)
        .expect("builder-provided malformed program.image should remain recoverable");
    assert_eq!(out.scenario.components.len(), 1);
}

#[test]
fn check_from_tree_handles_malformed_program_image_from_builder_with_source() {
    let manifest = Manifest::builder()
        .program(amber_manifest::Program::image(
            amber_manifest::ProgramImage::builder()
                .image("${config.image")
                .entrypoint(amber_manifest::ProgramEntrypoint(vec![
                    "run"
                        .parse::<amber_manifest::InterpolatedString>()
                        .unwrap()
                        .into(),
                ]))
                .common(amber_manifest::ProgramCommon::default())
                .build(),
        ))
        .build()
        .unwrap();
    let digest = manifest.digest();
    let url = Url::parse("file:///virtual/root.json5").unwrap();
    let root_ref = ManifestRef::from_url(url.clone());
    let store = DigestStore::default();
    store.put(digest, Arc::new(manifest));

    let source: Arc<str> = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "${config.image",
            entrypoint: ["run"],
          },
        }
        "#
    .into();
    let spans = Arc::new(amber_manifest::ManifestSpans::parse(&source));
    store.put_source(
        url.clone(),
        crate::frontend::store::StoredSource {
            digest,
            source,
            spans,
            bundle_source: None,
        },
    );

    let tree = ResolvedTree {
        root: ResolvedNode {
            name: String::new(),
            declared_ref: root_ref,
            digest,
            resolved_url: url,
            observed_url: None,
            config: None,
            children: BTreeMap::new(),
            child_templates: BTreeMap::new(),
        },
    };

    let compiler = Compiler::new(Resolver::new(), store);
    let out = compiler
        .check_from_tree(tree)
        .expect("builder-provided malformed program.image should remain recoverable");
    assert!(!out.has_errors);
}

#[tokio::test]
async fn bundle_builder_reserializes_when_source_missing() {
    let dir = tmp_dir("bundle-reserialize");
    let bundle_dir = dir.path().join("bundle");

    let source = r#"
        // comment to ensure we don't round-trip source formatting
        { manifest_version: "0.1.0" }
        "#;
    let manifest: Manifest = source.parse().unwrap();
    let digest = manifest.digest();

    let url = Url::parse("file:///virtual/root.json5").unwrap();
    let root_ref = ManifestRef::from_url(url.clone());
    let store = DigestStore::default();
    store.put(digest, Arc::new(manifest.clone()));

    let tree = ResolvedTree {
        root: ResolvedNode {
            name: String::new(),
            declared_ref: root_ref,
            digest,
            resolved_url: url,
            observed_url: None,
            config: None,
            children: BTreeMap::new(),
            child_templates: BTreeMap::new(),
        },
    };

    BundleBuilder::build(&tree, &store, &bundle_dir).unwrap();

    let digest_name = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.bytes());
    let manifest_path = bundle_dir
        .join("manifests")
        .join(format!("{digest_name}.json5"));
    let written = fs::read(&manifest_path).unwrap();
    let expected = serde_json::to_vec::<Manifest>(&manifest).unwrap();
    assert_eq!(written, expected);
}

#[tokio::test]
async fn bundle_builder_inlines_program_file_references() {
    let dir = tmp_dir("bundle-inline-file-ref");
    let root_path = dir.path().join("root.json5");
    let script_path = dir.path().join("script.py");
    let bundle_dir = dir.path().join("bundle");

    write_file(&script_path, "print('bundled')\n");
    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "python:3.13-alpine",
            entrypoint: ["python3", "-c", { file: "./script.py" }],
          },
        }
        "#,
    );

    let root_ref = manifest_ref_for_path(&root_path);
    let compiler = default_compiler();
    let tree = compiler
        .resolve_tree(root_ref, CompileOptions::default().resolve)
        .await
        .unwrap();

    BundleBuilder::build(&tree, compiler.store(), &bundle_dir).unwrap();

    let digest = tree.root.digest;
    let digest_name = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.bytes());
    let manifest_path = bundle_dir
        .join("manifests")
        .join(format!("{digest_name}.json5"));
    let bundled = fs::read_to_string(manifest_path).unwrap();

    assert!(bundled.contains("print('bundled')\\n"), "{bundled}");
    assert!(!bundled.contains("\"file\""), "{bundled}");
}

#[tokio::test]
async fn bundle_loader_rejects_duplicate_requests() {
    let dir = tmp_dir("bundle-duplicate");
    let bundle_dir = dir.path().join("bundle");
    fs::create_dir_all(bundle_dir.join("manifests")).unwrap();

    let source = r#"{ manifest_version: "0.1.0" }"#;
    let manifest: Manifest = source.parse().unwrap();
    let digest = manifest.digest();
    let url = Url::parse("file:///bundle/root.json5").unwrap();

    let digest_name = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.bytes());
    let manifest_path = bundle_dir
        .join("manifests")
        .join(format!("{digest_name}.json5"));
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

    let index = BundleIndex {
        schema: BUNDLE_SCHEMA.to_string(),
        version: BUNDLE_VERSION,
        root_url: url.clone(),
        requests: vec![
            BundleRequest {
                url: url.clone(),
                digest,
            },
            BundleRequest { url, digest },
        ],
    };

    let mut bytes = serde_json::to_vec_pretty(&index).unwrap();
    bytes.push(b'\n');
    fs::write(bundle_dir.join(BUNDLE_INDEX_NAME), bytes).unwrap();

    let loader = BundleLoader::from_root(&bundle_dir).unwrap();
    let err = match loader.load().await {
        Ok(_) => panic!("expected duplicate request error"),
        Err(err) => err,
    };
    match err {
        crate::bundle::Error::DuplicateRequest { .. } => {}
        other => panic!("expected duplicate request error, got {other:?}"),
    }
}

#[tokio::test]
async fn program_config_refs_in_each_mounts_and_network_are_validated() {
    let dir = tmp_dir("program-config-ref-validation");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              command_each_ref: { type: "string" },
              env_each_ref: { type: "string" },
              endpoint_ref: { type: "string" },
              mount_path_ref: { type: "string" },
              mount_source_ref: { type: "string" },
            },
          },
          program: {
            image: "app",
            entrypoint: [
              {
                each: "config.command_each_ref.extra",
                arg: "${item}",
              },
            ],
            env: {
              TOKEN: {
                each: "config.env_each_ref.extra",
                value: "${item}",
                join: ",",
              },
            },
            network: {
              endpoints: [
                {
                  name: "${config.endpoint_ref.extra}",
                  port: 8080,
                  protocol: "http",
                },
              ],
            },
            mounts: [
              {
                path: "/tmp/${config.mount_path_ref.extra}",
                from: "config.${config.mount_source_ref.extra}",
              },
            ],
          },
        }
        "#,
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect_err("invalid program config refs should fail validation");

    for location in [
        "program.entrypoint[0].each",
        "program.env.TOKEN.each",
        "program.network.endpoints[0].name",
        "program.mounts[0].path",
        "program.mounts[0].from",
    ] {
        assert!(
            error_contains(&err, location),
            "expected invalid config reference at {location}, got {err}"
        );
    }
}
