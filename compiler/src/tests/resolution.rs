use super::*;

struct MapBackend {
    manifests: BTreeMap<String, Arc<str>>,
}

impl MapBackend {
    fn new(manifests: BTreeMap<String, Arc<str>>) -> Self {
        Self { manifests }
    }
}

impl Backend for MapBackend {
    fn resolve_url<'a>(
        &'a self,
        url: &'a Url,
    ) -> Pin<Box<dyn Future<Output = Result<Resolution, amber_resolver::Error>> + Send + 'a>> {
        let url = url.clone();
        let source = self.manifests.get(url.as_str()).cloned();

        Box::pin(async move {
            tokio::task::yield_now().await;
            let source = source.ok_or_else(|| {
                amber_resolver::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no test manifest for {url}"),
                ))
            })?;
            let spans = Arc::new(amber_manifest::ManifestSpans::parse(&source));
            let manifest: Manifest = source.parse().unwrap();
            Ok(Resolution {
                url,
                manifest,
                source,
                spans,
                bundle_source: None,
            })
        })
    }
}

fn manifest_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json5\r\nConnection: \
         close\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
}

fn spawn_redirecting_relative_manifest_server(
    root_manifest: String,
    child_manifest: String,
) -> (Url, Url, Url, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let requested_url = Url::parse(&format!("{base}/start")).unwrap();
    let canonical_root_url = Url::parse(&format!("{base}/nested/root.json5")).unwrap();
    let canonical_child_url = Url::parse(&format!("{base}/nested/child.json5")).unwrap();

    let server_root_url = canonical_root_url.clone();
    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);

        for _ in 0..3 {
            let mut stream = accept_with_deadline(&listener, deadline);
            let path = read_request_path(&mut stream);
            let response = match path.as_str() {
                "/start" => format!(
                    "HTTP/1.1 302 Found\r\nLocation: {server_root_url}\r\nConnection: \
                     close\r\nContent-Length: 0\r\n\r\n"
                ),
                "/nested/root.json5" => manifest_response(&root_manifest),
                "/nested/child.json5" => manifest_response(&child_manifest),
                _ => "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                    .to_string(),
            };
            stream.write_all(response.as_bytes()).unwrap();
            stream.shutdown(Shutdown::Both).unwrap();
        }
    });

    (
        requested_url,
        canonical_root_url,
        canonical_child_url,
        handle,
    )
}

#[tokio::test]
async fn compile_twice_unpinned_fails_when_sources_removed() {
    let dir = tmp_dir("scenario-compile");
    let root_path = dir.path().join("root.json5");
    let a_path = dir.path().join("a.json5");
    let b_path = dir.path().join("b.json5");

    write_file(
        &a_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "a",
            entrypoint: ["a"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
          exports: { api: "api" },
        }
        "#,
    );

    write_file(
        &b_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "b",
            entrypoint: ["b"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { llm: { kind: "llm", endpoint: "endpoint" } },
          exports: { llm: "llm" },
        }
        "#,
    );

    write_file(
        &root_path,
        &format!(
            r#"
            {{
              manifest_version: "0.1.0",
              components: {{
                a: "{a}",
                b: "{b}",
              }},
            }}
            "#,
            a = file_url(&a_path),
            b = file_url(&b_path),
        ),
    );

    let compiler = compiler_with_noop_governance();
    let root_ref = manifest_ref_for_path(&root_path);

    let compilation = compiler
        .compile(root_ref.clone(), standard_compile_options())
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 3);

    fs::remove_file(&root_path).unwrap();
    fs::remove_file(&a_path).unwrap();
    fs::remove_file(&b_path).unwrap();

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("io error"));
}

#[tokio::test]
async fn compile_twice_with_digest_pins_succeeds_when_sources_removed() {
    let dir = tmp_dir("scenario-compile-digest-pins");
    let root_path = dir.path().join("root.json5");
    let a_path = dir.path().join("a.json5");
    let b_path = dir.path().join("b.json5");

    let a_contents = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "a",
            entrypoint: ["a"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
          exports: { api: "api" },
        }
    "#;
    let b_contents = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "b",
            entrypoint: ["b"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { llm: { kind: "llm", endpoint: "endpoint" } },
          exports: { llm: "llm" },
        }
    "#;

    write_file(&a_path, a_contents);
    write_file(&b_path, b_contents);

    let digest_a = a_contents.parse::<Manifest>().unwrap().digest();
    let digest_b = b_contents.parse::<Manifest>().unwrap().digest();

    let root_contents = format!(
        r#"
        {{
          manifest_version: "0.1.0",
          components: {{
            a: {{ url: "{a}", digest: "{da}" }},
            b: {{ url: "{b}", digest: "{db}" }},
          }},
        }}
        "#,
        a = file_url(&a_path),
        b = file_url(&b_path),
        da = digest_a,
        db = digest_b
    );
    write_file(&root_path, &root_contents);

    let root_digest = root_contents.parse::<Manifest>().unwrap().digest();
    let root_ref = ManifestRef::new(file_url(&root_path), Some(root_digest));

    let compiler = compiler_with_noop_governance();

    let compilation = compiler
        .compile(root_ref.clone(), standard_compile_options())
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 3);

    fs::remove_file(&root_path).unwrap();
    fs::remove_file(&a_path).unwrap();
    fs::remove_file(&b_path).unwrap();

    let compilation2 = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert_eq!(compilation2.scenario.components.len(), 3);

    let order = graph::topo_order(&compilation2.scenario).unwrap();
    assert_eq!(order.len(), compilation2.scenario.components.len());
}

#[tokio::test]
async fn provenance_records_redirect_when_fetched() {
    let contents = r#"{ manifest_version: "0.1.0" }"#.to_string();
    let digest = contents.parse::<Manifest>().unwrap().digest();
    let (url, server) = spawn_redirecting_manifest_server(contents);

    let compiler = compiler_with_noop_governance();
    let root_ref = ManifestRef::new(url.clone(), Some(digest));

    let compilation = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    let root_id = compilation.scenario.root;
    let prov = &compilation.provenance.components[root_id.0];
    assert_eq!(prov.declared_ref.url.as_url(), Some(&url));
    assert_eq!(prov.declared_ref.digest, Some(digest));
    assert_eq!(prov.observed_url.as_ref().map(|u| u.path()), Some("/final"));

    server.join().unwrap();
}

#[tokio::test]
async fn relative_manifest_refs_resolve_against_parent() {
    let dir = tmp_dir("scenario-relative-manifest-ref");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(&child_path, r#"{ manifest_version: "0.1.0" }"#);
    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: "./child.json5"
          }
        }
        "#,
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let compilation = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 2);

    let root_id = compilation.scenario.root;
    let root = compilation.scenario.components[root_id.0]
        .as_ref()
        .expect("root component should exist");
    let child_id = root
        .children
        .iter()
        .copied()
        .find(|id| {
            compilation.scenario.components[id.0]
                .as_ref()
                .expect("child should exist")
                .moniker
                .local_name()
                == Some("child")
        })
        .expect("child component");
    let prov = &compilation.provenance.components[child_id.0];
    assert_eq!(prov.declared_ref.url.as_str(), "./child.json5");
}

#[tokio::test]
async fn relative_root_manifest_refs_require_base_url() {
    let compiler = default_compiler();
    let root_ref = "./root.json5".parse().unwrap();

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    let crate::Error::Frontend(crate::frontend::Error::RelativeManifestRef { reference }) = err
    else {
        panic!("expected relative manifest ref error");
    };
    assert_eq!(reference.as_ref(), "./root.json5");
}

#[tokio::test]
async fn relative_manifest_refs_resolve_against_remote_parent_url() {
    let root_url: Url = "test://example/nested/root.json5".parse().unwrap();
    let child_url: Url = "test://example/nested/child.json5".parse().unwrap();
    let root_source: Arc<str> = r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: "./child.json5"
          }
        }
        "#
    .into();
    let child_source: Arc<str> = r#"{ manifest_version: "0.1.0" }"#.into();
    let backend = Arc::new(MapBackend::new(BTreeMap::from([
        (root_url.to_string(), root_source),
        (child_url.to_string(), child_source),
    ])));
    let resolver = Resolver::new().with_remote(RemoteResolver::new(["test"], backend));
    let compiler = Compiler::new(resolver, DigestStore::default());

    let compilation = compiler
        .compile(ManifestRef::from_url(root_url), standard_compile_options())
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 2);

    let root_id = compilation.scenario.root;
    let root = compilation.scenario.components[root_id.0]
        .as_ref()
        .expect("root component should exist");
    let child_id = root.children[0];
    let prov = &compilation.provenance.components[child_id.0];
    assert_eq!(prov.declared_ref.url.as_str(), "./child.json5");
    assert_eq!(prov.resolved_url, child_url);
}

#[tokio::test]
async fn relative_manifest_refs_resolve_against_redirect_target_url() {
    let root_manifest = r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: "./child.json5"
          }
        }
    "#
    .to_string();
    let child_manifest = r#"{ manifest_version: "0.1.0" }"#.to_string();
    let (requested_url, canonical_root_url, canonical_child_url, server) =
        spawn_redirecting_relative_manifest_server(root_manifest, child_manifest);

    let compiler = default_compiler();
    let compilation = compiler
        .compile(
            ManifestRef::from_url(requested_url.clone()),
            standard_compile_options(),
        )
        .await
        .unwrap();

    let root_prov = &compilation.provenance.components[compilation.scenario.root.0];
    assert_eq!(root_prov.resolved_url, requested_url);
    assert_eq!(root_prov.observed_url.as_ref(), Some(&canonical_root_url));

    let root = compilation.scenario.components[compilation.scenario.root.0]
        .as_ref()
        .expect("root component should exist");
    let child_id = root.children[0];
    let child_prov = &compilation.provenance.components[child_id.0];
    assert_eq!(child_prov.declared_ref.url.as_str(), "./child.json5");
    assert_eq!(child_prov.resolved_url, canonical_child_url);

    server.join().unwrap();
}

#[tokio::test]
async fn cached_redirected_manifest_keeps_canonical_base_for_relative_children() {
    let child_manifest = r#"{ manifest_version: "0.1.0" }"#.to_string();
    let child_digest = child_manifest.parse::<Manifest>().unwrap().digest();
    let root_manifest = format!(
        r#"
        {{
          manifest_version: "0.1.0",
          components: {{
            child: {{ url: "./child.json5", digest: "{child_digest}" }}
          }}
        }}
    "#
    );
    let root_digest = root_manifest.parse::<Manifest>().unwrap().digest();
    let (requested_url, canonical_root_url, canonical_child_url, server) =
        spawn_redirecting_relative_manifest_server(root_manifest, child_manifest);

    let compiler = default_compiler();
    let root_ref = ManifestRef::new(requested_url.clone(), Some(root_digest));

    let first = compiler
        .compile(root_ref.clone(), standard_compile_options())
        .await
        .unwrap();
    let first_root = &first.provenance.components[first.scenario.root.0];
    assert_eq!(first_root.observed_url.as_ref(), Some(&canonical_root_url));
    let first_child = first.scenario.components[first.scenario.root.0]
        .as_ref()
        .expect("root component should exist")
        .children[0];
    assert_eq!(
        first.provenance.components[first_child.0].resolved_url,
        canonical_child_url
    );

    server.join().unwrap();

    let second = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();
    let second_root = &second.provenance.components[second.scenario.root.0];
    assert_eq!(second_root.resolved_url, requested_url);
    assert_eq!(second_root.observed_url.as_ref(), Some(&canonical_root_url));
    let second_child = second.scenario.components[second.scenario.root.0]
        .as_ref()
        .expect("root component should exist")
        .children[0];
    assert_eq!(
        second.provenance.components[second_child.0].resolved_url,
        canonical_child_url
    );
}

#[tokio::test]
async fn relative_child_template_manifest_refs_resolve_against_remote_parent_url() {
    let root_url: Url = "test://example/jobs/root.json5".parse().unwrap();
    let alpha_url: Url = "test://example/jobs/alpha.json5".parse().unwrap();
    let beta_url: Url = "test://example/jobs/nested/beta.json5".parse().unwrap();
    let root_source: Arc<str> = r#"
        {
          manifest_version: "0.1.0",
          slots: {
            realm: { kind: "component", optional: true },
          },
          child_templates: {
            worker: {
              manifest: ["./alpha.json5", "./nested/beta.json5"],
              bindings: {
                realm: "slots.realm",
              },
            },
          },
        }
    "#
    .into();
    let manifest_source: Arc<str> = r#"{ manifest_version: "0.1.0" }"#.into();
    let backend = Arc::new(MapBackend::new(BTreeMap::from([
        (root_url.to_string(), root_source),
        (alpha_url.to_string(), Arc::clone(&manifest_source)),
        (beta_url.to_string(), manifest_source),
    ])));
    let resolver = Resolver::new().with_remote(RemoteResolver::new(["test"], backend));
    let compiler = Compiler::new(resolver, DigestStore::default());

    let compilation = compiler
        .compile(ManifestRef::from_url(root_url), standard_compile_options())
        .await
        .unwrap();

    let root = compilation.scenario.component(compilation.scenario.root);
    let template = root
        .child_templates
        .get("worker")
        .expect("child template should exist");
    let manifests = template
        .manifests
        .as_ref()
        .expect("bounded template should carry frozen manifest keys");

    assert_eq!(
        manifests,
        &vec![alpha_url.to_string(), beta_url.to_string()]
    );
}

#[tokio::test]
async fn missing_child_manifest_error_points_to_component_manifest_ref() {
    let dir = tmp_dir("missing-child-manifest");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.2.0",
          components: {
            foo: "./does-not-exist.json",
          },
        }
        "#,
    );

    let compiler = default_compiler();
    let err = compiler
        .check(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap_err();

    let crate::Error::Frontend(crate::frontend::Error::ManifestRefResolution {
        child,
        reference,
        ..
    }) = err
    else {
        panic!("expected contextual child manifest resolution error");
    };
    assert_eq!(child.as_ref(), "foo");
    assert_eq!(reference.as_ref(), "./does-not-exist.json");
}

#[tokio::test]
async fn cycle_is_detected_across_url_aliases_with_same_digest() {
    let (url, server) = spawn_alias_cycle_manifest_server();

    let compiler = default_compiler();
    let root_ref = ManifestRef::from_url(url);

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("cycle"));

    server.join().unwrap();
}

#[tokio::test]
async fn delegated_export_requires_child_export() {
    let dir = tmp_dir("scenario-delegated-export-missing");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(&child_path, r#"{ manifest_version: "0.1.0" }"#);
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{
                child: "{child}",
              }},
              exports: {{ api: "#child.api" }},
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(error_contains(&err, "target references non-exported `api`"));
    assert!(error_contains(&err, "root component"));
}

#[tokio::test]
async fn binding_rejects_missing_child_slot() {
    let dir = tmp_dir("scenario-missing-child-slot");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "child",
            entrypoint: ["child"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
          exports: { api: "api" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{
                child: "{child}",
              }},
              program: {{
                image: "root",
                entrypoint: ["root"],
                network: {{ endpoints: [{{ name: "endpoint", port: 80 }}] }},
              }},
              provides: {{ api: {{ kind: "http", endpoint: "endpoint" }} }},
              bindings: [
                {{ to: "#child.missing", from: "provides.api" }},
              ],
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(error_contains(
        &err,
        "unknown slot `missing` on component /child"
    ));
}

#[tokio::test]
async fn binding_rejects_duplicate_target_for_singular_child_slot() {
    let dir = tmp_dir("scenario-duplicate-singular-binding");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    let provider_a_path = dir.path().join("provider-a.json5");
    let provider_b_path = dir.path().join("provider-b.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "child",
            entrypoint: ["child"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          slots: { api: { kind: "http" } },
        }
        "#,
    );
    for provider_path in [&provider_a_path, &provider_b_path] {
        write_file(
            provider_path,
            r#"
            {
              manifest_version: "0.1.0",
              program: {
                image: "provider",
                entrypoint: ["provider"],
                network: { endpoints: [{ name: "api", port: 80 }] },
              },
              provides: { api: { kind: "http", endpoint: "api" } },
              exports: { api: "api" },
            }
            "#,
        );
    }
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{
                child: "{child}",
                provider_a: "{provider_a}",
                provider_b: "{provider_b}",
              }},
              bindings: [
                {{ to: "#child.api", from: "#provider_a.api" }},
                {{ to: "#child.api", from: "#provider_b.api" }},
              ],
            }}
            "##,
            child = file_url(&child_path),
            provider_a = file_url(&provider_a_path),
            provider_b = file_url(&provider_b_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(error_contains(&err, "bound more than once"));
}

#[tokio::test]
async fn resolve_tree_keeps_use_entries_out_of_component_tree() {
    let dir = tmp_dir("scenario-use-resolution");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    let wrapper_path = dir.path().join("wrapper.json5");

    write_file(&child_path, r#"{ manifest_version: "0.1.0" }"#);
    write_file(
        &wrapper_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "wrapper",
            entrypoint: ["wrapper"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { rewrite: { kind: "http", profile: "policy", endpoint: "api" } },
          exports: { rewrite: "rewrite" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
              components: {{
                child: "{child}",
              }},
            }}
            "##,
            wrapper = file_url(&wrapper_path),
            child = file_url(&child_path),
        ),
    );

    let compiler = compiler_with_noop_governance();
    let tree = compiler
        .resolve_tree(
            manifest_ref_for_path(&root_path),
            standard_compile_options().resolve,
        )
        .await
        .unwrap();

    assert!(tree.root.children.contains_key("child"));
    assert!(tree.root.uses.contains_key("wrapper"));

    let output = compiler
        .compile_from_tree(tree, standard_compile_options().optimize)
        .await
        .unwrap();
    assert_eq!(output.scenario.components.len(), 2);
}

#[tokio::test]
async fn use_config_with_config_interpolation_compiles() {
    let dir = tmp_dir("scenario-use-config-interp");
    let root_path = dir.path().join("root.json5");
    let policy_path = dir.path().join("policy.json5");

    write_file(
        &policy_path,
        r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: { token: { type: "string" } },
          },
          program: {
            image: "policy",
            entrypoint: ["policy"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { apply: { kind: "http", profile: "policy", endpoint: "api" } },
          exports: { apply: "apply" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              config_schema: {{
                type: "object",
                properties: {{ api_key: {{ type: "string" }} }},
              }},
              use: {{
                policy_comp: {{
                  manifest: "{policy}",
                  config: {{ token: "${{config.api_key}}" }},
                }},
              }},
              policies: ["#policy_comp.apply"],
            }}
            "##,
            policy = file_url(&policy_path),
        ),
    );

    let compiler = compiler_with_noop_governance();
    let output = compiler
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect("use config with config interpolation should compile");

    let governance = output
        .governance
        .as_ref()
        .expect("governance should be present");
    let root_id = governance.scenario.root;
    let root_digest = governance.scenario.component(root_id).digest;
    let root_manifest = output
        .store
        .get(&root_digest)
        .expect("governance root manifest in store");
    let config_schema = root_manifest
        .config_schema()
        .expect("governance root should have config schema");
    // The governance root schema should expose the api_key path from the outer scenario
    let schema_value = &config_schema.0;
    let props = schema_value
        .get("properties")
        .expect("schema should have properties");
    assert!(
        props.get("api_key").is_some(),
        "api_key should appear in governance root schema properties"
    );
}

#[tokio::test]
async fn use_config_with_config_interpolation_in_child_scope_compiles() {
    let dir = tmp_dir("scenario-use-config-interp-child");
    let root_path = dir.path().join("root.json5");
    let scope_path = dir.path().join("scope.json5");
    let policy_path = dir.path().join("policy.json5");

    write_file(
        &policy_path,
        r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: { token: { type: "string" } },
          },
          program: {
            image: "policy",
            entrypoint: ["policy"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { apply: { kind: "http", profile: "policy", endpoint: "api" } },
          exports: { apply: "apply" },
        }
        "#,
    );
    write_file(
        &scope_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              config_schema: {{
                type: "object",
                properties: {{ api_key: {{ type: "string" }} }},
              }},
              use: {{
                policy_comp: {{
                  manifest: "{policy}",
                  config: {{ token: "${{config.api_key}}" }},
                }},
              }},
              policies: ["#policy_comp.apply"],
            }}
            "##,
            policy = file_url(&policy_path),
        ),
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              config_schema: {{
                type: "object",
                properties: {{ root_api_key: {{ type: "string" }} }},
              }},
              components: {{
                scope: {{
                  manifest: "{scope}",
                  config: {{ api_key: "${{config.root_api_key}}" }},
                }},
              }},
            }}
            "##,
            scope = file_url(&scope_path),
        ),
    );

    let compiler = compiler_with_noop_governance();
    let output = compiler
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect("use config interpolation through child scope template should compile");

    let governance = output
        .governance
        .as_ref()
        .expect("governance should be present");
    let root_id = governance.scenario.root;
    let root_digest = governance.scenario.component(root_id).digest;
    let root_manifest = output
        .store
        .get(&root_digest)
        .expect("governance root manifest in store");
    let config_schema = root_manifest
        .config_schema()
        .expect("governance root should have config schema");
    // The child scope's api_key config is threaded through the outer root_api_key config ref,
    // so the governance root schema should expose root_api_key (not api_key).
    let schema_value = &config_schema.0;
    let props = schema_value
        .get("properties")
        .expect("schema should have properties");
    assert!(
        props.get("root_api_key").is_some(),
        "root_api_key should appear in governance root schema properties"
    );
    assert!(
        props.get("api_key").is_none(),
        "api_key is scoped to the child and should not appear directly in governance root schema"
    );
}

#[tokio::test]
async fn policy_symbolic_config_is_composed_against_scope_config() {
    let dir = tmp_dir("scenario-policy-symbolic-config-compose");
    let root_path = dir.path().join("root.json5");
    let scope_path = dir.path().join("scope.json5");
    let policy_path = dir.path().join("policy.json5");

    write_file(
        &policy_path,
        r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: { redaction_term: { type: "string" } },
            required: ["redaction_term"],
          },
          program: {
            image: "policy",
            entrypoint: ["policy"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { apply: { kind: "http", profile: "policy", endpoint: "api" } },
          exports: { apply: "apply" },
        }
        "#,
    );
    write_file(
        &scope_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              config_schema: {{
                type: "object",
                properties: {{ hidden_secret: {{ type: "string" }} }},
              }},
              use: {{
                policy_comp: {{
                  manifest: "{policy}",
                  config: {{ redaction_term: "$${{config.hidden_secret}}" }},
                }},
              }},
              policies: ["#policy_comp.apply"],
            }}
            "##,
            policy = file_url(&policy_path),
        ),
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              config_schema: {{
                type: "object",
                properties: {{ root_secret: {{ type: "string" }} }},
              }},
              components: {{
                scope: {{
                  manifest: "{scope}",
                  config: {{ hidden_secret: "${{config.root_secret}}" }},
                }},
              }},
            }}
            "##,
            scope = file_url(&scope_path),
        ),
    );

    let compiler = compiler_with_noop_governance();
    let output = compiler
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect("policy symbolic config composition should compile");

    let governance = output
        .governance
        .as_ref()
        .expect("governance should be present");
    let root_id = governance.scenario.root;
    let root_digest = governance.scenario.component(root_id).digest;
    let root_manifest = output
        .store
        .get(&root_digest)
        .expect("governance root manifest in store");
    let policy_component = root_manifest
        .components()
        .get("use_0_0")
        .expect("policy component should be present in governance root");
    let amber_manifest::ComponentDecl::Object(policy_component) = policy_component else {
        panic!("policy component should be in object form");
    };
    assert_eq!(
        policy_component.config.as_ref(),
        Some(&serde_json::json!({
            "redaction_term": {
                "$symbolic_config": "root_secret",
            },
        }))
    );
}

#[tokio::test]
async fn used_manifest_must_not_require_root_slots() {
    let dir = tmp_dir("scenario-use-required-slot");
    let root_path = dir.path().join("root.json5");
    let wrapper_path = dir.path().join("wrapper.json5");

    write_file(
        &wrapper_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { upstream: { kind: "http" } },
          program: {
            image: "wrapper",
            entrypoint: ["wrapper"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { rewrite: { kind: "http", profile: "policy", endpoint: "api" } },
          exports: { rewrite: "rewrite" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
            }}
            "##,
            wrapper = file_url(&wrapper_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap_err();

    match err {
        crate::Error::Frontend(crate::frontend::Error::UseRequiresRootSlots {
            name,
            slots,
            ..
        }) => {
            assert_eq!(name.as_ref(), "wrapper");
            assert_eq!(slots.as_ref(), "upstream");
        }
        other => panic!("expected UseRequiresRootSlots error, got: {other}"),
    }
}

#[tokio::test]
async fn compile_resolves_policy_exports_from_use_entries() {
    let dir = tmp_dir("scenario-policy-resolve");
    let root_path = dir.path().join("root.json5");
    let wrapper_path = dir.path().join("wrapper.json5");

    write_file(
        &wrapper_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "wrapper",
            entrypoint: ["wrapper"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { rewrite: { kind: "http", profile: "policy", endpoint: "api" } },
          exports: { rewrite: "rewrite" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
            }}
            "##,
            wrapper = file_url(&wrapper_path),
        ),
    );

    let output = compiler_with_noop_governance()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap();

    let governance = output.governance.expect("governance should exist");
    assert_eq!(governance.scopes.len(), 1);
    assert_eq!(
        governance.scopes[0].policies[0].export.as_str(),
        "policy_0_0"
    );
    assert_eq!(governance.scenario.exports.len(), 1);
    assert_eq!(
        governance.scenario.exports[0].capability.kind,
        amber_manifest::CapabilityKind::Http
    );
    assert_eq!(
        governance.scenario.exports[0].capability.profile.as_deref(),
        Some("policy")
    );
}

#[tokio::test]
async fn compile_follows_child_exports_for_policies() {
    let dir = tmp_dir("scenario-policy-child-export");
    let root_path = dir.path().join("root.json5");
    let wrapper_path = dir.path().join("wrapper.json5");
    let leaf_path = dir.path().join("leaf.json5");

    write_file(
        &leaf_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "leaf",
            entrypoint: ["leaf"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { rewrite: { kind: "http", profile: "policy", endpoint: "api" } },
          exports: { rewrite: "rewrite" },
        }
        "#,
    );
    write_file(
        &wrapper_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{
                leaf: "{leaf}",
              }},
              exports: {{ rewrite: "#leaf.rewrite" }},
            }}
            "##,
            leaf = file_url(&leaf_path),
        ),
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
            }}
            "##,
            wrapper = file_url(&wrapper_path),
        ),
    );

    let output = compiler_with_noop_governance()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap();

    let governance = output.governance.expect("governance should exist");
    assert_eq!(
        governance.scopes[0].policies[0].export.as_str(),
        "policy_0_0"
    );
    assert_eq!(governance.scenario.exports.len(), 1);
    assert_eq!(
        governance.scenario.exports[0].capability.kind,
        amber_manifest::CapabilityKind::Http
    );
    assert_eq!(
        governance.scenario.exports[0].capability.profile.as_deref(),
        Some("policy")
    );
}

#[tokio::test]
async fn policy_ref_requires_resolvable_export() {
    let dir = tmp_dir("scenario-policy-missing-export");
    let root_path = dir.path().join("root.json5");
    let wrapper_path = dir.path().join("wrapper.json5");

    write_file(&wrapper_path, r#"{ manifest_version: "0.1.0" }"#);
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
            }}
            "##,
            wrapper = file_url(&wrapper_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap_err();

    match err {
        crate::Error::Linker(crate::linker::Error::PolicyExportUnresolved {
            policy,
            use_name,
            export,
            ..
        }) => {
            assert_eq!(policy.as_ref(), "#wrapper.rewrite");
            assert_eq!(use_name.as_ref(), "wrapper");
            assert_eq!(export.as_ref(), "rewrite");
        }
        other => panic!("expected PolicyExportUnresolved error, got: {other}"),
    }
}

#[tokio::test]
async fn policy_ref_requires_http_policy_provide() {
    let dir = tmp_dir("scenario-policy-invalid-capability");
    let root_path = dir.path().join("root.json5");
    let wrapper_path = dir.path().join("wrapper.json5");

    write_file(
        &wrapper_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "wrapper",
            entrypoint: ["wrapper"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { rewrite: { kind: "http", endpoint: "api" } },
          exports: { rewrite: "rewrite" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
            }}
            "##,
            wrapper = file_url(&wrapper_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap_err();

    match err {
        crate::Error::Linker(crate::linker::Error::InvalidPolicyExport {
            policy, message, ..
        }) => {
            assert_eq!(policy.as_ref(), "#wrapper.rewrite");
            assert_eq!(
                message.as_ref(),
                "must resolve to an `http` provide with profile `policy`, got `http`"
            );
        }
        other => panic!("expected InvalidPolicyExport error, got: {other}"),
    }
}

#[tokio::test]
async fn policy_ref_rejects_slot_exports() {
    let dir = tmp_dir("scenario-policy-slot-export");
    let root_path = dir.path().join("root.json5");
    let wrapper_path = dir.path().join("wrapper.json5");

    write_file(
        &wrapper_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { rewrite: { kind: "http", profile: "policy", optional: true } },
          exports: { rewrite: "rewrite" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
            }}
            "##,
            wrapper = file_url(&wrapper_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap_err();

    match err {
        crate::Error::Linker(crate::linker::Error::InvalidPolicyExport {
            policy, message, ..
        }) => {
            assert_eq!(policy.as_ref(), "#wrapper.rewrite");
            assert_eq!(message.as_ref(), "must resolve to a provide, not a slot");
        }
        other => panic!("expected InvalidPolicyExport error, got: {other}"),
    }
}

#[tokio::test]
async fn compile_attaches_governance_artifact_for_policy_uses() {
    let dir = tmp_dir("compile-governance-artifact");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    let wrapper_path = dir.path().join("wrapper.json5");

    write_file(&child_path, r#"{ manifest_version: "0.1.0" }"#);
    write_file(
        &wrapper_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "wrapper",
            entrypoint: ["wrapper"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { rewrite: { kind: "http", profile: "policy", endpoint: "api" } },
          exports: { rewrite: "rewrite" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
              components: {{
                child: "{child}",
              }},
            }}
            "##,
            wrapper = file_url(&wrapper_path),
            child = file_url(&child_path),
        ),
    );

    let output = compiler_with_noop_governance()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap();

    let governance = output
        .governance
        .as_ref()
        .expect("governance artifact should be attached");
    assert_eq!(governance.scopes.len(), 1);
    assert_eq!(governance.scopes[0].root_moniker.as_str(), "/");
    assert_eq!(governance.scopes[0].policies.len(), 1);
    assert_eq!(
        governance.scopes[0].policies[0].export.as_str(),
        "policy_0_0"
    );
    assert_eq!(governance.scenario.exports[0].name, "policy_0_0");
    assert_eq!(governance.scenario.components.iter().flatten().count(), 2);
}

#[tokio::test]
async fn used_manifest_rejects_nested_governance() {
    let dir = tmp_dir("scenario-use-nested-governance");
    let root_path = dir.path().join("root.json5");
    let wrapper_path = dir.path().join("wrapper.json5");
    let nested_path = dir.path().join("nested.json5");

    write_file(&nested_path, r#"{ manifest_version: "0.1.0" }"#);
    write_file(
        &wrapper_path,
        &format!(
            r#"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              use: {{
                nested: "{nested}",
              }},
              program: {{
                image: "wrapper",
                entrypoint: ["wrapper"],
                network: {{ endpoints: [{{ name: "api", port: 80 }}] }},
              }},
              provides: {{ rewrite: {{ kind: "http", profile: "policy", endpoint: "api" }} }},
              exports: {{ rewrite: "rewrite" }},
            }}
            "#,
            nested = file_url(&nested_path),
        ),
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["governance"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
            }}
            "##,
            wrapper = file_url(&wrapper_path),
        ),
    );

    let err = default_compiler()
        .resolve_tree(
            manifest_ref_for_path(&root_path),
            standard_compile_options().resolve,
        )
        .await
        .unwrap_err();

    match err {
        crate::Error::Frontend(crate::frontend::Error::UseContainsGovernance {
            name,
            message,
            ..
        }) => {
            assert_eq!(name.as_ref(), "wrapper");
            assert_eq!(message.as_ref(), "nested `use` is not supported");
        }
        other => panic!("expected UseContainsGovernance error, got: {other}"),
    }
}
