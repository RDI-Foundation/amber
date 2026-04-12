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

    let compiler = default_compiler();
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

    let compiler = default_compiler();

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

    let compiler = default_compiler();
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
