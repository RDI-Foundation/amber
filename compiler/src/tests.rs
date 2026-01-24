use std::{
    collections::{BTreeMap, HashSet},
    fs,
    future::Future,
    io::{Read as _, Write as _},
    net::{Shutdown, TcpListener},
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use amber_manifest::{Manifest, ManifestRef};
use amber_resolver::{Backend, RemoteResolver, Resolution, Resolver};
use amber_scenario::{BindingFrom, graph};
use base64::Engine as _;
use miette::Severity;
use tempfile::TempDir;
use url::Url;

use crate::{
    CompileOptions, Compiler, DigestStore, OptimizeOptions, ResolvedNode, ResolvedTree,
    ResolverRegistry,
    bundle::{
        BUNDLE_INDEX_NAME, BUNDLE_SCHEMA, BUNDLE_VERSION, BundleBuilder, BundleIndex, BundleLoader,
        BundleRequest,
    },
    reporter::{Reporter as _, scenario_ir::ScenarioIrReporter},
};

fn error_contains(err: &crate::Error, needle: &str) -> bool {
    match err {
        crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) => {
            errors.iter().any(|err| err.to_string().contains(needle))
        }
        crate::Error::Linker(err) => err.to_string().contains(needle),
        other => other.to_string().contains(needle),
    }
}

fn tmp_dir(prefix: &str) -> TempDir {
    tempfile::Builder::new().prefix(prefix).tempdir().unwrap()
}

fn write_file(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
}

fn file_url(path: &Path) -> Url {
    Url::from_file_path(path).unwrap()
}

fn accept_with_deadline(listener: &TcpListener, deadline: Instant) -> std::net::TcpStream {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    panic!("timed out waiting for client connection");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => panic!("accept failed: {err}"),
        }
    }
}

fn read_request_path(stream: &mut std::net::TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).unwrap();
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }

    let text = std::str::from_utf8(&buf).unwrap();
    let first_line = text.lines().next().unwrap();
    let mut parts = first_line.split_whitespace();
    let _method = parts.next().unwrap();
    parts.next().unwrap().to_string()
}

fn spawn_redirecting_manifest_server(manifest_body: String) -> (Url, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let start_url = Url::parse(&format!("{base}/start")).unwrap();

    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = accept_with_deadline(&listener, deadline);
        let path = read_request_path(&mut stream);
        assert_eq!(path, "/start");

        let location = format!("{base}/final");
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nConnection: close\r\nContent-Length: \
             0\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.shutdown(Shutdown::Both).unwrap();

        let mut stream = accept_with_deadline(&listener, deadline);
        let path = read_request_path(&mut stream);
        assert_eq!(path, "/final");

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: \
             close\r\nContent-Length: {}\r\n\r\n{}",
            manifest_body.len(),
            manifest_body
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.shutdown(Shutdown::Both).unwrap();
    });

    (start_url, handle)
}

fn spawn_alias_cycle_manifest_server() -> (Url, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let start_url = Url::parse(&format!("{base}/a")).unwrap();

    let a_manifest = format!(
        r#"
        {{
          manifest_version: "0.1.0",
          components: {{
            b: "{base}/b",
          }},
        }}
        "#
    );

    let b_manifest = format!(
        r#"
        {{
          manifest_version: "0.1.0",
          components: {{
            a: "{base}/a_alias",
          }},
        }}
        "#
    );

    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut seen: HashSet<String> = HashSet::new();

        for _ in 0..5 {
            let mut stream = accept_with_deadline(&listener, deadline);
            let path = read_request_path(&mut stream);

            let (status, body) = match path.as_str() {
                "/a" | "/a_alias" => ("200 OK", a_manifest.clone()),
                "/b" => ("200 OK", b_manifest.clone()),
                _ => ("404 Not Found", String::new()),
            };

            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: \
                 close\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.shutdown(Shutdown::Both).unwrap();

            seen.insert(path);
            if seen.contains("/a") && seen.contains("/b") && seen.contains("/a_alias") {
                break;
            }
        }
    });

    (start_url, handle)
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

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let compilation = compiler
        .compile(
            root_ref.clone(),
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 3);

    fs::remove_file(&root_path).unwrap();
    fs::remove_file(&a_path).unwrap();
    fs::remove_file(&b_path).unwrap();

    let err = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
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

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());

    let compilation = compiler
        .compile(
            root_ref.clone(),
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 3);

    fs::remove_file(&root_path).unwrap();
    fs::remove_file(&a_path).unwrap();
    fs::remove_file(&b_path).unwrap();

    let compilation2 = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
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

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let root_ref = ManifestRef::new(url.clone(), Some(digest));

    let compilation = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
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

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let compilation = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
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
async fn relative_manifest_refs_require_file_base() {
    let source: Arc<str> = r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: "./child.json5"
          }
        }
        "#
    .into();
    let backend = Arc::new(StaticBackend::new(Arc::clone(&source)));
    let resolver = Resolver::new().with_remote(RemoteResolver::new(["test"], backend));
    let compiler = Compiler::new(resolver, DigestStore::default());
    let root_ref = ManifestRef::from_url("test://root".parse().unwrap());

    let err = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
        .await
        .unwrap_err();

    let crate::Error::Frontend(crate::frontend::Error::RelativeManifestRef { .. }) = err else {
        panic!("expected relative manifest ref error");
    };
}

#[tokio::test]
async fn cycle_is_detected_across_url_aliases_with_same_digest() {
    let (url, server) = spawn_alias_cycle_manifest_server();

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let root_ref = ManifestRef::from_url(url);

    let err = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
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

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let err = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
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
                {{ to: "#child.missing", from: "self.api" }},
              ],
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let err = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
        .await
        .unwrap_err();

    assert!(error_contains(
        &err,
        "unknown slot `missing` on component /child"
    ));
}

#[tokio::test]
async fn config_validation_error_points_to_invalid_value() {
    use miette::Diagnostic;

    let dir = tmp_dir("scenario-invalid-config-span");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              nested: {
                type: "object",
                properties: { x: { type: "number" } },
                required: ["x"],
              },
            },
            required: ["nested"],
          },
        }
        "#,
    );

    let root_source = format!(
        r##"
        {{
          manifest_version: "0.1.0",
          components: {{
            child: {{
              manifest: "{child}",
              config: {{ nested: {{ x: "bad" }} }},
            }},
          }},
        }}
        "##,
        child = file_url(&child_path),
    );
    write_file(&root_path, &root_source);

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));
    let output = compiler
        .check(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
        .await
        .unwrap();

    assert!(output.has_errors);

    let report = output
        .diagnostics
        .iter()
        .find(|report| {
            let diag: &dyn Diagnostic = &***report;
            diag.code()
                .is_some_and(|c| c.to_string() == "linker::invalid_config")
        })
        .expect("expected linker::invalid_config diagnostic");
    let diag: &dyn Diagnostic = &**report;
    let labels: Vec<_> = diag
        .labels()
        .expect("invalid_config should include a label")
        .collect();
    assert_eq!(labels.len(), 1);

    let label = &labels[0];
    let offset = root_source.find("\"bad\"").unwrap();
    assert_eq!(label.offset(), offset);
    assert_eq!(label.len(), "\"bad\"".len());
}

#[tokio::test]
async fn binding_interpolation_error_points_to_config_value() {
    use miette::Diagnostic;

    let dir = tmp_dir("scenario-binding-config-span");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              url: { type: "string" },
            },
            required: ["url"],
            additionalProperties: false,
          },
        }
        "#,
    );

    let root_source = format!(
        r##"
        {{
          manifest_version: "0.1.0",
          components: {{
            child: {{
              manifest: "{child}",
              config: {{ url: "${{bindings.missing.url}}" }},
            }},
          }},
        }}
        "##,
        child = file_url(&child_path),
    );
    write_file(&root_path, &root_source);

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));
    let output = compiler
        .check(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
        .await
        .unwrap();

    let report = output
        .diagnostics
        .iter()
        .find(|report| {
            let diag: &dyn Diagnostic = &***report;
            diag.code()
                .is_some_and(|c| c.to_string() == "compiler::invalid_bindings_interpolation")
        })
        .expect("expected invalid_bindings_interpolation diagnostic");
    let diag: &dyn Diagnostic = &**report;
    let labels: Vec<_> = diag
        .labels()
        .expect("binding interpolation diagnostic should include a label")
        .collect();
    assert_eq!(labels.len(), 1);

    let label = &labels[0];
    let needle = "\"${bindings.missing.url}\"";
    let offset = root_source.find(needle).unwrap();
    assert_eq!(label.offset(), offset);
    assert_eq!(label.len(), needle.len());
}

#[tokio::test]
async fn duplicate_slot_bindings_across_manifests_error() {
    let dir = tmp_dir("scenario-duplicate-slot-binding");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    let provider_path = dir.path().join("provider.json5");

    write_file(
        &provider_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "provider",
            entrypoint: ["provider"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { http: { kind: "http", endpoint: "endpoint" } },
          exports: { http: "http" },
        }
        "#,
    );
    write_file(
        &child_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{
                provider: "{provider}",
              }},
              slots: {{ api: {{ kind: "http" }} }},
              bindings: [
                {{ to: "self.api", from: "#provider.http" }},
              ],
            }}
            "##,
            provider = file_url(&provider_path),
        ),
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
                {{ to: "#child.api", from: "self.api" }},
              ],
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let err = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
        .await
        .unwrap_err();

    assert!(error_contains(&err, "bound more than once"));
}

#[tokio::test]
async fn type_mismatch_reports_expected_and_got() {
    let dir = tmp_dir("scenario-type-mismatch-message");
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
          provides: { http: { kind: "http", endpoint: "endpoint" } },
          exports: { http: "http" },
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
              slots: {{ llm: {{ kind: "llm" }} }},
              bindings: [
                {{ to: "self.llm", from: "#child.http" }},
              ],
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let err = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
        .await
        .unwrap_err();

    assert!(error_contains(&err, "expected llm, got http"));
    assert!(!err.to_string().contains("CapabilityDecl"));
}

#[tokio::test]
async fn delegated_export_chain_resolves_binding_source() {
    let dir = tmp_dir("scenario-delegated-export-chain");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    let grand_path = dir.path().join("grand.json5");

    write_file(
        &grand_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "grand",
            entrypoint: ["grand"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
          exports: { api: "api" },
        }
        "#,
    );
    write_file(
        &child_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{
                grand: "{grand}",
              }},
              exports: {{ api: "#grand.api" }},
            }}
            "##,
            grand = file_url(&grand_path),
        ),
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
              slots: {{ api: {{ kind: "http" }} }},
              bindings: [
                {{ to: "self.api", from: "#child.api" }},
              ],
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let compilation = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
        .await
        .unwrap();

    let binding = compilation.scenario.bindings.first().expect("binding");
    let from = match &binding.from {
        BindingFrom::Component(from) => from,
        BindingFrom::Framework(name) => {
            panic!("unexpected framework binding framework.{name}")
        }
    };
    let from_path = graph::component_path_for(&compilation.scenario.components, from.component);
    assert_eq!(from_path, "/child/grand");
    assert_eq!(from.name, "api");
}

struct CountingBackend {
    calls: AtomicUsize,
}

impl CountingBackend {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

struct StaticBackend {
    source: Arc<str>,
}

impl StaticBackend {
    fn new(source: Arc<str>) -> Self {
        Self { source }
    }
}

impl Backend for StaticBackend {
    fn resolve_url<'a>(
        &'a self,
        url: &'a Url,
    ) -> Pin<Box<dyn Future<Output = Result<Resolution, amber_resolver::Error>> + Send + 'a>> {
        let url = url.clone();
        let source = Arc::clone(&self.source);

        Box::pin(async move {
            tokio::task::yield_now().await;
            let spans = Arc::new(amber_manifest::ManifestSpans::parse(&source));
            let manifest: Manifest = source.parse().unwrap();
            Ok(Resolution {
                url,
                manifest,
                source,
                spans,
            })
        })
    }
}

impl Backend for CountingBackend {
    fn resolve_url<'a>(
        &'a self,
        url: &'a Url,
    ) -> Pin<Box<dyn Future<Output = Result<Resolution, amber_resolver::Error>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let url = url.clone();

        Box::pin(async move {
            tokio::task::yield_now().await;
            let source: Arc<str> = r#"{ manifest_version: "0.1.0" }"#.into();
            let spans = Arc::new(amber_manifest::ManifestSpans::parse(&source));
            let manifest: Manifest = source.parse().unwrap();
            Ok(Resolution {
                url,
                manifest,
                source,
                spans,
            })
        })
    }
}

#[tokio::test]
async fn resolution_deduplicates_inflight_requests() {
    let dir = tmp_dir("scenario-inflight-dedup");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          components: {
            a: "count://same",
            b: "count://same",
          }
        }
        "#,
    );

    let backend = Arc::new(CountingBackend::new());
    let resolver = Resolver::new().with_remote(RemoteResolver::new(["count"], backend.clone()));

    let compiler = Compiler::new(resolver, DigestStore::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let compilation = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 3);
    assert_eq!(backend.call_count(), 1);
}

#[tokio::test]
async fn resolution_environments_allow_parent_to_enable_resolvers_for_children() {
    let dir = tmp_dir("scenario-envs");
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
            a: { manifest: "count://same", environment: "counting" },
            b: { manifest: "count://same", environment: "counting" },
          }
        }
        "#,
    );

    let backend = Arc::new(CountingBackend::new());
    let base_resolver = Resolver::new();

    let mut registry = ResolverRegistry::new();
    registry.insert("count", RemoteResolver::new(["count"], backend.clone()));

    let compiler = Compiler::new(base_resolver, DigestStore::default()).with_registry(registry);
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let compilation = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 3);
    assert_eq!(backend.call_count(), 1);
}

#[tokio::test]
async fn compile_emits_manifest_lints() {
    let dir = tmp_dir("scenario-manifest-lints");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "root",
            entrypoint: ["root"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
        }
        "#,
    );

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let output = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        )
        .await
        .unwrap();

    assert_eq!(output.diagnostics.len(), 2);
    let diagnostics: Vec<_> = output.diagnostics.iter().collect();
    assert!(
        diagnostics
            .iter()
            .all(|diag| diag.severity() == Some(Severity::Warning))
    );
    let codes: Vec<_> = diagnostics
        .iter()
        .filter_map(|diag| diag.code().map(|code| code.to_string()))
        .collect();
    assert!(codes.contains(&"manifest::unused_program".to_string()));
    assert!(codes.contains(&"manifest::unused_provide".to_string()));
    assert!(diagnostics.iter().any(|diag| {
        diag.to_string() == "provide `api` is never used or exported (in component /)"
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compile_is_spawnable_on_multithread_runtime() {
    let dir = tmp_dir("scenario-compile-send");
    let root_path = dir.path().join("root.json5");

    write_file(&root_path, r#"{ manifest_version: "0.1.0" }"#);
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let compiler = Arc::new(Compiler::new(Resolver::new(), DigestStore::default()));

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

    let root_ref = ManifestRef::from_url(file_url(&root_path));
    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions::default();

    let tree = compiler
        .resolve_tree(root_ref.clone(), opts.resolve)
        .await
        .unwrap();
    let direct = compiler
        .compile_from_tree(tree.clone(), opts.optimize)
        .unwrap();
    let direct_ir = ScenarioIrReporter.emit(&direct).unwrap();

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
    let bundled_ir = ScenarioIrReporter.emit(&bundled).unwrap();

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

    let root_ref = ManifestRef::from_url(file_url(&root_path));
    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
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
    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
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

    let compiler = Compiler::new(Resolver::new(), DigestStore::default()).with_registry(registry);
    let tree = compiler
        .resolve_tree(
            ManifestRef::from_url(file_url(&root_path)),
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

    let root_ref = ManifestRef::from_url(file_url(&root_path));
    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
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
