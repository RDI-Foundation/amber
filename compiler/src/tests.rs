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
use miette::{Diagnostic, Severity};
use tempfile::TempDir;
use url::Url;

use crate::{
    CompileOptions, Compiler, DigestStore, ResolvedNode, ResolvedTree, ResolverRegistry,
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

fn default_compiler() -> Compiler {
    Compiler::new(Resolver::new(), DigestStore::default())
}

fn manifest_ref_for_path(path: &Path) -> ManifestRef {
    ManifestRef::from_url(file_url(path))
}

fn standard_compile_options() -> CompileOptions {
    CompileOptions::testing(false)
}

fn optimized_compile_options() -> CompileOptions {
    CompileOptions::testing(true)
}

async fn compile_single_child_fixture_error(
    dir_prefix: &str,
    child_manifest: &str,
    child_config: &str,
) -> crate::Error {
    let dir = tmp_dir(dir_prefix);
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(&child_path, child_manifest);
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.3.0",
              components: {{
                child: {{
                  manifest: "{child}",
                  config: {{
                    {child_config}
                  }}
                }}
              }},
              exports: {{ http: "#child.http" }}
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect_err("fixture should fail to compile")
}

fn compiled_scenario(output: &crate::CompileOutput) -> crate::reporter::CompiledScenario {
    crate::reporter::CompiledScenario::from_compile_output(output)
        .expect("test compiler output should convert to compiled Scenario")
}

fn has_diagnostic_code(diagnostics: &[miette::Report], code: &str) -> bool {
    diagnostics.iter().any(|report| {
        let diag: &dyn Diagnostic = &**report;
        diag.code().is_some_and(|c| c.to_string() == code)
    })
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
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    let crate::Error::Frontend(crate::frontend::Error::RelativeManifestRef { .. }) = err else {
        panic!("expected relative manifest ref error");
    };
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
                {{ to: "#child.missing", from: "self.api" }},
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

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
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
async fn missing_required_config_field_points_to_config_key() {
    use miette::Diagnostic;

    let dir = tmp_dir("scenario-missing-config-field-span");
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
              auth_json: { type: "string" },
              agents_md: { type: "string" },
              model: { type: "string" },
              theme: { type: "string" },
              workspace: { type: "string" },
            },
            required: ["auth_json", "agents_md", "model", "theme", "workspace"],
            additionalProperties: false,
          },
          program: {
            image: "child",
            entrypoint: ["child"],
            env: {
              AUTH_JSON: "${config.auth_json}",
              AGENTS_MD: "${config.agents_md}",
              MODEL: "${config.model}",
              THEME: "${config.theme}",
              WORKSPACE: "${config.workspace}",
            },
            network: {
              endpoints: [{ name: "agent", port: 8080 }],
            },
          },
          provides: {
            agent: { kind: "a2a", endpoint: "agent" },
          },
          exports: {
            agent: "self.agent",
          },
        }
        "#,
    );

    let root_source = format!(
        r##"
        {{
          manifest_version: "0.1.0",
          config_schema: {{
            type: "object",
            properties: {{
              auth_json: {{ type: "string" }},
              agents_md: {{ type: "string" }},
            }},
            required: ["auth_json", "agents_md"],
            additionalProperties: false,
          }},
          components: {{
            child: {{
              manifest: "{child}",
              config: {{
                auth_json: "${{config.auth_json}}",
                agents_md: "${{config.agents_md}}",
                theme: "amber",
                workspace: "/tmp/workspace",
              }},
            }},
          }},
          exports: {{ agent: "#child.agent" }},
        }}
        "##,
        child = file_url(&child_path),
    );
    write_file(&root_path, &root_source);

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
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
                && diag
                    .to_string()
                    .contains("missing required field config.model")
        })
        .expect("expected linker::invalid_config diagnostic for missing config.model");
    let diag: &dyn Diagnostic = &**report;
    let labels: Vec<_> = diag
        .labels()
        .expect("invalid_config should include a label")
        .collect();
    assert_eq!(labels.len(), 1);

    let label = &labels[0];
    let offset = root_source.find("config:").unwrap();
    assert_eq!(label.offset(), offset);
    assert_eq!(label.len(), "config".len());
}

#[tokio::test]
async fn type_mismatch_reports_expected_and_got() {
    let dir = tmp_dir("scenario-type-mismatch-message");
    let root_path = dir.path().join("root.json5");
    let provider_path = dir.path().join("provider.json5");
    let consumer_path = dir.path().join("consumer.json5");

    write_file(
        &provider_path,
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
        &consumer_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { llm: { kind: "llm" } },
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
                provider: "{provider}",
                consumer: "{consumer}",
              }},
              bindings: [
                {{ to: "#consumer.llm", from: "#provider.http" }},
              ],
            }}
            "##,
            provider = file_url(&provider_path),
            consumer = file_url(&consumer_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(error_contains(&err, "expected llm, got http"));
    assert!(!err.to_string().contains("CapabilityDecl"));
}

#[tokio::test]
async fn slot_forwarding_and_export_chain_resolve_to_provider() {
    let dir = tmp_dir("scenario-slot-forwarding");
    let root_path = dir.path().join("root.json5");
    let router_path = dir.path().join("router.json5");
    let gateway_path = dir.path().join("gateway.json5");
    let consumer_path = dir.path().join("consumer.json5");

    write_file(
        &gateway_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
          exports: { public_api: "api" },
        }
        "#,
    );
    write_file(
        &router_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{
                gateway: "{gateway}",
              }},
              bindings: [
                {{ to: "#gateway.api", from: "self.api" }},
              ],
              exports: {{ public_api: "#gateway.public_api" }},
            }}
            "##,
            gateway = file_url(&gateway_path),
        ),
    );
    write_file(
        &consumer_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              program: {{
                image: "root",
                entrypoint: ["root"],
                network: {{ endpoints: [{{ name: "api", port: 80 }}] }},
              }},
              provides: {{ api: {{ kind: "http", endpoint: "api" }} }},
              components: {{
                router: "{router}",
                consumer: "{consumer}",
              }},
              bindings: [
                {{ to: "#router.api", from: "self.api" }},
                {{ to: "#consumer.api", from: "#router.public_api" }},
              ],
            }}
            "##,
            router = file_url(&router_path),
            consumer = file_url(&consumer_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    let scenario = &output.scenario;
    let root = scenario.root;
    let consumer_id = scenario
        .components_iter()
        .find(|(_, c)| c.moniker.as_str() == "/consumer")
        .map(|(id, _)| id)
        .expect("consumer component");

    let binding = scenario
        .bindings
        .iter()
        .find(|b| b.to.component == consumer_id && b.to.name == "api")
        .expect("binding to consumer.api");

    assert!(
        matches!(
            &binding.from,
            BindingFrom::Component(provide)
                if provide.component == root && provide.name == "api"
        ),
        "expected consumer.api bound from root.api, got {:?}",
        binding.from
    );
}

#[tokio::test]
async fn variadic_slot_forwarding_preserves_all_sources_and_authored_order() {
    let dir = tmp_dir("scenario-variadic-slot-forwarding");
    let root_path = dir.path().join("root.json5");
    let relay_path = dir.path().join("relay.json5");
    let consumer_path = dir.path().join("consumer.json5");
    let provider_a_path = dir.path().join("provider-a.json5");
    let provider_b_path = dir.path().join("provider-b.json5");

    write_file(
        &provider_a_path,
        r#"
        {
          manifest_version: "0.3.0",
          program: {
            image: "provider-a",
            entrypoint: ["provider-a"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "api" } },
          exports: { api: "api" },
        }
        "#,
    );
    write_file(
        &provider_b_path,
        r#"
        {
          manifest_version: "0.3.0",
          program: {
            image: "provider-b",
            entrypoint: ["provider-b"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "api" } },
          exports: { api: "api" },
        }
        "#,
    );
    write_file(
        &consumer_path,
        r#"
        {
          manifest_version: "0.3.0",
          program: {
            image: "consumer",
            entrypoint: [
              "consumer",
              {
                each: "slots.upstream",
                argv: ["--upstream", "${item.url}"],
              },
            ],
            network: { endpoints: [{ name: "http", port: 80 }] },
          },
          slots: {
            upstream: { kind: "http", optional: true, multiple: true },
          },
          provides: { http: { kind: "http", endpoint: "http" } },
          exports: { http: "http" },
        }
        "#,
    );
    write_file(
        &relay_path,
        &format!(
            r##"
            {{
              manifest_version: "0.3.0",
              slots: {{
                upstream: {{ kind: "http", optional: true, multiple: true }},
              }},
              components: {{
                consumer: "{consumer}",
              }},
              bindings: [
                {{ to: "#consumer.upstream", from: "self.upstream" }},
              ],
              exports: {{ http: "#consumer.http" }},
            }}
            "##,
            consumer = file_url(&consumer_path),
        ),
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.3.0",
              components: {{
                relay: "{relay}",
                provider_a: "{provider_a}",
                provider_b: "{provider_b}",
              }},
              bindings: [
                {{ to: "#relay.upstream", from: "#provider_a.api" }},
                {{ to: "#relay.upstream", from: "#provider_b.api" }},
              ],
              exports: {{ http: "#relay.http" }},
            }}
            "##,
            relay = file_url(&relay_path),
            provider_a = file_url(&provider_a_path),
            provider_b = file_url(&provider_b_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let with_opt = compiler
        .compile(root_ref.clone(), optimized_compile_options())
        .await
        .expect("compile with optimizations");
    let without_opt = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .expect("compile without optimizations");

    let binding_order = |scenario: &amber_scenario::Scenario| {
        let consumer_id = scenario
            .components_iter()
            .find(|(_, c)| c.moniker.local_name() == Some("consumer"))
            .map(|(id, _)| id)
            .expect("consumer component");

        scenario
            .bindings
            .iter()
            .filter(|binding| binding.to.component == consumer_id && binding.to.name == "upstream")
            .map(|binding| match &binding.from {
                BindingFrom::Component(provide) => scenario
                    .component(provide.component)
                    .moniker
                    .local_name()
                    .expect("provider local name")
                    .to_string(),
                other => panic!("expected component binding, got {other:?}"),
            })
            .collect::<Vec<_>>()
    };

    assert_eq!(
        binding_order(&with_opt.scenario),
        vec!["provider_a", "provider_b"]
    );
    assert_eq!(
        binding_order(&without_opt.scenario),
        vec!["provider_a", "provider_b"]
    );
}

#[tokio::test]
async fn slot_cycle_reports_error() {
    let dir = tmp_dir("scenario-slot-cycle");
    let root_path = dir.path().join("root.json5");
    let a_path = dir.path().join("a.json5");
    let b_path = dir.path().join("b.json5");

    write_file(
        &a_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
          exports: { api: "api" },
        }
        "#,
    );
    write_file(
        &b_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
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
                a: "{a}",
                b: "{b}",
              }},
              bindings: [
                {{ to: "#a.api", from: "#b.api" }},
                {{ to: "#b.api", from: "#a.api" }},
              ],
            }}
            "##,
            a = file_url(&a_path),
            b = file_url(&b_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(error_contains(&err, "slot routing cycle detected"));
}

#[tokio::test]
async fn external_root_slot_with_weak_binding_is_allowed() {
    let dir = tmp_dir("external-root-slot-weak");
    let root_path = dir.path().join("root.json5");
    let client_path = dir.path().join("client.json5");

    write_file(
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
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{ client: "{client}" }},
              bindings: [
                {{ to: "#client.api", from: "self.api", weak: true }}
              ]
            }}
            "##,
            client = file_url(&client_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    let scenario = &output.scenario;
    let client_id = scenario
        .components_iter()
        .find(|(_, c)| c.moniker.as_str() == "/client")
        .map(|(id, _)| id)
        .expect("client component");
    let binding = scenario
        .bindings
        .iter()
        .find(|b| b.to.component == client_id && b.to.name == "api")
        .expect("binding to client.api");

    assert!(binding.weak, "binding should be weak");
    assert!(
        matches!(
            &binding.from,
            BindingFrom::External(slot)
                if slot.component == scenario.root && slot.name == "api"
        ),
        "expected external binding from root.api, got {:?}",
        binding.from
    );
}

#[tokio::test]
async fn external_root_slot_requires_weak_binding() {
    let dir = tmp_dir("external-root-slot-strong");
    let root_path = dir.path().join("root.json5");
    let client_path = dir.path().join("client.json5");

    write_file(
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
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{ client: "{client}" }},
              bindings: [
                {{ to: "#client.api", from: "self.api" }}
              ]
            }}
            "##,
            client = file_url(&client_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(
        error_contains(&err, "external slot"),
        "expected external slot weak-binding error, got {err}"
    );
}

#[tokio::test]
async fn storage_resource_binding_stays_strong() {
    let dir = tmp_dir("storage-resource-binding-strong");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/app && sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "slots.state" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          slots: {
            state: { kind: "storage" },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              resources: {{
                state: {{ kind: "storage" }}
              }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.state", from: "resources.state" }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .expect("compile storage scenario");

    let scenario = &output.scenario;
    let child_id = scenario
        .components_iter()
        .find(|(_, c)| c.moniker.as_str() == "/child")
        .map(|(id, _)| id)
        .expect("child component");
    let binding = scenario
        .bindings
        .iter()
        .find(|b| b.to.component == child_id && b.to.name == "state")
        .expect("binding to child.state");

    assert!(
        !binding.weak,
        "storage bindings should remain strong when routed from a storage resource"
    );
    assert!(
        matches!(
            &binding.from,
            BindingFrom::Resource(resource)
                if resource.component == scenario.root && resource.name == "state"
        ),
        "expected resource binding from resources.state, got {:?}",
        binding.from
    );
}

#[tokio::test]
async fn program_can_mount_local_storage_resource_directly() {
    let dir = tmp_dir("storage-resource-direct-mount");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          resources: {
            state: { kind: "storage" },
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/app && sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "resources.state" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
    );

    let output = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect("compile storage scenario with direct resource mount");

    let root = output.scenario.component(output.scenario.root);
    assert!(
        root.resources.contains_key("state"),
        "root should retain the directly mounted storage resource"
    );
    assert!(
        root.program
            .as_ref()
            .expect("root program")
            .mounts()
            .iter()
            .any(|mount| matches!(
                mount,
                amber_scenario::ProgramMount::Resource { resource, .. } if resource == "state"
            )),
        "program should keep the direct resource mount"
    );
    assert!(
        output.scenario.bindings.is_empty(),
        "direct resource mounts should not require synthetic bindings"
    );
}

#[tokio::test]
async fn directly_mounted_storage_resource_fanout_is_rejected_at_link_time() {
    let dir = tmp_dir("direct-storage-resource-fanout");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          resources: {
            state: { kind: "storage" },
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/a && test -d /var/lib/b && sleep 3600"],
            mounts: [
              { path: "/var/lib/a", from: "resources.state" },
              { path: "/var/lib/b", from: "resources.state" },
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
        .expect_err("direct storage fanout should fail during linking");

    let crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) = err else {
        panic!("expected linker error, got {err}");
    };
    assert!(
        errors.iter().any(|error| matches!(
            error,
            crate::linker::Error::StorageResourceFanout { resource, .. } if resource == "state"
        )),
        "expected storage resource fanout linker error, got {errors:?}"
    );
}

#[tokio::test]
async fn mounted_storage_slot_requires_resource_binding_at_link_time() {
    let dir = tmp_dir("mounted-storage-slot-requires-resource-binding");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/app && sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "slots.state" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          slots: {
            state: { kind: "storage" },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{ child: "{child}" }},
              exports: {{ http: "#child.http" }}
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect_err("missing storage resource binding should fail during linking");

    let crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) = err else {
        panic!("expected linker error, got {err}");
    };
    assert!(
        errors.iter().any(|error| matches!(
            error,
            crate::linker::Error::StorageMountRequiresResource { slot, .. } if slot == "state"
        )),
        "expected storage mount linker error, got {errors:?}"
    );
    assert!(
        !errors
            .iter()
            .any(|error| matches!(error, crate::linker::Error::UnboundSlot { slot, .. } if slot == "state")),
        "mounted storage should report the storage-specific linker error instead of a generic unbound slot: {errors:?}"
    );
}

#[tokio::test]
async fn config_expanded_storage_mount_slot_requires_resource_binding_at_link_time() {
    let err = compile_single_child_fixture_error(
        "config-expanded-storage-slot-requires-resource-binding",
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_source: { type: "string" },
            },
            required: ["mount_source"],
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/app && sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "${config.mount_source}" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          slots: {
            state: { kind: "storage" },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
        r#"
        mount_source: "slots.state"
        "#,
    )
    .await;

    let crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) = err else {
        panic!("expected linker error, got {err}");
    };
    assert!(
        errors.iter().any(|error| matches!(
            error,
            crate::linker::Error::StorageMountRequiresResource { slot, .. } if slot == "state"
        )),
        "expected storage mount linker error, got {errors:?}"
    );
    assert!(
        !errors
            .iter()
            .any(|error| matches!(error, crate::linker::Error::UnboundSlot { slot, .. } if slot == "state")),
        "config-expanded storage mount should not be reported as a generic unbound slot: {errors:?}"
    );
}

#[tokio::test]
async fn config_expanded_mount_unknown_slot_is_rejected_at_link_time() {
    let err = compile_single_child_fixture_error(
        "config-expanded-unknown-slot-mount",
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_source: { type: "string" },
            },
            required: ["mount_source"],
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "${config.mount_source}" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
        r#"
        mount_source: "slots.missing"
        "#,
    )
    .await;

    assert!(error_contains(
        &err,
        "mount source resolved to `slots.missing`"
    ));
    assert!(error_contains(&err, "no such slot exists on the component"));
}

#[tokio::test]
async fn config_expanded_mount_unknown_resource_is_rejected_at_link_time() {
    let err = compile_single_child_fixture_error(
        "config-expanded-unknown-resource-mount",
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_source: { type: "string" },
            },
            required: ["mount_source"],
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "${config.mount_source}" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
        r#"
        mount_source: "resources.state"
        "#,
    )
    .await;

    assert!(error_contains(
        &err,
        "mount source resolved to `resources.state`"
    ));
    assert!(error_contains(
        &err,
        "no such resource exists on the component"
    ));
}

#[tokio::test]
async fn config_expanded_framework_mount_requires_experimental_feature_at_link_time() {
    let err = compile_single_child_fixture_error(
        "config-expanded-framework-mount-feature",
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_source: { type: "string" },
            },
            required: ["mount_source"],
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 3600"],
            mounts: [
              { path: "/var/run/docker.sock", from: "${config.mount_source}" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
        r#"
        mount_source: "framework.docker"
        "#,
    )
    .await;

    assert!(error_contains(
        &err,
        "framework capability `framework.docker` requires experimental feature `docker`"
    ));
}

#[tokio::test]
async fn config_expanded_framework_mount_unknown_capability_is_rejected_at_link_time() {
    let err = compile_single_child_fixture_error(
        "config-expanded-framework-mount-unknown",
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_source: { type: "string" },
            },
            required: ["mount_source"],
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 3600"],
            mounts: [
              { path: "/var/run/cap.sock", from: "${config.mount_source}" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
        r#"
        mount_source: "framework.unknown"
        "#,
    )
    .await;

    assert!(error_contains(
        &err,
        "mount source resolved to unknown framework capability `framework.unknown`"
    ));
}

#[tokio::test]
async fn config_expanded_static_mount_paths_are_validated_at_link_time() {
    let err = compile_single_child_fixture_error(
        "config-expanded-static-mount-path-validation",
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_path: { type: "string" },
              mount_source: { type: "string" },
              value: { type: "string" },
            },
            required: ["mount_path", "mount_source", "value"],
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 3600"],
            mounts: [
              { path: "${config.mount_path}", from: "${config.mount_source}" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
        r#"
        mount_path: "relative/path",
        mount_source: "config.value",
        value: "hello"
        "#,
    )
    .await;

    assert!(error_contains(&err, "mount path must be absolute"), "{err}");
    assert!(error_contains(&err, "relative/path"), "{err}");
}

#[tokio::test]
async fn optional_mounted_storage_slot_is_rejected_at_link_time() {
    let dir = tmp_dir("optional-mounted-storage-slot");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/app && sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "slots.state" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          slots: {
            state: { kind: "storage", optional: true },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{ child: "{child}" }},
              exports: {{ http: "#child.http" }}
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect_err("optional mounted storage should fail during linking");

    let crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) = err else {
        panic!("expected linker error, got {err}");
    };
    assert!(
        errors.iter().any(|error| matches!(
            error,
            crate::linker::Error::StorageMountRequiresResource { slot, .. } if slot == "state"
        )),
        "expected optional storage mount linker error, got {errors:?}"
    );
}

#[tokio::test]
async fn mounted_storage_resource_fanout_is_rejected_at_link_time() {
    let dir = tmp_dir("mounted-storage-resource-fanout");
    let root_path = dir.path().join("root.json5");
    let first_child_path = dir.path().join("first.json5");
    let second_child_path = dir.path().join("second.json5");

    let child_manifest = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/app && sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "slots.state" },
            ],
          },
          slots: {
            state: { kind: "storage" },
          },
        }
        "#;
    write_file(&first_child_path, child_manifest);
    write_file(&second_child_path, child_manifest);
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              resources: {{
                state: {{ kind: "storage" }}
              }},
              components: {{
                first: "{first_child}",
                second: "{second_child}"
              }},
              bindings: [
                {{ to: "#first.state", from: "resources.state" }},
                {{ to: "#second.state", from: "resources.state" }}
              ]
            }}
            "##,
            first_child = file_url(&first_child_path),
            second_child = file_url(&second_child_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect_err("mounted storage fanout should fail during linking");

    let crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) = err else {
        panic!("expected linker error, got {err}");
    };
    assert!(
        errors.iter().any(|error| matches!(
            error,
            crate::linker::Error::StorageResourceFanout { resource, .. } if resource == "state"
        )),
        "expected storage fanout linker error, got {errors:?}"
    );
}

#[tokio::test]
async fn storage_resource_params_resolve_from_component_config() {
    let dir = tmp_dir("storage-resource-param-config");
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
              storage_size: { type: "string" },
            },
            required: ["storage_size"],
          },
          resources: {
            state: {
              kind: "storage",
              params: { size: "${config.storage_size}" },
            },
          },
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
                child: {{
                  manifest: "{child}",
                  config: {{
                    storage_size: "12Gi"
                  }}
                }}
              }}
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let output = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect("compile storage resource config scenario");

    let child = output
        .scenario
        .components_iter()
        .find(|(_, component)| component.moniker.as_str() == "/child")
        .map(|(_, component)| component)
        .expect("child component");
    assert_eq!(
        child
            .resources
            .get("state")
            .and_then(|resource| resource.params.size.as_deref()),
        Some("12Gi")
    );
}

#[tokio::test]
async fn storage_resource_params_reject_runtime_root_config() {
    let dir = tmp_dir("storage-resource-param-runtime-root");
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
              storage_size: { type: "string" },
            },
            required: ["storage_size"],
          },
          resources: {
            state: {
              kind: "storage",
              params: { size: "${config.storage_size}" },
            },
          },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              config_schema: {{
                type: "object",
                properties: {{
                  storage_size: {{ type: "string" }}
                }},
                required: ["storage_size"]
              }},
              components: {{
                child: {{
                  manifest: "{child}",
                  config: {{
                    storage_size: "${{config.storage_size}}"
                  }}
                }}
              }}
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect_err("runtime root config in storage resource params should fail");

    assert!(
        error_contains(&err, "resources.state.params.size"),
        "expected resource param error, got {err}"
    );
    assert!(
        error_contains(&err, "not available at compile time"),
        "expected compile-time config resolution error, got {err}"
    );
}

#[tokio::test]
async fn storage_resource_params_resolve_from_forwarded_object_defaults() {
    let dir = tmp_dir("storage-resource-param-forwarded-object-default");
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
              storage: {
                type: "object",
                properties: {
                  size: { type: "string", default: "12Gi" },
                },
              },
            },
          },
          resources: {
            state: {
              kind: "storage",
              params: { size: "${config.storage.size}" },
            },
          },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              config_schema: {{
                type: "object",
                properties: {{
                  storage: {{
                    type: "object",
                    properties: {{}}
                  }}
                }}
              }},
              components: {{
                child: {{
                  manifest: "{child}",
                  config: {{
                    storage: "${{config.storage}}"
                  }}
                }}
              }}
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let output = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect("compile storage resource config scenario");

    let child = output
        .scenario
        .components_iter()
        .find(|(_, component)| component.moniker.as_str() == "/child")
        .map(|(_, component)| component)
        .expect("child component");
    assert_eq!(
        child
            .resources
            .get("state")
            .and_then(|resource| resource.params.size.as_deref()),
        Some("12Gi")
    );
}

#[tokio::test]
async fn storage_resource_params_reject_forwarded_object_defaults_when_root_can_be_null() {
    let dir = tmp_dir("storage-resource-param-forwarded-object-nullable");
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
              storage: {
                type: "object",
                properties: {
                  size: { type: "string", default: "12Gi" },
                },
              },
            },
          },
          resources: {
            state: {
              kind: "storage",
              params: { size: "${config.storage.size}" },
            },
          },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              config_schema: {{
                type: "object",
                properties: {{
                  storage: {{
                    type: ["object", "null"],
                    properties: {{}}
                  }}
                }}
              }},
              components: {{
                child: {{
                  manifest: "{child}",
                  config: {{
                    storage: "${{config.storage}}"
                  }}
                }}
              }}
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect_err("nullable runtime root config in storage resource params should fail");

    assert!(
        error_contains(&err, "resources.state.params.size"),
        "expected resource param error, got {err}"
    );
    assert!(
        error_contains(&err, "not available at compile time"),
        "expected compile-time config resolution error, got {err}"
    );
}

#[tokio::test]
async fn exporting_unbound_optional_slot_errors() {
    let dir = tmp_dir("scenario-export-unbound-slot");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http", optional: true } },
          exports: { api: "api" },
        }
        "#,
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(
        error_contains(&err, "external slot"),
        "expected external-slot export error, got {err}"
    );
}

#[tokio::test]
async fn delegated_export_chain_resolves_binding_source() {
    let dir = tmp_dir("scenario-delegated-export-chain");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    let grand_path = dir.path().join("grand.json5");
    let consumer_path = dir.path().join("consumer.json5");

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
        &consumer_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
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
                consumer: "{consumer}",
              }},
              bindings: [
                {{ to: "#consumer.api", from: "#child.api" }},
              ],
            }}
            "##,
            child = file_url(&child_path),
            consumer = file_url(&consumer_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let compilation = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    let consumer_id = compilation
        .scenario
        .components_iter()
        .find(|(_, c)| c.moniker.as_str() == "/consumer")
        .map(|(id, _)| id)
        .expect("consumer component");

    let binding = compilation
        .scenario
        .bindings
        .iter()
        .find(|b| b.to.component == consumer_id && b.to.name == "api")
        .expect("binding");
    let from = match &binding.from {
        BindingFrom::Component(from) => from,
        BindingFrom::Resource(resource) => {
            panic!(
                "unexpected resource binding resources:{}:{}",
                graph::component_path_for(&compilation.scenario.components, resource.component),
                resource.name
            )
        }
        BindingFrom::Framework(name) => {
            panic!("unexpected framework binding framework.{name}")
        }
        BindingFrom::External(slot) => {
            panic!("unexpected external binding slots.{}", slot.name)
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
                bundle_source: None,
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
                bundle_source: None,
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
    let root_ref = manifest_ref_for_path(&root_path);

    let compilation = compiler
        .compile(root_ref, standard_compile_options())
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
    let root_ref = manifest_ref_for_path(&root_path);

    let compilation = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 3);
    assert_eq!(backend.call_count(), 1);
}

#[tokio::test]
async fn experimental_features_must_be_enabled_by_parent() {
    let dir = tmp_dir("scenario-experimental-parent");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["docker"],
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
                child: "{child}",
              }},
            }}
            "#,
            child = file_url(&child_path)
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let err = compiler
        .compile(root_ref, CompileOptions::default())
        .await
        .expect_err("missing parent experimental feature should fail");

    match err {
        crate::Error::Frontend(crate::frontend::Error::ExperimentalFeatureNotEnabled {
            child,
            missing_features,
            ..
        }) => {
            assert_eq!(child.as_ref(), "child");
            assert_eq!(missing_features.to_string(), "docker");
        }
        other => panic!("expected ExperimentalFeatureNotEnabled, got: {other}"),
    }
}

#[tokio::test]
async fn experimental_features_are_checked_per_edge() {
    let dir = tmp_dir("scenario-experimental-per-edge");
    let root_path = dir.path().join("root.json5");
    let parent_path = dir.path().join("parent.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["docker"],
        }
        "#,
    );

    write_file(
        &parent_path,
        &format!(
            r#"
            {{
              manifest_version: "0.1.0",
              components: {{
                leaf: "{child}",
              }},
            }}
            "#,
            child = file_url(&child_path)
        ),
    );

    write_file(
        &root_path,
        &format!(
            r#"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["docker"],
              components: {{
                parent: "{parent}",
              }},
            }}
            "#,
            parent = file_url(&parent_path)
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let err = compiler
        .compile(root_ref, CompileOptions::default())
        .await
        .expect_err("intermediate parent missing feature should fail");

    match err {
        crate::Error::Frontend(crate::frontend::Error::ExperimentalFeatureNotEnabled {
            child,
            missing_features,
            ..
        }) => {
            assert_eq!(child.as_ref(), "leaf");
            assert_eq!(missing_features.to_string(), "docker");
        }
        other => panic!("expected ExperimentalFeatureNotEnabled, got: {other}"),
    }
}

#[tokio::test]
async fn experimental_features_succeed_when_enabled_on_every_parent() {
    let dir = tmp_dir("scenario-experimental-enabled");
    let root_path = dir.path().join("root.json5");
    let parent_path = dir.path().join("parent.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["docker"],
        }
        "#,
    );

    write_file(
        &parent_path,
        &format!(
            r#"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["docker"],
              components: {{
                leaf: "{child}",
              }},
            }}
            "#,
            child = file_url(&child_path)
        ),
    );

    write_file(
        &root_path,
        &format!(
            r#"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["docker"],
              components: {{
                parent: "{parent}",
              }},
            }}
            "#,
            parent = file_url(&parent_path)
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .expect("features enabled across all edges should compile");

    assert_eq!(output.scenario.components_iter().count(), 3);
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

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let output = compiler
        .compile(root_ref, standard_compile_options())
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

#[tokio::test]
async fn unused_program_points_to_program_key() {
    use miette::Diagnostic;

    let dir = tmp_dir("unused-program-label");
    let root_path = dir.path().join("root.json5");
    let root_source = r#"
        {
          manifest_version: "0.3.0",
          program: {
            image: "unused-program",
            entrypoint: ["/app/start", "--mode", "serve"],
            env: {
              LOG_LEVEL: "info",
              FEATURE_FLAG: "true",
              DATA_DIR: "/app/data",
              CACHE_DIR: "/app/cache",
            },
            mounts: [
              { path: "/app/data", from: "resources.data" },
              { path: "/app/cache", from: "resources.cache" },
            ],
            network: {
              endpoints: [
                { name: "http", port: 8080 },
                { name: "metrics", port: 9090 },
              ],
            },
          },
          resources: {
            data: { kind: "storage", params: { size: "1Gi" } },
            cache: { kind: "storage", params: { size: "1Gi" } },
          },
        }
        "#;
    write_file(&root_path, root_source);

    let compiler = default_compiler();
    let output = compiler
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap();

    let report = output
        .diagnostics
        .iter()
        .find(|report| {
            let diag: &dyn Diagnostic = &***report;
            diag.code()
                .is_some_and(|c| c.to_string() == "manifest::unused_program")
        })
        .expect("expected manifest::unused_program diagnostic");
    let diag: &dyn Diagnostic = &**report;
    let labels: Vec<_> = diag
        .labels()
        .expect("unused_program should include a label")
        .collect();
    assert_eq!(labels.len(), 1);

    let label = &labels[0];
    let offset = root_source.find("program:").unwrap();
    assert_eq!(label.offset(), offset);
    assert_eq!(label.len(), "program".len());
}

#[tokio::test]
async fn optimized_compile_keeps_externally_rooted_child_without_exports() {
    let dir = tmp_dir("external-rooted-child-dce");
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
            env: { API_URL: "${slots.api.url}" }
          },
          slots: { api: { kind: "http" } }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "self.api", weak: true }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, optimized_compile_options())
        .await
        .unwrap();

    assert!(
        output
            .scenario
            .components_iter()
            .any(|(_, component)| component.moniker.as_str() == "/child"),
        "optimized compile should retain the externally rooted child"
    );
    let root = output.scenario.component(output.scenario.root);
    assert!(
        root.slots.contains_key("api"),
        "optimized compile should retain the external root slot"
    );
    assert!(output.scenario.bindings.iter().any(|binding| {
        matches!(
            &binding.from,
            BindingFrom::External(slot)
                if slot.component == output.scenario.root && slot.name == "api"
        ) && binding.to.name == "api"
    }));
}

#[tokio::test]
async fn optimized_compile_keeps_root_program_driven_by_external_slot_without_exports() {
    let dir = tmp_dir("external-rooted-root-dce");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
          program: {
            image: "root",
            entrypoint: ["root"],
            env: { API_URL: "${slots.api.url}" }
          }
        }
        "#,
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, optimized_compile_options())
        .await
        .unwrap();

    let root = output.scenario.component(output.scenario.root);
    assert!(
        root.program.is_some(),
        "optimized compile should retain the root program when it consumes an external slot"
    );
    assert!(
        root.slots.contains_key("api"),
        "optimized compile should retain the root external slot"
    );
    assert!(output.scenario.bindings.iter().any(|binding| {
        matches!(
            &binding.from,
            BindingFrom::External(slot)
                if slot.component == output.scenario.root && slot.name == "api"
        ) && binding.to.component == output.scenario.root
            && binding.to.name == "api"
    }));
}

#[tokio::test]
async fn optimized_compile_keeps_externally_rooted_child_with_repeated_each_without_exports() {
    let dir = tmp_dir("external-rooted-repeated-each-dce");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.3.0",
          program: {
            image: "child",
            entrypoint: [
              "child",
              { each: "slots.api", argv: ["--api", "${item.url}"] }
            ]
          },
          slots: { api: { kind: "http", optional: true, multiple: true } }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.3.0",
              slots: {{ api: {{ kind: "http", optional: true, multiple: true }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "self.api", weak: true }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, optimized_compile_options())
        .await
        .unwrap();

    assert!(
        output
            .scenario
            .components_iter()
            .any(|(_, component)| component.moniker.as_str() == "/child"),
        "optimized compile should retain the externally rooted child when it uses repeated `each`"
    );
    let root = output.scenario.component(output.scenario.root);
    assert!(
        root.slots.contains_key("api"),
        "optimized compile should retain the external root slot for repeated `each`"
    );
    assert!(output.scenario.bindings.iter().any(|binding| {
        matches!(
            &binding.from,
            BindingFrom::External(slot)
                if slot.component == output.scenario.root && slot.name == "api"
        ) && binding.to.name == "api"
    }));
}

#[tokio::test]
async fn optimized_compile_keeps_root_program_that_references_all_slots_without_exports() {
    let dir = tmp_dir("external-rooted-all-slots-dce");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: {
            admin: { kind: "http" },
            api: { kind: "http" }
          },
          program: {
            image: "root",
            entrypoint: ["root"],
            env: { ALL_SLOTS: "${slots}" }
          }
        }
        "#,
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, optimized_compile_options())
        .await
        .unwrap();

    let root = output.scenario.component(output.scenario.root);
    assert!(
        root.program.is_some(),
        "optimized compile should retain a root program that references all slots"
    );
    assert!(
        root.slots.contains_key("admin") && root.slots.contains_key("api"),
        "optimized compile should retain every root slot referenced by `${{slots}}`"
    );
    assert!(output.scenario.bindings.iter().any(|binding| {
        matches!(
            &binding.from,
            BindingFrom::External(slot)
                if slot.component == output.scenario.root && slot.name == "admin"
        ) && binding.to.component == output.scenario.root
            && binding.to.name == "admin"
    }));
    assert!(output.scenario.bindings.iter().any(|binding| {
        matches!(
            &binding.from,
            BindingFrom::External(slot)
                if slot.component == output.scenario.root && slot.name == "api"
        ) && binding.to.component == output.scenario.root
            && binding.to.name == "api"
    }));
}

#[tokio::test]
async fn check_suppresses_unused_program_for_externally_rooted_child() {
    let dir = tmp_dir("external-rooted-child-lint");
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
            env: { API_URL: "${slots.api.url}" }
          },
          slots: { api: { kind: "http" } }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "self.api", weak: true }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(!output.has_errors);
    assert!(
        !has_diagnostic_code(&output.diagnostics, "manifest::unused_program"),
        "unexpected manifest::unused_program diagnostics: {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn check_suppresses_unused_program_for_root_program_driven_by_external_slot() {
    let dir = tmp_dir("external-rooted-root-lint");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
          program: {
            image: "root",
            entrypoint: ["root"],
            env: { API_URL: "${slots.api.url}" }
          }
        }
        "#,
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(!output.has_errors);
    assert!(
        !has_diagnostic_code(&output.diagnostics, "manifest::unused_program"),
        "unexpected manifest::unused_program diagnostics: {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn check_suppresses_unused_program_for_externally_rooted_child_with_repeated_each() {
    let dir = tmp_dir("external-rooted-repeated-each-lint");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.3.0",
          program: {
            image: "child",
            entrypoint: [
              "child",
              { each: "slots.api", argv: ["--api", "${item.url}"] }
            ]
          },
          slots: { api: { kind: "http", optional: true, multiple: true } }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.3.0",
              slots: {{ api: {{ kind: "http", optional: true, multiple: true }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "self.api", weak: true }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(!output.has_errors);
    assert!(
        !has_diagnostic_code(&output.diagnostics, "manifest::unused_program"),
        "unexpected manifest::unused_program diagnostics: {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn check_keeps_unused_program_for_external_binding_to_unused_slot() {
    let dir = tmp_dir("external-binding-unused-program-lint");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "child",
            entrypoint: ["child"]
          },
          slots: { api: { kind: "http" } }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "self.api", weak: true }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(!output.has_errors);
    assert!(
        has_diagnostic_code(&output.diagnostics, "manifest::unused_program"),
        "expected manifest::unused_program diagnostics, got {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn check_suppresses_unused_program_but_not_unused_provide_for_externally_rooted_child() {
    let dir = tmp_dir("external-rooted-narrow-lint");
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
            env: { API_URL: "${slots.api.url}" },
            network: { endpoints: [{ name: "out", port: 8080 }] }
          },
          slots: { api: { kind: "http" } },
          provides: {
            out: { kind: "http", endpoint: "out" }
          }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "self.api", weak: true }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();
    let diagnostics: Vec<_> = output
        .diagnostics
        .iter()
        .map(|diag| diag.to_string())
        .collect();

    assert!(!output.has_errors);
    assert!(
        !has_diagnostic_code(&output.diagnostics, "manifest::unused_program"),
        "unexpected manifest::unused_program diagnostics: {:?}",
        diagnostics
    );
    assert!(
        diagnostics
            .iter()
            .any(|diag| diag == "provide `out` is never used or exported (in component /child)"),
        "expected the child unused-provide warning to remain: {:?}",
        diagnostics
    );
}

#[tokio::test]
async fn check_suppresses_unused_program_for_root_program_that_references_all_slots() {
    let dir = tmp_dir("external-rooted-all-slots-lint");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: {
            admin: { kind: "http" },
            api: { kind: "http" }
          },
          program: {
            image: "root",
            entrypoint: ["root"],
            env: { ALL_SLOTS: "${slots}" }
          }
        }
        "#,
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(!output.has_errors);
    assert!(
        !has_diagnostic_code(&output.diagnostics, "manifest::unused_program"),
        "unexpected manifest::unused_program diagnostics: {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn check_treats_weak_binding_targets_as_optional_for_unused_slot_lint() {
    let dir = tmp_dir("scenario-optional-slot-downstream-lint");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ upstream: {{ kind: "http", optional: true }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "self.upstream", weak: true }},
              ],
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(!output.has_errors);
    assert!(
        !has_diagnostic_code(&output.diagnostics, "manifest::unused_slot"),
        "unexpected manifest::unused_slot diagnostics: {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}

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
