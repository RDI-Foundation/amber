use std::{
    collections::HashSet,
    fs,
    future::Future,
    io::{Read as _, Write as _},
    net::{Shutdown, TcpListener},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use amber_manifest::{Manifest, ManifestRef};
use amber_resolver::{Backend, Cache, Cacheability, RemoteResolver, Resolution, Resolver};
use amber_scenario::graph;
use url::Url;

use crate::{CompileOptions, Compiler, ResolveMode};

fn tmp_dir(prefix: &str) -> PathBuf {
    let mut base = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    base.push(format!("{prefix}-{nanos}-{}", std::process::id()));
    fs::create_dir_all(&base).unwrap();
    base
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
            Ok((stream, _)) => return stream,
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

    // Important: /a and /a_alias must return *byte-identical* bodies so they have the same digest.
    let a_manifest = format!(
        r#"
        {{
          manifest_version: "1.0.0",
          components: {{
            b: "{base}/b",
          }},
        }}
        "#
    );

    let b_manifest = format!(
        r#"
        {{
          manifest_version: "1.0.0",
          components: {{
            a: "{base}/a_alias",
          }},
        }}
        "#
    );

    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut seen: HashSet<String> = HashSet::new();

        // We expect exactly these three requests, but tolerate a little extra in case of retries.
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
async fn compile_online_then_offline_from_cache() {
    let dir = tmp_dir("scenario-compile");
    let root_path = dir.join("root.json5");
    let a_path = dir.join("a.json5");
    let b_path = dir.join("b.json5");

    write_file(
        &a_path,
        r#"
        {
          manifest_version: "1.0.0",
          provides: { api: { kind: "http" } },
          exports: ["api"],
        }
        "#,
    );

    write_file(
        &b_path,
        r#"
        {
          manifest_version: "1.0.0",
          provides: { llm: { kind: "llm" } },
          exports: ["llm"],
        }
        "#,
    );

    write_file(
        &root_path,
        &format!(
            r#"
            {{
              manifest_version: "1.0.0",
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

    let cache = Cache::default();
    let compiler = Compiler::new(Resolver::new(), cache.clone());

    let root_ref = ManifestRef::from_url(file_url(&root_path));

    // Online compile fills cache.
    let scenario = compiler
        .compile(
            root_ref.clone(),
            CompileOptions {
                resolve: crate::ResolveOptions {
                    mode: ResolveMode::Online,
                    max_concurrency: 8,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(scenario.components.len(), 3);

    // Remove files; offline must rely on cache.
    fs::remove_file(&root_path).unwrap();
    fs::remove_file(&a_path).unwrap();
    fs::remove_file(&b_path).unwrap();

    let scenario2 = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions {
                    mode: ResolveMode::Offline,
                    max_concurrency: 8,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(scenario2.components.len(), 3);

    // Basic graph op sanity (no bindings ⇒ topo order is just all nodes).
    let order = graph::topo_order(&scenario2).unwrap();
    assert_eq!(order.len(), scenario2.components.len());
}

#[tokio::test]
async fn compile_online_then_offline_preserves_resolved_url() {
    let contents = r#"{ manifest_version: "1.0.0" }"#.to_string();
    let (url, server) = spawn_redirecting_manifest_server(contents);

    let cache = Cache::default();
    let compiler = Compiler::new(Resolver::new(), cache);
    let root_ref = ManifestRef::from_url(url.clone());

    let scenario = compiler
        .compile(
            root_ref.clone(),
            CompileOptions {
                resolve: crate::ResolveOptions {
                    mode: ResolveMode::Online,
                    max_concurrency: 8,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let root_component = &scenario.components[scenario.root.0];
    assert_eq!(root_component.resolved_url.path(), "/final");

    server.join().unwrap();

    let scenario2 = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions {
                    mode: ResolveMode::Offline,
                    max_concurrency: 8,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let root_component = &scenario2.components[scenario2.root.0];
    assert_eq!(root_component.resolved_url.path(), "/final");
}

#[tokio::test]
async fn binding_requires_export_on_child_slot() {
    let dir = tmp_dir("scenario-export-check");
    let root_path = dir.join("root.json5");
    let child_path = dir.join("child.json5");

    // Child has a slot but does NOT export it.
    // It is satisfied internally, so the manifest is valid; the parent still must not bind into it.
    write_file(
        &child_path,
        r#"
        {
          manifest_version: "1.0.0",
          slots: { needs: { kind: "http" } },
          provides: { internal: { kind: "http" } },
          bindings: [
            { to: "self.needs", from: "self.internal" },
          ],
          // exports omitted
        }
        "#,
    );

    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "1.0.0",
              components: {{
                child: "{child}",
              }},
              provides: {{
                api: {{ kind: "http" }},
              }},
              bindings: [
                {{ to: "#child.needs", from: "self.api" }},
              ],
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = Compiler::new(Resolver::new(), Cache::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let err = compiler
        .compile(root_ref, CompileOptions::default())
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not exported") || msg.contains("NotExported"));
}

#[tokio::test]
async fn binding_type_mismatch_is_an_error() {
    let dir = tmp_dir("scenario-type-mismatch");
    let root_path = dir.join("root.json5");
    let child_path = dir.join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "1.0.0",
          slots: { needs: { kind: "http" } },
          exports: ["needs"],
        }
        "#,
    );

    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "1.0.0",
              components: {{
                child: "{child}",
              }},
              provides: {{
                api: {{ kind: "llm" }},
              }},
              bindings: [
                {{ to: "#child.needs", from: "self.api" }},
              ],
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = Compiler::new(Resolver::new(), Cache::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let err = compiler
        .compile(root_ref, CompileOptions::default())
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("type mismatch") || msg.contains("TypeMismatch"));
}

#[tokio::test]
async fn weak_binding_missing_child_is_an_error() {
    let dir = tmp_dir("scenario-weak-missing-child");
    let root_path = dir.join("root.json5");

    write_file(
        &root_path,
        r##"
        {
          manifest_version: "1.0.0",
          slots: { needs: { kind: "http" } },
          bindings: [
            { to: "self.needs", from: "#missing.api", weak: true },
          ],
        }
        "##,
    );

    let compiler = Compiler::new(Resolver::new(), Cache::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let err = compiler
        .compile(root_ref, CompileOptions::default())
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("unknown child") || msg.contains("UnknownChild"));
}

#[tokio::test]
async fn weak_binding_missing_provide_is_an_error() {
    let dir = tmp_dir("scenario-weak-missing-provide");
    let root_path = dir.join("root.json5");

    write_file(
        &root_path,
        r##"
        {
          manifest_version: "1.0.0",
          slots: { needs: { kind: "http" } },
          bindings: [
            { to: "self.needs", from: "self.missing", weak: true },
          ],
        }
        "##,
    );

    let compiler = Compiler::new(Resolver::new(), Cache::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let err = compiler
        .compile(root_ref, CompileOptions::default())
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("unknown provide") || msg.contains("UnknownProvide"));
}

#[tokio::test]
async fn config_schema_is_enforced() {
    let dir = tmp_dir("scenario-config-schema");
    let root_path = dir.join("root.json5");
    let child_path = dir.join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "1.0.0",
          config_schema: {
            type: "object",
            required: ["foo"],
            properties: { foo: { type: "string" } },
          },
        }
        "#,
    );

    // Provide invalid config (foo is number, not string).
    write_file(
        &root_path,
        &format!(
            r#"
            {{
              manifest_version: "1.0.0",
              components: {{
                child: {{
                  manifest: "{child}",
                  config: {{ foo: 123 }},
                }},
              }},
            }}
            "#,
            child = file_url(&child_path),
        ),
    );

    let compiler = Compiler::new(Resolver::new(), Cache::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let err = compiler
        .compile(root_ref, CompileOptions::default())
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid config") || msg.contains("InvalidConfig"));
}

#[tokio::test]
async fn cycle_in_component_tree_is_detected() {
    let dir = tmp_dir("scenario-cycle");
    let a_path = dir.join("a.json5");
    let b_path = dir.join("b.json5");

    // A -> B
    write_file(
        &a_path,
        &format!(
            r#"
            {{
              manifest_version: "1.0.0",
              components: {{
                b: "{b}",
              }},
            }}
            "#,
            b = file_url(&b_path),
        ),
    );

    // B -> A
    write_file(
        &b_path,
        &format!(
            r#"
            {{
              manifest_version: "1.0.0",
              components: {{
                a: "{a}",
              }},
            }}
            "#,
            a = file_url(&a_path),
        ),
    );

    let compiler = Compiler::new(Resolver::new(), Cache::default());
    let root_ref = ManifestRef::from_url(file_url(&a_path));

    let err = compiler
        .compile(root_ref, CompileOptions::default())
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("cycle"));
}

#[tokio::test]
async fn cycle_is_detected_across_url_aliases_with_same_digest() {
    let (url, server) = spawn_alias_cycle_manifest_server();

    let compiler = Compiler::new(Resolver::new(), Cache::default());
    let root_ref = ManifestRef::from_url(url);

    let err = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions {
                    mode: ResolveMode::Online,
                    max_concurrency: 8,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap_err();

    assert!(err.to_string().contains("cycle"));

    server.join().unwrap();
}

#[tokio::test]
async fn digest_pinned_offline_rejects_mismatched_cached_url() {
    let dir = tmp_dir("scenario-digest-offline-mismatch");
    let root_path = dir.join("root.json5");
    let url = file_url(&root_path);

    let v1 = r#"{ manifest_version: "1.0.0" }"#;
    write_file(&root_path, v1);

    let cache = Cache::default();
    let compiler = Compiler::new(Resolver::new(), cache);

    // First compile caches v1 by URL.
    compiler
        .compile(
            ManifestRef::from_url(url.clone()),
            CompileOptions {
                resolve: crate::ResolveOptions {
                    mode: ResolveMode::Online,
                    max_concurrency: 8,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Remove the file to ensure offline depends solely on the cache.
    fs::remove_file(&root_path).unwrap();

    // Pin a digest for different content.
    let v2 = r#"
        {
          manifest_version: "1.0.0",
          provides: { api: { kind: "http" } },
          exports: ["api"],
        }
    "#;
    let digest_v2 = v2.parse::<Manifest>().unwrap().digest();
    let pinned = ManifestRef::new(url, Some(digest_v2));

    // Offline resolution must *not* accept the URL-cached manifest (v1) when digest is pinned.
    let err = compiler
        .compile(
            pinned,
            CompileOptions {
                resolve: crate::ResolveOptions {
                    mode: ResolveMode::Offline,
                    max_concurrency: 8,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap_err();

    assert!(err.to_string().contains("mismatched digest"));
}

#[tokio::test]
async fn digest_pinned_online_ignores_mismatched_cached_url_and_refetches() {
    let dir = tmp_dir("scenario-digest-online-refetch");
    let root_path = dir.join("root.json5");
    let url = file_url(&root_path);

    let v1 = r#"{ manifest_version: "1.0.0" }"#;
    write_file(&root_path, v1);

    let cache = Cache::default();
    let compiler = Compiler::new(Resolver::new(), cache);

    // Cache v1.
    compiler
        .compile(
            ManifestRef::from_url(url.clone()),
            CompileOptions {
                resolve: crate::ResolveOptions {
                    mode: ResolveMode::Online,
                    max_concurrency: 8,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Update the file to v2 and pin that digest.
    let v2 = r#"
        {
          manifest_version: "1.0.0",
          provides: { api: { kind: "http" } },
          exports: ["api"],
        }
    "#;
    write_file(&root_path, v2);
    let digest_v2 = v2.parse::<Manifest>().unwrap().digest();
    let pinned = ManifestRef::new(url.clone(), Some(digest_v2));

    // Online resolution should treat the mismatched URL-cache entry as a miss and re-resolve.
    let scenario = compiler
        .compile(
            pinned,
            CompileOptions {
                resolve: crate::ResolveOptions {
                    mode: ResolveMode::Online,
                    max_concurrency: 8,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let root_component = &scenario.components[scenario.root.0];
    assert_eq!(root_component.digest, digest_v2);
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

impl Backend for CountingBackend {
    fn resolve_url<'a>(
        &'a self,
        url: &'a Url,
    ) -> Pin<Box<dyn Future<Output = Result<Resolution, amber_resolver::Error>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let url = url.clone();

        Box::pin(async move {
            // Force at least one yield so sibling resolutions can overlap.
            tokio::task::yield_now().await;

            let manifest: Manifest = r#"{ manifest_version: "1.0.0" }"#.parse().unwrap();
            Ok(Resolution {
                url,
                manifest,
                cacheability: Cacheability::ByDigestOnly,
            })
        })
    }
}

#[tokio::test]
async fn resolution_deduplicates_inflight_requests() {
    let dir = tmp_dir("scenario-inflight-dedup");
    let root_path = dir.join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "1.0.0",
          components: {
            a: "count://same",
            b: "count://same",
          }
        }
        "#,
    );

    let backend = Arc::new(CountingBackend::new());
    let resolver = Resolver::new().with_remote(RemoteResolver::new(["count"], backend.clone()));

    let compiler = Compiler::new(resolver, Cache::default());
    let root_ref = ManifestRef::from_url(file_url(&root_path));

    let scenario = compiler
        .compile(
            root_ref,
            CompileOptions {
                resolve: crate::ResolveOptions {
                    mode: ResolveMode::Online,
                    max_concurrency: 8,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(scenario.components.len(), 3);

    // The shared manifest URL should have been resolved exactly once during a single compile.
    assert_eq!(backend.call_count(), 1);
}
