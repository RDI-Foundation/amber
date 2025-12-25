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
use amber_resolver::{Backend, RemoteResolver, Resolution, Resolver};
use amber_scenario::graph;
use url::Url;

use crate::{CompileOptions, Compiler, DigestStore, ResolverRegistry};

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
    let root_path = dir.join("root.json5");
    let a_path = dir.join("a.json5");
    let b_path = dir.join("b.json5");

    write_file(
        &a_path,
        r#"
        {
          manifest_version: "0.1.0",
          provides: { api: { kind: "http" } },
          exports: ["api"],
        }
        "#,
    );

    write_file(
        &b_path,
        r#"
        {
          manifest_version: "0.1.0",
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
            },
        )
        .await
        .unwrap_err();

    assert!(err.to_string().contains("io error"));
}

#[tokio::test]
async fn compile_twice_with_digest_pins_succeeds_when_sources_removed() {
    let dir = tmp_dir("scenario-compile-digest-pins");
    let root_path = dir.join("root.json5");
    let a_path = dir.join("a.json5");
    let b_path = dir.join("b.json5");

    let a_contents = r#"
        {
          manifest_version: "0.1.0",
          provides: { api: { kind: "http" } },
          exports: ["api"],
        }
    "#;
    let b_contents = r#"
        {
          manifest_version: "0.1.0",
          provides: { llm: { kind: "llm" } },
          exports: ["llm"],
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
            },
        )
        .await
        .unwrap();

    let root_id = compilation.scenario.root;
    let prov = &compilation.provenance.components[root_id.0];
    assert_eq!(prov.declared_ref.url, url);
    assert_eq!(prov.declared_ref.digest, Some(digest));
    assert_eq!(prov.observed_url.as_ref().map(|u| u.path()), Some("/final"));

    server.join().unwrap();
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
            },
        )
        .await
        .unwrap_err();

    assert!(err.to_string().contains("cycle"));

    server.join().unwrap();
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
            tokio::task::yield_now().await;
            let manifest: Manifest = r#"{ manifest_version: "0.1.0" }"#.parse().unwrap();
            Ok(Resolution { url, manifest })
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
    let root_path = dir.join("root.json5");

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
            },
        )
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 3);
    assert_eq!(backend.call_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compile_is_spawnable_on_multithread_runtime() {
    let dir = tmp_dir("scenario-compile-send");
    let root_path = dir.join("root.json5");

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
