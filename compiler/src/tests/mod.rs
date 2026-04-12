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

mod bundle;
mod features;
use self::features::CountingBackend;
mod lints;
mod resolution;
mod storage;
mod validation;
