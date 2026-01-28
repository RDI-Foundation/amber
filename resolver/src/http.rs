use std::{
    io,
    sync::{Arc, OnceLock},
    time::Duration,
};

use futures::StreamExt;
use reqwest::header::CONTENT_TYPE;
use url::Url;

use super::{Error, Resolution};

#[derive(Clone, Debug)]
pub struct HttpResolver {
    client: Arc<OnceLock<reqwest::Client>>,
    options: HttpResolverOptions,
}

impl HttpResolver {
    pub fn new() -> Self {
        Self::with_options(HttpResolverOptions::default())
    }

    pub fn with_options(options: HttpResolverOptions) -> Self {
        Self {
            client: Arc::new(OnceLock::new()),
            options,
        }
    }

    #[allow(clippy::result_large_err)]
    fn client(&self) -> Result<&reqwest::Client, Error> {
        self.client
            .get_or_try_init(|| {
                let mut builder = reqwest::Client::builder()
                    .connect_timeout(self.options.connect_timeout)
                    .timeout(self.options.request_timeout);
                if let Some(read_timeout) = self.options.read_timeout {
                    builder = builder.read_timeout(read_timeout);
                }
                builder.build()
            })
            .map_err(Error::from)
    }

    pub(super) async fn resolve_url(&self, url: &Url) -> Result<Resolution, Error> {
        let res = self
            .client()?
            .get(url.clone())
            .send()
            .await?
            .error_for_status()?;
        let resolved_url = res.url().clone();

        let max_body_bytes = self.options.max_body_bytes;
        if let Some(content_length) = res.content_length()
            && content_length > max_body_bytes as u64
        {
            return Err(Error::ResponseTooLarge {
                url: resolved_url,
                size: content_length,
                max_bytes: max_body_bytes,
            });
        }

        if self.options.content_type_policy == ContentTypePolicy::RequireTextOrJson {
            let content_type =
                res.headers()
                    .get(CONTENT_TYPE)
                    .ok_or_else(|| Error::MissingContentType {
                        url: resolved_url.clone(),
                    })?;
            let content_type =
                content_type
                    .to_str()
                    .map_err(|_| Error::UnsupportedContentType {
                        url: resolved_url.clone(),
                        content_type: "<invalid utf-8>".to_string(),
                    })?;
            let content_type = content_type
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            if !is_allowed_content_type(&content_type) {
                return Err(Error::UnsupportedContentType {
                    url: resolved_url.clone(),
                    content_type,
                });
            }
        }

        let mut body = Vec::new();
        let mut size = 0usize;
        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if size + chunk.len() > max_body_bytes {
                return Err(Error::ResponseTooLarge {
                    url: resolved_url.clone(),
                    size: (size + chunk.len()) as u64,
                    max_bytes: max_body_bytes,
                });
            }
            body.extend_from_slice(&chunk);
            size += chunk.len();
        }

        let body = std::str::from_utf8(&body)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let source: Arc<str> = body.into();
        let parsed = amber_manifest::ParsedManifest::parse_named(resolved_url.as_str(), source)?;
        let manifest = parsed.manifest;
        let source = parsed.source;
        let spans = parsed.spans;

        Ok(Resolution {
            url: resolved_url,
            manifest,
            source,
            spans,
        })
    }
}

impl Default for HttpResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentTypePolicy {
    Any,
    RequireTextOrJson,
}

#[derive(Clone, Debug)]
pub struct HttpResolverOptions {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub read_timeout: Option<Duration>,
    pub max_body_bytes: usize,
    pub content_type_policy: ContentTypePolicy,
}

impl Default for HttpResolverOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            read_timeout: Some(Duration::from_secs(30)),
            max_body_bytes: 1024 * 1024,
            content_type_policy: ContentTypePolicy::Any,
        }
    }
}

fn is_allowed_content_type(content_type: &str) -> bool {
    if content_type.starts_with("text/") {
        return true;
    }
    if content_type == "application/json" || content_type == "application/json5" {
        return true;
    }
    content_type.ends_with("+json")
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        net::{Shutdown, TcpListener},
        time::{Duration, Instant},
    };

    use amber_manifest::Manifest;
    use url::Url;

    use crate::Resolver;

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

    fn spawn_redirecting_manifest_server(
        manifest_body: String,
    ) -> (Url, std::thread::JoinHandle<()>) {
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
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nConnection: \
                 close\r\nContent-Length: 0\r\n\r\n"
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

    #[tokio::test]
    async fn follows_redirect_and_returns_final_url() {
        let contents = r#"{ manifest_version: "0.1.0" }"#.to_string();
        let (url, server) = spawn_redirecting_manifest_server(contents.clone());

        let resolver = Resolver::new();
        let res = resolver.resolve(&url, None).await.unwrap();

        let expected: Manifest = contents.parse().unwrap();
        assert_eq!(res.url.path(), "/final");
        assert_eq!(res.manifest, expected);

        server.join().unwrap();
    }

    #[tokio::test]
    async fn digest_mismatch_errors() {
        let contents = r#"{ manifest_version: "0.1.0" }"#.to_string();
        let (url, server) = spawn_redirecting_manifest_server(contents.clone());

        let resolver = Resolver::new();
        let manifest: Manifest = contents.parse().unwrap();
        let final_url = url.join("/final").unwrap();
        crate::tests::assert_digest_mismatch_errors(&resolver, &url, &final_url, &manifest).await;

        server.join().unwrap();
    }
}
