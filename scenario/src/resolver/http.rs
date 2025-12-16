use std::io;

use url::Url;

use super::{Error, Resolution};
use crate::cache::Cacheability;

#[derive(Clone, Debug, Default)]
pub struct HttpResolver {
    client: reqwest::Client,
}

impl HttpResolver {
    pub fn new() -> Self {
        Default::default()
    }

    pub(super) async fn resolve_url(&self, url: &Url) -> Result<Resolution, Error> {
        let res = self
            .client
            .get(url.clone())
            .send()
            .await?
            .error_for_status()?;
        let resolved_url = res.url().clone();

        let bytes = res.bytes().await?;
        let body = std::str::from_utf8(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let manifest = body.parse()?;

        Ok(Resolution {
            url: resolved_url,
            manifest,
            cacheability: Cacheability::ByDigestOnly,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        net::{Shutdown, TcpListener},
        time::{Duration, Instant},
    };

    use url::Url;

    use crate::{manifest::Manifest, resolver::Resolver};

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
        let contents = r#"{ manifest_version: "1.0.0" }"#.to_string();
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
        let contents = r#"{ manifest_version: "1.0.0" }"#.to_string();
        let (url, server) = spawn_redirecting_manifest_server(contents.clone());

        let resolver = Resolver::new();
        let manifest: Manifest = contents.parse().unwrap();
        crate::resolver::tests::assert_digest_mismatch_errors(&resolver, &url, &manifest).await;

        server.join().unwrap();
    }
}
