use std::{env, net::SocketAddr, sync::Arc};

use axum::{Router, body::Body, extract::State, routing::any};
use base64::Engine as _;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Uri, header};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde::Deserialize;
use thiserror::Error;
use tokio::net::TcpListener;
use url::Url;

#[derive(Debug, Error)]
pub enum RouterError {
    #[error("missing router config (set AMBER_ROUTER_CONFIG_B64 or AMBER_ROUTER_CONFIG_JSON)")]
    MissingConfig,
    #[error("invalid router config: {0}")]
    InvalidConfig(String),
    #[error("failed to bind {addr}: {source}")]
    BindFailed {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub struct RouterConfig {
    #[serde(default)]
    pub external_slots: Vec<ExternalSlotConfig>,
    #[serde(default)]
    pub exports: Vec<ExportConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExternalSlotConfig {
    pub name: String,
    pub listen_port: u16,
    pub url_env: String,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExportConfig {
    pub name: String,
    pub listen_port: u16,
    pub target_url: String,
}

#[derive(Clone)]
struct RouteState {
    client: HttpClient,
    target: RouteTarget,
}

type HttpClient = Client<HttpConnector, Body>;

#[derive(Clone, Debug)]
enum RouteTarget {
    External {
        name: String,
        url_env: String,
        optional: bool,
    },
    Export {
        target: Url,
    },
}

impl RouterConfig {
    pub fn from_env() -> Result<Self, RouterError> {
        if let Ok(b64) = env::var("AMBER_ROUTER_CONFIG_B64") {
            if b64.trim().is_empty() {
                return Err(RouterError::MissingConfig);
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|err| RouterError::InvalidConfig(err.to_string()))?;
            let parsed = serde_json::from_slice(&decoded)
                .map_err(|err| RouterError::InvalidConfig(err.to_string()))?;
            return Ok(parsed);
        }

        if let Ok(raw) = env::var("AMBER_ROUTER_CONFIG_JSON") {
            if raw.trim().is_empty() {
                return Err(RouterError::MissingConfig);
            }
            let parsed = serde_json::from_str(&raw)
                .map_err(|err| RouterError::InvalidConfig(err.to_string()))?;
            return Ok(parsed);
        }

        Err(RouterError::MissingConfig)
    }
}

pub async fn run(config: RouterConfig) -> Result<(), RouterError> {
    let client = build_client();
    let client = Arc::new(client);

    let mut handles = Vec::new();

    for slot in &config.external_slots {
        let target = RouteTarget::External {
            name: slot.name.clone(),
            url_env: slot.url_env.clone(),
            optional: slot.optional,
        };
        let addr = SocketAddr::from(([0, 0, 0, 0], slot.listen_port));
        handles.push(spawn_listener(addr, client.clone(), target).await?);
    }

    for export in &config.exports {
        let target = Url::parse(&export.target_url)
            .map_err(|err| RouterError::InvalidConfig(err.to_string()))?;
        let target = RouteTarget::Export { target };
        let addr = SocketAddr::from(([0, 0, 0, 0], export.listen_port));
        handles.push(spawn_listener(addr, client.clone(), target).await?);
    }

    for handle in handles {
        if let Err(err) = handle.await {
            eprintln!("router task failed: {err}");
        }
    }

    Ok(())
}

async fn spawn_listener(
    addr: SocketAddr,
    client: Arc<HttpClient>,
    target: RouteTarget,
) -> Result<tokio::task::JoinHandle<()>, RouterError> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| RouterError::BindFailed { addr, source })?;

    let state = RouteState {
        client: (*client).clone(),
        target,
    };

    let app = Router::new()
        .fallback(any(proxy_handler))
        .with_state(Arc::new(state));

    let handle = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            eprintln!("router listener failed on {addr}: {err}");
        }
    });

    Ok(handle)
}

fn build_client() -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    Client::builder(TokioExecutor::new()).build(connector)
}

async fn proxy_handler(State(state): State<Arc<RouteState>>, req: Request<Body>) -> Response<Body> {
    let target_url = match resolve_target_url(&state.target, &req) {
        Ok(url) => url,
        Err(err) => return err,
    };

    let mut parts = req.into_parts();
    let Some(host) = target_url.host_str() else {
        return error_response(StatusCode::BAD_GATEWAY, "target url missing host");
    };

    let host_header = match target_url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };

    parts.0.uri = match Uri::try_from(target_url.as_str()) {
        Ok(uri) => uri,
        Err(_) => return error_response(StatusCode::BAD_GATEWAY, "invalid target url"),
    };

    sanitize_request_headers(&mut parts.0.headers, &host_header);

    let proxied = Request::from_parts(parts.0, parts.1);

    let response = match state.client.request(proxied).await {
        Ok(resp) => resp,
        Err(err) => {
            eprintln!("router request failed: {err}");
            return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };

    let mut parts = response.into_parts();
    sanitize_response_headers(&mut parts.0.headers);
    let body = Body::new(parts.1);
    Response::from_parts(parts.0, body)
}

#[allow(clippy::result_large_err)]
fn resolve_target_url(target: &RouteTarget, req: &Request<Body>) -> Result<Url, Response<Body>> {
    match target {
        RouteTarget::External {
            name,
            url_env,
            optional,
        } => {
            let url = match env::var(url_env) {
                Ok(value) if !value.trim().is_empty() => value,
                _ => {
                    let message = if *optional {
                        format!("external slot {name} is optional and not configured")
                    } else {
                        format!("external slot {name} is not configured")
                    };
                    return Err(error_response(StatusCode::SERVICE_UNAVAILABLE, &message));
                }
            };
            let base = Url::parse(&url).map_err(|err| {
                error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("invalid external slot url for {name}: {err}"),
                )
            })?;
            Ok(join_url(&base, req.uri()))
        }
        RouteTarget::Export { target } => {
            let base = target.clone();
            Ok(join_url(&base, req.uri()))
        }
    }
}

fn join_url(base: &Url, uri: &Uri) -> Url {
    let mut out = base.clone();
    let base_path = base.path();
    let req_path = uri.path();
    let joined = join_paths(base_path, req_path);
    out.set_path(&joined);
    out.set_query(uri.query());
    out
}

fn join_paths(base: &str, req: &str) -> String {
    let base = base.trim_end_matches('/');
    let req = req.trim_start_matches('/');

    let combined = if base.is_empty() {
        if req.is_empty() {
            "/".to_string()
        } else {
            format!("/{req}")
        }
    } else if req.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{req}")
    };

    if combined.starts_with('/') {
        combined
    } else {
        format!("/{combined}")
    }
}

fn sanitize_request_headers(headers: &mut HeaderMap, host: &str) {
    remove_hop_by_hop(headers);
    headers.remove(header::HOST);
    if let Ok(value) = HeaderValue::from_str(host) {
        headers.insert(header::HOST, value);
    }
}

fn sanitize_response_headers(headers: &mut HeaderMap) {
    remove_hop_by_hop(headers);
}

fn remove_hop_by_hop(headers: &mut HeaderMap) {
    const HOP_HEADERS: [&str; 8] = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ];
    for name in HOP_HEADERS {
        headers.remove(name);
    }
}

fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    let mut res = Response::new(Body::from(message.to_string()));
    *res.status_mut() = status;
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_paths_handles_root() {
        assert_eq!(join_paths("/", "/foo"), "/foo");
        assert_eq!(join_paths("", "/foo"), "/foo");
        assert_eq!(join_paths("/", "/"), "/");
    }

    #[test]
    fn join_paths_preserves_base_prefix() {
        assert_eq!(join_paths("/v1", "/chat"), "/v1/chat");
        assert_eq!(join_paths("/v1/", "/chat"), "/v1/chat");
        assert_eq!(join_paths("/v1", "/"), "/v1");
    }

    #[test]
    fn config_from_env_prefers_b64() {
        unsafe {
            env::set_var(
                "AMBER_ROUTER_CONFIG_B64",
                base64::engine::general_purpose::STANDARD
                    .encode(r#"{"external_slots":[],"exports":[]}"#),
            );
            env::set_var("AMBER_ROUTER_CONFIG_JSON", "{}");
        }
        let cfg = RouterConfig::from_env().expect("config");
        assert!(cfg.external_slots.is_empty());
        unsafe {
            env::remove_var("AMBER_ROUTER_CONFIG_B64");
            env::remove_var("AMBER_ROUTER_CONFIG_JSON");
        }
    }
}
