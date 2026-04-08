use super::*;

#[allow(clippy::result_large_err)]
pub(super) async fn resolve_http_external_target(
    state: &HttpProxyState,
    uri: &Uri,
) -> Result<ResolvedHttpExternalTarget, Response<BoxBody>> {
    let override_url = {
        let overrides = state.external_overrides.read().await;
        overrides.get(&state.target.name).cloned()
    };
    let resolved =
        resolve_http_external_target_with_override(&state.target, override_url.as_deref(), uri)?;
    if let ResolvedHttpExternalTarget::Http(url) = &resolved {
        let Some(host) = url.host_str() else {
            return Err(error_response(
                StatusCode::BAD_GATEWAY,
                "external slot url missing host",
            ));
        };
        let Some(port) = url.port_or_known_default() else {
            return Err(error_response(
                StatusCode::BAD_GATEWAY,
                "external slot url missing port",
            ));
        };
        let addrs = resolve_external_host_with_policy(
            host,
            port,
            allows_loopback_external_target(&state.target),
        )
        .await
        .map_err(|err| error_response(StatusCode::BAD_GATEWAY, &err))?;
        pin_vetted_external_host(&state.vetted_external_addrs, host, &addrs).await;
    }
    Ok(resolved)
}

#[allow(clippy::result_large_err)]
pub(super) fn resolve_http_external_target_with_override(
    target: &ExternalTarget,
    override_url: Option<&str>,
    uri: &Uri,
) -> Result<ResolvedHttpExternalTarget, Response<BoxBody>> {
    let url = configured_external_url(target, override_url).ok_or_else(|| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &external_slot_not_configured_message(target),
        )
    })?;
    if url.starts_with("mesh://") {
        let mesh = parse_mesh_external(&url).map_err(|err| {
            error_response(
                StatusCode::BAD_GATEWAY,
                &format!("external slot url is invalid: {err}"),
            )
        })?;
        return Ok(ResolvedHttpExternalTarget::Mesh {
            target_url: url,
            mesh,
        });
    }

    let base = Url::parse(&url).map_err(|err| {
        error_response(
            StatusCode::BAD_GATEWAY,
            &format!("external slot url is invalid: {err}"),
        )
    })?;

    if !is_http_scheme(&base) {
        return Err(error_response(
            StatusCode::BAD_GATEWAY,
            "external slot url must be http/https",
        ));
    }
    let Some(host) = base.host_str() else {
        return Err(error_response(
            StatusCode::BAD_GATEWAY,
            "external slot url missing host",
        ));
    };
    validate_external_ip_literal(host, allows_loopback_external_target(target))
        .map_err(|err| error_response(StatusCode::BAD_GATEWAY, &err))?;

    Ok(ResolvedHttpExternalTarget::Http(join_url(&base, uri)))
}

pub(super) fn resolve_tcp_target(target: &ExternalTarget) -> Result<(String, u16), RouterError> {
    let url = configured_external_url(target, target.url_override.as_deref())
        .ok_or_else(|| RouterError::InvalidConfig(external_slot_not_configured_message(target)))?;

    let parsed = Url::parse(&url).map_err(|err| {
        RouterError::InvalidConfig(format!("external slot url is invalid: {err}"))
    })?;
    if parsed.scheme() != "tcp" {
        return Err(RouterError::InvalidConfig(
            "external tcp target url must use tcp://".to_string(),
        ));
    }
    let host = parsed.host_str().ok_or_else(|| {
        RouterError::InvalidConfig("external tcp target url missing host".to_string())
    })?;
    let port = parsed.port().ok_or_else(|| {
        RouterError::InvalidConfig("external tcp target url missing port".to_string())
    })?;
    validate_external_ip_literal(host, allows_loopback_external_target(target))
        .map_err(RouterError::InvalidConfig)?;

    Ok((host.to_string(), port))
}

fn validate_external_ip_literal(host: &str, allow_loopback: bool) -> Result<(), String> {
    let Ok(ip) = host.parse::<IpAddr>() else {
        return Ok(());
    };
    if !allow_loopback && is_disallowed_external_ip(ip) {
        return Err(format!(
            "external target {host} resolves to a disallowed address: {ip}"
        ));
    }
    Ok(())
}

pub(super) async fn resolve_external_host(
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, String> {
    resolve_external_host_with_policy(host, port, false).await
}

pub(super) async fn resolve_external_host_with_policy(
    host: &str,
    port: u16,
    allow_loopback: bool,
) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !allow_loopback && is_disallowed_external_ip(ip) {
            return Err(format!(
                "external target {host} resolves to a disallowed address: {ip}"
            ));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| format!("failed to resolve external target {host}:{port}: {err}"))?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(format!(
            "external target {host}:{port} did not resolve to an address"
        ));
    }
    for addr in &addrs {
        let ip = addr.ip();
        if !allow_loopback && is_disallowed_external_ip(ip) {
            return Err(format!(
                "external target {host}:{port} resolves to a disallowed address: {ip}"
            ));
        }
    }
    Ok(addrs)
}

pub(super) async fn connect_external_addrs(
    addrs: &[SocketAddr],
) -> io::Result<tokio::net::TcpStream> {
    let mut last_err = None;
    for addr in addrs {
        match tokio::net::TcpStream::connect(*addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "external target did not resolve to an address",
        )
    }))
}

async fn pin_vetted_external_host(
    vetted_external_addrs: &VettedExternalAddrs,
    host: &str,
    addrs: &[SocketAddr],
) {
    let pinned_addrs = addrs
        .iter()
        .map(|addr| SocketAddr::new(addr.ip(), 0))
        .collect::<Vec<_>>();
    vetted_external_addrs
        .write()
        .await
        .insert(host.to_string(), pinned_addrs);
}

fn is_disallowed_external_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unicast_link_local() {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback() || v4.is_link_local();
            }
            false
        }
    }
}

fn allows_loopback_external_target(target: &ExternalTarget) -> bool {
    target.url_env == amber_mesh::FRAMEWORK_COMPONENT_CCS_URL_ENV
        || (target.url_env.starts_with("AMBER_EXTERNAL_SLOT_") && target.url_env.ends_with("_URL"))
}

pub(super) fn join_url(base: &Url, uri: &Uri) -> Url {
    let mut out = base.clone();
    out.set_path(&join_paths(base.path(), uri.path()));
    if out.query().is_none() {
        out.set_query(uri.query());
    }
    out
}

pub(super) fn join_paths(base: &str, req: &str) -> String {
    let base = base.trim_end_matches('/');
    let req = req.trim_start_matches('/');

    let joined = if base.is_empty() {
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

    if joined.starts_with('/') {
        joined
    } else {
        format!("/{joined}")
    }
}

pub(super) fn is_http_scheme(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
}

pub(super) fn parse_mesh_external(value: &str) -> Result<MeshExternalTarget, RouterError> {
    let url = Url::parse(value)
        .map_err(|err| RouterError::InvalidConfig(format!("invalid mesh url: {err}")))?;
    if url.scheme() != "mesh" {
        return Err(RouterError::InvalidConfig(
            "mesh url must use mesh:// scheme".to_string(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| RouterError::InvalidConfig("mesh url missing host".to_string()))?;
    let port = url
        .port()
        .ok_or_else(|| RouterError::InvalidConfig("mesh url missing port".to_string()))?;

    let mut peer_id = None;
    let mut peer_key = None;
    let mut route_id = None;
    let mut capability = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "peer_id" => peer_id = Some(value.to_string()),
            "peer_key" => peer_key = Some(value.to_string()),
            "route_id" => route_id = Some(value.to_string()),
            "capability" => capability = Some(value.to_string()),
            _ => {}
        }
    }
    let peer_id = peer_id
        .ok_or_else(|| RouterError::InvalidConfig("mesh url missing peer_id".to_string()))?;
    let peer_key = peer_key
        .ok_or_else(|| RouterError::InvalidConfig("mesh url missing peer_key".to_string()))?;
    let peer_key = decode_peer_key(&peer_key).map_err(RouterError::InvalidConfig)?;

    Ok(MeshExternalTarget {
        peer_addr: format!("{host}:{port}"),
        peer_id,
        peer_key,
        route_id,
        capability,
    })
}

pub(super) fn error_response(status: StatusCode, message: &str) -> Response<BoxBody> {
    let body = Full::new(Bytes::from(message.to_string()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(body)
        .unwrap_or_else(|_| {
            Response::new(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
        })
}

fn configured_external_url(target: &ExternalTarget, override_url: Option<&str>) -> Option<String> {
    override_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var(&target.url_env).ok().and_then(|value| {
                let trimmed = value.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            })
        })
}

fn external_slot_not_configured_message(target: &ExternalTarget) -> String {
    if target.optional {
        format!(
            "external slot {} is optional and not configured",
            target.name
        )
    } else {
        format!("external slot {} is not configured", target.name)
    }
}

pub(super) fn sanitize_request_headers(headers: &mut HeaderMap, host_header: &str) {
    headers.remove(header::HOST);
    headers.insert(
        header::HOST,
        HeaderValue::from_str(host_header).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    strip_hop_by_hop(headers);
}

pub(super) fn sanitize_response_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop(headers);
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for name in [
        header::CONNECTION,
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        headers.remove(name);
    }
}

pub(super) fn build_client() -> (HttpClient, VettedExternalAddrs) {
    install_default_crypto_provider();
    let vetted_external_addrs = Arc::new(RwLock::new(HashMap::new()));
    let mut http = HttpConnector::new_with_resolver(ExternalHttpResolver {
        vetted_external_addrs: vetted_external_addrs.clone(),
        fallback: GaiResolver::new(),
    });
    http.enforce_http(false);
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    (
        Client::builder(TokioExecutor::new()).build(https),
        vetted_external_addrs,
    )
}

fn install_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
