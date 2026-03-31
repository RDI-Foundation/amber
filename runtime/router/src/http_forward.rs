use super::*;

pub(super) fn configure_http_external_request(
    request_parts: &mut http::request::Parts,
    target: &ResolvedHttpExternalTarget,
) -> Result<String, Box<Response<BoxBody>>> {
    match target {
        ResolvedHttpExternalTarget::Http(target_url) => {
            let Some(host) = target_url.host_str() else {
                return Err(Box::new(error_response(
                    StatusCode::BAD_GATEWAY,
                    "target url missing host",
                )));
            };
            request_parts.uri = Uri::try_from(target_url.as_str()).map_err(|_| {
                Box::new(error_response(
                    StatusCode::BAD_GATEWAY,
                    "invalid target url",
                ))
            })?;
            Ok(match target_url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
        }
        ResolvedHttpExternalTarget::Mesh { .. } => Ok(outgoing_host_header(
            &request_parts.uri,
            &request_parts.headers,
        )),
    }
}

pub(super) async fn send_request_to_http_external_target(
    state: &HttpProxyState,
    target: &ResolvedHttpExternalTarget,
    request: Request<BoxBody>,
) -> Result<Response<Incoming>, String> {
    match target {
        ResolvedHttpExternalTarget::Http(_) => {
            clear_mesh_http_upstream(state).await;
            state
                .client
                .request(request)
                .await
                .map_err(|err| err.to_string())
        }
        ResolvedHttpExternalTarget::Mesh { target_url, mesh } => {
            send_request_to_mesh_http_upstream(state, target_url, mesh, request).await
        }
    }
}

pub(super) async fn clear_mesh_http_upstream(state: &HttpProxyState) {
    state.mesh_upstream.lock().await.take();
}

pub(super) async fn send_http1_request(
    sender: &mut client_http1::SendRequest<BoxBody>,
    request: Request<BoxBody>,
) -> hyper::Result<Response<Incoming>> {
    sender.ready().await?;
    sender.send_request(request).await
}

pub(super) async fn send_request_to_mesh_http_upstream(
    state: &HttpProxyState,
    target_url: &str,
    mesh: &MeshExternalTarget,
    request: Request<BoxBody>,
) -> Result<Response<Incoming>, String> {
    let mut upstream = state.mesh_upstream.lock().await;
    if !upstream
        .as_ref()
        .is_some_and(|cached| cached.is_reusable_for(target_url))
    {
        *upstream = Some(
            connect_mesh_http_upstream(
                target_url.to_string(),
                mesh,
                &state.target.name,
                state.config.as_ref(),
            )
            .await
            .map_err(|err| err.to_string())?,
        );
    }

    let response = {
        let cached = upstream
            .as_mut()
            .expect("mesh upstream must exist after initialization");
        send_http1_request(&mut cached.sender, request).await
    };
    if response.is_err() {
        upstream.take();
    }
    response.map_err(|err| err.to_string())
}

pub(super) async fn connect_mesh_http_upstream(
    target_url: String,
    mesh: &MeshExternalTarget,
    capability: &str,
    config: &MeshConfig,
) -> Result<MeshHttpUpstream, RouterError> {
    let mut outbound =
        connect_noise_with_key(&mesh.peer_addr, &mesh.peer_id, mesh.peer_key, config).await?;
    let open = OpenFrame {
        route_id: mesh
            .route_id
            .clone()
            .unwrap_or_else(|| component_route_id(&mesh.peer_id, capability, MeshProtocol::Http)),
        capability: mesh
            .capability
            .clone()
            .unwrap_or_else(|| capability.to_string()),
        protocol: MeshProtocol::Http,
        slot: None,
        capability_kind: None,
        capability_profile: None,
    };
    outbound.send_open(&open).await?;

    let (local, remote) = duplex(64 * 1024);
    let bridge_task =
        tokio::spawn(async move { proxy_noise_to_plain(&mut outbound, remote).await });
    let (sender, conn) = client_http1::handshake(TokioIo::new(local))
        .await
        .map_err(|err| {
            RouterError::Transport(format!("external mesh upstream handshake failed: {err}"))
        })?;
    let conn_task = tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::warn!(
                target: "amber.internal",
                "external mesh upstream connection failed: {err}"
            );
        }
    });

    Ok(MeshHttpUpstream {
        target_url,
        sender,
        conn_task,
        bridge_task,
    })
}

pub(super) async fn proxy_outbound_http_request(
    state: OutboundHttpProxyState,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    proxy_http_request_to_noise(RewriteFlow::Outbound, state, req).await
}

pub(super) async fn proxy_inbound_http_request_to_noise(
    state: OutboundHttpProxyState,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    proxy_http_request_to_noise(RewriteFlow::Inbound, state, req).await
}

pub(super) fn outgoing_host_header(uri: &Uri, headers: &HeaderMap) -> String {
    uri.authority()
        .map(|value| value.as_str().trim().to_string())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.trim().to_string())
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

pub(super) fn strip_request_body_validators(headers: &mut HeaderMap) {
    headers.remove(http::header::HeaderName::from_static("content-md5"));
    headers.remove(http::header::HeaderName::from_static("digest"));
}

pub(super) fn strip_response_body_validators(headers: &mut HeaderMap) {
    headers.remove(header::ETAG);
    headers.remove(header::LAST_MODIFIED);
    headers.remove(http::header::HeaderName::from_static("content-md5"));
    headers.remove(http::header::HeaderName::from_static("digest"));
}

pub(super) fn content_length_header(length: usize) -> HeaderValue {
    HeaderValue::from_str(&length.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0"))
}

pub(super) fn collect_request_stream_rewriters(
    plugins: &[&dyn HttpExchangePlugin],
    ctx: &RewriteContext,
    parts: &http::request::Parts,
) -> Vec<Box<dyn StreamBodyRewriter>> {
    plugins
        .iter()
        .filter_map(|plugin| plugin.request_stream_rewriter(ctx, parts))
        .collect()
}

pub(super) fn collect_response_stream_rewriters(
    plugins: &[&dyn HttpExchangePlugin],
    ctx: &RewriteContext,
    parts: &http::response::Parts,
) -> Vec<Box<dyn StreamBodyRewriter>> {
    plugins
        .iter()
        .filter_map(|plugin| plugin.response_stream_rewriter(ctx, parts))
        .collect()
}

pub(super) fn is_identity_or_absent_content_encoding(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|raw| {
            raw.split(',').all(|item| {
                let encoding = item.split(';').next().unwrap_or("").trim();
                encoding.is_empty() || encoding.eq_ignore_ascii_case("identity")
            })
        })
        .unwrap_or(true)
}

pub(super) fn rewrite_stream_body(
    body: Incoming,
    rewriters: Vec<Box<dyn StreamBodyRewriter>>,
) -> BoxBody {
    let stream = futures::stream::try_unfold(
        (
            BodyStream::new(body),
            rewriters,
            false,
            false,
            VecDeque::<Frame<Bytes>>::new(),
        ),
        |(mut source, mut rewriters, mut finished, mut rewriting_complete, mut queue)| async move {
            loop {
                if let Some(frame) = queue.pop_front() {
                    return Ok(Some((
                        frame,
                        (source, rewriters, finished, rewriting_complete, queue),
                    )));
                }

                if finished {
                    return Ok(None);
                }

                match source.next().await {
                    Some(Ok(frame)) => match frame.into_data() {
                        Ok(chunk) => {
                            if rewriting_complete {
                                queue.push_back(Frame::data(chunk));
                                continue;
                            }

                            let mut rewritten = chunk.to_vec();
                            for rewriter in &mut rewriters {
                                rewritten = rewriter.rewrite_chunk(rewritten.as_slice(), false);
                            }
                            if rewritten.is_empty() {
                                continue;
                            }
                            queue.push_back(Frame::data(Bytes::from(rewritten)));
                        }
                        Err(frame) => {
                            if !rewriting_complete {
                                let mut flushed = Vec::new();
                                for rewriter in &mut rewriters {
                                    flushed = rewriter.rewrite_chunk(flushed.as_slice(), true);
                                }
                                if !flushed.is_empty() {
                                    queue.push_back(Frame::data(Bytes::from(flushed)));
                                }
                                rewriting_complete = true;
                            }
                            queue.push_back(frame);
                        }
                    },
                    Some(Err(err)) => return Err(err),
                    None => {
                        finished = true;
                        if rewriting_complete {
                            continue;
                        }

                        let mut flushed = Vec::new();
                        for rewriter in &mut rewriters {
                            flushed = rewriter.rewrite_chunk(flushed.as_slice(), true);
                        }
                        if !flushed.is_empty() {
                            queue.push_back(Frame::data(Bytes::from(flushed)));
                        }
                        rewriting_complete = true;
                    }
                }
            }
        },
    );

    http_body_util::BodyExt::map_err(StreamBody::new(stream), |err| err).boxed()
}

pub(super) fn apply_request_filters(
    plugins: &[&dyn HttpExchangePlugin],
    ctx: &RewriteContext,
    parts: &http::request::Parts,
    body: Option<&[u8]>,
) -> Option<Response<BoxBody>> {
    for plugin in plugins {
        match plugin.filter_request(ctx, parts, body) {
            FilterDecision::Continue => {}
            FilterDecision::Reject { status, message } => {
                return Some(error_response(status, &message));
            }
        }
    }
    None
}

pub(super) fn apply_response_filters(
    plugins: &[&dyn HttpExchangePlugin],
    ctx: &RewriteContext,
    parts: &http::response::Parts,
    body: Option<&[u8]>,
) -> Option<Response<BoxBody>> {
    for plugin in plugins {
        match plugin.filter_response(ctx, parts, body) {
            FilterDecision::Continue => {}
            FilterDecision::Reject { status, message } => {
                return Some(error_response(status, &message));
            }
        }
    }
    None
}
