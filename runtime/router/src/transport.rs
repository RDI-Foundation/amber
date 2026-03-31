use super::*;

#[derive(Clone)]
pub(super) struct NoiseSession {
    state: Arc<Mutex<TransportState>>,
    reader: Arc<Mutex<tokio::net::tcp::OwnedReadHalf>>,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    pub(super) remote_id: Option<String>,
}

impl NoiseSession {
    pub(super) async fn send_open(&self, open: &OpenFrame) -> Result<(), RouterError> {
        let bytes =
            serde_json::to_vec(open).map_err(|err| RouterError::Transport(err.to_string()))?;
        self.send_plain(&bytes).await
    }

    pub(super) async fn recv_open(&mut self) -> Result<OpenFrame, RouterError> {
        let bytes = self
            .recv_plain()
            .await?
            .ok_or_else(|| RouterError::Transport("missing open frame".to_string()))?;
        serde_json::from_slice(&bytes).map_err(|err| RouterError::Transport(err.to_string()))
    }

    async fn send_plain(&self, data: &[u8]) -> Result<(), RouterError> {
        if data.len() > MAX_FRAME {
            return Err(RouterError::Transport("frame too large".to_string()));
        }
        let mut out = vec![0u8; data.len() + 128];
        let len = {
            let mut state = self.state.lock().await;
            state
                .write_message(data, &mut out)
                .map_err(|err| RouterError::Transport(err.to_string()))?
        };
        let mut writer = self.writer.lock().await;
        write_frame(&mut writer, &out[..len]).await?;
        Ok(())
    }

    async fn recv_plain(&self) -> Result<Option<Vec<u8>>, RouterError> {
        let frame = {
            let mut reader = self.reader.lock().await;
            read_frame(&mut reader).await?
        };
        let Some(frame) = frame else {
            return Ok(None);
        };
        let mut buf = vec![0u8; MAX_FRAME];
        let len = {
            let mut state = self.state.lock().await;
            state
                .read_message(&frame, &mut buf)
                .map_err(|err| RouterError::Transport(err.to_string()))?
        };
        buf.truncate(len);
        Ok(Some(buf))
    }

    async fn shutdown(&self) {
        let mut writer = self.writer.lock().await;
        let _ = writer.shutdown().await;
    }
}

pub(super) async fn accept_noise(
    stream: tokio::net::TcpStream,
    keys: &NoiseKeys,
    trust: &TrustBundle,
) -> Result<NoiseSession, RouterError> {
    let (mut reader, mut writer) = stream.into_split();
    let mut builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
    builder = builder.local_private_key(&keys.private);
    let handshake = builder
        .build_responder()
        .map_err(|err| RouterError::Handshake(err.to_string()))?;

    let handshake = perform_handshake(handshake, &mut reader, &mut writer).await?;
    let remote_static = handshake
        .remote_static
        .ok_or_else(|| RouterError::Handshake("missing remote static".to_string()))?;
    let remote_id = trust.id_for_noise_key(&remote_static).await;

    Ok(NoiseSession {
        state: Arc::new(Mutex::new(handshake.transport)),
        reader: Arc::new(Mutex::new(reader)),
        writer: Arc::new(Mutex::new(writer)),
        remote_id,
    })
}

pub(super) async fn connect_noise(
    peer_addr: &str,
    peer_id: &str,
    config: &MeshConfig,
    trust: &TrustBundle,
) -> Result<NoiseSession, RouterError> {
    let remote = trust
        .noise_key(peer_id)
        .await
        .ok_or_else(|| RouterError::Auth(format!("unknown peer {peer_id}")))?;
    connect_noise_with_remote_key(peer_addr, peer_id, remote, config).await
}

pub(super) async fn connect_noise_with_key(
    peer_addr: &str,
    peer_id: &str,
    peer_key: [u8; 32],
    config: &MeshConfig,
) -> Result<NoiseSession, RouterError> {
    let remote = ed25519_public_to_x25519(peer_key)?;
    connect_noise_with_remote_key(peer_addr, peer_id, remote, config).await
}

async fn connect_noise_with_remote_key(
    peer_addr: &str,
    peer_id: &str,
    remote: [u8; 32],
    config: &MeshConfig,
) -> Result<NoiseSession, RouterError> {
    let noise_keys = noise_keys_for_identity(&config.identity)?;
    let stream = tokio::net::TcpStream::connect(peer_addr).await?;
    let (mut reader, mut writer) = stream.into_split();

    let mut builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
    builder = builder
        .local_private_key(&noise_keys.private)
        .remote_public_key(&remote);
    let handshake = builder
        .build_initiator()
        .map_err(|err| RouterError::Handshake(err.to_string()))?;

    let handshake = perform_handshake(handshake, &mut reader, &mut writer).await?;

    Ok(NoiseSession {
        state: Arc::new(Mutex::new(handshake.transport)),
        reader: Arc::new(Mutex::new(reader)),
        writer: Arc::new(Mutex::new(writer)),
        remote_id: Some(peer_id.to_string()),
    })
}

struct HandshakeResult {
    transport: TransportState,
    remote_static: Option<[u8; 32]>,
}

async fn perform_handshake(
    mut handshake: HandshakeState,
    reader: &mut tokio::net::tcp::OwnedReadHalf,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<HandshakeResult, RouterError> {
    let mut in_buf = vec![0u8; MAX_FRAME];
    let mut out_buf = vec![0u8; MAX_FRAME];

    while !handshake.is_handshake_finished() {
        if handshake.is_initiator() {
            let len = handshake
                .write_message(&[], &mut out_buf)
                .map_err(|err| RouterError::Handshake(err.to_string()))?;
            write_frame(writer, &out_buf[..len]).await?;
            if handshake.is_handshake_finished() {
                break;
            }
            let frame = read_frame(reader).await?;
            let frame = frame.ok_or_else(|| RouterError::Handshake("handshake EOF".to_string()))?;
            let _ = handshake
                .read_message(&frame, &mut in_buf)
                .map_err(|err| RouterError::Handshake(err.to_string()))?;
        } else {
            let frame = read_frame(reader).await?;
            let frame = frame.ok_or_else(|| RouterError::Handshake("handshake EOF".to_string()))?;
            let _ = handshake
                .read_message(&frame, &mut in_buf)
                .map_err(|err| RouterError::Handshake(err.to_string()))?;
            if handshake.is_handshake_finished() {
                break;
            }
            let len = handshake
                .write_message(&[], &mut out_buf)
                .map_err(|err| RouterError::Handshake(err.to_string()))?;
            write_frame(writer, &out_buf[..len]).await?;
        }
    }

    let remote_static = handshake.get_remote_static().map(|key| {
        let mut out = [0u8; 32];
        out.copy_from_slice(key);
        out
    });
    let transport = handshake
        .into_transport_mode()
        .map_err(|err| RouterError::Handshake(err.to_string()))?;
    Ok(HandshakeResult {
        transport,
        remote_static,
    })
}

async fn read_frame(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
) -> Result<Option<Vec<u8>>, RouterError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(RouterError::Transport("frame too large".to_string()));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

async fn write_frame(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    data: &[u8],
) -> Result<(), RouterError> {
    let len = u32::try_from(data.len())
        .map_err(|_| RouterError::Transport("frame too large".to_string()))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

pub(super) async fn proxy_noise_to_plain<S>(
    session: &mut NoiseSession,
    plain: S,
) -> Result<(), RouterError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut plain_reader, mut plain_writer) = split(plain);
    let session_in = session.clone();
    let session_out = session.clone();

    let to_plain = tokio::spawn(async move {
        while let Some(bytes) = session_in.recv_plain().await? {
            plain_writer.write_all(&bytes).await?;
        }
        let _ = plain_writer.shutdown().await;
        Ok::<(), RouterError>(())
    });

    let to_noise = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PLAINTEXT];
        loop {
            let n = plain_reader.read(&mut buf).await?;
            if n == 0 {
                session_out.shutdown().await;
                break;
            }
            session_out.send_plain(&buf[..n]).await?;
        }
        Ok::<(), RouterError>(())
    });

    let (left, right) = tokio::join!(to_plain, to_noise);
    left.map_err(|err| RouterError::Transport(err.to_string()))??;
    right.map_err(|err| RouterError::Transport(err.to_string()))??;
    Ok(())
}

pub(super) async fn proxy_noise_to_noise(
    left: &mut NoiseSession,
    right: NoiseSession,
) -> Result<(), RouterError> {
    let left_in = left.clone();
    let left_out = left.clone();
    let right_in = right.clone();
    let right_out = right.clone();

    let to_right = tokio::spawn(async move {
        while let Some(bytes) = left_in.recv_plain().await? {
            right_out.send_plain(&bytes).await?;
        }
        right_out.shutdown().await;
        Ok::<(), RouterError>(())
    });

    let to_left = tokio::spawn(async move {
        while let Some(bytes) = right_in.recv_plain().await? {
            left_out.send_plain(&bytes).await?;
        }
        left_out.shutdown().await;
        Ok::<(), RouterError>(())
    });

    let (left, right) = tokio::join!(to_right, to_left);
    left.map_err(|err| RouterError::Transport(err.to_string()))??;
    right.map_err(|err| RouterError::Transport(err.to_string()))??;
    Ok(())
}

pub(super) async fn proxy_noise_to_external(
    session: &mut NoiseSession,
    labels: HttpExchangeLabels,
    target: ExternalTarget,
    client: Arc<HttpClient>,
    config: Arc<MeshConfig>,
    external_overrides: ExternalOverrides,
    vetted_external_addrs: VettedExternalAddrs,
) -> Result<(), RouterError> {
    let (local, remote) = duplex(64 * 1024);
    let mut noise_session = session.clone();

    let bridge = tokio::spawn(async move { proxy_noise_to_plain(&mut noise_session, local).await });

    let state = HttpProxyState {
        client: (*client).clone(),
        target,
        labels,
        config,
        external_overrides,
        vetted_external_addrs,
        mesh_upstream: Arc::new(Mutex::new(None)),
    };

    let service = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move { Ok::<_, std::convert::Infallible>(proxy_http_request(state, req).await) }
    });

    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(remote), service)
        .await
    {
        return Err(RouterError::Transport(err.to_string()));
    }

    let _ = bridge.await;
    Ok(())
}

pub(super) async fn proxy_noise_to_external_tcp(
    session: &mut NoiseSession,
    target: ExternalTarget,
) -> Result<(), RouterError> {
    let (host, port) = resolve_tcp_target(&target)?;
    let addrs = resolve_external_host(host.as_str(), port)
        .await
        .map_err(RouterError::InvalidConfig)?;
    let upstream = connect_external_addrs(&addrs).await?;
    proxy_noise_to_plain(session, upstream).await
}

pub(super) async fn proxy_noise_to_local_http(
    session: &mut NoiseSession,
    route_id: Arc<str>,
    port: u16,
    client: Arc<HttpClient>,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
    labels: HttpExchangeLabels,
) -> Result<(), RouterError> {
    let (local, remote) = duplex(64 * 1024);
    let mut noise_session = session.clone();

    let bridge = tokio::spawn(async move { proxy_noise_to_plain(&mut noise_session, local).await });

    let base_url = Url::parse(&format!("http://127.0.0.1:{port}"))
        .map_err(|err| RouterError::InvalidConfig(format!("invalid local http target: {err}")))?;
    let state = LocalHttpProxyState {
        client: (*client).clone(),
        base_url,
        plugins,
        route_id,
        labels,
    };

    let service =
        ServiceBuilder::new()
            .layer(CompressionLayer::new())
            .service(tower_service_fn(move |req| {
                let state = state.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(proxy_local_http_request(state, req).await)
                }
            }));
    let service = TowerToHyperService::new(service);

    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(remote), service)
        .await
    {
        return Err(RouterError::Transport(err.to_string()));
    }

    let _ = bridge.await;
    Ok(())
}

pub(super) async fn proxy_noise_to_noise_http(
    session: &mut NoiseSession,
    outbound: NoiseSession,
    route_id: Arc<str>,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
    labels: HttpExchangeLabels,
) -> Result<(), RouterError> {
    let (incoming_local, incoming_remote) = duplex(64 * 1024);
    let mut incoming_session = session.clone();
    let incoming_bridge =
        tokio::spawn(
            async move { proxy_noise_to_plain(&mut incoming_session, incoming_local).await },
        );

    let (outgoing_local, outgoing_remote) = duplex(64 * 1024);
    let mut outgoing_session = outbound.clone();
    let outgoing_bridge =
        tokio::spawn(
            async move { proxy_noise_to_plain(&mut outgoing_session, outgoing_remote).await },
        );

    let (sender, conn) = client_http1::handshake(TokioIo::new(outgoing_local))
        .await
        .map_err(|err| {
            RouterError::Transport(format!("outbound upstream handshake failed: {err}"))
        })?;
    let conn_task = tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::warn!(target: "amber.internal", "outbound upstream connection failed: {err}");
        }
    });

    let state = OutboundHttpProxyState {
        upstream: Arc::new(Mutex::new(sender)),
        plugins,
        route_id,
        labels,
    };

    let service = ServiceBuilder::new()
        .layer(CompressionLayer::new())
        .service(tower_service_fn(move |req| {
            let state = state.clone();
            async move {
                Ok::<_, std::convert::Infallible>(
                    proxy_inbound_http_request_to_noise(state, req).await,
                )
            }
        }));
    let service = TowerToHyperService::new(service);

    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(incoming_remote), service)
        .await
    {
        return Err(RouterError::Transport(err.to_string()));
    }

    let _ = conn_task.await;
    let _ = outgoing_bridge.await;
    let _ = incoming_bridge.await;
    Ok(())
}

#[derive(Clone, Debug)]
pub(super) struct NoiseKeys {
    private: [u8; 32],
}

pub(super) fn noise_keys_for_identity(identity: &MeshIdentity) -> Result<NoiseKeys, RouterError> {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&identity.private_key[..32]);
    let private = ed25519_seed_to_x25519(seed);
    Ok(NoiseKeys { private })
}

fn ed25519_seed_to_x25519(seed: [u8; 32]) -> [u8; 32] {
    let hash = sha2::Sha512::digest(seed);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash[..32]);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

fn ed25519_public_to_x25519(public: [u8; 32]) -> Result<[u8; 32], RouterError> {
    let compressed = CompressedEdwardsY(public);
    let point = compressed
        .decompress()
        .ok_or_else(|| RouterError::Auth("invalid public key".to_string()))?;
    Ok(point.to_montgomery().to_bytes())
}

pub(super) struct TrustBundle {
    inner: RwLock<TrustState>,
}

struct TrustState {
    noise_by_id: HashMap<String, [u8; 32]>,
    id_by_noise: HashMap<[u8; 32], String>,
}

impl TrustBundle {
    pub(super) fn new(config: &MeshConfig) -> Result<Self, RouterError> {
        let mut noise_by_id = HashMap::new();
        let mut id_by_noise = HashMap::new();

        for peer in &config.peers {
            insert_peer(peer, &mut noise_by_id, &mut id_by_noise)?;
        }

        Ok(Self {
            inner: RwLock::new(TrustState {
                noise_by_id,
                id_by_noise,
            }),
        })
    }

    async fn noise_key(&self, id: &str) -> Option<[u8; 32]> {
        let inner = self.inner.read().await;
        inner.noise_by_id.get(id).copied()
    }

    async fn id_for_noise_key(&self, key: &[u8; 32]) -> Option<String> {
        let inner = self.inner.read().await;
        inner.id_by_noise.get(key).cloned()
    }

    pub(super) async fn insert_peer(&self, peer: &MeshPeer) -> Result<(), RouterError> {
        let noise = ed25519_public_to_x25519(peer.public_key)?;
        let mut inner = self.inner.write().await;
        if let Some(existing) = inner.noise_by_id.get(&peer.id).copied() {
            if existing == noise {
                return Ok(());
            }
            return Err(RouterError::Auth(format!(
                "peer {} already registered with a different key",
                peer.id
            )));
        }
        if let Some(existing_id) = inner.id_by_noise.get(&noise)
            && existing_id != &peer.id
        {
            return Err(RouterError::Auth(format!(
                "peer key already registered for {}",
                existing_id
            )));
        }
        inner.noise_by_id.insert(peer.id.clone(), noise);
        inner.id_by_noise.insert(noise, peer.id.clone());
        Ok(())
    }
}

fn insert_peer(
    peer: &MeshPeer,
    noise_by_id: &mut HashMap<String, [u8; 32]>,
    id_by_noise: &mut HashMap<[u8; 32], String>,
) -> Result<(), RouterError> {
    let noise = ed25519_public_to_x25519(peer.public_key)?;
    noise_by_id.insert(peer.id.clone(), noise);
    id_by_noise.insert(noise, peer.id.clone());
    Ok(())
}
