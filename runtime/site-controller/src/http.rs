use std::{
    fs,
    io::Write as _,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use miette::{IntoDiagnostic as _, Result, WrapErr as _};
use serde::{Deserialize, Serialize};

use super::{orchestration::ProtocolApiError, planner::ControlStateApp, *};

pub(super) async fn cleanup_dynamic_bridge_proxies(app: &ControlStateApp) -> Result<()> {
    app.runtime.cleanup().await
}

pub(super) fn required_header(
    headers: &HeaderMap,
    name: &str,
) -> std::result::Result<String, ProtocolApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            ProtocolApiError::unauthorized(format!(
                "missing authenticated control-state request header `{name}`"
            ))
        })
}

const REMOTE_CONTROLLER_REQUEST_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
const REMOTE_CONTROLLER_REQUEST_RETRY_DELAY: Duration = Duration::from_millis(250);

fn should_retry_remote_controller_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    )
}

pub(super) async fn post_json_with_retry<TReq: Serialize>(
    client: &ReqwestClient,
    url: &str,
    body: &TReq,
) -> std::result::Result<reqwest::Response, reqwest::Error> {
    let deadline = tokio::time::Instant::now() + REMOTE_CONTROLLER_REQUEST_RETRY_TIMEOUT;
    loop {
        match client.post(url).json(body).send().await {
            Ok(response)
                if should_retry_remote_controller_status(response.status())
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(REMOTE_CONTROLLER_REQUEST_RETRY_DELAY).await;
            }
            Ok(response) => return Ok(response),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(REMOTE_CONTROLLER_REQUEST_RETRY_DELAY).await;
            }
            Err(err) => return Err(err),
        }
    }
}

pub(super) async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("framework service should install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};

        signal(SignalKind::terminate())
            .expect("framework service should install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(unix)]
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    #[cfg(not(unix))]
    ctrl_c.await;
}

pub(super) fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| miette::miette!("failed to serialize {}: {err}", path.display()))?;
    write_bytes_atomic(path, &bytes)
}

pub(super) fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("tmp");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = path.with_file_name(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", tmp_path.display()))?;
    if let Err(err) = file.write_all(bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(miette::miette!(
            "failed to write {}: {err}",
            tmp_path.display()
        ));
    }
    if let Err(err) = file.sync_all() {
        let _ = fs::remove_file(&tmp_path);
        return Err(miette::miette!(
            "failed to sync {}: {err}",
            tmp_path.display()
        ));
    }
    drop(file);

    fs::rename(&tmp_path, path)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to replace {} with {}",
                path.display(),
                tmp_path.display()
            )
        })?;
    sync_parent_directory(path)?;
    Ok(())
}

pub(super) fn sync_parent_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to open parent directory {}", parent.display()))?
                .sync_all()
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("failed to sync parent directory {}", parent.display())
                })?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(super) fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T> {
    let bytes = fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {label} {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| miette::miette!("invalid {label} {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::{
        Json, Router,
        extract::State,
        http::StatusCode,
        response::{IntoResponse as _, Response},
        routing::post,
    };
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn post_json_with_retry_tolerates_transient_service_unavailable() {
        async fn handler(State(attempts): State<Arc<AtomicUsize>>) -> Response {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            if attempt < 2 {
                return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false})))
                    .into_response();
            }
            (StatusCode::OK, Json(json!({"ok": true}))).into_response()
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/retry", post(handler))
            .with_state(attempts.clone());
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let serve = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("test server should run");
        });

        let response = post_json_with_retry(
            &ReqwestClient::new(),
            &format!("http://{addr}/retry"),
            &json!({"hello": "world"}),
        )
        .await
        .expect("request should eventually succeed");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);

        serve.abort();
        let _ = serve.await;
    }
}
