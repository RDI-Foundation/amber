use std::{
    fs,
    io::Write as _,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use miette::{IntoDiagnostic as _, Result, WrapErr as _};
use serde::{Deserialize, Serialize};

use super::{
    orchestration::ProtocolApiError, planner::ControlStateApp, state::FRAMEWORK_AUTH_HEADER, *,
};

pub(super) async fn cleanup_dynamic_bridge_proxies(app: &ControlStateApp) -> Result<()> {
    app.runtime.cleanup().await
}

pub(super) fn authorize_framework_auth_header(
    headers: &HeaderMap,
    expected: &str,
) -> std::result::Result<(), ProtocolApiError> {
    let actual = required_header(headers, FRAMEWORK_AUTH_HEADER)?;
    if actual != expected {
        return Err(ProtocolApiError::unauthorized(
            "invalid authenticated framework request header",
        ));
    }
    Ok(())
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
                "missing authenticated framework request header `{name}`"
            ))
        })
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
