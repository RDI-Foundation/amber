use std::{
    env, fs,
    io::{BufRead as _, BufReader, Read},
    path::Path,
    process::{Command, ExitCode, ExitStatus, Stdio},
    thread,
};
#[cfg(unix)]
use std::{
    io,
    io::ErrorKind,
    net::TcpStream,
    os::unix::net::{UnixListener, UnixStream},
    os::unix::process::{CommandExt, ExitStatusExt},
};

use amber_helper::{HelperError, RunPlan, build_run_plan};
use amber_mesh::telemetry::{
    COMPONENT_MONIKER_ENV, OtlpIdentity, OtlpInstallMode, SCENARIO_SCOPE_ENV, SubscriberFormat,
    SubscriberOptions, init_otel_tracer, init_subscriber, observability_log_scope_name,
    shutdown_tracer_provider, structured_logs_enabled,
};
#[cfg(unix)]
use signal_hook::{consts::signal, iterator::Signals};
use tracing_subscriber::EnvFilter;

#[cfg(unix)]
const FORWARDED_SIGNALS: &[i32] = &[
    signal::SIGTERM,
    signal::SIGINT,
    signal::SIGHUP,
    signal::SIGQUIT,
];

fn main() -> ExitCode {
    init_tracing();

    let exit_code = match run_main() {
        Ok(code) => code,
        Err(err) => {
            tracing::error!("{err}");
            ExitCode::from(1)
        }
    };

    shutdown_tracer_provider();
    exit_code
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn,amber_helper=info,amber.program=info"));
    let moniker = std::env::var(COMPONENT_MONIKER_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "/unknown".to_string());
    let scope = std::env::var(SCENARIO_SCOPE_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let tracer = match init_otel_tracer(
        OtlpIdentity {
            moniker: moniker.as_str(),
            component_kind: Some("program"),
            scenario_scope: scope.as_deref(),
        },
        OtlpInstallMode::Simple,
    ) {
        Ok(tracer) => tracer,
        Err(err) => {
            eprintln!("warning: failed to initialize OTLP tracing: {err}");
            None
        }
    };
    let format = if structured_logs_enabled() {
        SubscriberFormat::RuntimeJson
    } else {
        SubscriberFormat::RuntimeText
    };
    init_subscriber(
        filter,
        tracer,
        format,
        SubscriberOptions {
            log_scope_name: Some(observability_log_scope_name(Some("program"))),
            ..SubscriberOptions::default()
        },
    );
}

fn run_main() -> Result<ExitCode, HelperError> {
    let mut args = env::args();
    let _exe = args.next();
    let Some(command) = args.next() else {
        return Err(usage_error());
    };

    match command.as_str() {
        "install" => {
            let Some(dest) = args.next() else {
                return Err(usage_error());
            };
            if args.next().is_some() {
                return Err(usage_error());
            }
            install(Path::new(&dest))?;
            Ok(ExitCode::SUCCESS)
        }
        "run" => {
            if args.next().is_some() {
                return Err(usage_error());
            }
            run()
        }
        _ => Err(usage_error()),
    }
}

fn usage_error() -> HelperError {
    HelperError::Msg("usage: amber-helper <install DEST|run>".to_string())
}

fn install(dest: &Path) -> Result<(), HelperError> {
    let exe = env::current_exe().map_err(|err| HelperError::Msg(err.to_string()))?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|err| HelperError::Msg(err.to_string()))?;
    }

    fs::copy(&exe, dest).map_err(|err| HelperError::Msg(err.to_string()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dest)
            .map_err(|err| HelperError::Msg(err.to_string()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(dest, perms).map_err(|err| HelperError::Msg(err.to_string()))?;
    }

    Ok(())
}

fn run() -> Result<ExitCode, HelperError> {
    let plan = build_run_plan(env::vars_os())?;
    exec_plan(plan)
}

fn exec_plan(plan: RunPlan) -> Result<ExitCode, HelperError> {
    let RunPlan {
        entrypoint,
        env,
        docker_mount_proxies,
    } = plan;

    if !docker_mount_proxies.is_empty() {
        start_docker_mount_proxies(&docker_mount_proxies)?;
    }

    let mut iter = entrypoint.into_iter();
    let Some(program) = iter.next() else {
        return Err(HelperError::Msg(
            "program entrypoint must not be empty".to_string(),
        ));
    };

    let mut cmd = Command::new(program);
    cmd.args(iter);
    cmd.env_clear();
    cmd.envs(env);
    let component_moniker = std::env::var(COMPONENT_MONIKER_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/unknown".to_string());

    #[cfg(unix)]
    {
        let status = run_child_with_signal_forwarding(&mut cmd, component_moniker.as_str())?;
        Ok(exit_code_from_status(status))
    }

    #[cfg(not(unix))]
    {
        if !docker_mount_proxies.is_empty() {
            return Err(HelperError::Msg(
                "docker mount proxy injection is only supported on unix targets".to_string(),
            ));
        }

        let status = run_child_with_log_capture(&mut cmd, component_moniker.as_str())?;
        Ok(exit_code_from_status(status))
    }
}

#[cfg(unix)]
fn run_child_with_signal_forwarding(
    cmd: &mut Command,
    component_moniker: &str,
) -> Result<ExitStatus, HelperError> {
    // Isolate the workload in its own process group so we can relay stop signals to
    // the full workload tree without signaling amber-helper itself.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }

    let mut child_with_logs = spawn_child_with_logs(cmd, component_moniker)?;
    let child = &mut child_with_logs.child;
    let child_pgid = child.id() as i32;

    let mut signals = Signals::new(FORWARDED_SIGNALS)
        .map_err(|err| HelperError::Msg(format!("failed to register signal handlers: {err}")))?;
    let signal_handle = signals.handle();
    let forwarder = thread::spawn(move || {
        for sig in signals.forever() {
            let rc = unsafe { libc::kill(-child_pgid, sig) };
            if rc == 0 {
                continue;
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                tracing::warn!(
                    "failed to forward signal {sig} to workload process group {child_pgid}: {err}"
                );
            }
        }
    });

    let status = wait_for_child_exit(child_with_logs)?;
    signal_handle.close();
    let _ = forwarder.join();
    Ok(status)
}

#[cfg(not(unix))]
fn run_child_with_log_capture(
    cmd: &mut Command,
    component_moniker: &str,
) -> Result<ExitStatus, HelperError> {
    wait_for_child_exit(spawn_child_with_logs(cmd, component_moniker)?)
}

struct ChildWithLogs {
    child: std::process::Child,
    forwarders: Vec<thread::JoinHandle<()>>,
}

fn spawn_child_with_logs(
    cmd: &mut Command,
    component_moniker: &str,
) -> Result<ChildWithLogs, HelperError> {
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|err| HelperError::Msg(format!("failed to spawn program: {err}")))?;
    let log_span = tracing::info_span!(
        "amber.node.logs",
        amber_kind = "node.log",
        amber_component_moniker = component_moniker
    );

    let mut forwarders = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        forwarders.push(start_log_forwarder(stdout, "stdout", log_span.clone()));
    }
    if let Some(stderr) = child.stderr.take() {
        forwarders.push(start_log_forwarder(stderr, "stderr", log_span));
    }

    Ok(ChildWithLogs { child, forwarders })
}

fn wait_for_child_exit(mut child_with_logs: ChildWithLogs) -> Result<ExitStatus, HelperError> {
    let status = child_with_logs
        .child
        .wait()
        .map_err(|err| HelperError::Msg(format!("failed to wait for program: {err}")))?;
    // Descendants can inherit stdout/stderr and keep the pipe writers open after the main
    // process exits. Dropping the join handles detaches the forwarders so helper shutdown is
    // driven by the workload exit status rather than EOF on those inherited pipes.
    child_with_logs.forwarders.clear();
    Ok(status)
}

fn start_log_forwarder<R: Read + Send + 'static>(
    reader: R,
    stream: &'static str,
    span: tracing::Span,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let read = match reader.read_until(b'\n', &mut buf) {
                Ok(read) => read,
                Err(err) => {
                    tracing::warn!("failed to read child {stream}: {err}");
                    break;
                }
            };
            if read == 0 {
                break;
            }

            let line = String::from_utf8_lossy(&buf);
            let line = line.trim_end_matches(['\r', '\n']);
            span.in_scope(|| match workload_log_level(stream) {
                tracing::Level::WARN => {
                    tracing::warn!(target: "amber.program", amber_stream = stream, amber_log_line = line, "{line}");
                }
                _ => {
                    tracing::info!(target: "amber.program", amber_stream = stream, amber_log_line = line, "{line}");
                }
            });
        }
    })
}

fn workload_log_level(stream: &str) -> tracing::Level {
    match stream {
        "stderr" => tracing::Level::WARN,
        _ => tracing::Level::INFO,
    }
}

fn exit_code_from_status(status: ExitStatus) -> ExitCode {
    if let Some(code) = status.code() {
        return ExitCode::from(code as u8);
    }

    #[cfg(unix)]
    if let Some(sig) = status.signal() {
        let mapped = (128 + sig).clamp(0, 255) as u8;
        return ExitCode::from(mapped);
    }

    ExitCode::from(1)
}

#[cfg(unix)]
fn start_docker_mount_proxies(specs: &[(String, String, u16)]) -> Result<(), HelperError> {
    for (path, tcp_host, tcp_port) in specs {
        let socket_path = Path::new(path);
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| HelperError::Msg(format!("failed to create {parent:?}: {err}")))?;
        }
        match fs::remove_file(socket_path) {
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                return Err(HelperError::Msg(format!(
                    "failed to remove existing socket {path}: {err}"
                )));
            }
        }

        let listener = UnixListener::bind(socket_path).map_err(|err| {
            HelperError::Msg(format!("failed to bind docker socket {path}: {err}"))
        })?;
        let target = format!("{tcp_host}:{tcp_port}");
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else {
                    continue;
                };
                let target = target.clone();
                thread::spawn(move || {
                    let Ok(upstream) = TcpStream::connect(&target) else {
                        return;
                    };
                    let _ = proxy_unix_to_tcp(stream, upstream);
                });
            }
        });
    }

    Ok(())
}

#[cfg(unix)]
fn proxy_unix_to_tcp(unix: UnixStream, tcp: TcpStream) -> io::Result<()> {
    let mut unix_reader = unix.try_clone()?;
    let mut unix_writer = unix;
    let mut tcp_reader = tcp.try_clone()?;
    let mut tcp_writer = tcp;

    let unix_to_tcp = thread::spawn(move || io::copy(&mut unix_reader, &mut tcp_writer));
    let tcp_to_unix = thread::spawn(move || io::copy(&mut tcp_reader, &mut unix_writer));

    let _ = unix_to_tcp.join();
    let _ = tcp_to_unix.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        process::Command,
        time::{Duration, Instant},
    };

    use super::{spawn_child_with_logs, wait_for_child_exit, workload_log_level};

    #[test]
    fn stderr_logs_are_promoted_to_warn() {
        assert_eq!(workload_log_level("stdout"), tracing::Level::INFO);
        assert_eq!(workload_log_level("stderr"), tracing::Level::WARN);
        assert_eq!(workload_log_level("other"), tracing::Level::INFO);
    }

    #[cfg(unix)]
    #[test]
    fn child_exit_is_not_blocked_by_descendant_holding_log_pipe_open() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 2 & exit 7"]);

        let child = spawn_child_with_logs(&mut cmd, "/test")
            .expect("child with log forwarding should spawn");
        let start = Instant::now();
        let status = wait_for_child_exit(child).expect("child wait should succeed");

        assert_eq!(status.code(), Some(7));
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "waiting for child exit took {:?}",
            start.elapsed()
        );
    }
}
