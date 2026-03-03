use std::{
    env, fs,
    path::Path,
    process::{Command, ExitCode, ExitStatus},
};
#[cfg(unix)]
use std::{
    io,
    io::ErrorKind,
    net::TcpStream,
    os::unix::net::{UnixListener, UnixStream},
    os::unix::process::{CommandExt, ExitStatusExt},
    thread,
};

use amber_helper::{HelperError, RunPlan, build_run_plan};
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

    match run_main() {
        Ok(code) => code,
        Err(err) => {
            tracing::error!("{err}");
            ExitCode::from(1)
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();
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

    #[cfg(unix)]
    {
        if docker_mount_proxies.is_empty() {
            let err = cmd.exec();
            return Err(HelperError::Msg(format!("failed to exec program: {err}")));
        }

        let status = run_child_with_signal_forwarding(&mut cmd)?;
        Ok(exit_code_from_status(status))
    }

    #[cfg(not(unix))]
    {
        if !docker_mount_proxies.is_empty() {
            return Err(HelperError::Msg(
                "docker mount proxy injection is only supported on unix targets".to_string(),
            ));
        }

        let status = cmd
            .status()
            .map_err(|err| HelperError::Msg(format!("failed to run program: {err}")))?;
        Ok(exit_code_from_status(status))
    }
}

#[cfg(unix)]
fn run_child_with_signal_forwarding(cmd: &mut Command) -> Result<ExitStatus, HelperError> {
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

    let mut child = cmd
        .spawn()
        .map_err(|err| HelperError::Msg(format!("failed to spawn program: {err}")))?;
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

    let status = child
        .wait()
        .map_err(|err| HelperError::Msg(format!("failed to wait for program: {err}")))?;
    signal_handle.close();
    let _ = forwarder.join();
    Ok(status)
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
