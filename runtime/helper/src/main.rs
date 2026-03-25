#[cfg(target_os = "linux")]
use std::mem::offset_of;
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
#[cfg(target_os = "linux")]
use std::{
    os::fd::{AsRawFd as _, FromRawFd as _},
    os::unix::fs::OpenOptionsExt as _,
};

use amber_helper::{
    DirectHardeningPlan, HelperError, RunPlan, build_run_plan, wait_for_mesh_config_scope,
};
use amber_mesh::telemetry::{
    COMPONENT_MONIKER_ENV, OtlpIdentity, OtlpInstallMode, SCENARIO_SCOPE_ENV, SubscriberFormat,
    SubscriberOptions, init_otel_tracer, init_subscriber, observability_log_scope_name,
    shutdown_tracer_provider, structured_logs_enabled,
};
#[cfg(target_os = "linux")]
use linux_raw_sys::landlock::{
    LANDLOCK_ACCESS_FS_EXECUTE, LANDLOCK_ACCESS_FS_IOCTL_DEV, LANDLOCK_ACCESS_FS_MAKE_BLOCK,
    LANDLOCK_ACCESS_FS_MAKE_CHAR, LANDLOCK_ACCESS_FS_MAKE_DIR, LANDLOCK_ACCESS_FS_MAKE_FIFO,
    LANDLOCK_ACCESS_FS_MAKE_REG, LANDLOCK_ACCESS_FS_MAKE_SOCK, LANDLOCK_ACCESS_FS_MAKE_SYM,
    LANDLOCK_ACCESS_FS_READ_DIR, LANDLOCK_ACCESS_FS_READ_FILE, LANDLOCK_ACCESS_FS_REFER,
    LANDLOCK_ACCESS_FS_REMOVE_DIR, LANDLOCK_ACCESS_FS_REMOVE_FILE, LANDLOCK_ACCESS_FS_TRUNCATE,
    LANDLOCK_ACCESS_FS_WRITE_FILE, LANDLOCK_CREATE_RULESET_VERSION, landlock_path_beneath_attr,
    landlock_rule_type, landlock_ruleset_attr,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use linux_raw_sys::ptrace::AUDIT_ARCH_AARCH64;
#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
use linux_raw_sys::ptrace::AUDIT_ARCH_RISCV64;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use linux_raw_sys::ptrace::AUDIT_ARCH_X86_64;
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
        "wait-mesh-config" => {
            let Some(config_path) = args.next() else {
                return Err(usage_error());
            };
            let Some(expected_scope) = args.next() else {
                return Err(usage_error());
            };
            let timeout_secs = match args.next() {
                Some(value) => value.parse::<u64>().map_err(|err| {
                    HelperError::Msg(format!(
                        "wait-mesh-config timeout must be an integer number of seconds: {err}"
                    ))
                })?,
                None => 180,
            };
            if args.next().is_some() {
                return Err(usage_error());
            }
            wait_for_mesh_config_scope(
                Path::new(&config_path),
                &expected_scope,
                std::time::Duration::from_secs(timeout_secs),
                std::time::Duration::from_millis(250),
            )?;
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(usage_error()),
    }
}

fn usage_error() -> HelperError {
    HelperError::Msg(
        "usage: amber-helper <install DEST|run|wait-mesh-config CONFIG EXPECTED_SCOPE \
         [TIMEOUT_SECONDS]>"
            .to_string(),
    )
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
        direct_hardening,
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
        let status = run_child_with_signal_forwarding(
            &mut cmd,
            component_moniker.as_str(),
            direct_hardening.as_ref(),
        )?;
        Ok(exit_code_from_status(status))
    }

    #[cfg(not(unix))]
    {
        if !docker_mount_proxies.is_empty() {
            return Err(HelperError::Msg(
                "docker mount proxy injection is only supported on unix targets".to_string(),
            ));
        }
        if direct_hardening.is_some() {
            return Err(HelperError::Msg(
                "direct hardening payloads are only supported on unix targets".to_string(),
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
    direct_hardening: Option<&DirectHardeningPlan>,
) -> Result<ExitStatus, HelperError> {
    let direct_hardening = direct_hardening.cloned();
    #[cfg(not(target_os = "linux"))]
    let _ = &direct_hardening;
    // Isolate the workload in its own process group so we can relay stop signals to
    // the full workload tree without signaling amber-helper itself.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setpgid(0, 0) == 0 {
                #[cfg(target_os = "linux")]
                if let Some(plan) = direct_hardening.as_ref() {
                    apply_linux_direct_hardening(plan)?;
                }
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

#[cfg(target_os = "linux")]
fn apply_linux_direct_hardening(plan: &DirectHardeningPlan) -> io::Result<()> {
    enable_no_new_privs()?;
    apply_landlock(plan)
        .map_err(|err| io::Error::other(format!("failed to apply Landlock ruleset: {err}")))?;
    apply_seccomp()
        .map_err(|err| io::Error::other(format!("failed to install seccomp filter: {err}")))
}

#[cfg(target_os = "linux")]
fn enable_no_new_privs() -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn apply_landlock(plan: &DirectHardeningPlan) -> io::Result<()> {
    let abi_version = landlock_abi_version()?;
    let handled_access_fs = landlock_handled_access_fs(abi_version);
    let ruleset_attr = landlock_ruleset_attr {
        handled_access_fs,
        handled_access_net: 0,
        scoped: 0,
    };
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &ruleset_attr as *const landlock_ruleset_attr,
            std::mem::size_of::<landlock_ruleset_attr>(),
            0usize,
        )
    };
    if ruleset_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let ruleset_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(ruleset_fd as i32) };

    let read_only_access = u64::from(
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
    );
    let writable_access = landlock_handled_access_fs(abi_version);

    for path in &plan.read_only_paths {
        add_landlock_rule(ruleset_fd.as_raw_fd(), path, read_only_access)?;
    }
    for path in &plan.writable_paths {
        add_landlock_rule(ruleset_fd.as_raw_fd(), path, writable_access)?;
    }

    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            ruleset_fd.as_raw_fd(),
            0u32,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn landlock_abi_version() -> io::Result<u32> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<landlock_ruleset_attr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc >= 0 {
        u32::try_from(rc).map_err(|_| io::Error::other("landlock ABI version is out of range"))
    } else {
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) | Some(libc::EINVAL) => {
                Err(io::Error::other(
                    "linux direct mode requires a Landlock-enabled kernel; the current kernel \
                     does not support Amber's Landlock rulesets",
                ))
            }
            _ => Err(err),
        }
    }
}

#[cfg(target_os = "linux")]
fn landlock_handled_access_fs(abi_version: u32) -> u64 {
    let mut access = u64::from(
        LANDLOCK_ACCESS_FS_EXECUTE
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_MAKE_FIFO
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_MAKE_SYM,
    );
    if abi_version >= 2 {
        access |= u64::from(LANDLOCK_ACCESS_FS_REFER);
    }
    if abi_version >= 3 {
        access |= u64::from(LANDLOCK_ACCESS_FS_TRUNCATE);
    }
    if abi_version >= 5 {
        access |= u64::from(LANDLOCK_ACCESS_FS_IOCTL_DEV);
    }
    access
}

#[cfg(target_os = "linux")]
fn add_landlock_rule(ruleset_fd: i32, path: &Path, allowed_access: u64) -> io::Result<()> {
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    let rule = landlock_path_beneath_attr {
        allowed_access,
        parent_fd: file.as_raw_fd(),
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            landlock_rule_type::LANDLOCK_RULE_PATH_BENEATH as u32,
            &rule as *const landlock_path_beneath_attr,
            0u32,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    )
))]
fn apply_seccomp() -> io::Result<()> {
    let mut filter = seccomp_filter_program();
    let mut program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut program as *mut libc::sock_fprog,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    ))
))]
fn apply_seccomp() -> io::Result<()> {
    Err(io::Error::other(format!(
        "linux direct mode seccomp hardening is not implemented for architecture {}",
        std::env::consts::ARCH
    )))
}

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    )
))]
fn seccomp_filter_program() -> Vec<libc::sock_filter> {
    let deny = seccomp_errno(libc::EPERM as u16);
    unsafe {
        let mut filter = vec![
            libc::BPF_STMT(
                (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                offset_of!(libc::seccomp_data, arch) as u32,
            ),
            libc::BPF_JUMP(
                (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                native_audit_arch(),
                1,
                0,
            ),
            libc::BPF_STMT(
                (libc::BPF_RET | libc::BPF_K) as u16,
                libc::SECCOMP_RET_KILL_PROCESS,
            ),
            libc::BPF_STMT(
                (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                offset_of!(libc::seccomp_data, nr) as u32,
            ),
        ];

        for syscall in denied_syscalls() {
            filter.push(libc::BPF_JUMP(
                (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                *syscall as u32,
                0,
                1,
            ));
            filter.push(libc::BPF_STMT((libc::BPF_RET | libc::BPF_K) as u16, deny));
        }

        // Amber components only communicate over Unix sockets, declared TCP/HTTP capability
        // paths, and optional public-network egress over IP sockets. Other socket families are
        // outside Amber's transport model and are denied in direct mode.
        filter.extend_from_slice(&[
            libc::BPF_JUMP(
                (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                libc::SYS_socket as u32,
                0,
                5,
            ),
            libc::BPF_STMT(
                (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                offset_of!(libc::seccomp_data, args) as u32,
            ),
            libc::BPF_JUMP(
                (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                libc::AF_UNIX as u32,
                3,
                0,
            ),
            libc::BPF_JUMP(
                (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                libc::AF_INET as u32,
                2,
                0,
            ),
            libc::BPF_JUMP(
                (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                libc::AF_INET6 as u32,
                1,
                0,
            ),
            libc::BPF_STMT((libc::BPF_RET | libc::BPF_K) as u16, deny),
            libc::BPF_STMT(
                (libc::BPF_RET | libc::BPF_K) as u16,
                libc::SECCOMP_RET_ALLOW,
            ),
        ]);

        filter
    }
}

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    )
))]
fn seccomp_errno(errno: u16) -> u32 {
    libc::SECCOMP_RET_ERRNO | u32::from(errno)
}

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    )
))]
fn denied_syscalls() -> &'static [libc::c_long] {
    &[
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kcmp,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_open_by_handle_at,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_fanotify_init,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
    ]
}

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    )
))]
fn native_audit_arch() -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        AUDIT_ARCH_AARCH64
    }
    #[cfg(target_arch = "riscv64")]
    {
        AUDIT_ARCH_RISCV64
    }
    #[cfg(target_arch = "x86_64")]
    {
        AUDIT_ARCH_X86_64
    }
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
