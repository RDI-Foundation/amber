#[cfg(target_os = "linux")]
use std::hash::{Hash as _, Hasher as _};

use super::*;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SpawnPidCapture {
    WrapperProcess,
    BubblewrapChild,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct LinuxNamespaceJoin {
    user: Option<CString>,
    net: Option<CString>,
}

#[cfg(target_os = "linux")]
pub(crate) struct BubblewrapInfoPipe {
    read: OwnedFd,
    write: OwnedFd,
}

#[cfg(target_os = "linux")]
pub(crate) fn insert_bubblewrap_info_fd(args: &mut Vec<String>, fd: RawFd) -> Result<()> {
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| miette::miette!("bubblewrap args are missing the `--` command separator"))?;
    args.splice(
        separator..separator,
        ["--info-fd".to_string(), fd.to_string()],
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn prepare_bubblewrap_info_pipe(
    command: &mut TokioCommand,
) -> Result<BubblewrapInfoPipe> {
    const BUBBLEWRAP_INFO_FD: RawFd = 3;

    let mut raw_fds = [-1; 2];
    if unsafe { libc::pipe2(raw_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(miette::miette!(
            "failed to create bubblewrap info pipe: {}",
            std::io::Error::last_os_error()
        ));
    }

    let read = unsafe { OwnedFd::from_raw_fd(raw_fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(raw_fds[1]) };
    let read_fd = read.as_raw_fd();
    let write_fd = write.as_raw_fd();

    unsafe {
        command.pre_exec(move || {
            if libc::close(read_fd) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if write_fd != BUBBLEWRAP_INFO_FD
                && libc::dup2(write_fd, BUBBLEWRAP_INFO_FD) != BUBBLEWRAP_INFO_FD
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(BUBBLEWRAP_INFO_FD, libc::F_SETFD, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if write_fd != BUBBLEWRAP_INFO_FD && libc::close(write_fd) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    Ok(BubblewrapInfoPipe { read, write })
}

pub(crate) async fn spawn_managed_command(
    name: String,
    mut command: TokioCommand,
    #[cfg(target_os = "linux")] namespace_join: Option<LinuxNamespaceJoin>,
    #[cfg(target_os = "linux")] pid_capture: SpawnPidCapture,
    children: &mut Vec<ManagedChild>,
    log_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<u32> {
    #[cfg(target_os = "linux")]
    let bubblewrap_info_pipe = match pid_capture {
        SpawnPidCapture::WrapperProcess => None,
        SpawnPidCapture::BubblewrapChild => Some(prepare_bubblewrap_info_pipe(&mut command)?),
    };
    #[cfg(target_os = "linux")]
    if let Some(namespace_join) = namespace_join {
        unsafe {
            command.pre_exec(move || enter_linux_namespaces(&namespace_join));
        }
    }

    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut wrapper = command
        .spawn()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to spawn process {name}"))?;

    #[cfg(target_os = "linux")]
    let managed_pid = if let Some(pipe) = bubblewrap_info_pipe {
        match read_bubblewrap_child_pid(pipe).await {
            Ok(pid) => pid,
            Err(err) => {
                let _ = wrapper.start_kill();
                let _ = wrapper.wait().await;
                return Err(err).wrap_err_with(|| {
                    format!("failed to capture bubblewrap child pid for {name}")
                });
            }
        }
    } else {
        wrapper
            .id()
            .ok_or_else(|| miette::miette!("failed to capture process id for {name}"))?
    };

    #[cfg(not(target_os = "linux"))]
    let managed_pid = wrapper
        .id()
        .ok_or_else(|| miette::miette!("failed to capture process id for {name}"))?;

    #[cfg(target_os = "linux")]
    let wrapper_pid = wrapper
        .id()
        .ok_or_else(|| miette::miette!("failed to capture process id for {name}"))?;

    if let Some(stdout) = wrapper.stdout.take() {
        let name = name.clone();
        log_tasks.push(tokio::spawn(async move {
            stream_logs(stdout, name, false).await;
        }));
    }
    if let Some(stderr) = wrapper.stderr.take() {
        let name = name.clone();
        log_tasks.push(tokio::spawn(async move {
            stream_logs(stderr, name, true).await;
        }));
    }

    children.push(ManagedChild {
        name,
        wrapper: Some(wrapper),
        #[cfg(target_os = "linux")]
        wrapper_pid,
        #[cfg(target_os = "linux")]
        managed_pid,
    });
    Ok(managed_pid)
}

#[cfg(target_os = "linux")]
pub(crate) fn prepare_linux_namespace_join(pid: u32) -> Result<Option<LinuxNamespaceJoin>> {
    let self_user = fs::read_link("/proc/self/ns/user")
        .into_diagnostic()
        .wrap_err("failed to read current user namespace")?;
    let target_user_path = format!("/proc/{pid}/ns/user");
    let target_user = fs::read_link(&target_user_path)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to read target user namespace for process {pid} ({})",
                target_user_path
            )
        })?;

    let self_net = fs::read_link("/proc/self/ns/net")
        .into_diagnostic()
        .wrap_err("failed to read current network namespace")?;
    let target_net_path = format!("/proc/{pid}/ns/net");
    let target_net = fs::read_link(&target_net_path)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to read target network namespace for process {pid} ({})",
                target_net_path
            )
        })?;

    let user = if self_user != target_user {
        Some(
            CString::new(target_user_path.as_str())
                .into_diagnostic()
                .wrap_err("user namespace path unexpectedly contains NUL bytes")?,
        )
    } else {
        None
    };
    let net = if self_net != target_net {
        Some(
            CString::new(target_net_path.as_str())
                .into_diagnostic()
                .wrap_err("network namespace path unexpectedly contains NUL bytes")?,
        )
    } else {
        None
    };

    if user.is_none() && net.is_none() {
        Ok(None)
    } else {
        Ok(Some(LinuxNamespaceJoin { user, net }))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn enter_linux_namespaces(namespace_join: &LinuxNamespaceJoin) -> std::io::Result<()> {
    if let Some(user) = namespace_join.user.as_ref() {
        enter_linux_namespace(
            user,
            libc::CLONE_NEWUSER,
            b"failed to open component user namespace\n",
            b"failed to join component user namespace\n",
        )?;
    }
    if let Some(net) = namespace_join.net.as_ref() {
        enter_linux_namespace(
            net,
            libc::CLONE_NEWNET,
            b"failed to open component network namespace\n",
            b"failed to join component network namespace\n",
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn enter_linux_namespace(
    path: &CString,
    namespace_kind: libc::c_int,
    open_error: &[u8],
    join_error: &[u8],
) -> std::io::Result<()> {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        let _ = unsafe {
            libc::write(
                libc::STDERR_FILENO,
                open_error.as_ptr().cast(),
                open_error.len(),
            )
        };
        return Err(err);
    }

    if unsafe { libc::setns(fd, namespace_kind) } != 0 {
        let err = std::io::Error::last_os_error();
        let _ = unsafe {
            libc::write(
                libc::STDERR_FILENO,
                join_error.as_ptr().cast(),
                join_error.len(),
            )
        };
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    unsafe {
        libc::close(fd);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) async fn read_bubblewrap_child_pid(pipe: BubblewrapInfoPipe) -> Result<u32> {
    drop(pipe.write);
    set_fd_nonblocking(pipe.read.as_raw_fd())?;
    let read = pipe.read;
    tokio::task::spawn_blocking(move || -> Result<u32> {
        let mut file: fs::File = read.into();
        let mut raw = String::new();
        let mut buffer = [0_u8; 512];
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match file.read(&mut buffer) {
                Ok(0) => {
                    return parse_bubblewrap_child_pid(raw.as_str()).wrap_err(
                        "bubblewrap info payload ended before a child pid was available",
                    );
                }
                Ok(read) => {
                    raw.push_str(&String::from_utf8_lossy(&buffer[..read]));
                    if let Ok(pid) = parse_bubblewrap_child_pid(raw.as_str()) {
                        return Ok(pid);
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Err(miette::miette!(
                            "timed out waiting for bubblewrap info payload"
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(err) => {
                    return Err(err)
                        .into_diagnostic()
                        .wrap_err("failed to read bubblewrap info payload");
                }
            }
        }
    })
    .await
    .into_diagnostic()
    .wrap_err("bubblewrap info reader task failed")?
}

#[cfg(target_os = "linux")]
pub(crate) fn set_fd_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(miette::miette!(
            "failed to read descriptor flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(miette::miette!(
            "failed to make descriptor nonblocking: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_bubblewrap_child_pid(raw: &str) -> Result<u32> {
    let payload: serde_json::Value = serde_json::from_str(raw.trim())
        .map_err(|err| miette::miette!("invalid bubblewrap info payload: {err}"))?;
    let child_pid = payload
        .get("child-pid")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| miette::miette!("bubblewrap info payload is missing `child-pid`"))?;
    u32::try_from(child_pid)
        .into_diagnostic()
        .wrap_err("bubblewrap child pid is out of range")
}

#[cfg(target_os = "linux")]
pub(crate) async fn spawn_component_slirp4netns(
    slirp4netns: &Path,
    runtime_root: &Path,
    component: &DirectComponentPlan,
    sidecar_pid: u32,
    mesh_port: u16,
    children: &mut Vec<ManagedChild>,
    log_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<()> {
    let slirp_root = direct_slirp4netns_root();
    fs::create_dir_all(&slirp_root)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create slirp runtime directory {}",
                slirp_root.display()
            )
        })?;
    let api_socket_path = direct_slirp4netns_api_socket_path(runtime_root, component.id);
    if api_socket_path.exists() {
        fs::remove_file(&api_socket_path)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to remove stale slirp api socket {}",
                    api_socket_path.display()
                )
            })?;
    }

    let mut command = TokioCommand::new(slirp4netns);
    command.args([
        "--configure".to_string(),
        "--mtu=65520".to_string(),
        "--api-socket".to_string(),
        api_socket_path.display().to_string(),
        sidecar_pid.to_string(),
        "tap0".to_string(),
    ]);
    command.current_dir(runtime_root);
    configure_managed_command_env(&mut command, runtime_root, &BTreeMap::new());
    let log_name = format!("{}-slirp4netns", component.sidecar.log_name);
    spawn_managed_command(
        log_name.clone(),
        command,
        None,
        SpawnPidCapture::WrapperProcess,
        children,
        log_tasks,
    )
    .await?;

    slirp4netns_add_hostfwd(&api_socket_path, mesh_port)
        .await
        .map_err(|err| {
            miette::miette!(
                "failed to expose mesh port {} for component {} via slirp4netns ({}): {err}",
                mesh_port,
                component.moniker,
                log_name
            )
        })
}

#[cfg(target_os = "linux")]
pub(crate) fn direct_slirp4netns_root() -> PathBuf {
    env::temp_dir().join("amber-direct-slirp4netns")
}

#[cfg(target_os = "linux")]
pub(crate) fn direct_slirp4netns_api_socket_path(
    runtime_root: &Path,
    component_id: usize,
) -> PathBuf {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    runtime_root.hash(&mut hasher);
    component_id.hash(&mut hasher);
    let suffix = hasher.finish();
    direct_slirp4netns_root().join(format!("c{component_id}-{suffix:016x}.sock"))
}

#[cfg(target_os = "linux")]
pub(crate) fn slirp4netns_add_hostfwd_payload(mesh_port: u16) -> serde_json::Value {
    serde_json::json!({
        "execute": "add_hostfwd",
        "arguments": {
            "proto": "tcp",
            "host_addr": "127.0.0.1",
            "host_port": mesh_port,
            // Let slirp target its configured guest address (10.0.2.100 by default).
            "guest_port": mesh_port,
        }
    })
}

#[cfg(target_os = "linux")]
pub(crate) async fn slirp4netns_add_hostfwd(api_socket_path: &Path, mesh_port: u16) -> Result<()> {
    use std::io::ErrorKind;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::net::UnixStream::connect(api_socket_path).await {
            Ok(mut stream) => {
                let payload = slirp4netns_add_hostfwd_payload(mesh_port);
                let payload = serde_json::to_vec(&payload).into_diagnostic()?;
                stream
                    .write_all(&payload)
                    .await
                    .into_diagnostic()
                    .wrap_err("failed to write slirp4netns add_hostfwd request")?;
                stream
                    .shutdown()
                    .await
                    .into_diagnostic()
                    .wrap_err("failed to finalize slirp4netns add_hostfwd request")?;

                let mut response = Vec::new();
                stream
                    .read_to_end(&mut response)
                    .await
                    .into_diagnostic()
                    .wrap_err("failed to read slirp4netns add_hostfwd response")?;
                let response: serde_json::Value = serde_json::from_slice(&response)
                    .into_diagnostic()
                    .wrap_err("invalid slirp4netns add_hostfwd response")?;
                if let Some(error) = response.get("error") {
                    return Err(miette::miette!(
                        "slirp4netns add_hostfwd rejected request: {}",
                        error
                    ));
                }
                return Ok(());
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::NotFound
                        | ErrorKind::ConnectionRefused
                        | ErrorKind::ConnectionAborted
                ) =>
            {
                if Instant::now() >= deadline {
                    break;
                }
                sleep(Duration::from_millis(25)).await;
            }
            Err(err) => {
                return Err(miette::miette!(
                    "failed to connect to slirp4netns api socket {}: {err}",
                    api_socket_path.display()
                ));
            }
        }
    }

    Err(miette::miette!(
        "timed out waiting for slirp4netns api socket {}",
        api_socket_path.display()
    ))
}

pub(crate) async fn stream_logs<R>(reader: R, name: String, stderr: bool)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if stderr {
                    eprintln!("[{name}] {line}");
                } else {
                    println!("[{name}] {line}");
                }
            }
            Ok(None) => break,
            Err(err) => {
                eprintln!("[{name}] log stream error: {err}");
                break;
            }
        }
    }
}

pub(crate) async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate())
            .into_diagnostic()
            .wrap_err("failed to install SIGTERM handler")?;
        let mut sighup = signal(SignalKind::hangup())
            .into_diagnostic()
            .wrap_err("failed to install SIGHUP handler")?;

        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                res.into_diagnostic().wrap_err("failed to install Ctrl+C handler")?;
            }
            _ = sigterm.recv() => {}
            _ = sighup.recv() => {}
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .into_diagnostic()
            .wrap_err("failed to install Ctrl+C handler")?;
        Ok(())
    }
}

pub(crate) async fn supervise_children(
    children: &mut [ManagedChild],
) -> Result<(RuntimeExitReason, i32)> {
    let mut shutdown = std::pin::pin!(wait_for_shutdown_signal());
    loop {
        tokio::select! {
            res = &mut shutdown => {
                res?;
                return Ok((RuntimeExitReason::CtrlC, 0));
            }
            _ = sleep(DIRECT_CHILD_POLL_INTERVAL) => {
                for child in children.iter_mut() {
                    #[cfg(target_os = "linux")]
                    if let Some(wrapper) = child.wrapper.as_mut()
                        && let Some(status) = wrapper.try_wait().into_diagnostic()?
                    {
                        child.wrapper = None;
                        if child.wrapper_pid == child.managed_pid
                            || !linux_pid_is_alive(child.managed_pid)
                        {
                            let exit_code = if status.success() {
                                0
                            } else {
                                status.code().unwrap_or(1).max(1)
                            };
                            return Ok((
                                RuntimeExitReason::ChildExited {
                                    name: child.name.clone(),
                                    status,
                                },
                                exit_code,
                            ));
                        }
                    }
                    #[cfg(target_os = "linux")]
                    if child.wrapper.is_none() && !linux_pid_is_alive(child.managed_pid) {
                        let status = synthetic_failure_exit_status();
                        return Ok((
                            RuntimeExitReason::ChildExited {
                                name: child.name.clone(),
                                status,
                            },
                            1,
                        ));
                    }
                    #[cfg(not(target_os = "linux"))]
                    if let Some(wrapper) = child.wrapper.as_mut()
                        && let Some(status) = wrapper.try_wait().into_diagnostic()?
                    {
                        let exit_code = if status.success() {
                            0
                        } else {
                            status.code().unwrap_or(1).max(1)
                        };
                        return Ok((
                            RuntimeExitReason::ChildExited {
                                name: child.name.clone(),
                                status,
                            },
                            exit_code,
                        ));
                    }
                }
            }
        }
    }
}

pub(crate) async fn terminate_children(children: &mut [ManagedChild]) {
    for child in children.iter_mut() {
        #[cfg(target_os = "linux")]
        {
            if linux_pid_is_alive(child.managed_pid) {
                let _ = send_sigterm(child.managed_pid);
            }
            if child.wrapper_pid != child.managed_pid {
                let _ = send_sigterm(child.wrapper_pid);
            }
        }
        #[cfg(not(target_os = "linux"))]
        if let Some(wrapper) = child.wrapper.as_mut()
            && wrapper.try_wait().ok().flatten().is_none()
            && let Some(pid) = wrapper.id()
        {
            let _ = send_sigterm(pid);
        }
    }

    let deadline = Instant::now() + DIRECT_SHUTDOWN_GRACE_PERIOD;
    loop {
        let mut all_exited = true;
        for child in children.iter_mut() {
            #[cfg(target_os = "linux")]
            if let Some(wrapper) = child.wrapper.as_mut()
                && wrapper.try_wait().ok().flatten().is_some()
            {
                child.wrapper = None;
            }
            #[cfg(target_os = "linux")]
            if linux_pid_is_alive(child.managed_pid) {
                all_exited = false;
            }
            #[cfg(target_os = "linux")]
            if child.wrapper.is_some() {
                all_exited = false;
            }
            #[cfg(not(target_os = "linux"))]
            if child
                .wrapper
                .as_mut()
                .is_some_and(|wrapper| wrapper.try_wait().ok().flatten().is_none())
            {
                all_exited = false;
            }
        }
        if all_exited || Instant::now() >= deadline {
            break;
        }
        sleep(DIRECT_CHILD_POLL_INTERVAL).await;
    }

    for child in children.iter_mut() {
        #[cfg(target_os = "linux")]
        {
            if linux_pid_is_alive(child.managed_pid) {
                let _ = kill_pid_force(child.managed_pid);
            }
            if child.wrapper_pid != child.managed_pid {
                let _ = kill_pid_force(child.wrapper_pid);
            }
        }
        #[cfg(not(target_os = "linux"))]
        if let Some(wrapper) = child.wrapper.as_mut()
            && wrapper.try_wait().ok().flatten().is_none()
        {
            let _ = wrapper.start_kill();
        }
    }
    for child in children.iter_mut() {
        if let Some(mut wrapper) = child.wrapper.take() {
            let _ = wrapper.wait().await;
        }
    }
}

#[cfg(unix)]
pub(crate) fn send_sigterm(pid: u32) -> std::result::Result<(), ()> {
    let pid = i32::try_from(pid).map_err(|_| ())?;
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc == 0 { Ok(()) } else { Err(()) }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_pid_is_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(target_os = "linux")]
pub(crate) fn kill_pid_force(pid: u32) -> std::result::Result<(), ()> {
    let pid = i32::try_from(pid).map_err(|_| ())?;
    let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
    if rc == 0 { Ok(()) } else { Err(()) }
}

#[cfg(all(target_os = "linux", unix))]
pub(crate) fn synthetic_failure_exit_status() -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt as _;

    std::process::ExitStatus::from_raw(1 << 8)
}

#[derive(Debug)]
pub(crate) enum DirectSandbox {
    #[cfg(target_os = "linux")]
    Bubblewrap {
        binary: PathBuf,
    },
    #[cfg(target_os = "macos")]
    Seatbelt {
        binary: PathBuf,
        profiles_dir: PathBuf,
        next_profile_id: usize,
    },
    None,
}

impl DirectSandbox {
    pub(crate) fn detect(runtime_root: &Path) -> Self {
        #[cfg(not(target_os = "macos"))]
        let _ = runtime_root;

        #[cfg(target_os = "linux")]
        if let Some(binary) = find_in_path("bwrap") {
            return Self::Bubblewrap { binary };
        }

        #[cfg(target_os = "macos")]
        if PathBuf::from("/usr/bin/sandbox-exec").is_file() {
            return Self::Seatbelt {
                binary: PathBuf::from("/usr/bin/sandbox-exec"),
                profiles_dir: runtime_root.join("seatbelt"),
                next_profile_id: 0,
            };
        }

        Self::None
    }

    pub(crate) fn is_available(&self) -> bool {
        !matches!(self, Self::None)
    }

    pub(crate) fn wrap_command(&mut self, spec: &ProcessSpec) -> Result<(String, Vec<String>)> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Bubblewrap { binary } => {
                let mut args = vec![
                    "--die-with-parent".to_string(),
                    "--new-session".to_string(),
                    "--unshare-pid".to_string(),
                    "--unshare-ipc".to_string(),
                    "--unshare-uts".to_string(),
                    "--proc".to_string(),
                    "/proc".to_string(),
                    "--dir".to_string(),
                    "/dev".to_string(),
                    "--tmpfs".to_string(),
                    "/dev/shm".to_string(),
                    "--symlink".to_string(),
                    "/proc/self/fd".to_string(),
                    "/dev/fd".to_string(),
                    "--symlink".to_string(),
                    "/proc/self/fd/0".to_string(),
                    "/dev/stdin".to_string(),
                    "--symlink".to_string(),
                    "/proc/self/fd/1".to_string(),
                    "/dev/stdout".to_string(),
                    "--symlink".to_string(),
                    "/proc/self/fd/2".to_string(),
                    "/dev/stderr".to_string(),
                    "--tmpfs".to_string(),
                    "/tmp".to_string(),
                    "--tmpfs".to_string(),
                    "/run".to_string(),
                    "--dir".to_string(),
                    "/var".to_string(),
                    "--symlink".to_string(),
                    "../run".to_string(),
                    "/var/run".to_string(),
                    "--symlink".to_string(),
                    "../tmp".to_string(),
                    "/var/tmp".to_string(),
                    "--bind".to_string(),
                    spec.work_dir.display().to_string(),
                    spec.work_dir.display().to_string(),
                    "--chdir".to_string(),
                    spec.work_dir.display().to_string(),
                ];
                if spec.drop_all_caps {
                    args.push("--cap-drop".to_string());
                    args.push("ALL".to_string());
                }
                if matches!(spec.network, ProcessNetwork::Isolated) {
                    args.push("--unshare-net".to_string());
                }
                let read_only_mounts = linux_read_only_mounts(spec);
                let normalized_work_dir = normalize_linux_writable_dir(&spec.work_dir);
                let run_root = Path::new("/run");
                let tmp_root = Path::new("/tmp");
                let mut bind_dirs = BTreeSet::new();
                for dir in &spec.bind_dirs {
                    if !dir.is_absolute() {
                        continue;
                    }
                    let dir = normalize_linux_writable_dir(dir);
                    if dir == normalized_work_dir {
                        continue;
                    }
                    bind_dirs.insert(dir);
                }
                let mut bind_mounts = BTreeSet::new();
                for mount in &spec.bind_mounts {
                    if !mount.source.is_absolute() || !mount.dest.is_absolute() {
                        continue;
                    }
                    bind_mounts.insert((mount.source.clone(), mount.dest.clone()));
                }

                let mut candidate_set = BTreeSet::new();
                for dir in &spec.writable_dirs {
                    if !dir.is_absolute() {
                        continue;
                    }
                    let dir = normalize_linux_writable_dir(dir);
                    if dir.starts_with(&normalized_work_dir)
                        || dir.starts_with(run_root)
                        || dir.starts_with(tmp_root)
                    {
                        continue;
                    }
                    candidate_set.insert(dir);
                }

                // Avoid nested tmpfs mounts: if a writable dir is already covered by a parent tmpfs
                // mount, the runtime can create subdirectories when needed.
                let mut candidates = candidate_set.into_iter().collect::<Vec<_>>();
                candidates.sort_by(|a, b| {
                    linux_path_depth(a)
                        .cmp(&linux_path_depth(b))
                        .then_with(|| a.cmp(b))
                });
                let mut tmpfs_dirs: Vec<PathBuf> = Vec::new();
                for dir in candidates {
                    if tmpfs_dirs.iter().any(|parent| dir.starts_with(parent)) {
                        continue;
                    }
                    tmpfs_dirs.push(dir);
                }

                let mut dirs_to_create_set = BTreeSet::new();
                for mount in &read_only_mounts {
                    linux_insert_mount_dest_dirs(
                        &mut dirs_to_create_set,
                        &mount.dest,
                        mount.source.is_dir(),
                    );
                }
                for dir in &tmpfs_dirs {
                    linux_insert_mount_dest_dirs(&mut dirs_to_create_set, dir, true);
                }
                for dir in &bind_dirs {
                    linux_insert_mount_dest_dirs(&mut dirs_to_create_set, dir, true);
                }
                for (_, dest) in &bind_mounts {
                    linux_insert_mount_dest_dirs(&mut dirs_to_create_set, dest, true);
                }
                let mut dirs_to_create = dirs_to_create_set.into_iter().collect::<Vec<_>>();
                dirs_to_create.sort_by(|a, b| {
                    linux_path_depth(a)
                        .cmp(&linux_path_depth(b))
                        .then_with(|| a.cmp(b))
                });

                for dir in dirs_to_create {
                    if dir == Path::new("/dev")
                        || dir == Path::new("/run")
                        || dir == Path::new("/tmp")
                        || dir == Path::new("/var")
                    {
                        continue;
                    }
                    args.push("--dir".to_string());
                    args.push(dir.display().to_string());
                }
                for mount in read_only_mounts {
                    args.push("--ro-bind".to_string());
                    args.push(mount.source.display().to_string());
                    args.push(mount.dest.display().to_string());
                }
                for hidden in &spec.hidden_paths {
                    if !hidden.is_absolute() {
                        continue;
                    }
                    linux_push_mount_dest_dirs(&mut args, hidden, true);
                    args.push("--tmpfs".to_string());
                    args.push(hidden.display().to_string());
                }
                for dir in tmpfs_dirs {
                    args.push("--tmpfs".to_string());
                    args.push(dir.display().to_string());
                }
                for dir in bind_dirs {
                    let rendered = dir.display().to_string();
                    args.push("--bind".to_string());
                    args.push(rendered.clone());
                    args.push(rendered);
                }
                for (source, dest) in bind_mounts {
                    args.push("--bind".to_string());
                    args.push(source.display().to_string());
                    args.push(dest.display().to_string());
                }
                for device in LINUX_DEFAULT_DEVICE_PATHS {
                    let device = Path::new(device);
                    if !device.exists() {
                        continue;
                    }
                    args.push("--dev-bind".to_string());
                    args.push(device.display().to_string());
                    args.push(device.display().to_string());
                }
                args.push("--".to_string());
                args.push(spec.program.clone());
                args.extend(spec.args.iter().cloned());

                if matches!(spec.network, ProcessNetwork::Join(_)) {
                    return Ok((binary.display().to_string(), args));
                }

                Ok((binary.display().to_string(), args))
            }
            #[cfg(target_os = "macos")]
            Self::Seatbelt {
                binary,
                profiles_dir,
                next_profile_id,
            } => {
                if !matches!(spec.network, ProcessNetwork::Host) {
                    return Err(miette::miette!(
                        "macOS direct runtime does not support non-host process networking"
                    ));
                }
                if spec
                    .bind_mounts
                    .iter()
                    .any(|mount| mount.source != mount.dest)
                {
                    return Err(miette::miette!(
                        "direct storage mounts require Linux bubblewrap-style bind mounts; macOS \
                         direct output cannot remap {}",
                        spec.bind_mounts
                            .iter()
                            .find(|mount| mount.source != mount.dest)
                            .map(|mount| mount.dest.display().to_string())
                            .unwrap_or_else(|| "storage mount".to_string())
                    ));
                }
                fs::create_dir_all(profiles_dir.as_path())
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!(
                            "failed to create seatbelt profile directory {}",
                            profiles_dir.display()
                        )
                    })?;
                let profile_path = profiles_dir.join(format!("profile-{next_profile_id}.sb"));
                *next_profile_id += 1;
                let profile = render_seatbelt_profile(spec);
                fs::write(&profile_path, profile)
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!(
                            "failed to write seatbelt profile {}",
                            profile_path.display()
                        )
                    })?;

                let mut args = vec![
                    "-f".to_string(),
                    profile_path.display().to_string(),
                    spec.program.clone(),
                ];
                args.extend(spec.args.iter().cloned());
                Ok((binary.display().to_string(), args))
            }
            Self::None => {
                if spec
                    .bind_mounts
                    .iter()
                    .any(|mount| mount.source != mount.dest)
                {
                    return Err(miette::miette!(
                        "direct storage mounts require a runtime that can bind {} into place",
                        spec.bind_mounts
                            .iter()
                            .find(|mount| mount.source != mount.dest)
                            .map(|mount| mount.dest.display().to_string())
                            .unwrap_or_else(|| "storage mount".to_string())
                    ));
                }
                Ok((spec.program.clone(), spec.args.clone()))
            }
        }
    }
}

pub(crate) const MANAGED_PROCESS_PATH: &str = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/\
                                               bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin";

#[cfg(target_os = "linux")]
pub(crate) const LINUX_DEFAULT_READ_ONLY_PATHS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/opt",
    "/nix/store",
    "/etc/alternatives",
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/localtime",
    "/etc/passwd",
    "/etc/group",
    "/etc/ld.so.cache",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/etc/protocols",
    "/etc/services",
];

#[cfg(target_os = "linux")]
pub(crate) const LINUX_DEFAULT_DEVICE_PATHS: &[&str] =
    &["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"];

pub(crate) fn configure_managed_command_env(
    command: &mut TokioCommand,
    work_dir: &Path,
    extra_env: &BTreeMap<String, String>,
) {
    command.env_clear();
    command.env("PATH", MANAGED_PROCESS_PATH);
    command.env("HOME", work_dir);
    command.env("TMPDIR", "/tmp");
    command.envs(extra_env);
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_read_only_mounts(spec: &ProcessSpec) -> Vec<ReadOnlyMount> {
    let mut mounts = BTreeMap::<PathBuf, ReadOnlyMount>::new();
    for mount in linux_default_read_only_mounts() {
        mounts.insert(mount.dest.clone(), mount);
    }
    if let Some(mount) = linux_program_support_mount(spec.program.as_str()) {
        mounts.entry(mount.dest.clone()).or_insert(mount);
    }
    for mount in &spec.read_only_mounts {
        if let Some(mount) = linux_normalize_read_only_mount(mount) {
            mounts.insert(mount.dest.clone(), mount);
        }
    }
    mounts.into_values().collect()
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_default_read_only_mounts() -> Vec<ReadOnlyMount> {
    LINUX_DEFAULT_READ_ONLY_PATHS
        .iter()
        .filter_map(|path| linux_same_path_read_only_mount(Path::new(path)))
        .collect()
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_program_support_mount(program: &str) -> Option<ReadOnlyMount> {
    let program = Path::new(program);
    if !program.is_absolute() {
        return None;
    }
    linux_same_path_read_only_mount(program.parent()?)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_same_path_read_only_mount(path: &Path) -> Option<ReadOnlyMount> {
    if !path.is_absolute() || !path.exists() {
        return None;
    }
    Some(ReadOnlyMount {
        source: fs::canonicalize(path)
            .ok()
            .unwrap_or_else(|| path.to_path_buf()),
        dest: path.to_path_buf(),
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_normalize_read_only_mount(mount: &ReadOnlyMount) -> Option<ReadOnlyMount> {
    if !mount.source.is_absolute() || !mount.dest.is_absolute() || !mount.source.exists() {
        return None;
    }
    Some(ReadOnlyMount {
        source: fs::canonicalize(&mount.source)
            .ok()
            .unwrap_or_else(|| mount.source.clone()),
        dest: mount.dest.clone(),
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn normalize_linux_writable_dir(path: &Path) -> PathBuf {
    if !path.is_absolute() {
        return path.to_path_buf();
    }

    let mut existing_prefix = path;
    let mut suffix = Vec::new();
    while !existing_prefix.exists() {
        let Some(name) = existing_prefix.file_name() else {
            return path.to_path_buf();
        };
        suffix.push(name.to_os_string());
        let Some(parent) = existing_prefix.parent() else {
            return path.to_path_buf();
        };
        existing_prefix = parent;
    }

    let Ok(mut normalized) = fs::canonicalize(existing_prefix) else {
        return path.to_path_buf();
    };
    for segment in suffix.into_iter().rev() {
        normalized.push(segment);
    }
    normalized
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_path_depth(path: &Path) -> usize {
    use std::path::Component;

    path.components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count()
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_insert_mount_dest_dirs(
    out: &mut BTreeSet<PathBuf>,
    path: &Path,
    include_self: bool,
) {
    for dir in linux_mount_dest_dirs(path, include_self) {
        out.insert(dir);
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_push_mount_dest_dirs(args: &mut Vec<String>, path: &Path, include_self: bool) {
    for dir in linux_mount_dest_dirs(path, include_self) {
        args.push("--dir".to_string());
        args.push(dir.display().to_string());
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_mount_dest_dirs(path: &Path, include_self: bool) -> Vec<PathBuf> {
    use std::path::Component;

    if !path.is_absolute() {
        return Vec::new();
    }

    let mut current = PathBuf::from("/");
    let mut out = Vec::new();
    for component in path.components() {
        if let Component::Normal(segment) = component {
            current.push(segment);
            out.push(current.clone());
        }
    }
    if !include_self {
        out.pop();
    }
    out
}

#[cfg(target_os = "macos")]
pub(crate) fn render_seatbelt_profile(spec: &ProcessSpec) -> String {
    let mut allowed = BTreeSet::new();
    insert_seatbelt_path_variants(&mut allowed, &spec.work_dir);
    allowed.insert("/tmp".to_string());
    allowed.insert("/private/tmp".to_string());
    for dir in &spec.writable_dirs {
        insert_seatbelt_path_variants(&mut allowed, dir);
    }
    for dir in &spec.bind_dirs {
        insert_seatbelt_path_variants(&mut allowed, dir);
    }

    let mut profile = String::new();
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n");
    profile.push_str("(import \"system.sb\")\n");
    profile.push_str("(allow process*)\n");
    profile.push_str("(allow network*)\n");
    for path in &spec.hidden_paths {
        let mut variants = BTreeSet::new();
        insert_seatbelt_path_variants(&mut variants, path);
        for rendered in variants {
            profile.push_str("(deny file-read* (subpath \"");
            profile.push_str(&rendered.replace('\\', "\\\\").replace('\"', "\\\""));
            profile.push_str("\"))\n");
            profile.push_str("(deny file-write* (subpath \"");
            profile.push_str(&rendered.replace('\\', "\\\\").replace('\"', "\\\""));
            profile.push_str("\"))\n");
        }
    }
    profile.push_str("(allow file-read*)\n");
    profile.push_str("(allow file-write*");
    for path in allowed {
        profile.push_str(" (subpath \"");
        profile.push_str(&path.replace('\\', "\\\\").replace('\"', "\\\""));
        profile.push_str("\")");
    }
    profile.push_str(")\n");
    profile
}

#[cfg(target_os = "macos")]
pub(crate) fn insert_seatbelt_path_variants(out: &mut BTreeSet<String>, path: &Path) {
    let raw = path.display().to_string();
    out.insert(raw.clone());
    if let Some(alias) = seatbelt_private_alias(raw.as_str()) {
        out.insert(alias);
    }

    if let Ok(canonical) = fs::canonicalize(path) {
        let canonical = canonical.display().to_string();
        out.insert(canonical.clone());
        if let Some(alias) = seatbelt_private_alias(canonical.as_str()) {
            out.insert(alias);
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn seatbelt_private_alias(path: &str) -> Option<String> {
    if path == "/private" {
        return Some("/".to_string());
    }
    if let Some(rest) = path.strip_prefix("/private/") {
        return Some(format!("/{rest}"));
    }
    if path == "/var" || path.starts_with("/var/") {
        return Some(format!("/private{path}"));
    }
    None
}

pub(crate) fn missing_direct_sandbox_help() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "install bubblewrap (`bwrap`) and ensure it is available in PATH (direct mode also uses \
         `slirp4netns`)"
    }
    #[cfg(target_os = "macos")]
    {
        "enable /usr/bin/sandbox-exec"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "this platform is not currently supported for `amber run` direct mode"
    }
}

pub(crate) fn find_in_path(name: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for path in env::split_paths(&path_var) {
        let candidate = path.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub(crate) fn resolve_runtime_binary(name: &str) -> Result<String> {
    if let Ok(dir) = env::var("AMBER_RUNTIME_BIN_DIR") {
        let candidate = Path::new(&dir).join(name);
        if candidate.is_file() {
            return Ok(candidate.display().to_string());
        }
        return Err(miette::miette!(
            "runtime binary `{name}` was not found in AMBER_RUNTIME_BIN_DIR ({})",
            Path::new(&dir).display()
        ));
    }

    if let Ok(current_exe) = env::current_exe()
        && let Some(bin_dir) = current_exe.parent()
    {
        for dir in [Some(bin_dir), bin_dir.parent()].into_iter().flatten() {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate.display().to_string());
            }
        }
    }

    if let Some(candidate) = find_in_path(name) {
        return Ok(candidate.display().to_string());
    }

    Err(miette::miette!(
        "could not locate runtime binary `{name}`; set AMBER_RUNTIME_BIN_DIR, place it next to \
         the `amber` binary, or add it to PATH"
    ))
}

pub(crate) fn provision_mesh_filesystem_with_peer_identities(
    plan: &MeshProvisionPlan,
    root: &Path,
    existing_peer_identities_by_id: &std::collections::BTreeMap<String, MeshIdentityPublic>,
) -> Result<()> {
    if plan.version != MESH_PROVISION_PLAN_VERSION {
        return Err(miette::miette!(
            "unsupported mesh provision plan version {}",
            plan.version
        ));
    }

    let mut identities: HashMap<String, MeshIdentity> = HashMap::new();
    for identity in existing_peer_identities_by_id.values() {
        identities.insert(
            identity.id.clone(),
            MeshIdentity {
                id: identity.id.clone(),
                public_key: identity.public_key,
                private_key: [0; 64],
                mesh_scope: identity.mesh_scope.clone(),
            },
        );
    }
    for target in &plan.targets {
        if existing_peer_identities_by_id.contains_key(&target.config.identity.id) {
            return Err(miette::miette!(
                "mesh provision plan target {} collides with an existing peer identity",
                target.config.identity.id
            ));
        }
        let id = target.config.identity.id.clone();
        let mesh_scope = target.config.identity.mesh_scope.clone();
        identities
            .entry(id)
            .or_insert_with(|| match plan.identity_seed.as_deref() {
                Some(seed) => {
                    MeshIdentity::derive(target.config.identity.id.clone(), mesh_scope, seed)
                }
                None => MeshIdentity::generate(target.config.identity.id.clone(), mesh_scope),
            });
    }

    for target in &plan.targets {
        let output_dir = output_dir_for_target(root, target)?;
        fs::create_dir_all(&output_dir)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to create mesh output directory {}",
                    output_dir.display()
                )
            })?;

        let identity = identities
            .get(&target.config.identity.id)
            .ok_or_else(|| {
                miette::miette!(
                    "missing generated identity for {}",
                    target.config.identity.id
                )
            })?
            .clone();
        let identity_secret = MeshIdentitySecret::from_identity(&identity);
        let public_config = target.config.to_public_config(&identities).map_err(|err| {
            miette::miette!(
                "failed to render mesh config for {}: {err}",
                target.config.identity.id
            )
        })?;

        let identity_path = output_dir.join(MESH_IDENTITY_FILENAME);
        let config_path = output_dir.join(MESH_CONFIG_FILENAME);
        let identity_json = serde_json::to_string_pretty(&identity_secret)
            .map_err(|err| miette::miette!("failed to serialize mesh identity: {err}"))?;
        let config_json = serde_json::to_string_pretty(&public_config)
            .map_err(|err| miette::miette!("failed to serialize mesh config: {err}"))?;
        fs::write(&identity_path, identity_json)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("failed to write mesh identity {}", identity_path.display())
            })?;
        fs::write(&config_path, config_json)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to write mesh config {}", config_path.display()))?;
    }

    Ok(())
}

pub(crate) fn required_existing_mesh_peer_identities(
    plan: &MeshProvisionPlan,
    available_peer_identities_by_id: &std::collections::BTreeMap<String, MeshIdentityPublic>,
) -> Result<std::collections::BTreeMap<String, MeshIdentityPublic>> {
    let target_ids = plan
        .targets
        .iter()
        .map(|target| target.config.identity.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let required_peer_ids = plan
        .targets
        .iter()
        .flat_map(|target| target.config.peers.iter())
        .filter(|peer| !target_ids.contains(peer.id.as_str()))
        .map(|peer| peer.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    required_peer_ids
        .into_iter()
        .map(|peer_id| {
            let identity = available_peer_identities_by_id
                .get(peer_id)
                .cloned()
                .ok_or_else(|| {
                    miette::miette!(
                        "mesh provision plan requires existing peer identity {peer_id}, but it is \
                         not currently available"
                    )
                })?;
            Ok((peer_id.to_string(), identity))
        })
        .collect()
}

pub(crate) fn output_dir_for_target(root: &Path, target: &MeshProvisionTarget) -> Result<PathBuf> {
    match &target.output {
        MeshProvisionOutput::Filesystem { dir } => {
            let path = Path::new(dir);
            if path.is_absolute() {
                return Err(miette::miette!(
                    "mesh provision plan contains absolute filesystem output path {}",
                    path.display()
                ));
            }
            Ok(root.join(path))
        }
        MeshProvisionOutput::KubernetesSecret { name, .. } => Err(miette::miette!(
            "direct runtime does not support kubernetes provision target {}",
            name
        )),
    }
}

pub(crate) async fn proxy(args: ProxyArgs, verbose: u8) -> Result<()> {
    if args.site.is_none()
        && let Some(run_root) =
            mixed_run::maybe_resolve_run_root(&args.output, args.storage_root.as_deref())?
    {
        if args.project_name.is_some()
            || args.mesh_addr.is_some()
            || args.router_addr.is_some()
            || args.router_control_addr.is_some()
            || args.router_config_b64.is_some()
            || args.router_config.is_some()
        {
            return Err(miette::miette!(
                "run-scoped `amber proxy <run-id>` does not support site-scoped router overrides; \
                 pass `--site` to target one internal site explicitly"
            ));
        }

        let run_plan: RunPlan = mixed_run::read_json(&run_root.join("run-plan.json"), "run plan")?;
        let interface = collect_run_interface(&run_plan)?;
        let mut slot_bindings = BTreeMap::new();
        for raw in &args.slot {
            let (slot_name, upstream) = parse_named_socket_addr(raw, "--slot")?;
            let slot = interface
                .external_slots
                .iter()
                .find(|slot| slot.name == slot_name)
                .ok_or_else(|| {
                    miette::miette!(
                        "run does not declare external slot `{slot_name}`; available external \
                         slots: {}",
                        interface
                            .external_slots
                            .iter()
                            .map(|slot| slot.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })?;
            slot_bindings.insert(slot_name, slot_url_from_socket(slot, upstream)?);
        }
        let mut export_bindings = BTreeMap::new();
        for raw in &args.export {
            let (export_name, listen) = parse_named_socket_addr(raw, "--export")?;
            export_bindings.insert(export_name, listen);
        }

        let plan_path =
            mixed_run::write_run_outside_proxy_plan(&run_root, &slot_bindings, &export_bindings)?;
        let _ = verbose;
        return mixed_run::run_outside_proxy(plan_path).await;
    }

    let run_proxy_target = mixed_run::maybe_resolve_proxy_run_target(
        &args.output,
        args.site.as_deref(),
        args.storage_root.as_deref(),
    )?;
    let mut proxy = ProxyCommand::new(
        run_proxy_target
            .as_ref()
            .map(|target| target.artifact_dir.as_path())
            .unwrap_or_else(|| Path::new(&args.output)),
    );
    if let Some(project_name) = args.project_name.as_deref() {
        proxy.set_project_name(project_name)?;
    }
    for raw in &args.slot {
        let (slot, upstream) = parse_named_socket_addr(raw, "--slot")?;
        proxy.add_slot_binding(slot, upstream)?;
    }
    for raw in &args.export {
        let (export, listen) = parse_named_socket_addr(raw, "--export")?;
        proxy.add_export_binding(export, listen)?;
    }
    if let Some(mesh_addr) = args.mesh_addr.as_deref() {
        proxy.set_mesh_addr(mesh_addr)?;
    }
    if let Some(router_addr) = args.router_addr {
        proxy.set_router_addr(router_addr);
    } else if let Some(run_proxy_target) = run_proxy_target.as_ref()
        && let Some(router_addr) = run_proxy_target.router_addr
    {
        proxy.set_router_addr(router_addr);
    }
    if let Some(router_control_addr) = args.router_control_addr.as_deref() {
        apply_router_control_override(&mut proxy, router_control_addr)?;
    } else if let Some(run_proxy_target) = run_proxy_target.as_ref()
        && let Some(router_control_addr) = run_proxy_target.router_control_addr.as_deref()
    {
        apply_router_control_override(&mut proxy, router_control_addr)?;
    }
    if let Some(config) = load_router_config_optional(&args)? {
        proxy.set_router_config(config);
    }

    let proxy = proxy.prepare().await?;
    let proxy_identity = proxy.public_identity();
    init_proxy_tracing(verbose, &proxy_identity)?;
    proxy.run().await
}
