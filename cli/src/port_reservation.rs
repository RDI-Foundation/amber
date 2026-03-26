#[cfg(unix)]
use std::os::fd::{AsRawFd as _, RawFd};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr, TcpListener},
};

use miette::{Context as _, IntoDiagnostic as _, Result};

#[derive(Debug)]
pub(crate) struct ReservedTcpPort {
    listener: TcpListener,
}

impl ReservedTcpPort {
    pub(crate) fn bind(listen_addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(listen_addr)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to reserve tcp listener at {listen_addr}"))?;
        Ok(Self { listener })
    }

    pub(crate) fn port(&self) -> Result<u16> {
        Ok(self.listener.local_addr().into_diagnostic()?.port())
    }

    #[cfg(unix)]
    pub(crate) fn clear_close_on_exec(&self) -> Result<()> {
        let fd = self.listener.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(miette::miette!(
                "failed to read listener fd flags for {fd}: {}",
                std::io::Error::last_os_error()
            ));
        }
        let new_flags = flags & !libc::FD_CLOEXEC;
        if unsafe { libc::fcntl(fd, libc::F_SETFD, new_flags) } != 0 {
            return Err(miette::miette!(
                "failed to clear close-on-exec on listener fd {fd}: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn raw_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }
}

pub(crate) fn reserve_unique_tcp_port(
    reserved_ports: &mut BTreeSet<u16>,
    listen_ip: IpAddr,
    preferred_port: Option<u16>,
    description: &str,
) -> Result<ReservedTcpPort> {
    if let Some(preferred_port) = preferred_port {
        if !reserved_ports.insert(preferred_port) {
            return Err(miette::miette!(
                "{description} {preferred_port} was requested twice in one runtime"
            ));
        }
        return ReservedTcpPort::bind(SocketAddr::new(listen_ip, preferred_port));
    }

    for _ in 0..256 {
        let reservation = ReservedTcpPort::bind(SocketAddr::new(listen_ip, 0))?;
        let port = reservation.port()?;
        if reserved_ports.insert(port) {
            return Ok(reservation);
        }
    }

    Err(miette::miette!(
        "ran out of ports while reserving {description}"
    ))
}
