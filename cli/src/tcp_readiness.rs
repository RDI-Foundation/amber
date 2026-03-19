use std::{
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use miette::Result;

pub(crate) fn wait_for_stable_endpoint(addr: SocketAddr, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if endpoint_accepts_stable_connection(
            addr,
            Duration::from_millis(250),
            Duration::from_millis(250),
        ) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(miette::miette!("timeout after {:?}", timeout))
}

pub(crate) fn endpoint_accepts_stable_connection(
    addr: SocketAddr,
    connect_timeout: Duration,
    probe_timeout: Duration,
) -> bool {
    let Ok(stream) = TcpStream::connect_timeout(&addr, connect_timeout) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(probe_timeout));
    let mut probe = [0u8; 1];
    match stream.peek(&mut probe) {
        Ok(0) => false,
        Ok(_) => true,
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            true
        }
        Err(_) => false,
    }
}

pub(crate) fn wait_for_http_response(addr: SocketAddr, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if endpoint_returns_http_response(
            addr,
            Duration::from_millis(250),
            Duration::from_millis(250),
        ) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(miette::miette!("timeout after {:?}", timeout))
}

pub(crate) fn endpoint_returns_http_response(
    addr: SocketAddr,
    connect_timeout: Duration,
    io_timeout: Duration,
) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, connect_timeout) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(io_timeout));
    let _ = stream.set_write_timeout(Some(io_timeout));
    if stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }

    let mut response = [0u8; 256];
    match stream.read(&mut response) {
        Ok(0) => false,
        Ok(count) => response[..count].starts_with(b"HTTP/1."),
        Err(_) => false,
    }
}
