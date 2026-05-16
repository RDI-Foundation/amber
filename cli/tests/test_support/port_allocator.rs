use std::{
    collections::BTreeSet,
    net::{SocketAddr, TcpListener},
    sync::{Mutex, OnceLock},
};

const TEST_PORT_RANGE_START: u16 = 20_000;
const TEST_PORT_RANGE_END: u16 = 30_000;
static RESERVED_TEST_PORTS: OnceLock<Mutex<BTreeSet<u16>>> = OnceLock::new();

pub(crate) fn reserve_test_loopback_port() -> u16 {
    let reserved = RESERVED_TEST_PORTS.get_or_init(|| Mutex::new(BTreeSet::new()));
    let mut reserved = reserved
        .lock()
        .expect("test port allocator should not be poisoned");
    let span = u32::from(TEST_PORT_RANGE_END - TEST_PORT_RANGE_START);
    let mut next =
        TEST_PORT_RANGE_START + (std::process::id() % span) as u16 + reserved.len() as u16;
    for _ in 0..usize::from(TEST_PORT_RANGE_END - TEST_PORT_RANGE_START) {
        if next >= TEST_PORT_RANGE_END {
            next = TEST_PORT_RANGE_START;
        }
        let port = next;
        next += 1;
        if reserved.contains(&port) {
            continue;
        }
        match TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))) {
            Ok(listener) => {
                drop(listener);
                reserved.insert(port);
                return port;
            }
            Err(_) => continue,
        }
    }
    panic!(
        "failed to allocate a unique test loopback port in {}-{}",
        TEST_PORT_RANGE_START,
        TEST_PORT_RANGE_END - 1
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_test_loopback_port_uses_reserved_test_range() {
        let port = reserve_test_loopback_port();
        assert!(
            (TEST_PORT_RANGE_START..TEST_PORT_RANGE_END).contains(&port),
            "test allocator returned port outside reserved range: {port}"
        );
    }

    #[test]
    fn reserve_test_loopback_port_does_not_reuse_ports_in_process() {
        let first = reserve_test_loopback_port();
        let second = reserve_test_loopback_port();
        assert_ne!(first, second);
    }
}
