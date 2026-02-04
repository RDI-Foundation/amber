pub mod docker_compose;
pub mod kubernetes;

pub(crate) mod addressing;
pub(crate) mod config;
pub(crate) mod plan;
pub(crate) mod router_config;

// RFC1918 + link-local + CGNAT: treated as local/private ranges.
pub(crate) const LOCAL_NETWORK_CIDRS: [&str; 5] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
];
