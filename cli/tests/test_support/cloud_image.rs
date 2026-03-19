pub fn default_host_arch_cloud_image_filename() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "ubuntu-24.04-minimal-cloudimg-arm64.img",
        "x86_64" => "ubuntu-24.04-minimal-cloudimg-amd64.img",
        other => panic!("VM tests support only aarch64 and x86_64 hosts, found {other}"),
    }
}
