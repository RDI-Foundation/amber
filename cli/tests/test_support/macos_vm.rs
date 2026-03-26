use std::{
    env,
    path::{Path, PathBuf},
};

pub fn resolve_aarch64_firmware() -> PathBuf {
    if let Ok(path) = env::var("AMBER_VM_AARCH64_FIRMWARE") {
        let path = PathBuf::from(path);
        assert!(
            path.is_file(),
            "AMBER_VM_AARCH64_FIRMWARE points to a missing file: {}",
            path.display()
        );
        return path;
    }

    let candidates = [
        "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
        "/usr/local/share/qemu/edk2-aarch64-code.fd",
        "/usr/share/AAVMF/AAVMF_CODE.fd",
        "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
        "/usr/share/edk2/aarch64/QEMU_EFI.fd",
        "/usr/share/edk2/ovmf/AAVMF_CODE.fd",
    ];
    candidates
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| {
            panic!("could not locate AArch64 UEFI firmware; set AMBER_VM_AARCH64_FIRMWARE")
        })
}
