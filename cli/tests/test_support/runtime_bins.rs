#[path = "target_dir.rs"]
mod target_dir_support;

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

use target_dir_support::cargo_target_dir;

pub fn runtime_bin_dir(workspace_root: &Path) -> &'static PathBuf {
    static BIN_DIR: OnceLock<PathBuf> = OnceLock::new();
    BIN_DIR.get_or_init(|| {
        let output = Command::new("cargo")
            .current_dir(workspace_root)
            .arg("build")
            .arg("-q")
            .arg("-p")
            .arg("amber-cli")
            .arg("-p")
            .arg("amber-router")
            .arg("-p")
            .arg("amber-helper")
            .output()
            .expect("failed to build amber runtime binaries");
        assert!(
            output.status.success(),
            "failed to build runtime binaries\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        cargo_target_dir(workspace_root).join("debug")
    })
}
