use std::{
    env,
    path::{Path, PathBuf},
};

pub fn cargo_target_dir(workspace_root: &Path) -> PathBuf {
    match env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            if dir.is_absolute() {
                dir
            } else {
                workspace_root.join(dir)
            }
        }
        None => workspace_root.join("target"),
    }
}
