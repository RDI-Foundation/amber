use std::path::{Path, PathBuf};

pub fn cli_test_outputs_root(workspace_root: &Path) -> PathBuf {
    workspace_root.join("target").join("cli-test-outputs")
}
