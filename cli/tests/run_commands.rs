use std::{fs, process::Command};

use serde_json::json;

fn amber_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_amber"))
}

#[test]
fn ps_lists_active_runs_from_storage_root() {
    let temp = tempfile::tempdir().expect("tempdir should exist");
    let storage_root = temp.path().join("state");
    let run_root = storage_root.join("runs").join("run-123");
    let artifact_dir = run_root.join("sites").join("direct_local").join("artifact");
    fs::create_dir_all(&artifact_dir).expect("artifact dir should exist");

    fs::write(
        run_root.join("receipt.json"),
        serde_json::to_vec_pretty(&json!({
            "schema": "amber.run.receipt",
            "version": 1,
            "run_id": "run-123",
            "mesh_scope": "mesh.scope.test",
            "plan_path": run_root.join("run-plan.json"),
            "run_root": run_root,
            "sites": {
                "direct_local": {
                    "kind": "direct",
                    "artifact_dir": artifact_dir,
                    "supervisor_pid": 12345
                }
            }
        }))
        .expect("receipt should serialize"),
    )
    .expect("receipt should write");

    let output = amber_command()
        .arg("ps")
        .arg("--storage-root")
        .arg(&storage_root)
        .output()
        .expect("failed to run amber ps");

    assert!(
        output.status.success(),
        "amber ps failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("RUN ID"),
        "expected ps header, got:\n{stdout}"
    );
    assert!(
        stdout.contains("run-123"),
        "expected run id, got:\n{stdout}"
    );
    assert!(
        stdout.contains(
            &storage_root
                .join("runs")
                .join("run-123")
                .display()
                .to_string()
        ),
        "expected run root, got:\n{stdout}"
    );
    assert!(
        output.stderr.is_empty(),
        "amber ps should not write stderr, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn logs_prints_persisted_run_logs() {
    let temp = tempfile::tempdir().expect("tempdir should exist");
    let storage_root = temp.path().join("state");
    let run_root = storage_root.join("runs").join("run-456");
    let log_path = run_root.join("logs").join("manager.log");
    fs::create_dir_all(
        log_path
            .parent()
            .expect("log path should have a parent directory"),
    )
    .expect("log directory should exist");
    fs::write(&log_path, "hello from amber logs\n").expect("log file should write");

    let output = amber_command()
        .arg("logs")
        .arg("run-456")
        .arg("--storage-root")
        .arg(&storage_root)
        .output()
        .expect("failed to run amber logs");

    assert!(
        output.status.success(),
        "amber logs failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("==> logs/manager.log <=="),
        "expected log label, got:\n{stdout}"
    );
    assert!(
        stdout.contains("hello from amber logs"),
        "expected persisted log content, got:\n{stdout}"
    );
    assert!(
        output.stderr.is_empty(),
        "amber logs should not write stderr, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
