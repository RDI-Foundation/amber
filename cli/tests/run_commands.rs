use std::{fs, process::Command};

use serde_json::json;

fn amber_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_amber"))
}

#[test]
fn ps_defaults_to_tsv_when_stdout_is_not_a_tty() {
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
        stdout.contains("RUN ID\tSITES\tMESH SCOPE\tRUN ROOT"),
        "expected tsv header, got:\n{stdout}"
    );
    assert!(
        stdout.contains("run-123\t1\tmesh.scope.test"),
        "expected tsv row, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("sites: direct_local (direct)"),
        "default non-tty output should stay machine-oriented, got:\n{stdout}"
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
fn ps_supports_explicit_human_format() {
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
        .arg("--human")
        .arg("--storage-root")
        .arg(&storage_root)
        .output()
        .expect("failed to run amber ps --human");

    assert!(
        output.status.success(),
        "amber ps --human failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("run-123"),
        "expected run id, got:\n{stdout}"
    );
    assert!(
        stdout.contains("sites: direct_local (direct)"),
        "expected site summary, got:\n{stdout}"
    );
    assert!(
        stdout.contains("mesh: mesh.scope.test"),
        "expected mesh scope, got:\n{stdout}"
    );
    assert!(
        stdout.contains("exports: unknown"),
        "expected export summary, got:\n{stdout}"
    );
}

#[test]
fn ps_supports_explicit_tsv_format() {
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
        .arg("--tsv")
        .arg("--storage-root")
        .arg(&storage_root)
        .output()
        .expect("failed to run amber ps --tsv");

    assert!(
        output.status.success(),
        "amber ps --tsv failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("RUN ID\tSITES\tMESH SCOPE\tRUN ROOT"),
        "expected tsv header, got:\n{stdout}"
    );
    assert!(
        stdout.contains("run-123\t1\tmesh.scope.test"),
        "expected tsv row, got:\n{stdout}"
    );
}

#[test]
fn logs_prints_persisted_trace_log() {
    let temp = tempfile::tempdir().expect("tempdir should exist");
    let storage_root = temp.path().join("state");
    let run_root = storage_root.join("runs").join("run-456");
    let log_path = run_root.join("observability").join("events.ndjson");
    fs::create_dir_all(
        log_path
            .parent()
            .expect("log path should have a parent directory"),
    )
    .expect("log directory should exist");
    fs::write(
        &log_path,
        concat!(
            "{\"schema\":\"amber.trace.event\",\"version\":1,",
            "\"message\":\"request received from public by /server [headers]\",",
            "\"trace_id\":\"1a1a1a1a1a1a1a1a\",",
            "\"attributes\":{",
            "\"amber_lifecycle_stage\":\"receiver_request\",",
            "\"amber_source_ref\":\"public\",",
            "\"amber_destination_component\":\"/server\",",
            "\"amber_edge_ref\":\"/public.a2a -> /server.a2a\",",
            "\"amber_exchange_step\":\"headers\",",
            "\"amber_http_subject\":\"agent card\"",
            "}}\n"
        ),
    )
    .expect("log file should write");

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
        stdout.contains("agent card"),
        "expected rendered structured trace content, got:\n{stdout}"
    );
    assert!(
        output.stderr.is_empty(),
        "amber logs should not write stderr, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn logs_reports_missing_persisted_trace_log() {
    let temp = tempfile::tempdir().expect("tempdir should exist");
    let storage_root = temp.path().join("state");
    let run_root = storage_root.join("runs").join("run-789");
    fs::create_dir_all(&run_root).expect("run root should exist");

    let output = amber_command()
        .arg("logs")
        .arg("run-789")
        .arg("--storage-root")
        .arg(&storage_root)
        .output()
        .expect("failed to run amber logs");

    assert!(
        !output.status.success(),
        "amber logs should fail when no interaction trace log exists\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("has no persisted interaction traces"),
        "expected missing-trace error, got:\n{stderr}"
    );
}
