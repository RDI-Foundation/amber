use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use miette::{Context as _, IntoDiagnostic as _, Result};
use tokio::time::sleep;

use crate::mixed_run::{self, RunReceipt};

#[derive(Clone, Copy, Debug)]
pub(crate) struct RunLogOptions {
    pub(crate) follow: bool,
    pub(crate) print_existing: bool,
}

impl Default for RunLogOptions {
    fn default() -> Self {
        Self {
            follow: true,
            print_existing: true,
        }
    }
}

pub(crate) fn print_run_ps(storage_root: &Path) -> Result<()> {
    let runs_dir = storage_root.join("runs");
    let mut receipts = Vec::new();
    if runs_dir.is_dir() {
        for entry in fs::read_dir(&runs_dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to list {}", runs_dir.display()))?
        {
            let entry = entry.into_diagnostic()?;
            let run_root = entry.path();
            let receipt_path = run_root.join("receipt.json");
            if !receipt_path.is_file() {
                continue;
            }
            let receipt: RunReceipt = mixed_run::read_json(&receipt_path, "run receipt")?;
            receipts.push(receipt);
        }
    }

    receipts.sort_by(|left, right| left.run_id.cmp(&right.run_id));
    if receipts.is_empty() {
        println!("no active runs");
        return Ok(());
    }

    println!("RUN ID\tSITES\tMESH SCOPE\tRUN ROOT");
    for receipt in receipts {
        println!(
            "{}\t{}\t{}\t{}",
            receipt.run_id,
            receipt.sites.len(),
            receipt.mesh_scope,
            receipt.run_root
        );
    }
    Ok(())
}

pub(crate) fn print_run_logs(run_root: &Path) -> Result<()> {
    for path in collect_log_files(run_root)? {
        let contents = fs::read(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read {}", path.display()))?;
        if contents.is_empty() {
            continue;
        }
        print_log_chunk(run_root, &path, &contents);
    }
    Ok(())
}

pub(crate) async fn stream_run_logs_until(run_root: &Path, options: RunLogOptions) -> Result<()> {
    let mut follower = LogFollower::new(run_root.to_path_buf(), options.print_existing);
    follower.poll_once()?;
    if !options.follow {
        return Ok(());
    }

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.into_diagnostic().wrap_err("failed to wait for Ctrl-C")?;
                return Ok(());
            }
            _ = sleep(Duration::from_millis(250)) => {
                follower.poll_once()?;
            }
        }
    }
}

struct LogFollower {
    run_root: PathBuf,
    offsets: BTreeMap<PathBuf, usize>,
    print_existing: bool,
}

impl LogFollower {
    fn new(run_root: PathBuf, print_existing: bool) -> Self {
        Self {
            run_root,
            offsets: BTreeMap::new(),
            print_existing,
        }
    }

    fn poll_once(&mut self) -> Result<()> {
        for path in collect_log_files(&self.run_root)? {
            let bytes = fs::read(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read {}", path.display()))?;
            let offset = self
                .offsets
                .entry(path.clone())
                .or_insert_with(|| if self.print_existing { 0 } else { bytes.len() });
            if bytes.len() < *offset {
                *offset = 0;
            }
            if bytes.len() == *offset {
                continue;
            }
            print_log_chunk(&self.run_root, &path, &bytes[*offset..]);
            *offset = bytes.len();
        }
        Ok(())
    }
}

fn collect_log_files(run_root: &Path) -> Result<Vec<PathBuf>> {
    if !run_root.exists() {
        return Err(miette::miette!(
            "run root {} does not exist",
            run_root.display()
        ));
    }
    let mut stack = vec![run_root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to list {}", path.display()))?
        {
            let entry = entry.into_diagnostic()?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                stack.push(entry_path);
                continue;
            }
            if entry_path.extension().and_then(|ext| ext.to_str()) == Some("log") {
                files.push(entry_path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn print_log_chunk(run_root: &Path, path: &Path, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let label = path
        .strip_prefix(run_root)
        .unwrap_or(path)
        .display()
        .to_string();
    print!("==> {label} <==\n{}", String::from_utf8_lossy(bytes));
}
