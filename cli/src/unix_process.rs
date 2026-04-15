#[cfg(unix)]
use std::{
    collections::{BTreeSet, HashMap},
    process::Command,
};

#[cfg(unix)]
use miette::{Context as _, IntoDiagnostic as _, Result};
#[cfg(unix)]
use tokio::time::{Duration, Instant, sleep};

#[cfg(unix)]
pub(crate) fn pid_is_alive(pid: u32) -> bool {
    let alive = unsafe {
        libc::kill(pid as i32, 0) == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    };
    alive && process_status_code(pid) != Some('Z')
}

#[cfg(unix)]
pub(crate) async fn terminate_process_roots(root_pids: &[u32], timeout: Duration) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    for root_pid in root_pids {
        for pid in process_tree_postorder(*root_pid)? {
            if seen.insert(pid) {
                ordered.push(pid);
            }
        }
    }
    if ordered.is_empty() {
        return Ok(());
    }

    send_signal_to_pids(&ordered, libc::SIGTERM);
    wait_for_pids_exit(&ordered, timeout).await;

    let survivors = ordered
        .iter()
        .copied()
        .filter(|pid| pid_is_alive(*pid))
        .collect::<Vec<_>>();
    if survivors.is_empty() {
        return Ok(());
    }

    send_signal_to_pids(&survivors, libc::SIGKILL);
    wait_for_pids_exit(&survivors, Duration::from_secs(2)).await;
    Ok(())
}

#[cfg(unix)]
fn process_status_code(pid: u32) -> Option<char> {
    let output = Command::new("ps")
        .arg("-o")
        .arg("stat=")
        .arg("-p")
        .arg(pid.to_string())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_process_status_code(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(unix)]
fn parse_process_status_code(raw: &str) -> Option<char> {
    raw.split_whitespace()
        .next()?
        .chars()
        .next()
        .map(|state| state.to_ascii_uppercase())
}

#[cfg(unix)]
fn send_signal_to_pids(pids: &[u32], signal: i32) {
    for pid in pids {
        unsafe {
            libc::kill(*pid as i32, signal);
        }
    }
}

#[cfg(unix)]
async fn wait_for_pids_exit(pids: &[u32], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pids.iter().all(|pid| !pid_is_alive(*pid)) {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(unix)]
fn process_tree_postorder(root_pid: u32) -> Result<Vec<u32>> {
    let output = Command::new("ps")
        .arg("-axo")
        .arg("pid=,ppid=")
        .output()
        .into_diagnostic()
        .wrap_err("failed to enumerate process tree")?;
    if !output.status.success() {
        return Err(miette::miette!(
            "failed to enumerate process tree: status {}",
            output.status
        ));
    }

    let parent_by_pid = parse_process_table(&String::from_utf8_lossy(&output.stdout))?;
    if !parent_by_pid.contains_key(&root_pid) && !pid_is_alive(root_pid) {
        return Ok(Vec::new());
    }

    let mut children_by_parent = HashMap::<u32, Vec<u32>>::new();
    for (pid, ppid) in parent_by_pid {
        children_by_parent.entry(ppid).or_default().push(pid);
    }

    let mut ordered = Vec::new();
    collect_process_tree_postorder(root_pid, &children_by_parent, &mut ordered);
    Ok(ordered)
}

#[cfg(unix)]
fn collect_process_tree_postorder(
    pid: u32,
    children_by_parent: &HashMap<u32, Vec<u32>>,
    ordered: &mut Vec<u32>,
) {
    if let Some(children) = children_by_parent.get(&pid) {
        for child in children {
            collect_process_tree_postorder(*child, children_by_parent, ordered);
        }
    }
    ordered.push(pid);
}

#[cfg(unix)]
fn parse_process_table(raw: &str) -> Result<HashMap<u32, u32>> {
    let mut parent_by_pid = HashMap::new();
    for line in raw.lines() {
        let mut fields = line.split_whitespace();
        let Some(pid) = fields.next() else {
            continue;
        };
        let Some(ppid) = fields.next() else {
            continue;
        };
        let pid = pid
            .parse::<u32>()
            .into_diagnostic()
            .wrap_err_with(|| format!("invalid process table pid `{pid}`"))?;
        let ppid = ppid
            .parse::<u32>()
            .into_diagnostic()
            .wrap_err_with(|| format!("invalid process table parent pid `{ppid}`"))?;
        parent_by_pid.insert(pid, ppid);
    }
    Ok(parent_by_pid)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn parse_process_table_reads_pid_parent_pairs() {
        let table = parse_process_table("10 1\n11 10\n").expect("process table should parse");
        assert_eq!(table.get(&10), Some(&1));
        assert_eq!(table.get(&11), Some(&10));
    }

    #[test]
    fn collect_process_tree_postorder_lists_descendants_before_root() {
        let tree = HashMap::from([(1, vec![2, 3]), (2, vec![4])]);
        let mut ordered = Vec::new();
        collect_process_tree_postorder(1, &tree, &mut ordered);
        assert_eq!(ordered, vec![4, 2, 3, 1]);
    }
}
