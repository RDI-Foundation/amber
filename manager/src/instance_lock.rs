use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process,
};

use thiserror::Error;

const LOCK_FILE_NAME: &str = "manager.lock";

#[derive(Debug)]
pub struct InstanceLock {
    #[cfg_attr(unix, allow(dead_code))]
    path: PathBuf,
    _file: File,
}

impl InstanceLock {
    pub fn acquire(data_dir: &Path) -> Result<Self, InstanceLockError> {
        #[cfg(unix)]
        {
            Self::acquire_unix(data_dir)
        }

        #[cfg(not(unix))]
        {
            Self::acquire_pid_file(data_dir)
        }
    }

    #[cfg(unix)]
    fn acquire_unix(data_dir: &Path) -> Result<Self, InstanceLockError> {
        use std::os::fd::AsRawFd;

        let path = data_dir.join(LOCK_FILE_NAME);
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| InstanceLockError::Open {
                path: path.clone(),
                source,
            })?;

        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let source = io::Error::last_os_error();
            if source
                .raw_os_error()
                .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
            {
                return Err(InstanceLockError::AlreadyRunning {
                    path: path.clone(),
                    pid: read_pid_file(&path),
                });
            }
            return Err(InstanceLockError::Lock { path, source });
        }

        write_pid(&mut file, &path)?;
        Ok(Self { path, _file: file })
    }

    #[cfg(not(unix))]
    fn acquire_pid_file(data_dir: &Path) -> Result<Self, InstanceLockError> {
        let path = data_dir.join(LOCK_FILE_NAME);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|source| {
                if source.kind() == io::ErrorKind::AlreadyExists {
                    InstanceLockError::AlreadyRunning {
                        path: path.clone(),
                        pid: read_pid_file(&path),
                    }
                } else {
                    InstanceLockError::Open {
                        path: path.clone(),
                        source,
                    }
                }
            })?;

        write_pid(&mut file, &path)?;
        Ok(Self { path, _file: file })
    }
}

#[cfg(not(unix))]
impl Drop for InstanceLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn write_pid(file: &mut File, path: &Path) -> Result<(), InstanceLockError> {
    file.set_len(0).map_err(|source| InstanceLockError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    writeln!(file, "{}", process::id()).map_err(|source| InstanceLockError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| InstanceLockError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn read_pid_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[derive(Debug, Error)]
pub enum InstanceLockError {
    #[error(
        "manager data dir {} is already in use{}",
        .path.display(),
        .pid.map(|pid| format!(" (pid {pid})")).unwrap_or_default()
    )]
    AlreadyRunning { path: PathBuf, pid: Option<u32> },

    #[error("failed to open manager lock file {}: {source}", .path.display())]
    Open { path: PathBuf, source: io::Error },

    #[error("failed to lock manager data dir {}: {source}", .path.display())]
    Lock { path: PathBuf, source: io::Error },

    #[error("failed to update manager lock file {}: {source}", .path.display())]
    Write { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::{InstanceLock, InstanceLockError};

    #[test]
    fn same_data_dir_cannot_be_locked_twice() {
        let tempdir = TempDir::new().expect("tempdir");
        let first = InstanceLock::acquire(tempdir.path()).expect("acquire first lock");
        let second = InstanceLock::acquire(tempdir.path())
            .expect_err("same data dir should reject a second manager");

        assert!(matches!(second, InstanceLockError::AlreadyRunning { .. }));

        drop(first);

        let _third = InstanceLock::acquire(tempdir.path())
            .expect("lock should be released when the manager exits");
    }
}
