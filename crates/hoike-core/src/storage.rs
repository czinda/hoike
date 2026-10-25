//! Process exclusion for state directories (audit remediation F04).
//!
//! One writer per state directory is a structural rule of the anti-rollback
//! store: high-water marks, manifest digests, and committed generation
//! snapshots must advance as one coherent unit. In-process mutexes cannot
//! fence a second process, so every mutating surface (`serve`, `init-state`,
//! offline `import`) holds an OS advisory exclusive lock on `.writer.lock`
//! inside the state directory for its full lifetime.
//!
//! The lock file is never unlinked: removing a live lock inode would let a
//! second writer create a fresh, unlocked inode and bypass exclusion. The
//! file's presence is not the lock — the kernel-held `flock` is.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::error::{CoreError, Result};

/// Name of the advisory writer lock file inside the state directory.
/// `StateStore::initialize` ignores exactly this one file when checking that
/// a new directory is empty; every other entry is recovery material.
pub const WRITER_LOCK_FILE: &str = ".writer.lock";

/// An exclusive, non-blocking OS lock on a state directory.
///
/// The guard owns the open lock file; dropping it closes the descriptor and
/// releases the kernel lock. It also records the canonical state directory so
/// `ResponderState::load` can verify that the guard it retains really protects
/// the directory the configuration names. Cloning the enclosing `Arc` (as the
/// responder and every detached writer task does) keeps the lock held; only
/// the final drop releases it.
pub struct StateDirectoryLock {
    /// The open lock file. Never read or written: owning it is what holds the
    /// kernel lock, and dropping it is what releases exclusion.
    #[allow(dead_code)]
    file: File,
    state_dir: PathBuf,
}

impl StateDirectoryLock {
    /// Acquire the exclusive writer lock on `state_dir`, creating the
    /// directory and lock file if needed. Fails immediately (never blocks)
    /// when another process holds the lock.
    pub fn acquire(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir).map_err(|e| {
            CoreError::StateLock(format!(
                "failed to create state directory {}: {e}",
                state_dir.display()
            ))
        })?;
        let canonical = std::fs::canonicalize(state_dir).map_err(|e| {
            CoreError::StateLock(format!(
                "failed to resolve state directory {}: {e}",
                state_dir.display()
            ))
        })?;
        let lock_path = canonical.join(WRITER_LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                CoreError::StateLock(format!(
                    "failed to open writer lock {}: {e}",
                    lock_path.display()
                ))
            })?;
        lock_exclusive(&file, &lock_path)?;
        Ok(Self {
            file,
            state_dir: canonical,
        })
    }

    /// The canonical state directory protected by this guard.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }
}

#[cfg(unix)]
fn lock_exclusive(file: &File, lock_path: &Path) -> Result<()> {
    use std::os::fd::AsFd;
    match rustix::fs::flock(
        file.as_fd(),
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    ) {
        Ok(()) => Ok(()),
        Err(e) if e == rustix::io::Errno::AGAIN => Err(CoreError::StateLock(format!(
            "another writer process holds the state directory lock {} — one writer per \
             state directory; stop the other process before restarting",
            lock_path.display()
        ))),
        Err(e) => Err(CoreError::StateLock(format!(
            "failed to lock {}: {e}",
            lock_path.display()
        ))),
    }
}

#[cfg(not(unix))]
fn lock_exclusive(_file: &File, lock_path: &Path) -> Result<()> {
    let _ = lock_path;
    Err(CoreError::StateLock(
        "writer exclusion is only implemented for Unix flock targets".into(),
    ))
}
