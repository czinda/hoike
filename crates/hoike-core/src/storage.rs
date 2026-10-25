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

/// Durable, atomic replacement of `path` with `bytes` (design §S5).
///
/// The single consolidated publication primitive for state descriptors,
/// immutable generation snapshots, and configured bundle paths: write a
/// fresh temporary file in the destination directory, fsync it, rename it
/// over the target, then fsync the directory so the rename itself is
/// durable. Readers see either the complete old or the complete new bytes.
///
/// A failure before the rename leaves the previous contents untouched (the
/// temporary file is removed). A directory-fsync failure *after* the rename
/// is reported as [`CoreError::DurabilityUncertain`]: the replacement may
/// or may not survive a crash, and callers must neither claim rollback nor
/// completion.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| {
        CoreError::StateStore(format!("cannot create directory {}: {e}", parent.display()))
    })?;
    let tmp = parent.join(format!(
        ".hoike-{}-{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        #[cfg(test)]
        if let Some(mode) = fault_injection::check() {
            return match mode {
                fault_injection::FaultMode::BeforeRename => Err(CoreError::Io(
                    std::io::Error::other("injected failure before rename (test)"),
                )),
                fault_injection::FaultMode::DirFsyncAfterRename => {
                    std::fs::rename(&tmp, path)?;
                    Err(CoreError::DurabilityUncertain {
                        path: path.to_path_buf(),
                        reason: "injected directory-fsync failure (test)".into(),
                    })
                }
            };
        }
        std::fs::rename(&tmp, path)?;
        let dir_fsync = std::fs::File::open(parent).and_then(|dir| dir.sync_all());
        if let Err(e) = dir_fsync {
            return Err(CoreError::DurabilityUncertain {
                path: path.to_path_buf(),
                reason: format!("directory fsync failed after replacing the file: {e}"),
            });
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Test-only fault injection for [`write_atomic`] (audit remediation F05).
///
/// Unit tests in the owning modules use this to fail a specific write at a
/// specific point (before the rename, or at the post-rename directory
/// fsync). It is a thread-local counter — cargo's parallel test threads
/// never see each other's configuration — and compiles away entirely in
/// production builds; it is not a filesystem abstraction.
#[cfg(test)]
pub(crate) mod fault_injection {
    use std::cell::Cell;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum FaultMode {
        /// Fail after the temporary file is written and synced, before the
        /// rename: the previous file is untouched.
        BeforeRename,
        /// Perform the rename, then fail the directory fsync: the outcome
        /// is indeterminate.
        DirFsyncAfterRename,
    }

    thread_local! {
        static SPEC: Cell<Option<(usize, FaultMode)>> = const { Cell::new(None) };
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    /// Fail the `fail_at_call`-th (0-based) `write_atomic` call on this
    /// thread at `mode`, counting from this call.
    pub fn set(fail_at_call: usize, mode: FaultMode) {
        SPEC.with(|s| s.set(Some((fail_at_call, mode))));
        CALLS.with(|c| c.set(0));
    }

    pub fn clear() {
        SPEC.with(|s| s.set(None));
    }

    /// Returns the injected failure mode when the current call is the
    /// configured one.
    pub fn check() -> Option<FaultMode> {
        let call = CALLS.with(|c| {
            let n = c.get();
            c.set(n + 1);
            n
        });
        SPEC.with(|s| s.get().filter(|(at, _)| *at == call).map(|(_, mode)| mode))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_durably_and_cleans_up_on_pre_rename_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");

        // A rename onto a directory fails after the temporary file is
        // written: old contents survive, no temporary is left behind.
        let blocked = dir.path().join("blocked");
        std::fs::create_dir(&blocked).unwrap();
        std::fs::write(blocked.join("previous"), b"old").unwrap();
        assert!(write_atomic(&blocked, b"new").is_err());
        assert_eq!(std::fs::read(blocked.join("previous")).unwrap(), b"old");
        assert!(
            !std::fs::read_dir(dir.path()).unwrap().any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp"))
        );
    }

    #[test]
    fn write_atomic_reports_post_rename_fsync_failure_as_durability_uncertain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        write_atomic(&path, b"old").unwrap();

        fault_injection::set(0, fault_injection::FaultMode::DirFsyncAfterRename);
        let err = write_atomic(&path, b"new").unwrap_err();
        fault_injection::clear();
        assert!(
            matches!(err, CoreError::DurabilityUncertain { .. }),
            "post-rename directory-fsync failure must be the typed error: {err}"
        );
        // The rename itself happened; the outcome is genuinely indeterminate,
        // and the error must say so instead of claiming nothing changed.
        assert!(err.to_string().contains("durability uncertain"), "{err}");
        assert!(
            !err.to_string().to_lowercase().contains("nothing changed"),
            "{err}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }
}
