//! F04 — explicit state bootstrap and process exclusion.
//!
//! A state directory is operator-acknowledged state, not a cache that can be
//! silently rebuilt. Missing state after recorded history, and committed state
//! missing its paired records or snapshots, must be explicit errors — never a
//! fresh timeline that would accept an older epoch. One writer process per
//! state directory is enforced with an OS advisory lock held for the writer's
//! full lifetime.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use ahu::{
    BundleBuilder, BundleType, CaScope, Completeness, Continuity, Integrity, Manifest, ResponderId,
    ResponderIdType, Window,
};
use hoike_core::state::StateStore;
use hoike_core::{Config, ResponderState, StateDirectoryLock};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Structural mock bundle (demo admission) — these tests exercise state
/// bootstrap, not seal authenticity.
fn make_bundle(producer: &str, epoch: u64) -> Vec<u8> {
    let manifest = Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: producer.into(),
        created_at: 1700000000 + epoch * 3600,
        bundle_type: BundleType::Full,
        ca_scopes: vec![CaScope {
            hash_algorithm: vec![0x01],
            issuer_name_hash: vec![0xAA; 32],
            issuer_key_hash: vec![0xBB; 32],
            epoch,
            responder_id: ResponderId {
                id_type: ResponderIdType::ByKey,
                value: vec![0xCC; 20],
            },
            responder_chain: None,
            signature_algorithm: vec![0x02],
            completeness: Completeness::AuthoritativeComplete,
        }],
        window: Window {
            produced_at: 1700000000 + epoch * 3600,
            this_update_min: 1700000000 + epoch * 3600,
            next_update_min: 1700086400 + epoch * 3600,
            next_update_max: 1700093600 + epoch * 3600,
        },
        integrity: Integrity {
            index_digest: [0; 32],
            data_digest: [0; 32],
        },
        entry_count: 0,
        continuity: Continuity {
            prev_manifest_digest: None,
            base_manifest_digest: None,
            chain_length: 0,
        },
        shard: None,
        compression: None,
        extensions: None,
    };

    let mut builder = BundleBuilder::new(manifest);
    builder.add_entry([epoch as u8; 32], format!("response-{epoch}").into_bytes());
    builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap()
}

fn write_config(dir: &Path) -> Config {
    toml::from_str(&format!(
        "[server]\nmode = 'edge'\n[storage]\nbundle_dir = '{0}'\nstate_db = '{0}/state'\n\
         allow_unauthenticated_bundles = true\n[[ca]]\nlabel = 'test'\n",
        dir.display()
    ))
    .unwrap()
}

/// Explicitly bootstrap a newly created fixture directory, then acquire the
/// writer lock. Mirrors `hoike init-state` + `hoike serve` ordering.
fn init_state(config: &Config) -> Arc<StateDirectoryLock> {
    StateStore::initialize(&config.storage.state_db.join("state.json")).unwrap();
    Arc::new(StateDirectoryLock::acquire(&config.storage.state_db).unwrap())
}

fn load_responder(config: &Config) -> hoike_core::error::Result<ResponderState> {
    let guard = Arc::new(StateDirectoryLock::acquire(&config.storage.state_db).unwrap());
    ResponderState::load(config.clone(), guard)
}

/// Parse the first committed snapshot path out of a state file.
fn committed_snapshot(state_path: &Path) -> PathBuf {
    let raw = std::fs::read_to_string(state_path).unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    value["active_bundles"]
        .as_object()
        .expect("committed state has active bundles")
        .values()
        .next()
        .expect("at least one active bundle")
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn missing_state_after_epoch_99_rejects_epoch_5() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let state_path = state_dir.join("state.json");
    std::fs::create_dir_all(&state_dir).unwrap();
    // Valid persisted state recording epoch 99 for one scope.
    std::fs::write(
        &state_path,
        serde_json::json!({
            "high_water_marks": { "producer:0b0b": 99 },
            "manifest_digests": { "producer:0b0b": hex::encode([9u8; 32]) },
        })
        .to_string(),
    )
    .unwrap();
    assert!(
        StateStore::open(&state_path).is_ok(),
        "valid legacy state must open"
    );

    // The state file goes missing (loss, partial restore, wrong volume).
    std::fs::remove_file(&state_path).unwrap();

    // Opening missing state must be an error that points at explicit
    // initialization or recovery — never a silently fresh timeline.
    let err = match StateStore::open(&state_path) {
        Err(e) => e,
        Ok(_) => panic!("missing state must not open"),
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("init-state") || msg.contains("restore"),
        "error must point to explicit initialization/recovery: {msg}"
    );

    // A load with an epoch-5 bundle must be rejected outright; accepting it
    // would forget the epoch-99 high-water mark.
    let config = write_config(dir.path());
    std::fs::write(dir.path().join("test.ahu"), make_bundle("producer", 5)).unwrap();
    let load = load_responder(&config);
    assert!(
        load.is_err(),
        "a responder must not serve an older bundle over missing state"
    );
    // No state file may be recreated implicitly.
    assert!(!state_path.exists());
}

#[test]
fn initialization_refuses_existing_or_orphaned_state() {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state/state.json");

    // A fresh directory initializes.
    StateStore::initialize(&state_path).unwrap();
    let before = std::fs::read(&state_path).unwrap();
    assert!(!before.is_empty());

    // Re-initializing existing state is refused and changes nothing.
    assert!(StateStore::initialize(&state_path).is_err());
    assert_eq!(std::fs::read(&state_path).unwrap(), before);

    // An orphaned directory — recovery material without a state file — is
    // refused: creating or having a directory does not authorize resetting it.
    let orphan = dir.path().join("orphan/state");
    std::fs::create_dir_all(orphan.join("generations")).unwrap();
    std::fs::write(
        orphan.join("generations/deadbeef.ahu"),
        b"leftover snapshot",
    )
    .unwrap();
    assert!(StateStore::initialize(&orphan.join("state.json")).is_err());
    assert!(!orphan.join("state.json").exists());

    // A sync cookie left behind is equally recovery material.
    let cookie = dir.path().join("cookie/state");
    std::fs::create_dir_all(&cookie).unwrap();
    std::fs::write(cookie.join("sync-test.json"), b"{}").unwrap();
    assert!(StateStore::initialize(&cookie.join("state.json")).is_err());
    assert!(!cookie.join("state.json").exists());

    // The writer lock file alone does not block initialization of a new
    // directory: it is the one file initialization is allowed to ignore.
    let fresh = dir.path().join("fresh/state");
    drop(StateDirectoryLock::acquire(&fresh).unwrap());
    assert!(fresh.join(".writer.lock").exists());
    StateStore::initialize(&fresh.join("state.json")).unwrap();

    // A lock file must not mask other recovery material in the same
    // directory, whatever the directory iteration order.
    let masked = dir.path().join("masked/state");
    drop(StateDirectoryLock::acquire(&masked).unwrap());
    std::fs::write(masked.join("sync-lost.json"), b"{}").unwrap();
    assert!(StateStore::initialize(&masked.join("state.json")).is_err());
    assert!(!masked.join("state.json").exists());
}

#[test]
fn incomplete_committed_state_requires_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    std::fs::write(dir.path().join("test.ahu"), make_bundle("producer", 1)).unwrap();
    let guard = init_state(&config);
    let responder = ResponderState::load(config.clone(), guard).unwrap();
    drop(responder);
    let state_path = config.storage.state_db.join("state.json");
    let snapshot = committed_snapshot(&state_path);
    let snapshot_bytes = std::fs::read(&snapshot).unwrap();
    let state_bytes = std::fs::read(&state_path).unwrap();

    // Corrupt JSON was already an error; keep it an error.
    std::fs::write(&state_path, b"{ not json").unwrap();
    assert!(StateStore::open(&state_path).is_err());
    std::fs::write(&state_path, &state_bytes).unwrap();

    // A missing snapshot referenced by committed state is recovery failure.
    std::fs::remove_file(&snapshot).unwrap();
    assert!(
        StateStore::open(&state_path).is_err(),
        "missing committed snapshot must fail open"
    );
    std::fs::write(&snapshot, &snapshot_bytes).unwrap();

    // A tampered snapshot (content no longer matches its digest name) is
    // recovery failure.
    std::fs::write(&snapshot, b"tampered").unwrap();
    assert!(
        StateStore::open(&state_path).is_err(),
        "mismatched snapshot digest must fail open"
    );
    std::fs::write(&snapshot, &snapshot_bytes).unwrap();

    // A committed snapshot whose scope has no high-water mark is an
    // interrupted commit, not a new scope.
    let mut value: serde_json::Value = serde_json::from_slice(&state_bytes).unwrap();
    value["high_water_marks"].as_object_mut().unwrap().clear();
    value["manifest_digests"].as_object_mut().unwrap().clear();
    std::fs::write(&state_path, value.to_string()).unwrap();
    assert!(
        StateStore::open(&state_path).is_err(),
        "active snapshot without rollback marks must fail open"
    );

    // Unpaired records are corrupt state, not a partial new scope.
    let mut value: serde_json::Value = serde_json::from_slice(&state_bytes).unwrap();
    value["high_water_marks"].as_object_mut().unwrap().clear();
    std::fs::write(&state_path, value.to_string()).unwrap();
    assert!(
        StateStore::open(&state_path).is_err(),
        "manifest digest without a high-water record must fail open"
    );

    // The untouched committed state still opens (marks and snapshots intact).
    std::fs::write(&state_path, &state_bytes).unwrap();
    assert!(StateStore::open(&state_path).is_ok());
}

// ── Two-process exclusion ──────────────────────────────────────────────
//
// The lock tests re-execute this test binary as real subprocesses, selected
// by HOIKE_STATE_LOCK_WORKER, so exclusion is proven across actual process
// boundaries with a pipe handshake — no sleep-based timing and no PID files.

const WORKER_MODE_ENV: &str = "HOIKE_STATE_LOCK_WORKER";
const WORKER_DIR_ENV: &str = "HOIKE_STATE_LOCK_WORKER_DIR";

fn spawn_worker(mode: &str, dir: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    // Run only the worker entry below, with test output unpiped so the
    // protocol lines reach our pipes instead of libtest's capture.
    command
        .args(["--exact", "lock_worker", "--nocapture"])
        .env(WORKER_MODE_ENV, mode)
        .env(WORKER_DIR_ENV, dir);
    command
}

/// Worker entry. Re-executed as a subprocess by the tests above; returns
/// immediately (a passing no-op test) when the selector env is absent.
#[test]
fn lock_worker() {
    let mode = match std::env::var_os(WORKER_MODE_ENV) {
        None => return,
        Some(mode) => mode,
    };
    let dir = PathBuf::from(std::env::var_os(WORKER_DIR_ENV).expect("worker dir"));
    match mode.to_string_lossy().as_ref() {
        // Try to acquire the lock once; exit 0 on success, panic (nonzero
        // exit) on failure. The parent distinguishes outcomes by exit status.
        "try" => {
            StateDirectoryLock::acquire(&dir).unwrap_or_else(|e| {
                panic!("worker could not acquire lock: {e}");
            });
        }
        // Hold the lock and speak a line protocol on stdin/stdout:
        //   parent reads "acquired" once the lock is held
        //   "clone" → the original owner drops its handle while a writer
        //             retains the shared guard, reply "cloned"
        //   "drop"  → the retained handle drops, reply "dropped"
        //   "exit"  → release everything and exit 0
        "hold" => {
            // The original owner's handle; the lock lives while any handle
            // to this allocation survives (the responder's Arc semantics).
            let mut owner: Option<Arc<StateDirectoryLock>> =
                Some(Arc::new(StateDirectoryLock::acquire(&dir).unwrap()));
            let mut stdout = std::io::stdout();
            writeln!(stdout, "acquired").unwrap();
            stdout.flush().unwrap();
            let mut retained: Option<Arc<StateDirectoryLock>> = None;
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                match line.unwrap().as_str() {
                    "clone" => {
                        // The listener owner goes away; the writer keeps the
                        // shared guard alive.
                        retained = owner.take();
                        writeln!(stdout, "cloned").unwrap();
                        stdout.flush().unwrap();
                    }
                    "drop" => {
                        retained.take();
                        writeln!(stdout, "dropped").unwrap();
                        stdout.flush().unwrap();
                    }
                    "exit" => break,
                    other => panic!("unknown worker command: {other}"),
                }
            }
            // Any surviving handles drop here on exit.
        }
        other => panic!("unknown worker mode: {other}"),
    }
}

/// Read lines from a worker's stdout until the expected marker arrives
/// (libtest prints its own banners first).
fn wait_for_marker(reader: &mut BufReader<std::process::ChildStdout>, marker: &str) {
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        assert!(n > 0, "worker closed stdout before sending {marker}");
        if line.trim() == marker {
            return;
        }
    }
}

#[test]
fn state_directory_lock_is_process_exclusive() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    StateStore::initialize(&state_dir.join("state.json")).unwrap();

    // First writer: a real subprocess holding the lock, handshake via pipe.
    let mut first = spawn_worker("hold", &state_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first_stdin = first.stdin.take().unwrap();
    let mut first_stdout = BufReader::new(first.stdout.take().unwrap());
    wait_for_marker(&mut first_stdout, "acquired");

    // A second real process must fail to acquire while the first lives.
    let second_writer_status = spawn_worker("try", &state_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!second_writer_status.success());

    // Release the first writer through the pipe and wait for its exit.
    writeln!(first_stdin, "exit").unwrap();
    first_stdin.flush().unwrap();
    drop(first_stdin);
    assert!(first.wait().unwrap().success());

    // The lock is a kernel object tied to the open file, not a PID file that
    // could go stale: a writer after the first process exits succeeds.
    let writer_after_first_process_exit = spawn_worker("try", &state_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(writer_after_first_process_exit.success());

    // The lock file itself is never unlinked.
    assert!(state_dir.join(hoike_core::WRITER_LOCK_FILE).exists());
}

#[test]
fn writer_guard_outlives_listener_owner() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    StateStore::initialize(&state_dir.join("state.json")).unwrap();

    let mut owner = spawn_worker("hold", &state_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut owner_stdin = owner.stdin.take().unwrap();
    let mut owner_stdout = BufReader::new(owner.stdout.take().unwrap());
    wait_for_marker(&mut owner_stdout, "acquired");

    // The listener owner drops its original guard handle but a writer clone
    // is retained — exactly how a detached signer task keeps the responder
    // alive after the listener that created it goes away.
    writeln!(owner_stdin, "clone").unwrap();
    owner_stdin.flush().unwrap();
    wait_for_marker(&mut owner_stdout, "cloned");

    // A second process stays excluded while the clone is retained.
    let during = spawn_worker("try", &state_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !during.success(),
        "second writer must stay excluded while a guard clone is retained"
    );

    // Only the final clone's drop releases the lock.
    writeln!(owner_stdin, "drop").unwrap();
    owner_stdin.flush().unwrap();
    wait_for_marker(&mut owner_stdout, "dropped");
    writeln!(owner_stdin, "exit").unwrap();
    owner_stdin.flush().unwrap();
    drop(owner_stdin);
    assert!(owner.wait().unwrap().success());

    let after = spawn_worker("try", &state_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(after.success());
}
