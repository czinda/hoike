//! F04 — explicit state bootstrap at the real CLI boundary.
//!
//! `hoike serve` must never create rollback state implicitly. A missing state
//! directory is an operator error pointing at `hoike init-state`; an existing
//! one is never re-initialized or reset by a restart. One writer process per
//! state directory is enforced with the OS writer lock for the process's full
//! lifetime, and a restart after a clean shutdown preserves the committed
//! marks and the lock file.

use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ahu::{
    BundleBuilder, BundleType, CaScope, Completeness, Continuity, Integrity, Manifest, ResponderId,
    ResponderIdType, Window,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Structural mock bundle (demo admission) — this file exercises bootstrap,
/// not seal authenticity.
fn build_bundle(epoch: u64) -> Vec<u8> {
    let manifest = Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: "cli-init-test".into(),
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

struct Fixture {
    dir: tempfile::TempDir,
    config: PathBuf,
    port: u16,
    second_port: u16,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.ahu"), build_bundle(1)).unwrap();
        // Reserve ephemeral ports so writers are rejected for the state lock,
        // not for a bind conflict. Two distinct ports: the excluded second
        // writer must fail on the state directory, not the listener.
        let reserve = || {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            port
        };
        let port = reserve();
        let second_port = reserve();
        let config = dir.path().join("hoike.toml");
        std::fs::write(
            &config,
            format!(
                "[server]\nmode = 'edge'\nlisten = '127.0.0.1:{port}'\n\
                 [storage]\nbundle_dir = '{dir}'\nstate_db = '{dir}/state'\n\
                 allow_unauthenticated_bundles = true\n\
                 [[ca]]\nlabel = 'test'\n",
                dir = dir.path().display()
            ),
        )
        .unwrap();
        Self {
            dir,
            config,
            port,
            second_port,
        }
    }

    fn state_path(&self) -> PathBuf {
        self.dir.path().join("state/state.json")
    }

    fn hoike(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_hoike"))
            .current_dir(self.dir.path())
            .args(args)
            .env("RUST_LOG", "error")
            .output()
            .unwrap()
    }

    /// A serve command against the same state directory on `listen_port`.
    fn serve_command(&self, listen_port: u16) -> Command {
        let config_path = self.dir.path().join(format!("serve-{listen_port}.toml"));
        let text = std::fs::read_to_string(&self.config).unwrap();
        std::fs::write(
            &config_path,
            text.replace(
                &format!("127.0.0.1:{}", self.port),
                &format!("127.0.0.1:{listen_port}"),
            ),
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_hoike"));
        command
            .current_dir(self.dir.path())
            .args(["serve", "--config", &config_path.to_string_lossy()])
            .env("RUST_LOG", "error");
        command
    }

    fn spawn_serve(&self, listen_port: u16) -> std::process::Child {
        self.serve_command(listen_port)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn wait_listening(&self, child: &mut std::process::Child, port: u16) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("server exited before listening: {status}");
            }
            if TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                Duration::from_millis(200),
            )
            .is_ok()
            {
                return;
            }
            assert!(Instant::now() < deadline, "server did not start listening");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Wait for a child that is expected to exit on its own.
    fn wait_exited(&self, child: &mut std::process::Child) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "process did not exit");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn high_water_marks(&self) -> serde_json::Map<String, serde_json::Value> {
        let raw = std::fs::read_to_string(self.state_path()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        value["high_water_marks"].as_object().unwrap().clone()
    }
}

#[test]
fn init_state_initializes_once_and_never_resets() {
    let f = Fixture::new();
    assert!(!f.state_path().exists());

    let first = f.hoike(&["init-state", "--config", "hoike.toml"]);
    assert!(first.status.success(), "{first:?}");
    assert!(
        f.state_path().exists(),
        "init-state must create the state file"
    );
    let created = std::fs::read(f.state_path()).unwrap();

    // A second initialization is refused and changes nothing: existing state
    // is never reset.
    let second = f.hoike(&["init-state", "--config", "hoike.toml"]);
    assert!(!second.status.success(), "{second:?}");
    assert_eq!(std::fs::read(f.state_path()).unwrap(), created);

    // The writer lock file from the finished init-state process remains (it
    // is never unlinked), but holds no lock once the process exits.
    assert!(f.dir.path().join("state/.writer.lock").exists());
}

#[test]
fn serve_requires_explicit_state_initialization() {
    let f = Fixture::new();
    assert!(!f.state_path().exists());

    let mut child = f.spawn_serve(f.port);
    // The server must refuse to start on missing state rather than serve a
    // silently fresh timeline. Either it exits nonzero, or it starts
    // listening — which would prove implicit initialization.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "serve must fail on missing state");
            assert!(
                !f.state_path().exists(),
                "serve must not create state implicitly"
            );
            return;
        }
        if TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], f.port)),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            let _ = child.kill();
            child.wait().unwrap();
            panic!("serve implicitly initialized missing state and served");
        }
        assert!(
            Instant::now() < deadline,
            "serve neither started nor failed"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn check_stays_read_only_without_state() {
    let f = Fixture::new();
    let output = f.hoike(&["check", "--config", "hoike.toml"]);
    assert!(output.status.success(), "{output:?}");
    assert!(!f.state_path().exists(), "check created state");
}

#[test]
fn serve_is_process_exclusive_and_restart_preserves_state() {
    let f = Fixture::new();
    let init = f.hoike(&["init-state", "--config", "hoike.toml"]);
    assert!(init.status.success(), "{init:?}");

    // First writer: a real serve process, ready when it accepts connections.
    let mut first = f.spawn_serve(f.port);
    f.wait_listening(&mut first, f.port);

    // A second serve process on the same state directory (distinct port) must
    // be rejected by the writer lock for its whole lifetime.
    let mut second = f
        .serve_command(f.second_port)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let second_status = f.wait_exited(&mut second);
    assert!(!second_status.success(), "second writer must be excluded");
    let mut stderr = String::new();
    second
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        stderr.contains("lock"),
        "exclusion error must identify the writer lock: {stderr}"
    );

    // Stop the first writer; its process exit releases the OS lock.
    first.kill().unwrap();
    first.wait().unwrap();

    // The committed marks survive the shutdown.
    let marks_before = f.high_water_marks();
    assert!(
        marks_committed(&marks_before),
        "first serve must have committed rollback marks: {marks_before:?}"
    );

    // Restart without re-initializing: existing state is reused, never reset
    // or deleted, and no explicit initialization is needed.
    let mut restart = f.spawn_serve(f.port);
    f.wait_listening(&mut restart, f.port);
    restart.kill().unwrap();
    restart.wait().unwrap();

    assert!(f.state_path().exists(), "restart must not delete state");
    assert_eq!(
        f.high_water_marks(),
        marks_before,
        "restart must not reset or lose committed marks"
    );
    assert!(
        f.dir.path().join("state/.writer.lock").exists(),
        "the lock file is never unlinked"
    );
}

fn marks_committed(marks: &serde_json::Map<String, serde_json::Value>) -> bool {
    !marks.is_empty()
        && marks
            .values()
            .all(|v| v.as_u64().is_some_and(|epoch| epoch >= 1))
}
