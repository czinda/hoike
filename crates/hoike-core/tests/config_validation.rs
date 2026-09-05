use hoike_core::Config;

#[test]
fn combined_mode_without_source_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("hoike.toml");

    std::fs::write(
        &config_path,
        r#"
[server]
mode = "combined"
listen = "127.0.0.1:0"

[storage]
bundle_dir = "/tmp/hoike-test"

[[ca]]
label = "test-ca"
"#,
    )
    .unwrap();

    let config = Config::from_file(&config_path).unwrap();
    let result = config.validate_for_mode();
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("no source configured"), "got: {msg}");
}

#[test]
fn edge_mode_without_source_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let bundle_dir = dir.path().join("bundles");
    std::fs::create_dir_all(&bundle_dir).unwrap();

    let config_path = dir.path().join("hoike.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[server]
mode = "edge"

[storage]
bundle_dir = "{}"

[[ca]]
label = "test-ca"
"#,
            bundle_dir.display()
        ),
    )
    .unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert!(config.validate_for_mode().is_ok());
}

#[test]
fn combined_mode_with_source_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("hoike.toml");
    let crl_path = dir.path().join("test.crl");
    std::fs::write(&crl_path, b"placeholder").unwrap();

    std::fs::write(
        &config_path,
        format!(
            r#"
[server]
mode = "combined"

[storage]
bundle_dir = "{dir}"

[[ca]]
label = "test-ca"
batch_interval = 60

[ca.source]
type = "crl"
path = "{crl}"

[ca.signing_key]
type = "demo"
"#,
            dir = dir.path().display(),
            crl = crl_path.display(),
        ),
    )
    .unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert!(config.validate_for_mode().is_ok());
    assert!(config.is_combined());
    assert!(config.needs_signing());
    assert_eq!(config.ca[0].batch_interval, 60);
}

#[test]
fn combined_mode_without_signing_key_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("hoike.toml");
    let crl_path = dir.path().join("test.crl");
    std::fs::write(&crl_path, b"placeholder").unwrap();

    std::fs::write(
        &config_path,
        format!(
            r#"
[server]
mode = "combined"

[storage]
bundle_dir = "{dir}"

[[ca]]
label = "test-ca"

[ca.source]
type = "crl"
path = "{crl}"
"#,
            dir = dir.path().display(),
            crl = crl_path.display(),
        ),
    )
    .unwrap();

    let config = Config::from_file(&config_path).unwrap();
    let result = config.validate_for_mode();
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("signing_key"), "got: {msg}");
}

#[test]
fn pkcs11_config_without_pin_allows_interactive_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("hoike.toml");
    let crl_path = dir.path().join("test.crl");
    std::fs::write(&crl_path, b"placeholder").unwrap();

    std::fs::write(
        &config_path,
        format!(
            r#"
[server]
mode = "combined"

[storage]
bundle_dir = "{dir}"

[[ca]]
label = "test-ca"

[ca.source]
type = "crl"
path = "{crl}"

[ca.signing_key]
type = "pkcs11"
module = "/usr/lib/libCryptoki2_64.so"
token_label = "my-partition"
key_label = "hoike-responder"
"#,
            dir = dir.path().display(),
            crl = crl_path.display(),
        ),
    )
    .unwrap();

    let config = Config::from_file(&config_path).unwrap();
    let result = config.validate_for_mode();
    assert!(
        result.is_ok(),
        "PKCS#11 without pin/pin_env should pass validation (interactive prompt at runtime)"
    );
}

#[test]
fn file_signing_key_config_parses() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("hoike.toml");
    let crl_path = dir.path().join("test.crl");
    let key_path = dir.path().join("responder.pem");
    std::fs::write(&crl_path, b"placeholder").unwrap();
    std::fs::write(&key_path, b"placeholder").unwrap();

    std::fs::write(
        &config_path,
        format!(
            r#"
[server]
mode = "combined"

[storage]
bundle_dir = "{dir}"

[[ca]]
label = "test-ca"

[ca.source]
type = "crl"
path = "{crl}"

[ca.signing_key]
type = "file"
path = "{key}"
"#,
            dir = dir.path().display(),
            crl = crl_path.display(),
            key = key_path.display(),
        ),
    )
    .unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert!(config.validate_for_mode().is_ok());
    assert!(matches!(
        config.ca[0].signing_key,
        Some(hoike_core::config::SigningKeyConfig::File { .. })
    ));
}

#[test]
fn gossip_config_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let bundle_dir = dir.path().join("bundles");
    std::fs::create_dir_all(&bundle_dir).unwrap();
    let config_path = dir.path().join("hoike.toml");

    std::fs::write(
        &config_path,
        format!(
            r#"
[server]
mode = "edge"

[storage]
bundle_dir = "{}"

[gossip]
enabled = true
bind = "0.0.0.0:7947"
seeds = ["edge-a.pki.example:7946", "edge-b.pki.example:7946"]
node_name = "test-edge-01"

[[ca]]
label = "test-ca"
"#,
            bundle_dir.display()
        ),
    )
    .unwrap();

    let config = Config::from_file(&config_path).unwrap();
    let gossip = config
        .gossip
        .as_ref()
        .expect("gossip section should be present");
    assert!(gossip.enabled);
    assert_eq!(gossip.bind, "0.0.0.0:7947");
    assert_eq!(gossip.seeds.len(), 2);
    assert_eq!(gossip.node_name, "test-edge-01");
}

#[test]
fn gossip_absent_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let bundle_dir = dir.path().join("bundles");
    std::fs::create_dir_all(&bundle_dir).unwrap();
    let config_path = dir.path().join("hoike.toml");

    std::fs::write(
        &config_path,
        format!(
            r#"
[server]
mode = "edge"

[storage]
bundle_dir = "{}"

[[ca]]
label = "test-ca"
"#,
            bundle_dir.display()
        ),
    )
    .unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert!(config.gossip.is_none());
}

fn parse_config(text: &str) -> Config {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, text).unwrap();
    Config::from_file(&path).unwrap()
}

#[test]
fn configured_tls_never_degrades_to_plaintext() {
    let config = parse_config(
        r#"
[server]
admin_listen = "127.0.0.1:8443"
[server.admin_tls]
cert = "cert.pem"
key = "key.pem"
[storage]
bundle_dir = "/tmp/bundles"
"#,
    );
    assert!(
        config
            .validate_transport(false)
            .unwrap_err()
            .to_string()
            .contains("without the tls feature")
    );
    assert!(config.validate_transport(true).is_ok());
    let mut no_listener = config.clone();
    no_listener.server.admin_listen = None;
    assert!(
        no_listener
            .validate_transport(true)
            .unwrap_err()
            .to_string()
            .contains("admin_listen")
    );
}

#[test]
fn plaintext_forwarding_requires_explicit_opt_in() {
    let mut config = parse_config(
        r#"
[server]
[storage]
bundle_dir = "/tmp/bundles"
[[ca]]
label = "test"
forward_to = "http://127.0.0.1/ocsp"
"#,
    );
    assert!(config.validate_for_mode().is_err());
    config.ca[0].forward_insecure = true;
    assert!(config.validate_for_mode().is_ok());
    config.ca[0].forward_to = Some("file:///etc/passwd".into());
    assert!(config.validate_for_mode().is_err());
}

#[test]
fn generic_source_defaults_to_partial_completeness() {
    let config = parse_config(
        r#"
[server]
[storage]
bundle_dir = "/tmp/bundles"
[[ca]]
label = "test"
"#,
    );
    assert_eq!(config.ca[0].completeness, "partial");
}
