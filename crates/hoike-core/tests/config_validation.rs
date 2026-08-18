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
