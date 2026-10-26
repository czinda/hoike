//! Startup-validated outbound clients for nonce forwarding (October audit
//! F10, design S8).
//!
//! Forwarding trust belongs to each configured CA. `build_forward_clients`
//! constructs one reused reqwest client per forward-enabled CA label:
//!
//! - with `forward_ca`, the PEM bundle is parsed at construction, must yield
//!   at least one certificate, and becomes the *only* trusted root material
//!   (`tls_built_in_root_certs(false)` + one `add_root_certificate` per
//!   parsed root). Hostname and validity checking stay on; invalid-certificate
//!   or invalid-hostname acceptance is never enabled.
//! - without `forward_ca`, the client keeps reqwest's bundled WebPKI roots
//!   (the `rustls-tls` feature selects webpki-roots — not the system store).
//!
//! All clients share the serving policy that `forward_request` enforced from
//! the start: a 10-second timeout and no redirects. An unreadable, empty, or
//! malformed root file, a `forward_ca` on a non-HTTPS target, or a duplicate
//! CA label is a configuration error — construction fails instead of
//! silently falling back to a different trust policy. `hoike check` calls the
//! same function, so it fails on the same inputs without opening a listener
//! or sending a request.

use hoike_core::config::Config;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// Build the per-CA forwarding clients described by `config`, keyed by CA
/// label. Only CAs with a `forward_to` target get a client; a non-forwarding
/// CA requires none.
pub fn build_forward_clients(config: &Config) -> Result<HashMap<String, reqwest::Client>, String> {
    let mut labels: HashSet<&str> = HashSet::new();
    let mut clients = HashMap::new();
    for ca in &config.ca {
        // Duplicate labels must reject rather than overwrite one CA's trust
        // policy with another's. (Config validation rejects these too; this
        // keeps the constructor self-contained for `hoike check` and tests.)
        if !labels.insert(ca.label.as_str()) {
            return Err(format!(
                "duplicate CA label '{}' — each forwarding CA needs a unique trust policy",
                ca.label
            ));
        }
        let Some(url) = ca.forward_to.as_deref() else {
            continue;
        };
        let mut builder = base_client_builder();
        if let Some(ca_path) = &ca.forward_ca {
            // Pinned private roots are meaningless without TLS: reject a
            // custom root configured for a cleartext (or otherwise non-HTTPS)
            // target rather than shipping trust material that is never used.
            if !url.starts_with("https://") {
                return Err(format!(
                    "CA '{}': forward_ca requires an https:// forward_to (got '{url}')",
                    ca.label
                ));
            }
            let pem = std::fs::read(ca_path).map_err(|e| {
                format!(
                    "CA '{}': cannot read forward_ca {}: {e}",
                    ca.label,
                    ca_path.display()
                )
            })?;
            let roots = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
                format!(
                    "CA '{}': invalid forward_ca PEM bundle {}: {e}",
                    ca.label,
                    ca_path.display()
                )
            })?;
            if roots.is_empty() {
                return Err(format!(
                    "CA '{}': forward_ca {} contains no certificates",
                    ca.label,
                    ca_path.display()
                ));
            }
            builder = builder.tls_built_in_root_certs(false);
            for root in roots {
                builder = builder.add_root_certificate(root);
            }
        }
        let client = builder
            .build()
            .map_err(|e| format!("CA '{}': building forwarding client: {e}", ca.label))?;
        clients.insert(ca.label.clone(), client);
    }
    Ok(clients)
}

/// The shared forward-channel policy: 10-second timeout, no redirects.
fn base_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
}
