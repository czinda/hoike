//! Observability facade: Prometheus metrics + structured audit log.
//!
//! Every recording function here is a thin wrapper that compiles to a no-op
//! unless the `metrics` feature is enabled. This keeps instrumentation call
//! sites in the OCSP hot path free of `#[cfg]` noise and imposes zero cost on
//! the default build. The audit log (`audit!`) is always active — it is a
//! `tracing` event on the dedicated `audit` target, which existing subscribers
//! can route to their own sink.
//!
//! Design reference: `hoike-design.md` §9 (metric surface).

use hoike_core::router::ScopeDetail;

/// Emit a structured audit event on the `audit` tracing target.
///
/// Audit events are operational-security records — bundle loads, epoch
/// transitions, request rejections, and signer generations — kept distinct
/// from ordinary diagnostic logging so operators can route them to a separate,
/// longer-retention sink.
#[macro_export]
macro_rules! audit {
    ($($arg:tt)*) => {
        ::tracing::info!(target: "audit", $($arg)*);
    };
}
// Re-export so `crate::obs::audit!` (internal) and `hoike_server::obs::audit!`
// (from the CLI crate) both resolve to the crate-root macro that `#[macro_export]`
// creates.
pub use crate::audit;

/// Classify a bundle load/reload error into a stable `reason` label for the
/// `hoike_bundle_load_failures_total` counter. Anti-rollback and continuity
/// violations are the operationally interesting cases; everything else collapses
/// to coarse buckets. Always available (no metrics dep) so call sites can
/// classify even in the default build.
pub fn load_failure_reason(err: &hoike_core::CoreError) -> &'static str {
    use hoike_core::CoreError::*;
    match err {
        EpochRollback { .. } | EpochJumpTooLarge { .. } => "rollback",
        ForkDetected { .. } => "fork",
        Bundle(_) => "bundle",
        StateStore(_) => "state",
        Io(_) => "io",
        _ => "other",
    }
}

// ---------------------------------------------------------------------------
// Feature-on implementation
// ---------------------------------------------------------------------------
#[cfg(feature = "metrics")]
mod imp {
    use super::ScopeDetail;
    use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
    use std::sync::OnceLock;

    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

    /// Install the global Prometheus recorder. Idempotent: a second call while a
    /// recorder is already installed returns `false` and changes nothing.
    pub fn install() -> bool {
        if HANDLE.get().is_some() {
            return false;
        }
        match PrometheusBuilder::new().install_recorder() {
            Ok(handle) => {
                describe();
                HANDLE.set(handle).is_ok()
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to install Prometheus recorder");
                false
            }
        }
    }

    /// Render the current metric registry in Prometheus text exposition format.
    /// Returns `None` if the recorder was never installed.
    pub fn render() -> Option<String> {
        HANDLE.get().map(|h| h.render())
    }

    fn describe() {
        use metrics::{describe_counter, describe_gauge, describe_histogram};
        describe_counter!(
            "hoike_requests_total",
            "OCSP requests processed, by CA, HTTP method, and response status"
        );
        describe_histogram!(
            "hoike_request_duration_seconds",
            "OCSP request processing latency in seconds, by CA"
        );
        describe_counter!(
            "hoike_certid_hash_alg_total",
            "CertID hashAlgorithm OIDs seen in requests, by CA"
        );
        describe_counter!(
            "hoike_nonce_requests_total",
            "Nonce handling outcomes, by CA, policy, and outcome"
        );
        describe_gauge!("hoike_bundle_epoch", "Current epoch per CA scope");
        describe_gauge!("hoike_bundle_entries", "Entry count per CA scope");
        describe_gauge!(
            "hoike_bundle_age_seconds",
            "Seconds since the serving bundle was produced, per CA scope"
        );
        describe_gauge!(
            "hoike_bundle_next_update_seconds",
            "Seconds until the serving bundle's nextUpdate, per CA scope"
        );
        describe_counter!(
            "hoike_bundle_load_failures_total",
            "Bundle load/reload failures, by CA and reason"
        );
        describe_histogram!(
            "hoike_signer_generation_duration_seconds",
            "Signer bundle-generation latency in seconds, by CA"
        );
        describe_gauge!(
            "hoike_gossip_members",
            "Known gossip fleet members by SWIM state (alive/suspect/down)"
        );
    }

    pub fn record_request(ca: &str, method: &'static str, status: &'static str) {
        metrics::counter!(
            "hoike_requests_total",
            "ca" => ca.to_string(),
            "method" => method,
            "status" => status,
        )
        .increment(1);
    }

    pub fn record_request_duration(ca: &str, seconds: f64) {
        metrics::histogram!("hoike_request_duration_seconds", "ca" => ca.to_string())
            .record(seconds);
    }

    pub fn record_certid_alg(ca: &str, alg: &str) {
        metrics::counter!(
            "hoike_certid_hash_alg_total",
            "ca" => ca.to_string(),
            "alg" => alg.to_string(),
        )
        .increment(1);
    }

    pub fn record_nonce(ca: &str, policy: &str, outcome: &'static str) {
        metrics::counter!(
            "hoike_nonce_requests_total",
            "ca" => ca.to_string(),
            "policy" => policy.to_string(),
            "outcome" => outcome,
        )
        .increment(1);
    }

    pub fn record_bundle_load_failure(ca: &str, reason: &'static str) {
        metrics::counter!(
            "hoike_bundle_load_failures_total",
            "ca" => ca.to_string(),
            "reason" => reason,
        )
        .increment(1);
    }

    pub fn record_signer_generation(ca: &str, seconds: f64) {
        metrics::histogram!("hoike_signer_generation_duration_seconds", "ca" => ca.to_string())
            .record(seconds);
    }

    /// Set the fleet-membership gauge from a scrape-time census of SWIM states.
    /// Values are absolute counts per state; a state with zero members is still
    /// emitted so the series never silently disappears from a scrape.
    pub fn record_gossip_members(alive: u64, suspect: u64, down: u64) {
        metrics::gauge!("hoike_gossip_members", "state" => "alive").set(alive as f64);
        metrics::gauge!("hoike_gossip_members", "state" => "suspect").set(suspect as f64);
        metrics::gauge!("hoike_gossip_members", "state" => "down").set(down as f64);
    }

    /// Refresh the bundle freshness gauges from the currently loaded scopes.
    /// Called on each `/metrics` scrape (collect-on-scrape), so the age and
    /// next-update figures are computed against the scrape-time clock.
    pub fn update_bundle_gauges(scopes: &[ScopeDetail], now: u64) {
        for s in scopes {
            let labels = [
                ("ca", s.ca_label.clone()),
                ("producer", s.producer_id.clone()),
            ];
            metrics::gauge!("hoike_bundle_epoch", &labels).set(s.epoch as f64);
            metrics::gauge!("hoike_bundle_entries", &labels).set(s.entry_count as f64);
            let age = now.saturating_sub(s.window.produced_at);
            metrics::gauge!("hoike_bundle_age_seconds", &labels).set(age as f64);
            let ttl = s.window.next_update_min.saturating_sub(now);
            metrics::gauge!("hoike_bundle_next_update_seconds", &labels).set(ttl as f64);
        }
    }
}

// ---------------------------------------------------------------------------
// Feature-off implementation (all no-ops)
// ---------------------------------------------------------------------------
#[cfg(not(feature = "metrics"))]
mod imp {
    use super::ScopeDetail;

    pub fn install() -> bool {
        false
    }
    pub fn render() -> Option<String> {
        None
    }
    #[inline]
    pub fn record_request(_ca: &str, _method: &'static str, _status: &'static str) {}
    #[inline]
    pub fn record_request_duration(_ca: &str, _seconds: f64) {}
    #[inline]
    pub fn record_certid_alg(_ca: &str, _alg: &str) {}
    #[inline]
    pub fn record_nonce(_ca: &str, _policy: &str, _outcome: &'static str) {}
    #[inline]
    pub fn record_bundle_load_failure(_ca: &str, _reason: &'static str) {}
    #[inline]
    pub fn record_signer_generation(_ca: &str, _seconds: f64) {}
    #[inline]
    pub fn record_gossip_members(_alive: u64, _suspect: u64, _down: u64) {}
    #[inline]
    pub fn update_bundle_gauges(_scopes: &[ScopeDetail], _now: u64) {}
}

pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;
    use hoike_core::CoreError;

    #[test]
    fn load_failure_reason_classifies_each_variant() {
        // Anti-rollback / continuity — the operationally interesting cases.
        assert_eq!(
            load_failure_reason(&CoreError::EpochRollback {
                scope: "test".into(),
                epoch: 1,
                high_water: 2,
            }),
            "rollback"
        );
        assert_eq!(
            load_failure_reason(&CoreError::EpochJumpTooLarge {
                scope: "test".into(),
                epoch: 100,
                high_water: 1,
                jump: 99,
                max_jump: 24,
            }),
            "rollback"
        );
        assert_eq!(
            load_failure_reason(&CoreError::ForkDetected {
                scope: "test".into(),
            }),
            "fork"
        );
        // Coarse buckets.
        assert_eq!(
            load_failure_reason(&CoreError::Bundle(ahu::AhuError::BadMagic {
                found: *b"XXXX",
            })),
            "bundle"
        );
        assert_eq!(
            load_failure_reason(&CoreError::StateStore("sled boom".into())),
            "state"
        );
        assert_eq!(
            load_failure_reason(&CoreError::Io(std::io::Error::other("disk gone"))),
            "io"
        );
        // Everything else collapses to "other".
        assert_eq!(load_failure_reason(&CoreError::NoMatchingScope), "other");
        assert_eq!(
            load_failure_reason(&CoreError::Config("bad toml".into())),
            "other"
        );
    }

    // The recorder is a process-global singleton (`install_recorder`), so this
    // single test drives the whole feature-on surface: install once, record one
    // sample of every series, then assert the rendered exposition names them.
    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_registry_snapshot_contains_all_series() {
        assert!(install(), "recorder should install on first call");
        assert!(!install(), "second install is a no-op");

        record_request("ca-a", "get", "good");
        record_request_duration("ca-a", 0.001);
        record_certid_alg("ca-a", "2.16.840.1.101.3.4.2.1");
        record_nonce("ca-a", "ignore", "ignored");
        record_bundle_load_failure("ca-a", "rollback");
        record_signer_generation("ca-a", 0.05);

        let scopes = [ScopeDetail {
            ca_label: "ca-a".into(),
            producer_id: "hoike-combined".into(),
            epoch: 3,
            completeness: "authoritative-complete".into(),
            entry_count: 7,
            window: ahu::Window {
                produced_at: 1000,
                this_update_min: 1000,
                next_update_min: 5000,
                next_update_max: 5000,
            },
        }];
        update_bundle_gauges(&scopes, 2000);

        let body = render().expect("recorder installed, render must succeed");
        for series in [
            "hoike_requests_total",
            "hoike_request_duration_seconds",
            "hoike_certid_hash_alg_total",
            "hoike_nonce_requests_total",
            "hoike_bundle_load_failures_total",
            "hoike_signer_generation_duration_seconds",
            "hoike_bundle_epoch",
            "hoike_bundle_entries",
            "hoike_bundle_age_seconds",
            "hoike_bundle_next_update_seconds",
        ] {
            assert!(
                body.contains(series),
                "exposition must contain {series}; got:\n{body}"
            );
        }
        // Spot-check a computed gauge value: age = now(2000) - produced_at(1000).
        assert!(
            body.contains("hoike_bundle_age_seconds") && body.contains("1000"),
            "age gauge should be now - produced_at = 1000"
        );
    }
}
