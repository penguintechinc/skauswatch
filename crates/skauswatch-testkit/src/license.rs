//! Dev-mode and gated `LicenseClient` builders for tests — the shared
//! implementation behind the `dev_license()`/`gated_license()` helpers that
//! were duplicated verbatim across every `services/codescan-backend/src/routes/*.rs`
//! test module (and, per `docs/v2-port/testing-pattern.md`, the pattern every
//! other service's route tests should follow too).

use std::sync::Arc;

use penguin_licensing::{LicenseClient, LicenseConfig};

/// A license client in dev/bypass posture (`release_mode = false`, the
/// `LicenseConfig::new` default) — `flag_enabled`/feature checks pass
/// unconditionally, for exercising the success path behind a module's
/// license gate. Panics on construction failure (test-infra fault).
#[allow(clippy::panic)]
pub fn dev_license(product: &str) -> Arc<LicenseClient> {
    let cfg = match LicenseConfig::new(product) {
        Ok(c) => c,
        Err(e) => panic!("skauswatch-testkit: license config: {e}"),
    };
    match LicenseClient::new(cfg) {
        Ok(c) => c,
        Err(e) => panic!("skauswatch-testkit: license client: {e}"),
    }
}

/// A license client in release/gated posture (`release_mode = true`) —
/// flags/features are denied unless explicitly entitled, for exercising a
/// module's 403 "license required" path. Panics on construction failure
/// (test-infra fault).
#[allow(clippy::panic)]
pub fn gated_license(product: &str) -> Arc<LicenseClient> {
    let mut cfg = match LicenseConfig::new(product) {
        Ok(c) => c,
        Err(e) => panic!("skauswatch-testkit: license config: {e}"),
    };
    cfg.release_mode = true;
    match LicenseClient::new(cfg) {
        Ok(c) => c,
        Err(e) => panic!("skauswatch-testkit: license client: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dev_license_flags_are_enabled() {
        assert!(dev_license("skauswatch").flag_enabled("any.flag").await);
    }

    #[tokio::test]
    async fn gated_license_flags_are_denied() {
        assert!(!gated_license("skauswatch").flag_enabled("any.flag").await);
    }
}
