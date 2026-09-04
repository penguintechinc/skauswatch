//! Canonical skauswatch feature-flag inventory. Every flag defaults OFF in
//! PostHog; enforcement is a gate on the matching router plus frontend nav
//! gating via GET /api/v1/license/features. Keep in sync with
//! docs/feature-flags.md.
//!
//! Three distinct concepts, deliberately not blurred together:
//!
//! 1. **Core** — always-on foundation (user/IAM, auth, tenancy) plus
//!    core-infra toggles like `skauswatch.openapi-docs`. Never appears in
//!    this registry: core has no flag (true always-on) or, for a core-infra
//!    toggle, is intentionally excluded from the licensable inventory below
//!    (see the note on [`MODULE_FLAGS`]).
//! 2. [`MODULE_FLAGS`] — feature groups the platform *operator* enables or
//!    disables, whether for licensing or simply to not expose a group they
//!    don't use (e.g. they run a competing product for depgate, so they
//!    turn it off to save resources).
//! 3. [`TIER_FLAGS`] — entitlements the customer's license *tier* grants
//!    (Professional/Enterprise), controlled by the license server rather
//!    than the operator. Distinct intent from module flags, so it stays a
//!    separate list — never merge the two.

/// Module gates — operator-controlled feature groups, one per /api/v1
/// router / worker job family or licensed sub-product. Enabling/disabling
/// one is an operator decision (licensing, or simply not exposing a group
/// they don't run), never a license-tier entitlement — see [`TIER_FLAGS`]
/// for that distinct concept.
///
/// `skauswatch.openapi-docs` (`OPENAPI_FLAG` in
/// `routes/openapi.rs`) is deliberately **not** listed here — it's a
/// core-infra toggle, not a licensable module, so it's excluded from this
/// registry (and therefore from the `/api/v1/license/features` inventory)
/// by design.
pub const MODULE_FLAGS: &[&str] = &[
    "skauswatch.vault",
    "skauswatch.codescan",
    "skauswatch.depgate",
    "skauswatch.s3-scan",
    "skauswatch.threat-intel",
    "skauswatch.siem",
    "skauswatch.alerts",
    "skauswatch.approvals",
    "skauswatch.asm",
    "skauswatch.endpoint",
    "skauswatch.research",
    "skauswatch.ai-review",
    "skauswatch.monitor",
    "skauswatch.log-ingest",
    "skauswatch.pki",
    "skauswatch.scanner",
    "skauswatch.codescan.sentinel",
    "skauswatch.depgate.socket",
];

/// Tier-bound flags (Professional/Enterprise, checked with RequireTier
/// too). License-server-controlled entitlements — distinct intent from the
/// operator-controlled module toggles in [`MODULE_FLAGS`]: a tier flag
/// reflects what the customer's license grants, not what the operator has
/// chosen to expose. Keep this list separate; never merge it into
/// [`MODULE_FLAGS`].
pub const TIER_FLAGS: &[&str] = &[
    "skauswatch.whitelabel",
    "skauswatch.google-sso",
    "skauswatch.saml-sso",
    "skauswatch.oidc-sso",
    "skauswatch.audit-compliance",
    "skauswatch.waddleai",
    "skauswatch.advanced-analytics",
];

/// All known flags, for the /api/v1/license/features frontend contract.
pub fn all_flags() -> impl Iterator<Item = &'static str> {
    MODULE_FLAGS.iter().chain(TIER_FLAGS).copied()
}

#[cfg(test)]
mod tests {
    use super::{MODULE_FLAGS, TIER_FLAGS, all_flags};

    #[test]
    fn module_flags_contains_the_merged_set_including_newly_registered_gates() {
        for flag in [
            "skauswatch.vault",
            "skauswatch.codescan",
            "skauswatch.depgate",
            "skauswatch.s3-scan",
            "skauswatch.threat-intel",
            "skauswatch.siem",
            "skauswatch.alerts",
            "skauswatch.approvals",
            "skauswatch.asm",
            "skauswatch.endpoint",
            "skauswatch.research",
            "skauswatch.ai-review",
            "skauswatch.monitor",
            "skauswatch.log-ingest",
            "skauswatch.pki",
            "skauswatch.scanner",
            "skauswatch.codescan.sentinel",
            "skauswatch.depgate.socket",
        ] {
            assert!(MODULE_FLAGS.contains(&flag), "MODULE_FLAGS missing {flag}");
        }
        assert_eq!(MODULE_FLAGS.len(), 18);
    }

    #[test]
    fn module_flags_does_not_contain_users_core_is_always_on() {
        assert!(
            !MODULE_FLAGS.contains(&"skauswatch.users"),
            "users is core (always-on), not a module flag"
        );
    }

    #[test]
    fn module_flags_does_not_contain_the_core_infra_openapi_toggle() {
        assert!(
            !MODULE_FLAGS.contains(&"skauswatch.openapi-docs"),
            "openapi-docs is core-infra, intentionally excluded from the licensable registry"
        );
    }

    #[test]
    fn tier_flags_is_unchanged() {
        assert_eq!(
            TIER_FLAGS,
            [
                "skauswatch.whitelabel",
                "skauswatch.google-sso",
                "skauswatch.saml-sso",
                "skauswatch.oidc-sso",
                "skauswatch.audit-compliance",
                "skauswatch.waddleai",
                "skauswatch.advanced-analytics",
            ]
        );
        assert_eq!(TIER_FLAGS.len(), 7);
    }

    #[test]
    fn all_flags_is_exactly_modules_then_tier_no_more_no_less() {
        let expected: Vec<&str> = MODULE_FLAGS.iter().chain(TIER_FLAGS).copied().collect();
        let actual: Vec<&str> = all_flags().collect();
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), MODULE_FLAGS.len() + TIER_FLAGS.len());
    }
}
