//! Canonical skauswatch feature-flag inventory. Every flag defaults OFF in
//! PostHog; enforcement is a gate on the matching router plus frontend nav
//! gating via GET /api/v1/license/features. Keep in sync with
//! docs/feature-flags.md.

/// Module gates — licensed sub-products.
pub const MODULE_FLAGS: &[&str] = &["skauswatch.icebox", "skauswatch.darwin"];

/// Core feature-area flags, one per /api/v1 router / worker job family.
pub const CORE_FLAGS: &[&str] = &[
    "skauswatch.s3-scan",
    "skauswatch.threat-intel",
    "skauswatch.siem",
    "skauswatch.alerts",
    "skauswatch.approvals",
    "skauswatch.asm",
    "skauswatch.edr",
    "skauswatch.research",
    "skauswatch.ai-review",
    "skauswatch.aaa-monitor",
    "skauswatch.log-ingest",
    "skauswatch.pki",
];

/// Tier-bound flags (Professional/Enterprise, checked with RequireTier too).
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
    MODULE_FLAGS
        .iter()
        .chain(CORE_FLAGS)
        .chain(TIER_FLAGS)
        .copied()
}
