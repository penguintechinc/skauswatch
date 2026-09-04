//! CodeScan Sentinel policy engine (P3, docs/v2-port/v2.1-codescan-sentinel.md
//! §6): evaluates one finding against a tenant's priority-ordered
//! `codescan_policy_rules` (first match wins) and falls back to the fixed
//! default action matrix (§5) when nothing matches. Pure, no I/O — `crate::db`
//! owns fetching rules and persisting the resulting decision plus its audit
//! row (`codescan_policy_decisions`); `crate::handler` is the only caller.
//!
//! Enterprise-gated (spec §13): `handler::CodeScanReviewHandler` decides
//! whether this module runs at all for a given scan (license tier check),
//! independent of whether AI triage itself succeeded this run — see
//! [`Reachability::bucket`]'s `Unknown` case, which is exactly the "AI
//! triage unavailable/disabled but the policy engine is still licensed"
//! state (WaddleAI unconfigured/unreachable this run).

use serde::{Deserialize, Serialize};

/// The four actions the policy engine can resolve to — matches
/// `codescan_findings.action`'s `CHECK` constraint and
/// `codescan_policy_rules.action`'s exactly (spec §6).
pub const VALID_ACTIONS: [&str; 4] = ["ignore", "document", "alert", "fix"];

/// Exposure classification for a reachable finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
    Internal,
    External,
    None,
}

impl Exposure {
    pub fn as_str(self) -> &'static str {
        match self {
            Exposure::Internal => "internal",
            Exposure::External => "external",
            Exposure::None => "none",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "internal" => Some(Exposure::Internal),
            "external" => Some(Exposure::External),
            "none" => Some(Exposure::None),
            _ => None,
        }
    }
}

/// One finding's reachability state as known at policy-evaluation time.
/// Every field is `None` when no verdict is available yet — the prefilter
/// alone can prove `used = Some(false)`; only AI triage ever sets
/// `reachable`/`exposure`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reachability {
    pub used: Option<bool>,
    pub reachable: Option<bool>,
    pub exposure: Option<Exposure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReachabilityBucket {
    /// The prefilter or AI triage affirmatively showed the package/path is
    /// not used or not reachable.
    NotUsed,
    ReachableInternal,
    ReachableExternal,
    /// No verdict at all (AI triage never ran or never returned one this
    /// scan) — deliberately distinct from `NotUsed`: absence of evidence is
    /// not evidence of absence.
    Unknown,
}

impl Reachability {
    fn bucket(self) -> ReachabilityBucket {
        match (self.used, self.reachable) {
            (Some(false), _) | (_, Some(false)) => ReachabilityBucket::NotUsed,
            (_, Some(true)) if self.exposure == Some(Exposure::External) => {
                ReachabilityBucket::ReachableExternal
            }
            (_, Some(true)) => ReachabilityBucket::ReachableInternal,
            _ => ReachabilityBucket::Unknown,
        }
    }
}

fn reachability_rule_matches(rule_value: &str, bucket: ReachabilityBucket) -> bool {
    matches!(
        (bucket, rule_value.to_ascii_lowercase().as_str()),
        (ReachabilityBucket::NotUsed, "unreachable")
            | (ReachabilityBucket::ReachableInternal, "reachable")
            | (ReachabilityBucket::ReachableExternal, "reachable")
            | (ReachabilityBucket::Unknown, "unknown")
    )
}

/// One tenant-configured rule (`codescan_policy_rules`), priority-ordered
/// ascending — priority `0` is evaluated first. Every match field is `None`
/// (wildcard) or `Some(exact match, case-insensitive)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub id: i64,
    pub priority: i32,
    pub repo: Option<String>,
    pub ecosystem: Option<String>,
    pub package: Option<String>,
    pub cve: Option<String>,
    pub severity: Option<String>,
    /// `"reachable"` | `"unreachable"` | `"unknown"`.
    pub reachability: Option<String>,
    /// `"internal"` | `"external"` | `"none"`.
    pub exposure: Option<String>,
    pub tool: Option<String>,
    pub kind: Option<String>,
    pub action: String,
}

/// Everything a rule or the default matrix might key on for one finding.
#[derive(Debug, Clone)]
pub struct FindingContext {
    pub repo: String,
    pub ecosystem: String,
    pub package: String,
    pub cve: String,
    pub severity: String,
    pub tool: String,
    pub kind: String,
    pub reachability: Reachability,
}

/// The resolved outcome of [`evaluate`] — always audit-logged by the caller
/// via `db::insert_policy_decision`. `matched_rule_id: None` means the
/// default matrix decided, not an admin-configured rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: String,
    pub matched_rule_id: Option<i64>,
    pub reason: String,
}

fn field_matches(rule_value: &Option<String>, actual: &str) -> bool {
    rule_value
        .as_ref()
        .is_none_or(|v| v.eq_ignore_ascii_case(actual))
}

fn exposure_matches(rule_value: &Option<String>, actual: Option<Exposure>) -> bool {
    match rule_value {
        None => true,
        Some(v) => actual.is_some_and(|e| e.as_str().eq_ignore_ascii_case(v)),
    }
}

fn rule_matches(rule: &PolicyRule, ctx: &FindingContext) -> bool {
    field_matches(&rule.repo, &ctx.repo)
        && field_matches(&rule.ecosystem, &ctx.ecosystem)
        && field_matches(&rule.package, &ctx.package)
        && field_matches(&rule.cve, &ctx.cve)
        && field_matches(&rule.severity, &ctx.severity)
        && field_matches(&rule.tool, &ctx.tool)
        && field_matches(&rule.kind, &ctx.kind)
        && exposure_matches(&rule.exposure, ctx.reachability.exposure)
        && rule
            .reachability
            .as_ref()
            .is_none_or(|v| reachability_rule_matches(v, ctx.reachability.bucket()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeverityBucket {
    HighOrCritical,
    MediumOrLow,
}

fn severity_bucket(severity: &str) -> SeverityBucket {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "high" => SeverityBucket::HighOrCritical,
        _ => SeverityBucket::MediumOrLow,
    }
}

/// The fixed fallback matrix (spec §5). The "not used/dead path" column
/// also covers `ReachabilityBucket::Unknown` when severity is medium/low
/// (nothing actionable to alert on either way); for critical/high with an
/// *unknown* verdict (AI triage never ran this scan — WaddleAI unconfigured/
/// unreachable, or the tenant isn't Enterprise-licensed for the policy
/// engine but this function got called anyway) this fails open to `alert`,
/// preserving the pre-P3 deterministic behavior
/// (`handler::CodeScanReviewHandler::bridge_alert` used to fire
/// unconditionally on every critical/high CVE) rather than silently going
/// quiet just because reachability is unproven.
fn default_matrix(ctx: &FindingContext) -> Decision {
    let sev = severity_bucket(&ctx.severity);
    let bucket = ctx.reachability.bucket();
    let (action, reason) = match (sev, bucket) {
        (SeverityBucket::HighOrCritical, ReachabilityBucket::ReachableExternal) => (
            "alert",
            "critical/high + reachable+external: alert (this cell's fix-PR half is P4 — see \
             `should_also_fix`, called separately by `handler` alongside this decision)",
        ),
        (SeverityBucket::HighOrCritical, ReachabilityBucket::ReachableInternal) => {
            ("fix", "critical/high + reachable+internal: fix")
        }
        (SeverityBucket::HighOrCritical, ReachabilityBucket::NotUsed) => {
            ("document", "critical/high + not used/dead path: document")
        }
        (SeverityBucket::HighOrCritical, ReachabilityBucket::Unknown) => (
            "alert",
            "critical/high with no reachability verdict available this scan: fail open to alert \
             (matches pre-P3 deterministic behavior)",
        ),
        (SeverityBucket::MediumOrLow, ReachabilityBucket::ReachableExternal) => {
            ("fix", "medium/low + reachable+external: fix")
        }
        (SeverityBucket::MediumOrLow, ReachabilityBucket::ReachableInternal) => {
            ("document", "medium/low + reachable+internal: document")
        }
        (SeverityBucket::MediumOrLow, ReachabilityBucket::NotUsed) => {
            ("document", "medium/low + not used/dead path: document")
        }
        (SeverityBucket::MediumOrLow, ReachabilityBucket::Unknown) => (
            "document",
            "medium/low with no reachability verdict available: document",
        ),
    };
    Decision {
        action: action.to_owned(),
        matched_rule_id: None,
        reason: format!("default action matrix: {reason}"),
    }
}

/// True when the default action matrix's "critical/high + reachable
/// +external" cell — spec §5's combined `alert + fix` cell, which
/// `evaluate`'s single-`action`-column `Decision` can't express on its own
/// — should *also* enqueue this finding into CodeScan Sentinel P4's grouped
/// auto-fix pipeline on top of the `alert` it already resolved to.
/// `handler::CodeScanReviewHandler::scan_and_persist_branch` calls this
/// alongside checking `decision.action == "fix"` to build its fix-candidate
/// list.
///
/// Deliberately only fires when the *default matrix* decided
/// (`matched_rule_id.is_none()`): an admin-configured rule that explicitly
/// resolves a finding to `"alert"` means alert only — never an implicit
/// upgrade to also opening a fix PR the admin didn't ask for.
pub fn should_also_fix(ctx: &FindingContext, decision: &Decision) -> bool {
    decision.action == "alert"
        && decision.matched_rule_id.is_none()
        && severity_bucket(&ctx.severity) == SeverityBucket::HighOrCritical
        && ctx.reachability.bucket() == ReachabilityBucket::ReachableExternal
}

/// Evaluates `ctx` against `rules` (need not be pre-sorted — this sorts a
/// local copy by `priority` ascending), returning the first match; falls
/// back to [`default_matrix`] when nothing matches.
pub fn evaluate(ctx: &FindingContext, rules: &[PolicyRule]) -> Decision {
    let mut sorted: Vec<&PolicyRule> = rules.iter().collect();
    sorted.sort_by_key(|r| r.priority);
    let decision = sorted
        .into_iter()
        .find(|&rule| rule_matches(rule, ctx))
        .map_or_else(
            || default_matrix(ctx),
            |rule| Decision {
                action: rule.action.clone(),
                matched_rule_id: Some(rule.id),
                reason: format!(
                    "matched policy rule #{} (priority {})",
                    rule.id, rule.priority
                ),
            },
        );
    // An admin-configured rule's `action` is only validated at the API
    // layer (`codescan-backend::routes::policy_rules`) against this same
    // set — this assertion is the engine's own belt-and-suspenders check
    // that it never resolves to anything outside the four spec actions
    // (spec §6), and gives `VALID_ACTIONS` real production use rather than
    // existing purely for documentation/tests.
    debug_assert!(
        VALID_ACTIONS.contains(&decision.action.as_str()),
        "policy engine resolved to an action outside the spec's four actions: {}",
        decision.action
    );
    decision
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn base_ctx() -> FindingContext {
        FindingContext {
            repo: "acme/widgets".to_owned(),
            ecosystem: "npm".to_owned(),
            package: "left-pad".to_owned(),
            cve: "GHSA-xxxx".to_owned(),
            severity: "high".to_owned(),
            tool: String::new(),
            kind: "cve".to_owned(),
            reachability: Reachability::default(),
        }
    }

    fn wildcard_rule(id: i64, priority: i32, action: &str) -> PolicyRule {
        PolicyRule {
            id,
            priority,
            repo: None,
            ecosystem: None,
            package: None,
            cve: None,
            severity: None,
            reachability: None,
            exposure: None,
            tool: None,
            kind: None,
            action: action.to_owned(),
        }
    }

    #[test]
    fn empty_rules_falls_back_to_default_matrix() {
        let decision = evaluate(&base_ctx(), &[]);
        assert_eq!(decision.action, "alert");
        assert_eq!(decision.matched_rule_id, None);
    }

    #[test]
    fn a_wildcard_rule_matches_everything() {
        let rules = vec![wildcard_rule(1, 0, "ignore")];
        let decision = evaluate(&base_ctx(), &rules);
        assert_eq!(decision.action, "ignore");
        assert_eq!(decision.matched_rule_id, Some(1));
    }

    #[test]
    fn field_specific_rule_only_matches_the_named_package() {
        let mut rule = wildcard_rule(2, 0, "document");
        rule.package = Some("some-other-pkg".to_owned());
        let decision = evaluate(&base_ctx(), &[rule]);
        assert_ne!(
            decision.matched_rule_id,
            Some(2),
            "must not match a different package"
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        let mut rule = wildcard_rule(3, 0, "document");
        rule.package = Some("LEFT-PAD".to_owned());
        let decision = evaluate(&base_ctx(), &[rule]);
        assert_eq!(decision.matched_rule_id, Some(3));
    }

    #[test]
    fn lower_priority_number_wins_regardless_of_rule_order() {
        let low_priority_wins = wildcard_rule(10, 5, "fix");
        let high_priority_wins = wildcard_rule(11, 1, "ignore");
        // Deliberately out of priority order in the input slice.
        let decision = evaluate(&base_ctx(), &[low_priority_wins, high_priority_wins]);
        assert_eq!(decision.matched_rule_id, Some(11));
        assert_eq!(decision.action, "ignore");
    }

    #[test]
    fn first_non_matching_rule_falls_through_to_the_next() {
        let mut miss = wildcard_rule(20, 0, "ignore");
        miss.severity = Some("low".to_owned());
        let hit = wildcard_rule(21, 1, "document");
        let decision = evaluate(&base_ctx(), &[miss, hit]);
        assert_eq!(decision.matched_rule_id, Some(21));
    }

    #[test]
    fn reachability_rule_matches_the_collapsed_bucket() {
        let mut ctx = base_ctx();
        ctx.reachability = Reachability {
            used: Some(true),
            reachable: Some(true),
            exposure: Some(Exposure::External),
        };
        let mut rule = wildcard_rule(30, 0, "alert");
        rule.reachability = Some("reachable".to_owned());
        assert_eq!(evaluate(&ctx, &[rule.clone()]).matched_rule_id, Some(30));

        rule.reachability = Some("unreachable".to_owned());
        assert_ne!(evaluate(&ctx, &[rule]).matched_rule_id, Some(30));
    }

    #[test]
    fn exposure_rule_requires_an_actual_exposure_verdict() {
        let mut rule = wildcard_rule(40, 0, "alert");
        rule.exposure = Some("external".to_owned());
        // No AI verdict at all -> exposure is None -> must not match.
        assert_ne!(evaluate(&base_ctx(), &[rule]).matched_rule_id, Some(40));
    }

    #[test]
    fn default_matrix_critical_reachable_external_is_alert() {
        let mut ctx = base_ctx();
        ctx.severity = "critical".to_owned();
        ctx.reachability = Reachability {
            used: Some(true),
            reachable: Some(true),
            exposure: Some(Exposure::External),
        };
        assert_eq!(evaluate(&ctx, &[]).action, "alert");
    }

    #[test]
    fn should_also_fix_true_for_default_matrix_critical_reachable_external() {
        let mut ctx = base_ctx();
        ctx.severity = "critical".to_owned();
        ctx.reachability = Reachability {
            used: Some(true),
            reachable: Some(true),
            exposure: Some(Exposure::External),
        };
        let decision = evaluate(&ctx, &[]);
        assert_eq!(decision.action, "alert");
        assert!(
            should_also_fix(&ctx, &decision),
            "spec §5's combined alert+fix cell"
        );
    }

    #[test]
    fn should_also_fix_false_when_an_admin_rule_resolved_to_alert() {
        let mut ctx = base_ctx();
        ctx.severity = "critical".to_owned();
        ctx.reachability = Reachability {
            used: Some(true),
            reachable: Some(true),
            exposure: Some(Exposure::External),
        };
        let rule = wildcard_rule(1, 0, "alert");
        let decision = evaluate(&ctx, &[rule]);
        assert_eq!(decision.action, "alert");
        assert!(
            !should_also_fix(&ctx, &decision),
            "an explicit admin rule choosing alert must never be silently upgraded to also fix"
        );
    }

    #[test]
    fn should_also_fix_false_outside_the_critical_external_cell() {
        let mut ctx = base_ctx();
        ctx.severity = "medium".to_owned();
        ctx.reachability = Reachability::default();
        let decision = evaluate(&ctx, &[]);
        assert!(!should_also_fix(&ctx, &decision));
    }

    #[test]
    fn default_matrix_high_reachable_internal_is_fix() {
        let mut ctx = base_ctx();
        ctx.severity = "high".to_owned();
        ctx.reachability = Reachability {
            used: Some(true),
            reachable: Some(true),
            exposure: Some(Exposure::Internal),
        };
        assert_eq!(evaluate(&ctx, &[]).action, "fix");
    }

    #[test]
    fn default_matrix_high_not_used_is_document() {
        let mut ctx = base_ctx();
        ctx.severity = "high".to_owned();
        ctx.reachability = Reachability {
            used: Some(false),
            reachable: None,
            exposure: None,
        };
        assert_eq!(evaluate(&ctx, &[]).action, "document");
    }

    #[test]
    fn default_matrix_high_unknown_reachability_fails_open_to_alert() {
        let mut ctx = base_ctx();
        ctx.severity = "critical".to_owned();
        ctx.reachability = Reachability::default();
        let decision = evaluate(&ctx, &[]);
        assert_eq!(
            decision.action, "alert",
            "no reachability data available must not silently suppress a critical/high alert"
        );
    }

    #[test]
    fn default_matrix_low_reachable_external_is_fix() {
        let mut ctx = base_ctx();
        ctx.severity = "low".to_owned();
        ctx.reachability = Reachability {
            used: Some(true),
            reachable: Some(true),
            exposure: Some(Exposure::External),
        };
        assert_eq!(evaluate(&ctx, &[]).action, "fix");
    }

    #[test]
    fn default_matrix_low_reachable_internal_is_document() {
        let mut ctx = base_ctx();
        ctx.severity = "medium".to_owned();
        ctx.reachability = Reachability {
            used: Some(true),
            reachable: Some(true),
            exposure: Some(Exposure::Internal),
        };
        assert_eq!(evaluate(&ctx, &[]).action, "document");
    }

    #[test]
    fn default_matrix_low_not_used_is_document() {
        let mut ctx = base_ctx();
        ctx.severity = "low".to_owned();
        ctx.reachability = Reachability {
            used: Some(false),
            reachable: None,
            exposure: None,
        };
        assert_eq!(evaluate(&ctx, &[]).action, "document");
    }

    #[test]
    fn default_matrix_low_unknown_reachability_is_document() {
        let mut ctx = base_ctx();
        ctx.severity = "unknown".to_owned();
        ctx.reachability = Reachability::default();
        assert_eq!(evaluate(&ctx, &[]).action, "document");
    }

    #[test]
    fn exposure_as_str_and_parse_round_trip() {
        for e in [Exposure::Internal, Exposure::External, Exposure::None] {
            assert_eq!(Exposure::parse(e.as_str()), Some(e));
        }
        assert_eq!(Exposure::parse("bogus"), None);
        assert_eq!(Exposure::parse("EXTERNAL"), Some(Exposure::External));
    }

    #[test]
    fn valid_actions_matches_the_four_spec_actions() {
        assert_eq!(VALID_ACTIONS, ["ignore", "document", "alert", "fix"]);
    }
}
