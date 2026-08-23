//! Policy/quarantine decision engine (`docs/v2-port/v2.1-depgate.md` §6):
//! turns one scan verdict plus any package-risk heuristic findings
//! (`crate::heuristics`) into an `allow`/`warn`/`block`/`quarantine`
//! action. Pure evaluation, no I/O — `crate::scanpipe` calls
//! [`evaluate`] and is responsible for acting on the result and audit-
//! logging it (`crate::db::insert_policy_decision`).
//!
//! Rule precedence: every enabled `depgate_policy_rules` row whose columns
//! all match (or are left `NULL`, meaning "any") is a candidate; the
//! highest-`priority` candidate wins. Only when **no** rule matches does
//! the hardcoded default apply — an admin can always override the default
//! by configuring a rule, but nothing does so unless asked to.

use crate::heuristics::{RiskFinding, Severity};

/// The four dispositions a policy evaluation can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Serve normally, no flag.
    Allow,
    /// Serve, but the event is recorded/surfaced as a warning.
    Warn,
    /// Refuse the request; do not cache or quarantine (used for policy
    /// rules an admin wants to hard-deny without the audit/disposition
    /// workflow quarantine implies — e.g. a blanket ecosystem ban).
    Block,
    /// Refuse the request and record a `depgate_quarantine` row for
    /// disposition review.
    Quarantine,
}

impl Action {
    /// Canonical lowercase string, matching the DB `CHECK` constraint.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Warn => "warn",
            Action::Block => "block",
            Action::Quarantine => "quarantine",
        }
    }
}

impl std::str::FromStr for Action {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(Action::Allow),
            "warn" => Ok(Action::Warn),
            "block" => Ok(Action::Block),
            "quarantine" => Ok(Action::Quarantine),
            other => Err(format!("unrecognized policy action: {other:?}")),
        }
    }
}

/// One policy rule, ecosystem/service-agnostic form of
/// `crate::db::PolicyRuleRow` — decoupled from the DB row shape so this
/// module stays pure/DB-free and independently unit-testable.
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// Stable identifier, echoed on the resulting [`Decision`] and audit
    /// row.
    pub id: uuid::Uuid,
    /// Match priority — highest wins.
    pub priority: i32,
    /// `None` matches any ecosystem.
    pub ecosystem: Option<String>,
    /// Glob against the package/repo name. `None` matches any.
    pub name_glob: Option<String>,
    /// Glob against the tag/version/reference string. `None` matches any.
    pub version_glob: Option<String>,
    /// Exact-match scan verdict. `None` matches any.
    pub verdict: Option<String>,
    /// Exact-match heuristic check name. `None` combined with
    /// `min_severity` means "any finding at or above this severity";
    /// `None` with no `min_severity` means "findings are irrelevant to
    /// this rule".
    pub risk_check: Option<String>,
    /// Minimum heuristic severity required for a match.
    pub min_severity: Option<Severity>,
    /// Resulting action when this rule matches.
    pub action: Action,
    /// Disabled rules are never matched.
    pub enabled: bool,
}

/// What's being evaluated — one ingested artifact's verdict plus its
/// heuristic findings.
#[derive(Debug, Clone, Copy)]
pub struct PolicyInput<'a> {
    /// Ecosystem discriminator (`"oci"`/`"npm"`/`"pypi"`).
    pub ecosystem: &'a str,
    /// Package/repo name.
    pub name: &'a str,
    /// Tag/version/reference string.
    pub version: &'a str,
    /// The scan verdict (`Verdict::as_str()`).
    pub verdict: &'a str,
    /// Heuristic findings recorded for this artifact.
    pub findings: &'a [RiskFinding],
}

/// The result of one policy evaluation.
#[derive(Debug, Clone)]
pub struct Decision {
    /// The action to take.
    pub action: Action,
    /// The rule that produced this decision, if any (`None` means a
    /// hardcoded default applied).
    pub matched_rule_id: Option<uuid::Uuid>,
    /// Human-readable "why" — always populated, since every decision is
    /// audit-logged (§6: "answerable: why was this package blocked?").
    pub reason: String,
}

/// A simple glob matcher supporting `*` (any run of characters, including
/// empty) and `?` (exactly one character) — enough for
/// `depgate_policy_rules.name_glob`/`version_glob` without pulling in a
/// dedicated glob crate for two wildcard characters.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (plen, tlen) = (p.len(), t.len());
    let mut dp = vec![vec![false; tlen + 1]; plen + 1];
    dp[0][0] = true;
    for i in 1..=plen {
        if p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }
    for i in 1..=plen {
        for j in 1..=tlen {
            dp[i][j] = match p[i - 1] {
                '*' => dp[i - 1][j] || dp[i][j - 1],
                '?' => dp[i - 1][j - 1],
                c => dp[i - 1][j - 1] && c == t[j - 1],
            };
        }
    }
    dp[plen][tlen]
}

fn rule_matches(rule: &PolicyRule, input: &PolicyInput<'_>) -> bool {
    if !rule.enabled {
        return false;
    }
    if let Some(eco) = &rule.ecosystem
        && eco != input.ecosystem
    {
        return false;
    }
    if let Some(glob) = &rule.name_glob
        && !glob_match(glob, input.name)
    {
        return false;
    }
    if let Some(glob) = &rule.version_glob
        && !glob_match(glob, input.version)
    {
        return false;
    }
    if let Some(v) = &rule.verdict
        && v != input.verdict
    {
        return false;
    }
    match (&rule.risk_check, rule.min_severity) {
        (Some(check), min) => input
            .findings
            .iter()
            .any(|f| &f.check == check && min.is_none_or(|m| f.severity >= m)),
        (None, Some(min)) => input.findings.iter().any(|f| f.severity >= min),
        (None, None) => true,
    }
}

/// Default action when no configured rule matches — §6's documented
/// baseline. `infected`/`error`/`skipped` verdicts fail closed
/// (quarantine); `pup` is flagged but not blocked; a `clean` verdict is
/// allowed unless heuristics found something, in which case a `critical`
/// finding still escalates to `block` even though the malware scanner
/// itself found nothing — heuristics catching what the scanner didn't is
/// exactly the case worth being strict about.
fn default_decision(verdict: &str, findings: &[RiskFinding]) -> Decision {
    let (action, reason) = match verdict {
        "infected" => (
            Action::Quarantine,
            "default policy: malware verdict is always quarantined".to_owned(),
        ),
        "pup" => (
            Action::Warn,
            "default policy: potentially-unwanted-program verdict is flagged, not blocked"
                .to_owned(),
        ),
        "error" | "skipped" => (
            Action::Quarantine,
            "default policy: verdict is not clean — failing closed".to_owned(),
        ),
        _ => {
            if findings.is_empty() {
                (
                    Action::Allow,
                    "default policy: clean verdict, no risk findings".to_owned(),
                )
            } else {
                let worst = findings
                    .iter()
                    .map(|f| f.severity)
                    .max()
                    .unwrap_or(Severity::Info);
                if worst >= Severity::Critical {
                    (
                        Action::Block,
                        format!(
                            "default policy: clean verdict, but a {}-severity risk finding was present",
                            worst.as_str()
                        ),
                    )
                } else {
                    (
                        Action::Warn,
                        "default policy: clean verdict, risk-signal-only — served with a warning"
                            .to_owned(),
                    )
                }
            }
        }
    };
    Decision {
        action,
        matched_rule_id: None,
        reason,
    }
}

/// Evaluates `input` against `rules`, falling back to [`default_decision`]
/// when nothing matches.
#[must_use]
pub fn evaluate(input: &PolicyInput<'_>, rules: &[PolicyRule]) -> Decision {
    let winner = rules
        .iter()
        .filter(|r| rule_matches(r, input))
        .max_by_key(|r| r.priority);
    match winner {
        Some(rule) => Decision {
            action: rule.action,
            matched_rule_id: Some(rule.id),
            reason: format!(
                "matched policy rule {} (priority {})",
                rule.id, rule.priority
            ),
        },
        None => default_decision(input.verdict, input.findings),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use uuid::Uuid;

    use super::*;

    fn finding(check: &str, severity: Severity) -> RiskFinding {
        RiskFinding {
            check: check.to_owned(),
            severity,
            detail: "test".to_owned(),
        }
    }

    fn rule(action: Action, priority: i32) -> PolicyRule {
        PolicyRule {
            id: Uuid::new_v4(),
            priority,
            ecosystem: None,
            name_glob: None,
            version_glob: None,
            verdict: None,
            risk_check: None,
            min_severity: None,
            action,
            enabled: true,
        }
    }

    #[test]
    fn action_round_trips() {
        for a in [
            Action::Allow,
            Action::Warn,
            Action::Block,
            Action::Quarantine,
        ] {
            assert_eq!(a.as_str().parse::<Action>().expect("round trip"), a);
        }
        assert!("bogus".parse::<Action>().is_err());
    }

    #[test]
    fn glob_match_supports_star_and_question_mark() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("left-*", "left-pad"));
        assert!(!glob_match("left-*", "right-pad"));
        assert!(glob_match("pkg-?.0.0", "pkg-1.0.0"));
        assert!(!glob_match("pkg-?.0.0", "pkg-10.0.0"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exactly"));
    }

    #[test]
    fn default_infected_is_always_quarantined() {
        let d = default_decision("infected", &[]);
        assert_eq!(d.action, Action::Quarantine);
        assert_eq!(d.matched_rule_id, None);
    }

    #[test]
    fn default_pup_is_warned_not_blocked() {
        assert_eq!(default_decision("pup", &[]).action, Action::Warn);
    }

    #[test]
    fn default_error_and_skipped_fail_closed() {
        assert_eq!(default_decision("error", &[]).action, Action::Quarantine);
        assert_eq!(default_decision("skipped", &[]).action, Action::Quarantine);
    }

    #[test]
    fn default_clean_with_no_findings_allows() {
        assert_eq!(default_decision("clean", &[]).action, Action::Allow);
    }

    #[test]
    fn default_clean_with_low_findings_warns() {
        let findings = vec![finding("npm_install_script", Severity::Low)];
        assert_eq!(default_decision("clean", &findings).action, Action::Warn);
    }

    #[test]
    fn default_clean_with_critical_finding_blocks() {
        let findings = vec![finding("suspicious_base64_exec", Severity::Critical)];
        assert_eq!(default_decision("clean", &findings).action, Action::Block);
    }

    #[test]
    fn evaluate_falls_back_to_default_when_no_rules_configured() {
        let input = PolicyInput {
            ecosystem: "npm",
            name: "left-pad",
            version: "1.3.0",
            verdict: "clean",
            findings: &[],
        };
        let d = evaluate(&input, &[]);
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.matched_rule_id, None);
    }

    #[test]
    fn evaluate_prefers_highest_priority_matching_rule() {
        let input = PolicyInput {
            ecosystem: "npm",
            name: "left-pad",
            version: "1.3.0",
            verdict: "clean",
            findings: &[],
        };
        let low = rule(Action::Block, 10);
        let high = rule(Action::Allow, 100);
        let d = evaluate(&input, &[low.clone(), high.clone()]);
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.matched_rule_id, Some(high.id));
    }

    #[test]
    fn evaluate_ignores_disabled_rules() {
        let input = PolicyInput {
            ecosystem: "npm",
            name: "left-pad",
            version: "1.3.0",
            verdict: "clean",
            findings: &[],
        };
        let mut disabled = rule(Action::Block, 1000);
        disabled.enabled = false;
        let d = evaluate(&input, &[disabled]);
        assert_eq!(d.action, Action::Allow); // falls through to default
    }

    #[test]
    fn evaluate_matches_on_ecosystem_and_name_glob() {
        let input = PolicyInput {
            ecosystem: "npm",
            name: "evil-pkg",
            version: "1.0.0",
            verdict: "clean",
            findings: &[],
        };
        let mut r = rule(Action::Block, 50);
        r.ecosystem = Some("npm".to_owned());
        r.name_glob = Some("evil-*".to_owned());
        let d = evaluate(&input, &[r.clone()]);
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.matched_rule_id, Some(r.id));
    }

    #[test]
    fn evaluate_does_not_match_a_different_ecosystem() {
        let input = PolicyInput {
            ecosystem: "pypi",
            name: "evil-pkg",
            version: "1.0.0",
            verdict: "clean",
            findings: &[],
        };
        let mut r = rule(Action::Block, 50);
        r.ecosystem = Some("npm".to_owned());
        let d = evaluate(&input, &[r]);
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn evaluate_matches_on_risk_check_and_min_severity() {
        let input = PolicyInput {
            ecosystem: "npm",
            name: "some-pkg",
            version: "1.0.0",
            verdict: "clean",
            findings: &[finding("typosquat_distance", Severity::High)],
        };
        let mut r = rule(Action::Quarantine, 50);
        r.risk_check = Some("typosquat_distance".to_owned());
        r.min_severity = Some(Severity::High);
        let d = evaluate(&input, &[r.clone()]);
        assert_eq!(d.action, Action::Quarantine);

        // A lower-severity finding for the same check does not match the
        // rule, so this falls through to the default policy — which still
        // warns (a risk finding is present), just doesn't escalate to the
        // rule's configured `Quarantine`.
        let input_low = PolicyInput {
            findings: &[finding("typosquat_distance", Severity::Medium)],
            ..input
        };
        let d_low = evaluate(&input_low, &[r]);
        assert_eq!(d_low.action, Action::Warn);
        assert_eq!(d_low.matched_rule_id, None);
    }

    #[test]
    fn evaluate_matches_on_bare_min_severity_across_any_check() {
        let input = PolicyInput {
            ecosystem: "npm",
            name: "some-pkg",
            version: "1.0.0",
            verdict: "clean",
            findings: &[finding(
                "suspicious_embedded_credential",
                Severity::Critical,
            )],
        };
        let mut r = rule(Action::Quarantine, 50);
        r.min_severity = Some(Severity::High);
        let d = evaluate(&input, &[r]);
        assert_eq!(d.action, Action::Quarantine);
    }

    #[test]
    fn evaluate_version_glob_restricts_the_match() {
        let mut r = rule(Action::Block, 50);
        r.version_glob = Some("0.*".to_owned());
        let matching = PolicyInput {
            ecosystem: "npm",
            name: "pkg",
            version: "0.1.0",
            verdict: "clean",
            findings: &[],
        };
        let not_matching = PolicyInput {
            version: "1.0.0",
            ..matching
        };
        assert_eq!(evaluate(&matching, &[r.clone()]).action, Action::Block);
        assert_eq!(evaluate(&not_matching, &[r]).action, Action::Allow);
    }
}
