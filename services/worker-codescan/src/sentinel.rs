//! CodeScan Sentinel scan orchestration
//! (docs/v2-port/v2.1-codescan-sentinel.md §9-§12, P1): resolves a repo's
//! default + latest `release/*` branch, fetches every supported dependency
//! manifest via the provider's Contents API
//! (`git_provider::fetch_file_at_ref`), and resolves each declared
//! dependency's latest version + OSV advisories via deps.dev
//! (`license_scan::RegistryClient::lookup_latest_and_advisories`).
//! Report-only, no AI — P1 per the spec's phasing table (§11); AI-assisted
//! triage arrives in P3 gated on WaddleAI.
//!
//! This module is the pure "compute" layer: it never touches the database.
//! `handler::CodeScanReviewHandler::handle_sentinel_scan` is the orchestrator
//! that calls into here and persists the result via `crate::db`.

use crate::git_provider::{self, GitCredentials};
#[cfg(test)]
use crate::license_scan::AdvisoryRef;
use crate::license_scan::{DepsDevLookup, Ecosystem, RegistryClient};

/// PostHog flag gating the Sentinel scheduler loop (`crate::scheduler::run`)
/// and the report endpoints in codescan-backend
/// (`services/codescan-backend/src/routes/findings.rs`). Independent of
/// `CODESCAN_FLAG` (`skauswatch.codescan`) — Sentinel's deterministic scans
/// stand alone at Professional tier without the AI-review feature or
/// WaddleAI (spec §13).
pub const SENTINEL_FLAG: &str = "skauswatch.codescan.sentinel";

/// Dependency manifests Sentinel knows how to parse — the same four
/// ecosystems `license_scan` already supports for diff-based scanning.
pub(crate) const MANIFEST_FILES: &[&str] =
    &["package.json", "requirements.txt", "Cargo.toml", "go.mod"];

/// One dependency declaration extracted from a whole manifest file (as
/// opposed to a diff) — reuses `license_scan`'s per-line parsers applied to
/// every line of the fetched file rather than only `+`-prefixed diff lines.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestDependency {
    ecosystem: Ecosystem,
    name: String,
    version: String,
}

/// Applies the ecosystem-appropriate per-line parser (shared with
/// `license_scan::extract_dependencies`) to every line of `content`,
/// deduplicating by package name within this one file.
fn extract_manifest_dependencies(file_name: &str, content: &str) -> Vec<ManifestDependency> {
    let Some(eco) = crate::license_scan::ecosystem_for_file(file_name) else {
        return Vec::new();
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut deps = Vec::new();
    for line in content.lines() {
        let parsed = match eco {
            Ecosystem::Npm => crate::license_scan::parse_npm_dep_line(line),
            Ecosystem::PyPi => crate::license_scan::parse_pypi_dep_line(line),
            Ecosystem::Crates => crate::license_scan::parse_cargo_dep_line(line),
            Ecosystem::Go => crate::license_scan::parse_go_mod_dep_line(line),
        };
        if let Some((name, version)) = parsed
            && seen.insert(name.clone())
        {
            deps.push(ManifestDependency {
                ecosystem: eco,
                name,
                version,
            });
        }
    }
    deps
}

/// One computed finding for a single dependency in a single (repo, branch)
/// scan — the shape `db::upsert_finding` persists into `codescan_findings`.
/// `advisory_id` is `""` for a plain-outdated ('sca') finding, matching the
/// migration's non-CVE sentinel value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanFinding {
    pub kind: &'static str,
    pub ecosystem: &'static str,
    pub package_name: String,
    pub current_version: String,
    pub latest_version: Option<String>,
    pub advisory_id: String,
    pub severity: String,
}

/// Strips manifest-range decoration (`^`, `~`, `>=`, leading `v`) for a
/// best-effort textual comparison against deps.dev's resolved latest
/// version. Deliberately not full semver-range resolution (no lockfile is
/// read in P1) — see module docs' known limitation.
fn normalize_version(v: &str) -> &str {
    v.trim()
        .trim_start_matches(['^', '~', '=', '>', '<', ' '])
        .trim_start_matches('v')
}

fn is_outdated(current: &str, latest: Option<&str>) -> bool {
    latest.is_some_and(|latest| normalize_version(current) != normalize_version(latest))
}

/// Turns one resolved dependency lookup into zero or more findings:
/// - `lookup_failed` (deps.dev has no record of the package at all) always
///   yields exactly one fail-safe `sca`/`unknown`-severity finding — matches
///   `license_scan`'s "never dropped" convention for unresolvable packages.
/// - Otherwise, an outdated current version yields one `sca` finding
///   (severity `low`, informational), and every OSV advisory yields its own
///   `cve` finding — a package can be both outdated *and* have advisories.
fn dependency_findings(dep: &ManifestDependency, lookup: &DepsDevLookup) -> Vec<ScanFinding> {
    let ecosystem = dep.ecosystem.wire_name();

    if lookup.lookup_failed {
        return vec![ScanFinding {
            kind: "sca",
            ecosystem,
            package_name: dep.name.clone(),
            current_version: dep.version.clone(),
            latest_version: None,
            advisory_id: String::new(),
            severity: "unknown".to_owned(),
        }];
    }

    let mut findings = Vec::new();
    if is_outdated(&dep.version, lookup.latest_version.as_deref()) {
        findings.push(ScanFinding {
            kind: "sca",
            ecosystem,
            package_name: dep.name.clone(),
            current_version: dep.version.clone(),
            latest_version: lookup.latest_version.clone(),
            advisory_id: String::new(),
            severity: "low".to_owned(),
        });
    }
    for advisory in &lookup.advisories {
        findings.push(ScanFinding {
            kind: "cve",
            ecosystem,
            package_name: dep.name.clone(),
            current_version: dep.version.clone(),
            latest_version: lookup.latest_version.clone(),
            advisory_id: advisory.id.clone(),
            severity: advisory.severity.clone(),
        });
    }
    findings
}

/// Resolves the branches Sentinel scans for one repo: its default branch,
/// plus the highest-versioned `release/*` branch if one exists and differs
/// from the default (spec §10 — "default + latest release branch").
pub async fn resolve_target_branches(
    provider: &str,
    repo_url: &str,
    creds: &GitCredentials,
) -> anyhow::Result<Vec<String>> {
    let default_branch = git_provider::fetch_default_branch(provider, repo_url, creds).await?;
    let all_branches = git_provider::list_branch_names(provider, repo_url, creds).await?;
    let mut targets = vec![default_branch.clone()];
    if let Some(release) = git_provider::latest_release_branch(&all_branches)
        && release != default_branch
    {
        targets.push(release);
    }
    Ok(targets)
}

/// Scans one (repo, branch): fetches every known manifest via the
/// provider's Contents API, extracts declared dependencies, and resolves
/// each one's latest version + OSV advisories. Never fails outright — an
/// unreachable manifest is logged and skipped (mirrors
/// `git_provider::fetch_pr_diff`'s degrade-not-abort convention).
pub async fn scan_branch(
    provider: &str,
    repo_url: &str,
    branch: &str,
    creds: &GitCredentials,
    registry: &RegistryClient,
) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    for manifest in MANIFEST_FILES {
        let content = match git_provider::fetch_file_at_ref(
            provider, repo_url, manifest, branch, creds,
        )
        .await
        {
            Ok(Some(c)) => c,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(
                    repo = repo_url,
                    branch,
                    manifest,
                    error = %e,
                    "failed to fetch manifest, skipping"
                );
                continue;
            }
        };
        for dep in extract_manifest_dependencies(manifest, &content) {
            let lookup = registry
                .lookup_latest_and_advisories(dep.ecosystem, &dep.name, &dep.version)
                .await;
            findings.extend(dependency_findings(&dep, &lookup));
        }
    }
    findings
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn extract_manifest_dependencies_reads_every_line_not_just_diff_hunks() {
        let content = "{\n  \"dependencies\": {\n    \"left-pad\": \"^1.3.0\",\n    \"axios\": \"1.7.0\"\n  }\n}\n";
        let deps = extract_manifest_dependencies("package.json", content);
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "left-pad"));
        assert!(deps.iter().any(|d| d.name == "axios"));
    }

    #[test]
    fn extract_manifest_dependencies_is_empty_for_an_unrecognized_file() {
        assert!(extract_manifest_dependencies("README.md", "left-pad ^1.3.0").is_empty());
    }

    #[test]
    fn extract_manifest_dependencies_dedupes_within_one_file() {
        let content = "flask==2.0.0\nflask==2.0.0\n";
        let deps = extract_manifest_dependencies("requirements.txt", content);
        assert_eq!(deps.len(), 1);
    }

    #[test]
    fn is_outdated_treats_manifest_ranges_leniently() {
        assert!(!is_outdated("^1.3.0", Some("1.3.0")));
        assert!(is_outdated("^1.3.0", Some("1.4.0")));
        assert!(!is_outdated("v1.2.3", Some("1.2.3")));
        assert!(!is_outdated("1.0.0", None));
    }

    #[test]
    fn dependency_findings_records_unknown_severity_fail_safe_when_lookup_failed() {
        let dep = ManifestDependency {
            ecosystem: Ecosystem::Npm,
            name: "ghost-pkg".to_owned(),
            version: "1.0.0".to_owned(),
        };
        let lookup = DepsDevLookup {
            latest_version: None,
            advisories: vec![],
            lookup_failed: true,
        };
        let findings = dependency_findings(&dep, &lookup);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "sca");
        assert_eq!(findings[0].severity, "unknown");
        assert_eq!(findings[0].advisory_id, "");
    }

    #[test]
    fn dependency_findings_emits_sca_for_outdated_and_cve_per_advisory() {
        let dep = ManifestDependency {
            ecosystem: Ecosystem::Npm,
            name: "left-pad".to_owned(),
            version: "1.0.0".to_owned(),
        };
        let lookup = DepsDevLookup {
            latest_version: Some("1.3.0".to_owned()),
            advisories: vec![AdvisoryRef {
                id: "GHSA-xxxx-yyyy-zzzz".to_owned(),
                severity: "high".to_owned(),
                summary: None,
            }],
            lookup_failed: false,
        };
        let findings = dependency_findings(&dep, &lookup);
        assert_eq!(findings.len(), 2, "one sca + one cve finding");
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "sca" && f.advisory_id.is_empty())
        );
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "cve" && f.advisory_id == "GHSA-xxxx-yyyy-zzzz")
        );
    }

    #[test]
    fn dependency_findings_emits_nothing_when_up_to_date_and_no_advisories() {
        let dep = ManifestDependency {
            ecosystem: Ecosystem::Crates,
            name: "axum".to_owned(),
            version: "0.8.9".to_owned(),
        };
        let lookup = DepsDevLookup {
            latest_version: Some("0.8.9".to_owned()),
            advisories: vec![],
            lookup_failed: false,
        };
        assert!(dependency_findings(&dep, &lookup).is_empty());
    }

    #[tokio::test]
    async fn resolve_target_branches_includes_default_and_latest_release() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"default_branch": "main"})),
            )
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"name": "main"},
                {"name": "release/v1.0.x"},
                {"name": "release/v2.0.x"},
            ])))
            .mount(&mock)
            .await;

        let creds = GitCredentials {
            provider: "github".to_owned(),
            token: "tok".to_owned(),
            base_url: Some(mock.uri()),
        };
        let branches = resolve_target_branches("github", "https://github.com/acme/widgets", &creds)
            .await
            .expect("resolve should succeed");
        assert_eq!(branches, vec!["main", "release/v2.0.x"]);
    }

    #[tokio::test]
    async fn resolve_target_branches_does_not_duplicate_when_default_is_the_release_branch() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "default_branch": "release/v2.0.x"
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"name": "release/v2.0.x"},
            ])))
            .mount(&mock)
            .await;

        let creds = GitCredentials {
            provider: "github".to_owned(),
            token: "tok".to_owned(),
            base_url: Some(mock.uri()),
        };
        let branches = resolve_target_branches("github", "https://github.com/acme/widgets", &creds)
            .await
            .expect("resolve should succeed");
        assert_eq!(branches, vec!["release/v2.0.x"]);
    }

    #[tokio::test]
    async fn scan_branch_skips_missing_manifests_and_resolves_present_ones() {
        let mock = MockServer::start().await;
        for manifest in MANIFEST_FILES {
            if *manifest == "package.json" {
                continue;
            }
            Mock::given(method("GET"))
                .and(path(format!("/repos/acme/widgets/contents/{manifest}")))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/contents/package.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("{\"dependencies\": {\"left-pad\": \"1.0.0\"}}"),
            )
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/left-pad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/left-pad/versions/1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "advisoryKeys": []
            })))
            .mount(&mock)
            .await;

        let creds = GitCredentials {
            provider: "github".to_owned(),
            token: "tok".to_owned(),
            base_url: Some(mock.uri()),
        };
        let registry = RegistryClient::new(None, None, None, Some(mock.uri()));
        let findings = scan_branch(
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds,
            &registry,
        )
        .await;
        assert!(
            findings.is_empty(),
            "up-to-date dep with no advisories yields no findings"
        );
    }
}
