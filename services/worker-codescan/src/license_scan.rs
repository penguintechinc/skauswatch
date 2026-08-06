//! Dependency + license detection from a unified PR/MR diff — populates
//! `codescan_license_detections` (policy evaluation against
//! `codescan_license_policies` happens in `handler`, which also writes
//! `codescan_license_violations`).
//!
//! Net-new logic: v1's `CycloneDXScanner` shelled out to external CLIs
//! (`cyclonedx`/ScanCode) against a full repo checkout, and was never
//! instantiated outside its own file (see
//! docs/v2-port/phase12-scope-codeai.md row 3) — there is no working
//! behavior to port, and this worker never clones a full repo (only diffs,
//! see `git_provider`). This scans added dependency-manifest lines in the
//! diff (npm `package.json`, Python `requirements.txt`, Rust `Cargo.toml`)
//! and resolves each package's license via the ecosystem's public registry
//! API. Go (`go.mod`) is intentionally out of scope: unlike the other three,
//! there is no registry endpoint that returns a per-module license field —
//! flagged as a follow-up.
//!
//! Registry lookups are best-effort and non-fatal: a slow/unreachable/
//! rate-limited registry must never fail the review pipeline, mirroring how
//! `git_provider::fetch_pr_diff` failures degrade to an empty diff rather
//! than erroring out. A lookup failure yields a finding with
//! `license_name: None` (recorded, not silently dropped) rather than
//! aborting the scan.

use std::collections::BTreeSet;
use std::time::Duration;

/// One detected dependency + (best-effort) resolved license.
#[derive(Debug, Clone, PartialEq)]
pub struct LicenseFinding {
    /// Package/module name as it appears in the manifest.
    pub package_name: String,
    /// Version specifier as it appears in the manifest (may be a range,
    /// e.g. `"^1.3.0"`, not a resolved exact version).
    pub package_version: String,
    /// `None` when the registry lookup failed or returned no usable license
    /// field — still recorded (see module docs), just unresolved.
    pub license_name: Option<String>,
    /// Which registry resolved (or attempted to resolve) `license_name`:
    /// `"npm_registry"`, `"pypi"`, or `"crates_io"`.
    pub license_source: &'static str,
    /// Manifest file this dependency was found in.
    pub file_path: String,
    /// `0.85` when a license was resolved, `0.0` when the lookup failed.
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Ecosystem {
    Npm,
    PyPi,
    Crates,
}

fn ecosystem_for_file(path: &str) -> Option<Ecosystem> {
    let lower = path.to_lowercase();
    if lower.ends_with("package.json") {
        Some(Ecosystem::Npm)
    } else if lower.ends_with("requirements.txt") {
        Some(Ecosystem::PyPi)
    } else if lower.ends_with("cargo.toml") {
        Some(Ecosystem::Crates)
    } else {
        None
    }
}

/// `package.json` keys that are never dependency entries — skipped even
/// when they syntactically look like `"key": "string value"`.
const NPM_METADATA_KEYS: &[&str] = &[
    "name",
    "version",
    "description",
    "main",
    "module",
    "license",
    "private",
    "author",
    "homepage",
    "repository",
    "bugs",
    "keywords",
    "type",
    "types",
    "exports",
    "files",
    "engines",
    "packageManager",
];

fn parse_npm_dep_line(line: &str) -> Option<(String, String)> {
    let content = line.trim().trim_end_matches(',');
    let content = content.strip_prefix('"')?;
    let (key, rest) = content.split_once('"')?;
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let (val, _) = rest.split_once('"')?;
    if key.is_empty() || val.is_empty() || NPM_METADATA_KEYS.contains(&key) {
        return None;
    }
    let first = val.chars().next()?;
    let looks_like_version = first.is_ascii_digit()
        || matches!(first, '^' | '~' | '>' | '<' | '=' | '*')
        || val.starts_with("workspace:")
        || val.starts_with("file:");
    if !looks_like_version {
        return None;
    }
    Some((key.to_owned(), val.to_owned()))
}

fn is_valid_pkg_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn parse_pypi_dep_line(line: &str) -> Option<(String, String)> {
    let content = line.trim();
    if content.is_empty() || content.starts_with('#') {
        return None;
    }
    for sep in ["==", ">=", "<=", "~=", "!="] {
        if let Some(idx) = content.find(sep) {
            let name = content[..idx].trim();
            let version_part = &content[idx + sep.len()..];
            let version = version_part
                .split([';', ' ', ','])
                .next()
                .unwrap_or("")
                .trim();
            if is_valid_pkg_name(name) {
                let version = if version.is_empty() { "*" } else { version };
                return Some((name.to_owned(), version.to_owned()));
            }
            return None;
        }
    }
    if is_valid_pkg_name(content) {
        return Some((content.to_owned(), "*".to_owned()));
    }
    None
}

/// `Cargo.toml` keys that belong to `[package]`, not a dependency table.
const CARGO_METADATA_KEYS: &[&str] = &[
    "name",
    "version",
    "edition",
    "authors",
    "license",
    "license-file",
    "description",
    "repository",
    "readme",
    "keywords",
    "categories",
    "publish",
    "default-run",
    "resolver",
    "homepage",
    "documentation",
    "rust-version",
    "build",
    "links",
    "exclude",
    "include",
];

fn parse_cargo_dep_line(line: &str) -> Option<(String, String)> {
    let content = line.trim();
    let (key_part, rest) = content.split_once('=')?;
    let key = key_part.trim();
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        || CARGO_METADATA_KEYS.contains(&key)
    {
        return None;
    }
    let rest = rest.trim();
    let version = if let Some(v) = rest.strip_prefix('"') {
        v.split('"').next()?.to_owned()
    } else if rest.starts_with('{') {
        let idx = rest.find("version")?;
        let after = rest.get(idx..)?;
        let (_, after_key) = after.split_once('"')?;
        let (version, _) = after_key.split_once('"')?;
        version.to_owned()
    } else {
        return None;
    };
    if version.is_empty() {
        return None;
    }
    Some((key.to_owned(), version))
}

#[derive(Debug, Clone)]
struct DependencyRef {
    ecosystem: Ecosystem,
    name: String,
    version: String,
    file_path: String,
}

/// Scans a unified diff for added dependency-manifest lines, tracking the
/// "current file" via the most recent `+++ b/...` header (mirrors
/// `detection::touched_files`'s header scanning, but also needs the
/// per-file context to interpret line bodies).
fn extract_dependencies(diff: &str) -> Vec<DependencyRef> {
    let mut current_file: Option<String> = None;
    let mut current_ecosystem: Option<Ecosystem> = None;
    let mut deps = Vec::new();

    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ b/") {
            let path = path.trim().to_owned();
            current_ecosystem = ecosystem_for_file(&path);
            current_file = Some(path);
            continue;
        }
        if !line.starts_with('+') || line.starts_with("+++") {
            continue;
        }
        let (Some(eco), Some(path)) = (current_ecosystem, &current_file) else {
            continue;
        };
        let body = &line[1..];
        let parsed = match eco {
            Ecosystem::Npm => parse_npm_dep_line(body),
            Ecosystem::PyPi => parse_pypi_dep_line(body),
            Ecosystem::Crates => parse_cargo_dep_line(body),
        };
        if let Some((name, version)) = parsed {
            deps.push(DependencyRef {
                ecosystem: eco,
                name,
                version,
                file_path: path.clone(),
            });
        }
    }
    deps
}

async fn lookup_npm_license(client: &reqwest::Client, base: &str, pkg: &str) -> Option<String> {
    let url = format!(
        "{}/{}",
        base.trim_end_matches('/'),
        urlencoding::encode(pkg)
    );
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    match json.get("license") {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(serde_json::Value::Object(obj)) => {
            obj.get("type").and_then(|t| t.as_str()).map(str::to_owned)
        }
        _ => None,
    }
}

async fn lookup_pypi_license(client: &reqwest::Client, base: &str, pkg: &str) -> Option<String> {
    let url = format!(
        "{}/pypi/{}/json",
        base.trim_end_matches('/'),
        urlencoding::encode(pkg)
    );
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    let info = json.get("info")?;
    if let Some(license) = info.get("license").and_then(|v| v.as_str()) {
        let trimmed = license.trim();
        if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("UNKNOWN") {
            return Some(trimmed.to_owned());
        }
    }
    info.get("classifiers")
        .and_then(|v| v.as_array())
        .and_then(|classifiers| {
            classifiers.iter().find_map(|c| {
                c.as_str()
                    .and_then(|s| s.strip_prefix("License :: OSI Approved :: "))
                    .map(|rest| rest.trim().to_owned())
            })
        })
}

async fn lookup_crates_license(client: &reqwest::Client, base: &str, pkg: &str) -> Option<String> {
    let url = format!(
        "{}/api/v1/crates/{}",
        base.trim_end_matches('/'),
        urlencoding::encode(pkg)
    );
    // crates.io requires a descriptive User-Agent or rejects the request.
    let resp = client
        .get(&url)
        .header(
            "User-Agent",
            "skauswatch-worker-codescan (license-scan; support@penguintech.io)",
        )
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    json.get("versions")?
        .as_array()?
        .first()?
        .get("license")?
        .as_str()
        .map(str::to_owned)
}

/// Resolves dependency licenses against the public npm/PyPI/crates.io
/// registries (or test doubles, via the base-URL overrides). One instance is
/// built once at worker startup (`handler::CodeScanReviewHandler::new`) and
/// reused across reviews.
pub struct RegistryClient {
    http: reqwest::Client,
    npm_base: String,
    pypi_base: String,
    crates_base: String,
}

impl RegistryClient {
    /// `None` for any base URL uses that ecosystem's public registry.
    pub fn new(
        npm_base: Option<String>,
        pypi_base: Option<String>,
        crates_base: Option<String>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "failed to build license-registry HTTP client with timeout, using default");
                reqwest::Client::new()
            });
        Self {
            http,
            npm_base: npm_base.unwrap_or_else(|| "https://registry.npmjs.org".to_owned()),
            pypi_base: pypi_base.unwrap_or_else(|| "https://pypi.org".to_owned()),
            crates_base: crates_base.unwrap_or_else(|| "https://crates.io".to_owned()),
        }
    }

    /// Extracts added dependencies from `diff` and resolves each one's
    /// license. Always returns `Ok`-shaped data (never fails the caller) —
    /// per-dependency lookup failures are recorded as `license_name: None`
    /// findings, not dropped or propagated as an error.
    pub async fn scan_diff(&self, diff: &str) -> Vec<LicenseFinding> {
        let mut seen = BTreeSet::new();
        let mut findings = Vec::new();
        for dep in extract_dependencies(diff) {
            if !seen.insert((dep.ecosystem, dep.name.clone())) {
                continue;
            }
            let (license, source) = match dep.ecosystem {
                Ecosystem::Npm => (
                    lookup_npm_license(&self.http, &self.npm_base, &dep.name).await,
                    "npm_registry",
                ),
                Ecosystem::PyPi => (
                    lookup_pypi_license(&self.http, &self.pypi_base, &dep.name).await,
                    "pypi",
                ),
                Ecosystem::Crates => (
                    lookup_crates_license(&self.http, &self.crates_base, &dep.name).await,
                    "crates_io",
                ),
            };
            let confidence = if license.is_some() { 0.85 } else { 0.0 };
            findings.push(LicenseFinding {
                package_name: dep.name,
                package_version: dep.version,
                license_name: license,
                license_source: source,
                file_path: dep.file_path,
                confidence,
            });
        }
        findings
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn extracts_npm_dependency_added_lines_only() {
        let diff = "--- a/package.json\n+++ b/package.json\n@@ -1,3 +1,4 @@\n \
                     {\n   \"dependencies\": {\n+    \"left-pad\": \"^1.3.0\"\n   }\n }\n";
        let deps = extract_dependencies(diff);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "left-pad");
        assert_eq!(deps[0].version, "^1.3.0");
        assert_eq!(deps[0].file_path, "package.json");
    }

    #[test]
    fn skips_npm_metadata_keys() {
        let diff =
            "--- a/package.json\n+++ b/package.json\n@@ -1 +1 @@\n-x\n+  \"name\": \"my-app\"\n";
        assert!(extract_dependencies(diff).is_empty());
    }

    #[test]
    fn extracts_pypi_pinned_and_unpinned_requirements() {
        let diff = "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1,2 @@\n \
                     requests==2.31.0\n+django>=4.2,<5.0\n+flask\n";
        let deps = extract_dependencies(diff);
        assert!(
            deps.iter()
                .any(|d| d.name == "django" && d.version == "4.2")
        );
        assert!(deps.iter().any(|d| d.name == "flask" && d.version == "*"));
    }

    #[test]
    fn extracts_cargo_dependency_with_bare_string_version() {
        let diff = "--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1 +1 @@\n-x\n+axum = \"0.8.9\"\n";
        let deps = extract_dependencies(diff);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "axum");
        assert_eq!(deps[0].version, "0.8.9");
    }

    #[test]
    fn extracts_cargo_dependency_with_table_version() {
        let diff = "--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1 +1 @@\n-x\n\
                     +tokio = { version = \"1.52.3\", features = [\"full\"] }\n";
        let deps = extract_dependencies(diff);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "tokio");
        assert_eq!(deps[0].version, "1.52.3");
    }

    #[test]
    fn skips_cargo_package_metadata_keys() {
        let diff =
            "--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1 +1 @@\n-x\n+license = \"AGPL-3.0-only\"\n";
        assert!(extract_dependencies(diff).is_empty());
    }

    #[test]
    fn ignores_non_manifest_files() {
        let diff = "--- a/src/main.rs\n+++ b/src/main.rs\n@@ -1 +1 @@\n-x\n+\"react\": \"1.0.0\"\n";
        assert!(extract_dependencies(diff).is_empty());
    }

    #[test]
    fn deduplicates_repeated_dependency_lines() {
        let diff = "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-x\n+flask==2.0.0\n\
                     --- a/requirements.txt\n+++ b/requirements.txt\n@@ -2 +2 @@\n-y\n+flask==2.0.0\n";
        // extract_dependencies itself doesn't dedupe (that's scan_diff's job
        // via `seen`), but confirms both lines still parse identically.
        let deps = extract_dependencies(diff);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, deps[1].name);
    }

    #[tokio::test]
    async fn scan_diff_resolves_npm_license_via_registry() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/left-pad"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"license": "MIT"})),
            )
            .mount(&mock)
            .await;

        let client = RegistryClient::new(Some(mock.uri()), None, None);
        let diff = "--- a/package.json\n+++ b/package.json\n@@ -1 +1 @@\n-x\n+  \"left-pad\": \"^1.3.0\"\n";
        let findings = client.scan_diff(diff).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].package_name, "left-pad");
        assert_eq!(findings[0].license_name.as_deref(), Some("MIT"));
        assert_eq!(findings[0].license_source, "npm_registry");
    }

    #[tokio::test]
    async fn scan_diff_handles_object_shaped_npm_license_field() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/old-style-pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "license": {"type": "ISC", "url": "https://example.com"}
            })))
            .mount(&mock)
            .await;

        let client = RegistryClient::new(Some(mock.uri()), None, None);
        let diff = "--- a/package.json\n+++ b/package.json\n@@ -1 +1 @@\n-x\n+  \"old-style-pkg\": \"1.0.0\"\n";
        let findings = client.scan_diff(diff).await;
        assert_eq!(findings[0].license_name.as_deref(), Some("ISC"));
    }

    #[tokio::test]
    async fn scan_diff_resolves_pypi_license_from_classifiers_when_license_field_is_empty() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/django/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "info": {
                    "license": "",
                    "classifiers": [
                        "Framework :: Django",
                        "License :: OSI Approved :: BSD License",
                    ]
                }
            })))
            .mount(&mock)
            .await;

        let client = RegistryClient::new(None, Some(mock.uri()), None);
        let diff =
            "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-x\n+django==4.2\n";
        let findings = client.scan_diff(diff).await;
        assert_eq!(findings[0].license_name.as_deref(), Some("BSD License"));
    }

    #[tokio::test]
    async fn scan_diff_resolves_crates_io_license() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/crates/axum"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": [{"num": "0.8.9", "license": "MIT"}]
            })))
            .mount(&mock)
            .await;

        let client = RegistryClient::new(None, None, Some(mock.uri()));
        let diff = "--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1 +1 @@\n-x\n+axum = \"0.8.9\"\n";
        let findings = client.scan_diff(diff).await;
        assert_eq!(findings[0].license_name.as_deref(), Some("MIT"));
        assert_eq!(findings[0].license_source, "crates_io");
    }

    #[tokio::test]
    async fn scan_diff_records_a_finding_with_no_license_when_registry_lookup_fails() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/mystery-pkg"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let client = RegistryClient::new(Some(mock.uri()), None, None);
        let diff = "--- a/package.json\n+++ b/package.json\n@@ -1 +1 @@\n-x\n+  \"mystery-pkg\": \"1.0.0\"\n";
        let findings = client.scan_diff(diff).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].license_name, None);
        assert!((findings[0].confidence - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn scan_diff_deduplicates_the_same_package_across_hunks() {
        let mock = MockServer::start().await;
        // `.expect(1)` is checked when `mock` is dropped at the end of this
        // test — a second lookup for the same (ecosystem, package) would
        // fail the test.
        Mock::given(method("GET"))
            .and(path("/pypi/flask/json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"info": {"license": "BSD-3-Clause"}})),
            )
            .expect(1)
            .mount(&mock)
            .await;

        let client = RegistryClient::new(None, Some(mock.uri()), None);
        let diff = "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-x\n+flask==2.0.0\n\
                     --- a/requirements.txt\n+++ b/requirements.txt\n@@ -2 +2 @@\n-y\n+flask==2.0.0\n";
        let findings = client.scan_diff(diff).await;
        assert_eq!(
            findings.len(),
            1,
            "duplicate dependency must be deduplicated"
        );
    }

    #[tokio::test]
    async fn scan_diff_is_empty_for_a_diff_with_no_manifest_changes() {
        let client = RegistryClient::new(None, None, None);
        let diff = "--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-x\n+y\n";
        assert!(client.scan_diff(diff).await.is_empty());
    }
}
