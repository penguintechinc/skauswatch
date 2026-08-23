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
//! diff (npm `package.json`, Python `requirements.txt`, Rust `Cargo.toml`,
//! Go `go.mod`) and resolves each package's license via the ecosystem's
//! public registry API. Go has no registry endpoint of its own that returns
//! a per-module license field (unlike npm/PyPI/crates.io), so it resolves
//! via [deps.dev](https://deps.dev) (Google's open-source insights API,
//! `GET /v3/systems/GO/packages/{module}/versions/{version}`), which
//! aggregates license data it already extracted from the module source.
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
    /// `"npm_registry"`, `"pypi"`, `"crates_io"`, or `"deps_dev"` (Go).
    pub license_source: &'static str,
    /// Manifest file this dependency was found in.
    pub file_path: String,
    /// `0.85` when a license was resolved, `0.0` when the lookup failed.
    pub confidence: f64,
}

/// Ecosystem discriminator shared by diff-based license scanning
/// ([`RegistryClient::scan_diff`]) and whole-file Sentinel dependency
/// extraction (`crate::sentinel::extract_manifest_dependencies`) — `pub(crate)`
/// so both call sites share one set of per-ecosystem line parsers rather than
/// forking them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Ecosystem {
    Npm,
    PyPi,
    Crates,
    Go,
}

impl Ecosystem {
    /// deps.dev "system" path segment for this ecosystem (`GET
    /// /v3/systems/{system}/packages/...`) — used both by the existing Go
    /// license lookup below and by the Sentinel latest-version/OSV-advisory
    /// lookups (`latest_version`/`advisories`), which query deps.dev for
    /// every ecosystem, not just Go.
    pub(crate) fn deps_dev_system(self) -> &'static str {
        match self {
            Ecosystem::Npm => "NPM",
            Ecosystem::PyPi => "PYPI",
            Ecosystem::Crates => "CARGO",
            Ecosystem::Go => "GO",
        }
    }

    /// Short lowercase label persisted in `codescan_findings.ecosystem` by
    /// `crate::sentinel` — distinct from [`deps_dev_system`], which is the
    /// API's own uppercase path segment.
    pub(crate) fn wire_name(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "pypi",
            Ecosystem::Crates => "cargo",
            Ecosystem::Go => "go",
        }
    }
}

pub(crate) fn ecosystem_for_file(path: &str) -> Option<Ecosystem> {
    let lower = path.to_lowercase();
    if lower.ends_with("package.json") {
        Some(Ecosystem::Npm)
    } else if lower.ends_with("requirements.txt") {
        Some(Ecosystem::PyPi)
    } else if lower.ends_with("cargo.toml") {
        Some(Ecosystem::Crates)
    } else if lower.ends_with("go.mod") {
        Some(Ecosystem::Go)
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

pub(crate) fn parse_npm_dep_line(line: &str) -> Option<(String, String)> {
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

pub(crate) fn is_valid_pkg_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

pub(crate) fn parse_pypi_dep_line(line: &str) -> Option<(String, String)> {
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

pub(crate) fn parse_cargo_dep_line(line: &str) -> Option<(String, String)> {
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

/// True for a plausible Go module path: `/`-separated segments of
/// alphanumerics/`-`/`_`, containing at least one `.` (every real module
/// path is rooted at a domain, e.g. `github.com/...`, `golang.org/x/...`) —
/// this is what lets a bare two-token line like `go 1.21` or
/// `module example.com/foo` fall through to the version-shape check below
/// instead of needing an explicit directive-keyword denylist.
pub(crate) fn is_valid_go_module_path(s: &str) -> bool {
    s.contains('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '-' | '_'))
}

/// True for a Go module version: `v` followed by a digit — covers plain
/// semver (`v1.2.3`), pseudo-versions
/// (`v0.0.0-20200101000000-abcdef123456`), and `+incompatible` suffixes.
/// Deliberately loose (no full semver validation) since go.mod versions are
/// always toolchain-generated, never hand-typed ranges like npm/PyPI.
pub(crate) fn is_valid_go_module_version(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('v')) && matches!(chars.next(), Some(c) if c.is_ascii_digit())
}

/// Parses one added `go.mod` line into `(module_path, version)`. Handles
/// both the single-line form (`require github.com/pkg/errors v0.9.1`) and
/// bare lines inside a `require ( ... )` block (`github.com/pkg/errors
/// v0.9.1 // indirect`) — indirect dependencies are parsed the same as
/// direct ones (mirrors how the npm parser doesn't distinguish
/// `dependencies` from `devDependencies`). `module`/`go`/`toolchain`/
/// `replace`/`exclude`/`retract` directives and the block delimiters
/// (`require (`, `)`) are rejected by the module-path/version shape checks
/// below rather than an explicit keyword list.
pub(crate) fn parse_go_mod_dep_line(line: &str) -> Option<(String, String)> {
    let content = match line.trim().split_once("//") {
        Some((before, _comment)) => before.trim(),
        None => line.trim(),
    };
    let mut fields = content.split_whitespace().peekable();
    if fields.peek() == Some(&"require") {
        fields.next();
    }
    let module = fields.next()?;
    let version = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    if !is_valid_go_module_path(module) || !is_valid_go_module_version(version) {
        return None;
    }
    Some((module.to_owned(), version.to_owned()))
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
            Ecosystem::Go => parse_go_mod_dep_line(body),
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

/// Resolves a Go module's license via deps.dev, which indexes it out of the
/// module source itself (there is no per-module license field in the Go
/// module proxy protocol the way npm/PyPI/crates.io registries expose one).
/// `licenses` can hold more than one SPDX id for a dual-licensed module
/// (e.g. `["MIT", "Apache-2.0"]`); joined with `" OR "` to keep a single
/// `license_name` string, consistent with how an npm/crates.io SPDX
/// expression like `"MIT OR Apache-2.0"` already arrives as one string.
async fn lookup_go_license(
    client: &reqwest::Client,
    base: &str,
    module: &str,
    version: &str,
) -> Option<String> {
    let url = format!(
        "{}/v3/systems/GO/packages/{}/versions/{}",
        base.trim_end_matches('/'),
        urlencoding::encode(module),
        urlencoding::encode(version)
    );
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    let licenses: Vec<&str> = json
        .get("licenses")?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .collect();
    if licenses.is_empty() {
        None
    } else {
        Some(licenses.join(" OR "))
    }
}

/// One OSV/deps.dev security advisory affecting a specific resolved
/// dependency version. `severity` is a best-effort CVSS-score bucket
/// (`critical`/`high`/`medium`/`low`) or `"unknown"` when deps.dev has no
/// score for it — never dropped just because it can't be scored (see module
/// docs' fail-safe rule, extended to Sentinel's CVE findings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdvisoryRef {
    /// OSV/GHSA advisory id (e.g. `"GHSA-xxxx-xxxx-xxxx"`).
    pub id: String,
    /// `critical` | `high` | `medium` | `low` | `unknown`.
    pub severity: String,
    /// Short human-readable title, when deps.dev's advisory detail lookup
    /// succeeds; `None` if that lookup failed (the advisory id itself is
    /// still recorded — see [`deps_dev_advisory_detail`]).
    pub summary: Option<String>,
}

/// Result of a Sentinel latest-version + OSV-advisory lookup for one
/// dependency (`RegistryClient::lookup_latest_and_advisories`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DepsDevLookup {
    /// The ecosystem's current default/latest release, when deps.dev has
    /// package metadata for this name at all.
    pub latest_version: Option<String>,
    /// Advisories tied to the manifest-declared version specifically (only
    /// resolvable when that specifier is an exact version deps.dev
    /// recognizes, not a range like `^1.3.0` — a range simply yields no
    /// advisories, which is not the same as `lookup_failed`).
    pub advisories: Vec<AdvisoryRef>,
    /// `true` when deps.dev has no record of this package at all (unknown
    /// name, transport error, rate limit, etc.) — the caller must still
    /// record a fail-safe "unknown severity" finding rather than dropping
    /// the dependency (see `sentinel::scan_branch`).
    pub lookup_failed: bool,
}

/// Buckets a CVSS score into the house severity vocabulary (matches
/// `manager`'s `alerts.severity` set minus `"info"`, which Sentinel never
/// emits). `None` (no score published) maps to `"unknown"`, not `"low"` —
/// silently downgrading an unscored advisory would be a false negative.
fn severity_from_cvss(score: Option<f64>) -> &'static str {
    match score {
        Some(s) if s >= 9.0 => "critical",
        Some(s) if s >= 7.0 => "high",
        Some(s) if s >= 4.0 => "medium",
        Some(s) if s >= 0.0 => "low",
        _ => "unknown",
    }
}

/// `GET /v3/systems/{system}/packages/{name}` — deps.dev's package-level
/// endpoint, listing every known version. Returns the version flagged
/// `isDefault: true` (deps.dev's own notion of "current release"), or
/// `None` if the package is unknown to deps.dev or the request fails.
async fn deps_dev_latest_version(
    client: &reqwest::Client,
    base: &str,
    system: &str,
    name: &str,
) -> Option<String> {
    let url = format!(
        "{}/v3/systems/{}/packages/{}",
        base.trim_end_matches('/'),
        system,
        urlencoding::encode(name)
    );
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    json.get("versions")?.as_array()?.iter().find_map(|v| {
        if v.get("isDefault").and_then(serde_json::Value::as_bool) != Some(true) {
            return None;
        }
        v.get("versionKey")?
            .get("version")?
            .as_str()
            .map(str::to_owned)
    })
}

/// `GET /v3/advisories/{id}` — resolves one advisory id to a severity
/// bucket and title. Never fails the caller: a lookup failure still yields
/// the advisory (severity `"unknown"`, no summary) rather than dropping it,
/// since the id itself already came from a real `advisoryKeys` entry on the
/// dependency's version.
async fn deps_dev_advisory_detail(client: &reqwest::Client, base: &str, id: &str) -> AdvisoryRef {
    let url = format!(
        "{}/v3/advisories/{}",
        base.trim_end_matches('/'),
        urlencoding::encode(id)
    );
    let fallback = || AdvisoryRef {
        id: id.to_owned(),
        severity: "unknown".to_owned(),
        summary: None,
    };
    let Ok(resp) = client.get(&url).send().await else {
        return fallback();
    };
    if !resp.status().is_success() {
        return fallback();
    }
    let Ok(json) = resp.json::<serde_json::Value>().await else {
        return fallback();
    };
    let score = json
        .get("cvss3Score")
        .or_else(|| json.get("cvssScore"))
        .and_then(serde_json::Value::as_f64);
    AdvisoryRef {
        id: id.to_owned(),
        severity: severity_from_cvss(score).to_owned(),
        summary: json
            .get("title")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
    }
}

/// `GET /v3/systems/{system}/packages/{name}/versions/{version}` — the same
/// endpoint [`lookup_go_license`] already calls for license data, extended
/// to also read `advisoryKeys` (each `{id: "GHSA-..."}`) and resolve every
/// one via [`deps_dev_advisory_detail`]. `None` means the version-specific
/// lookup itself failed (unknown/unrecognized version — routine for a
/// manifest range specifier like `^1.3.0`, not treated as `lookup_failed`
/// by the caller); `Some(vec![])` means the lookup succeeded and the
/// version simply has no known advisories.
async fn deps_dev_advisories_for_version(
    client: &reqwest::Client,
    base: &str,
    system: &str,
    name: &str,
    version: &str,
) -> Option<Vec<AdvisoryRef>> {
    let url = format!(
        "{}/v3/systems/{}/packages/{}/versions/{}",
        base.trim_end_matches('/'),
        system,
        urlencoding::encode(name),
        urlencoding::encode(version)
    );
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    let ids: Vec<String> = json
        .get("advisoryKeys")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.get("id").and_then(|v| v.as_str()))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut advisories = Vec::with_capacity(ids.len());
    for id in ids {
        advisories.push(deps_dev_advisory_detail(client, base, &id).await);
    }
    Some(advisories)
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
    /// deps.dev base URL. Doubles as the general Sentinel latest-version/
    /// OSV-advisory lookup base for *every* ecosystem (`lookup_latest_and_advisories`),
    /// not just the original Go-license use (`lookup_go_license`) the field
    /// name predates.
    go_base: String,
}

impl RegistryClient {
    /// `None` for any base URL uses that ecosystem's public registry.
    pub fn new(
        npm_base: Option<String>,
        pypi_base: Option<String>,
        crates_base: Option<String>,
        go_base: Option<String>,
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
            go_base: go_base.unwrap_or_else(|| "https://api.deps.dev".to_owned()),
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
                Ecosystem::Go => (
                    lookup_go_license(&self.http, &self.go_base, &dep.name, &dep.version).await,
                    "deps_dev",
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

    /// Sentinel SCA/CVE lookup (docs/v2-port/v2.1-codescan-sentinel.md §9,
    /// §12): resolves `name`'s latest published version and any OSV
    /// advisories tied to the manifest-declared `version`, both via
    /// deps.dev. Always returns — never a `Result` the caller must unwrap —
    /// per the module's fail-safe convention; see [`DepsDevLookup::lookup_failed`].
    pub(crate) async fn lookup_latest_and_advisories(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> DepsDevLookup {
        let system = ecosystem.deps_dev_system();
        let latest_version = deps_dev_latest_version(&self.http, &self.go_base, system, name).await;
        let advisories =
            deps_dev_advisories_for_version(&self.http, &self.go_base, system, name, version)
                .await
                .unwrap_or_default();
        DepsDevLookup {
            lookup_failed: latest_version.is_none(),
            latest_version,
            advisories,
        }
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

    #[test]
    fn extracts_go_mod_single_line_require() {
        let diff = "--- a/go.mod\n+++ b/go.mod\n@@ -1 +1 @@\n-x\n\
                     +require github.com/pkg/errors v0.9.1\n";
        let deps = extract_dependencies(diff);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "github.com/pkg/errors");
        assert_eq!(deps[0].version, "v0.9.1");
        assert_eq!(deps[0].file_path, "go.mod");
    }

    #[test]
    fn extracts_go_mod_require_block_direct_and_indirect() {
        let diff = "--- a/go.mod\n+++ b/go.mod\n@@ -1,2 +1,4 @@\n \
                     require (\n+\tgithub.com/pkg/errors v0.9.1\n\
                     +\tgolang.org/x/sync v0.5.0 // indirect\n )\n";
        let deps = extract_dependencies(diff);
        assert_eq!(deps.len(), 2);
        assert!(
            deps.iter()
                .any(|d| d.name == "github.com/pkg/errors" && d.version == "v0.9.1")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "golang.org/x/sync" && d.version == "v0.5.0")
        );
    }

    #[test]
    fn skips_go_mod_module_go_and_toolchain_directives() {
        let diff = "--- a/go.mod\n+++ b/go.mod\n@@ -1,3 +1,3 @@\n-x\n\
                     +module github.com/acme/widgets\n+go 1.21\n+toolchain go1.21.5\n";
        assert!(extract_dependencies(diff).is_empty());
    }

    #[test]
    fn skips_go_mod_replace_and_exclude_directives() {
        let diff = "--- a/go.mod\n+++ b/go.mod\n@@ -1,2 +1,2 @@\n-x\n\
                     +replace github.com/foo/bar => github.com/fork/bar v1.0.0\n\
                     +exclude github.com/broken/pkg v0.1.0\n";
        assert!(extract_dependencies(diff).is_empty());
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

        let client = RegistryClient::new(Some(mock.uri()), None, None, None);
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

        let client = RegistryClient::new(Some(mock.uri()), None, None, None);
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

        let client = RegistryClient::new(None, Some(mock.uri()), None, None);
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

        let client = RegistryClient::new(None, None, Some(mock.uri()), None);
        let diff = "--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1 +1 @@\n-x\n+axum = \"0.8.9\"\n";
        let findings = client.scan_diff(diff).await;
        assert_eq!(findings[0].license_name.as_deref(), Some("MIT"));
        assert_eq!(findings[0].license_source, "crates_io");
    }

    #[tokio::test]
    async fn scan_diff_resolves_go_license_via_deps_dev() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/v3/systems/GO/packages/github.com%2Fpkg%2Ferrors/versions/v0.9.1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "licenses": ["BSD-2-Clause"]
            })))
            .mount(&mock)
            .await;

        let client = RegistryClient::new(None, None, None, Some(mock.uri()));
        let diff = "--- a/go.mod\n+++ b/go.mod\n@@ -1 +1 @@\n-x\n\
                     +require github.com/pkg/errors v0.9.1\n";
        let findings = client.scan_diff(diff).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].package_name, "github.com/pkg/errors");
        assert_eq!(findings[0].license_name.as_deref(), Some("BSD-2-Clause"));
        assert_eq!(findings[0].license_source, "deps_dev");
        assert!((findings[0].confidence - 0.85).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn scan_diff_joins_dual_licenses_for_a_go_module() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/v3/systems/GO/packages/gopkg.in%2Fyaml.v3/versions/v3.0.1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "licenses": ["MIT", "Apache-2.0"]
            })))
            .mount(&mock)
            .await;

        let client = RegistryClient::new(None, None, None, Some(mock.uri()));
        let diff = "--- a/go.mod\n+++ b/go.mod\n@@ -1 +1 @@\n-x\n\
                     +require gopkg.in/yaml.v3 v3.0.1\n";
        let findings = client.scan_diff(diff).await;
        assert_eq!(
            findings[0].license_name.as_deref(),
            Some("MIT OR Apache-2.0")
        );
    }

    #[tokio::test]
    async fn scan_diff_flags_go_module_unknown_when_deps_dev_has_no_record() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/v3/systems/GO/packages/github.com%2Fghost%2Fmodule/versions/v1.0.0",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let client = RegistryClient::new(None, None, None, Some(mock.uri()));
        let diff = "--- a/go.mod\n+++ b/go.mod\n@@ -1 +1 @@\n-x\n\
                     +require github.com/ghost/module v1.0.0\n";
        let findings = client.scan_diff(diff).await;
        assert_eq!(findings.len(), 1, "a lookup failure must still be recorded");
        assert_eq!(findings[0].license_name, None);
        assert_eq!(findings[0].license_source, "deps_dev");
        assert!((findings[0].confidence - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn scan_diff_records_a_finding_with_no_license_when_registry_lookup_fails() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/mystery-pkg"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let client = RegistryClient::new(Some(mock.uri()), None, None, None);
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

        let client = RegistryClient::new(None, Some(mock.uri()), None, None);
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
        let client = RegistryClient::new(None, None, None, None);
        let diff = "--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-x\n+y\n";
        assert!(client.scan_diff(diff).await.is_empty());
    }

    #[test]
    fn deps_dev_system_maps_every_ecosystem() {
        assert_eq!(Ecosystem::Npm.deps_dev_system(), "NPM");
        assert_eq!(Ecosystem::PyPi.deps_dev_system(), "PYPI");
        assert_eq!(Ecosystem::Crates.deps_dev_system(), "CARGO");
        assert_eq!(Ecosystem::Go.deps_dev_system(), "GO");
    }

    #[test]
    fn severity_from_cvss_buckets_scores() {
        assert_eq!(severity_from_cvss(Some(9.8)), "critical");
        assert_eq!(severity_from_cvss(Some(7.5)), "high");
        assert_eq!(severity_from_cvss(Some(5.0)), "medium");
        assert_eq!(severity_from_cvss(Some(1.0)), "low");
        assert_eq!(severity_from_cvss(None), "unknown");
    }

    #[tokio::test]
    async fn lookup_latest_and_advisories_resolves_latest_version_and_advisories() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/left-pad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": [
                    {"versionKey": {"version": "1.2.0"}, "isDefault": false},
                    {"versionKey": {"version": "1.3.0"}, "isDefault": true},
                ]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/left-pad/versions/1.1.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "advisoryKeys": [{"id": "GHSA-aaaa-bbbb-cccc"}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/advisories/GHSA-aaaa-bbbb-cccc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "Prototype pollution",
                "cvss3Score": 8.1
            })))
            .mount(&mock)
            .await;

        let client = RegistryClient::new(None, None, None, Some(mock.uri()));
        let result = client
            .lookup_latest_and_advisories(Ecosystem::Npm, "left-pad", "1.1.0")
            .await;
        assert_eq!(result.latest_version.as_deref(), Some("1.3.0"));
        assert!(!result.lookup_failed);
        assert_eq!(result.advisories.len(), 1);
        assert_eq!(result.advisories[0].id, "GHSA-aaaa-bbbb-cccc");
        assert_eq!(result.advisories[0].severity, "high");
        assert_eq!(
            result.advisories[0].summary.as_deref(),
            Some("Prototype pollution")
        );
    }

    #[tokio::test]
    async fn lookup_latest_and_advisories_marks_lookup_failed_when_package_unknown() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/PYPI/packages/ghost-pkg"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/PYPI/packages/ghost-pkg/versions/1.0.0"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let client = RegistryClient::new(None, None, None, Some(mock.uri()));
        let result = client
            .lookup_latest_and_advisories(Ecosystem::PyPi, "ghost-pkg", "1.0.0")
            .await;
        assert!(
            result.lookup_failed,
            "an unknown package must be flagged lookup_failed, never silently treated as clean"
        );
        assert_eq!(result.latest_version, None);
        assert!(result.advisories.is_empty());
    }

    #[tokio::test]
    async fn lookup_latest_and_advisories_records_advisory_with_unknown_severity_when_detail_fetch_fails()
     {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/CARGO/packages/some-crate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": [{"versionKey": {"version": "2.0.0"}, "isDefault": true}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/CARGO/packages/some-crate/versions/1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "advisoryKeys": [{"id": "RUSTSEC-2020-0001"}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/advisories/RUSTSEC-2020-0001"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let client = RegistryClient::new(None, None, None, Some(mock.uri()));
        let result = client
            .lookup_latest_and_advisories(Ecosystem::Crates, "some-crate", "1.0.0")
            .await;
        assert!(!result.lookup_failed, "the package itself resolved fine");
        assert_eq!(result.advisories.len(), 1);
        assert_eq!(result.advisories[0].id, "RUSTSEC-2020-0001");
        assert_eq!(
            result.advisories[0].severity, "unknown",
            "an advisory whose detail lookup fails must still be recorded, not dropped"
        );
        assert_eq!(result.advisories[0].summary, None);
    }

    #[tokio::test]
    async fn lookup_latest_and_advisories_tolerates_a_manifest_range_version() {
        // The manifest-declared version is often a range (`^1.3.0`), which
        // deps.dev's exact-version endpoint 404s on — this must not be
        // treated as lookup_failed as long as the package-level lookup
        // itself succeeded.
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/axios"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": [{"versionKey": {"version": "1.7.0"}, "isDefault": true}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/axios/versions/%5E1.3.0"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let client = RegistryClient::new(None, None, None, Some(mock.uri()));
        let result = client
            .lookup_latest_and_advisories(Ecosystem::Npm, "axios", "^1.3.0")
            .await;
        assert!(!result.lookup_failed);
        assert_eq!(result.latest_version.as_deref(), Some("1.7.0"));
        assert!(result.advisories.is_empty());
    }
}
