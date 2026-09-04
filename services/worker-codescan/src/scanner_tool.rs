//! CodeScan Sentinel's pluggable scanner-tool registry
//! (docs/v2-port/v2.1-codescan-sentinel.md §3, P2): SAST (semgrep), secrets
//! (gitleaks), and IaC/misconfig (trivy `fs --scanners misconfig`) tools run
//! as subprocesses against a fetched branch working copy
//! (`crate::tree_fetch::WorkingTree`) and are normalized into the same
//! `ToolFinding` shape `db::upsert_tool_finding` persists into
//! `codescan_findings` (kind `sast`/`secret`/`iac`) alongside P1's SCA/CVE
//! rows. SBOM generation (syft, CycloneDX) shares the registry but produces
//! a document (`SbomDocument`), not findings — see [`ScanOutcome`].
//!
//! Adding a tool is one [`ScannerTool`] impl + one entry in
//! [`default_registry`] — the same "one place to add" shape as
//! `license_scan`'s per-ecosystem parsers.
//!
//! **Graceful degradation is structural, not incidental**: every tool goes
//! through [`ProcessRunner::run`], whose only two outcomes are "ran (with
//! some exit status)" or "binary not found" — there is no panic path. A
//! missing binary yields [`ScanOutcome::Unavailable`], which the caller
//! (`handler::CodeScanReviewHandler`) logs and skips, never treating it as a
//! scan failure. [`ProcessRunner`] is the test seam: unit tests below inject
//! a fake implementation returning recorded tool-output fixtures instead of
//! shelling out to a real binary, so `cargo test` never depends on semgrep/
//! gitleaks/trivy/syft actually being installed. Separately,
//! `handler.rs`'s own integration tests exercise the *real*
//! [`TokioProcessRunner`] against binaries that genuinely aren't present in
//! the build/test container — proving the unavailable-path end to end, not
//! just in a fake.
//!
//! Fixture note: the JSON fixtures embedded in this module's tests are
//! schema-accurate representative samples of each tool's documented output
//! shape (semgrep `--json`, gitleaks `--report-format json`, trivy
//! `--format json` for `fs --scanners misconfig`, syft `-o cyclonedx-json`)
//! — not literal output captured from a local run, since this build
//! environment has network access but does not install these tools as part
//! of the Rust workspace build. They match the real, versioned field names
//! and nesting each tool documents/publishes.

use std::path::Path;

use async_trait::async_trait;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// How long any single scanner-tool subprocess is allowed to run before
/// [`TokioProcessRunner`] gives up and surfaces a timeout error — mirrors
/// `backend.md`'s "timeout every external call" discipline for what is,
/// from the worker's perspective, an external dependency. Deliberately
/// generous (large monorepos, semgrep's `--config auto` ruleset download) —
/// this bounds worst-case hangs, not routine runtime.
const TOOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// One normalized finding from a SAST/secret/IaC tool — the shape
/// `db::upsert_tool_finding` persists into `codescan_findings` alongside
/// P1's SCA/CVE rows (same table, disjoint `kind` values, additive columns
/// from migrations/0005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolFinding {
    /// `"sast"` | `"secret"` | `"iac"` — one of the kinds
    /// migrations/0004's `CHECK` constraint already accepts.
    pub kind: &'static str,
    /// `"semgrep"` | `"gitleaks"` | `"trivy"`.
    pub tool: &'static str,
    pub rule_id: String,
    /// Normalized to this store's shared scale: critical/high/medium/low/unknown.
    pub severity: String,
    pub file_path: Option<String>,
    pub line: Option<i32>,
    pub title: String,
}

impl ToolFinding {
    /// Deterministic dedupe/upsert key for one `(tenant, repo, branch,
    /// kind)` scope — sha256 hex over the fields that identify "the same
    /// finding reappearing" across scans, so an unchanged finding updates
    /// its existing row (`last_seen`) on the next run instead of
    /// accumulating a duplicate. Two distinct hits for the same rule on the
    /// same file+line collapse into one row by design — matches how
    /// gitleaks/semgrep themselves already dedupe identical matches within
    /// one file.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.tool.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.rule_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.file_path.as_deref().unwrap_or("").as_bytes());
        hasher.update(b"\0");
        hasher.update(
            self.line
                .map(|l| l.to_string())
                .unwrap_or_default()
                .as_bytes(),
        );
        format!("{:x}", hasher.finalize())
    }
}

/// One CycloneDX SBOM document produced by the `sbom`-kind tool (syft) —
/// never becomes a `codescan_findings` row; stored instead in
/// `codescan_sbom_artifacts` (`db::insert_sbom_artifact`).
#[derive(Debug, Clone)]
pub struct SbomDocument {
    pub format: &'static str,
    /// Raw CycloneDX JSON bytes as emitted by the tool, unmodified.
    pub content: Vec<u8>,
}

/// What one tool invocation produced. A tool is either a finding-producer
/// (sast/secret/iac) or an SBOM-document-producer (sbom) — never both, kept
/// as separate variants (rather than an "always both, usually empty"
/// struct) so a caller can't accidentally read the wrong field.
#[derive(Debug, Clone)]
pub enum ScanOutcome {
    Findings(Vec<ToolFinding>),
    Sbom(SbomDocument),
    /// The tool's binary was not present in the worker image — recorded,
    /// never fatal (module docs above).
    Unavailable,
}

/// One subprocess invocation's raw result — the boundary
/// [`ScannerTool::scan`] implementations parse. `found = false` means the
/// binary itself could not be located (see [`TokioProcessRunner`]); every
/// other field is only meaningful when `found` is `true`.
#[derive(Debug, Clone, Default)]
pub struct ProcessOutput {
    pub found: bool,
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Abstraction over subprocess execution — the test seam described in the
/// module docs above.
#[async_trait]
pub trait ProcessRunner: Send + Sync {
    async fn run(&self, program: &str, args: &[&str], cwd: &Path) -> anyhow::Result<ProcessOutput>;
}

/// Real subprocess execution via `tokio::process::Command`, bounded by
/// [`TOOL_TIMEOUT`]. `ErrorKind::NotFound` from `spawn()` (the binary isn't
/// on `PATH`) is the one error this treats as data (`found: false`) rather
/// than propagating — every other I/O error (permission denied, etc.) is a
/// genuine unexpected failure the caller should log.
pub struct TokioProcessRunner;

#[async_trait]
impl ProcessRunner for TokioProcessRunner {
    async fn run(&self, program: &str, args: &[&str], cwd: &Path) -> anyhow::Result<ProcessOutput> {
        let fut = tokio::process::Command::new(program)
            .args(args)
            .current_dir(cwd)
            .kill_on_drop(true)
            .output();
        match tokio::time::timeout(TOOL_TIMEOUT, fut).await {
            Ok(Ok(out)) => Ok(ProcessOutput {
                found: true,
                success: out.status.success(),
                stdout: out.stdout,
                stderr: out.stderr,
            }),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(ProcessOutput {
                found: false,
                ..Default::default()
            }),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => anyhow::bail!("{program} timed out after {TOOL_TIMEOUT:?}"),
        }
    }
}

/// One pluggable scanner tool — see module docs for the registry shape.
#[async_trait]
pub trait ScannerTool: Send + Sync {
    /// Stable identifier, matches `ToolFinding::tool`/`SbomDocument::format`
    /// provenance for logging.
    fn name(&self) -> &'static str;
    /// Cheap, filesystem-metadata-only applicability check against the
    /// fetched tree's file list — avoids invoking a tool guaranteed to find
    /// nothing (spec §3: "Detect applicability from the tree").
    fn is_applicable(&self, files: &[String]) -> bool;
    async fn scan(&self, root: &Path, runner: &dyn ProcessRunner) -> anyhow::Result<ScanOutcome>;
}

/// Many of these scanners (semgrep, gitleaks, trivy) exit non-zero
/// precisely when they *found something* — a routine, expected outcome, not
/// a failure — so `ScannerTool::scan` implementations parse `stdout`
/// regardless of `success`. This only logs the non-zero exit at debug level
/// (with `stderr` for context) so a genuinely broken invocation is still
/// visible in logs without treating it as fatal.
fn log_nonzero_exit(tool: &str, out: &ProcessOutput) {
    if !out.success {
        tracing::debug!(
            tool,
            stderr = %String::from_utf8_lossy(&out.stderr),
            "tool exited non-zero; parsing stdout anyway (many scanners exit non-zero \
             precisely when findings are present)"
        );
    }
}

fn normalize_semgrep_severity(raw: &str) -> String {
    match raw.to_uppercase().as_str() {
        "ERROR" => "high",
        "WARNING" => "medium",
        "INFO" => "low",
        _ => "unknown",
    }
    .to_owned()
}

fn normalize_trivy_severity(raw: &str) -> String {
    match raw.to_uppercase().as_str() {
        "CRITICAL" => "critical",
        "HIGH" => "high",
        "MEDIUM" => "medium",
        "LOW" => "low",
        _ => "unknown",
    }
    .to_owned()
}

#[derive(Deserialize, Default)]
struct SemgrepOutput {
    #[serde(default)]
    results: Vec<SemgrepResult>,
}

#[derive(Deserialize)]
struct SemgrepResult {
    check_id: String,
    path: String,
    start: SemgrepPos,
    extra: SemgrepExtra,
}

#[derive(Deserialize)]
struct SemgrepPos {
    line: i64,
}

#[derive(Deserialize)]
struct SemgrepExtra {
    severity: String,
    message: String,
}

/// Parses `semgrep --config auto --json` stdout into normalized `sast`
/// findings. Malformed/empty stdout degrades to "no findings" rather than
/// an error — a scan that produced garbage output is not worth failing the
/// whole branch scan over (mirrors `sentinel::dependency_findings`'s
/// never-drop-the-scan philosophy).
fn parse_semgrep_json(stdout: &[u8]) -> Vec<ToolFinding> {
    let parsed: SemgrepOutput = serde_json::from_slice(stdout).unwrap_or_default();
    parsed
        .results
        .into_iter()
        .map(|r| ToolFinding {
            kind: "sast",
            tool: "semgrep",
            rule_id: r.check_id,
            severity: normalize_semgrep_severity(&r.extra.severity),
            file_path: Some(r.path),
            line: i32::try_from(r.start.line).ok(),
            title: r.extra.message,
        })
        .collect()
}

/// SAST via semgrep — always applicable (semgrep's `auto` ruleset covers
/// every language it supports; an unrecognized language yields zero rules
/// matched, not an error).
pub struct SemgrepTool;

#[async_trait]
impl ScannerTool for SemgrepTool {
    fn name(&self) -> &'static str {
        "semgrep"
    }

    fn is_applicable(&self, _files: &[String]) -> bool {
        true
    }

    async fn scan(&self, root: &Path, runner: &dyn ProcessRunner) -> anyhow::Result<ScanOutcome> {
        let out = runner
            .run(
                "semgrep",
                &["--config", "auto", "--json", "--quiet", "."],
                root,
            )
            .await?;
        if !out.found {
            return Ok(ScanOutcome::Unavailable);
        }
        log_nonzero_exit("semgrep", &out);
        Ok(ScanOutcome::Findings(parse_semgrep_json(&out.stdout)))
    }
}

#[derive(Deserialize)]
struct GitleaksLeak {
    #[serde(rename = "RuleID")]
    rule_id: String,
    #[serde(rename = "File")]
    file: String,
    #[serde(rename = "StartLine")]
    start_line: i64,
    #[serde(rename = "Description")]
    description: String,
}

/// Parses `gitleaks detect --report-format json` stdout (a bare JSON array
/// of leaks — gitleaks writes `[]`, not an object, when clean). Malformed
/// stdout degrades to "no leaks found" — same rationale as
/// `parse_semgrep_json`.
fn parse_gitleaks_json(stdout: &[u8]) -> Vec<ToolFinding> {
    let parsed: Vec<GitleaksLeak> = serde_json::from_slice(stdout).unwrap_or_default();
    parsed
        .into_iter()
        .map(|l| ToolFinding {
            kind: "secret",
            tool: "gitleaks",
            rule_id: l.rule_id,
            // Gitleaks itself has no severity scale — a leaked secret is
            // always treated as critical, matching how P1 treats an
            // unresolvable dependency as a fail-safe rather than dropping it.
            severity: "critical".to_owned(),
            file_path: Some(l.file),
            line: i32::try_from(l.start_line).ok(),
            title: l.description,
        })
        .collect()
}

/// Secrets via gitleaks — always applicable. `--no-git` is required because
/// `crate::tree_fetch::WorkingTree` is a zip-archive extraction, not a git
/// clone (no `.git` history to diff against), so gitleaks must scan the
/// working tree's current file contents directly. `--report-path /dev/stdout`
/// keeps the tool's output on the same stdout stream every other tool here
/// uses — this is a Linux-only trick, acceptable since the worker only ever
/// runs inside the Debian runtime container. `--exit-code 0` avoids treating
/// "leaks found" (gitleaks' normal nonzero exit) as a process failure.
pub struct GitleaksTool;

#[async_trait]
impl ScannerTool for GitleaksTool {
    fn name(&self) -> &'static str {
        "gitleaks"
    }

    fn is_applicable(&self, _files: &[String]) -> bool {
        true
    }

    async fn scan(&self, root: &Path, runner: &dyn ProcessRunner) -> anyhow::Result<ScanOutcome> {
        let out = runner
            .run(
                "gitleaks",
                &[
                    "detect",
                    "--source",
                    ".",
                    "--no-git",
                    "--report-format",
                    "json",
                    "--report-path",
                    "/dev/stdout",
                    "--exit-code",
                    "0",
                ],
                root,
            )
            .await?;
        if !out.found {
            return Ok(ScanOutcome::Unavailable);
        }
        log_nonzero_exit("gitleaks", &out);
        Ok(ScanOutcome::Findings(parse_gitleaks_json(&out.stdout)))
    }
}

#[derive(Deserialize, Default)]
struct TrivyOutput {
    #[serde(default, rename = "Results")]
    results: Vec<TrivyResult>,
}

#[derive(Deserialize)]
struct TrivyResult {
    #[serde(rename = "Target")]
    target: String,
    #[serde(default, rename = "Misconfigurations")]
    misconfigurations: Vec<TrivyMisconfig>,
}

#[derive(Deserialize)]
struct TrivyMisconfig {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Title")]
    title: String,
    #[serde(rename = "Severity")]
    severity: String,
    #[serde(default, rename = "CauseMetadata")]
    cause_metadata: Option<TrivyCauseMetadata>,
}

#[derive(Deserialize)]
struct TrivyCauseMetadata {
    #[serde(rename = "StartLine")]
    start_line: Option<i64>,
}

/// Parses `trivy fs --scanners misconfig --format json` stdout into
/// normalized `iac` findings. Malformed stdout degrades to "no
/// misconfigurations found".
fn parse_trivy_config_json(stdout: &[u8]) -> Vec<ToolFinding> {
    let parsed: TrivyOutput = serde_json::from_slice(stdout).unwrap_or_default();
    parsed
        .results
        .into_iter()
        .flat_map(|r| {
            let target = r.target;
            r.misconfigurations.into_iter().map(move |m| ToolFinding {
                kind: "iac",
                tool: "trivy",
                rule_id: m.id,
                severity: normalize_trivy_severity(&m.severity),
                file_path: Some(target.clone()),
                line: m
                    .cause_metadata
                    .and_then(|c| c.start_line)
                    .and_then(|l| i32::try_from(l).ok()),
                title: m.title,
            })
        })
        .collect()
}

/// IaC/container-config misconfig via `trivy fs --scanners misconfig` —
/// only applicable when the tree actually has something trivy's config
/// scanners understand (Dockerfiles, Kubernetes/Helm/Compose YAML) per spec
/// §3; running it unconditionally would burn a scan cycle on every repo for
/// zero possible findings.
pub struct TrivyConfigTool;

impl TrivyConfigTool {
    fn looks_like_iac(file: &str) -> bool {
        let lower = file.to_lowercase();
        let base = lower.rsplit('/').next().unwrap_or(lower.as_str());
        base == "dockerfile"
            || base.starts_with("dockerfile.")
            || lower.ends_with(".yaml")
            || lower.ends_with(".yml")
    }
}

#[async_trait]
impl ScannerTool for TrivyConfigTool {
    fn name(&self) -> &'static str {
        "trivy"
    }

    fn is_applicable(&self, files: &[String]) -> bool {
        files.iter().any(|f| Self::looks_like_iac(f))
    }

    async fn scan(&self, root: &Path, runner: &dyn ProcessRunner) -> anyhow::Result<ScanOutcome> {
        let out = runner
            .run(
                "trivy",
                &[
                    "fs",
                    "--scanners",
                    "misconfig",
                    "--format",
                    "json",
                    "--quiet",
                    ".",
                ],
                root,
            )
            .await?;
        if !out.found {
            return Ok(ScanOutcome::Unavailable);
        }
        log_nonzero_exit("trivy", &out);
        Ok(ScanOutcome::Findings(parse_trivy_config_json(&out.stdout)))
    }
}

/// SBOM generation via syft, CycloneDX JSON — always applicable (every repo
/// with at least a manifest file produces a meaningful SBOM; an empty repo
/// still yields a valid, empty CycloneDX document).
pub struct SyftTool;

#[async_trait]
impl ScannerTool for SyftTool {
    fn name(&self) -> &'static str {
        "syft"
    }

    fn is_applicable(&self, _files: &[String]) -> bool {
        true
    }

    async fn scan(&self, root: &Path, runner: &dyn ProcessRunner) -> anyhow::Result<ScanOutcome> {
        let out = runner
            .run("syft", &[".", "-o", "cyclonedx-json", "-q"], root)
            .await?;
        if !out.found {
            return Ok(ScanOutcome::Unavailable);
        }
        log_nonzero_exit("syft", &out);
        // Validate the document actually parses as JSON before storing it —
        // a tool that ran but emitted garbage (truncated output, a stray
        // warning on stdout) must not poison `codescan_sbom_artifacts` with
        // an unparseable blob. Degrades to "no SBOM produced this run"
        // rather than failing the branch scan.
        if serde_json::from_slice::<serde_json::Value>(&out.stdout).is_err() {
            return Ok(ScanOutcome::Findings(Vec::new()));
        }
        Ok(ScanOutcome::Sbom(SbomDocument {
            format: "cyclonedx-json",
            content: out.stdout,
        }))
    }
}

/// The full P2 tool registry — adding a tool is one [`ScannerTool`] impl
/// plus one entry here.
pub fn default_registry() -> Vec<Box<dyn ScannerTool>> {
    vec![
        Box::new(SemgrepTool),
        Box::new(GitleaksTool),
        Box::new(TrivyConfigTool),
        Box::new(SyftTool),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    struct FakeRunner {
        found: bool,
        stdout: &'static [u8],
        success: bool,
    }

    impl FakeRunner {
        fn ok(found: bool, stdout: &'static [u8]) -> Self {
            Self {
                found,
                stdout,
                success: true,
            }
        }
    }

    #[async_trait]
    impl ProcessRunner for FakeRunner {
        async fn run(
            &self,
            _program: &str,
            _args: &[&str],
            _cwd: &Path,
        ) -> anyhow::Result<ProcessOutput> {
            Ok(ProcessOutput {
                found: self.found,
                success: self.success,
                stdout: self.stdout.to_vec(),
                stderr: b"non-zero exit stderr".to_vec(),
            })
        }
    }

    // Schema-accurate representative fixture — see module docs' Fixture
    // note for why this isn't a literal captured run.
    const SEMGREP_FIXTURE: &str = r#"{
        "results": [
            {
                "check_id": "python.lang.security.audit.hardcoded-password",
                "path": "app/config.py",
                "start": {"line": 12, "col": 5},
                "end": {"line": 12, "col": 30},
                "extra": {
                    "severity": "ERROR",
                    "message": "Hardcoded password detected",
                    "metadata": {"cwe": ["CWE-798"]}
                }
            },
            {
                "check_id": "generic.secrets.security.detected-generic-api-key",
                "path": "app/config.py",
                "start": {"line": 20, "col": 1},
                "end": {"line": 20, "col": 40},
                "extra": {
                    "severity": "WARNING",
                    "message": "Possible API key detected",
                    "metadata": {}
                }
            }
        ],
        "errors": []
    }"#;

    #[tokio::test]
    async fn semgrep_tool_parses_a_captured_fixture() {
        let runner = FakeRunner::ok(true, SEMGREP_FIXTURE.as_bytes());
        let outcome = SemgrepTool
            .scan(Path::new("/tmp"), &runner)
            .await
            .unwrap_or_else(|e| panic!("scan: {e}"));
        let ScanOutcome::Findings(findings) = outcome else {
            panic!("expected Findings outcome");
        };
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].kind, "sast");
        assert_eq!(findings[0].tool, "semgrep");
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[0].file_path.as_deref(), Some("app/config.py"));
        assert_eq!(findings[0].line, Some(12));
        assert_eq!(findings[1].severity, "medium");
    }

    #[tokio::test]
    async fn semgrep_tool_still_parses_findings_when_the_process_exits_non_zero() {
        // semgrep (like gitleaks/trivy) exits non-zero precisely when it
        // found something — must not be mistaken for a failed invocation.
        let runner = FakeRunner {
            found: true,
            stdout: SEMGREP_FIXTURE.as_bytes(),
            success: false,
        };
        let outcome = SemgrepTool
            .scan(Path::new("/tmp"), &runner)
            .await
            .unwrap_or_else(|e| panic!("scan: {e}"));
        let ScanOutcome::Findings(findings) = outcome else {
            panic!("expected Findings outcome");
        };
        assert_eq!(findings.len(), 2, "non-zero exit must not suppress parsing");
    }

    #[tokio::test]
    async fn semgrep_tool_reports_unavailable_when_binary_missing() {
        let runner = FakeRunner::ok(false, b"");
        let outcome = SemgrepTool
            .scan(Path::new("/tmp"), &runner)
            .await
            .unwrap_or_else(|e| panic!("scan: {e}"));
        assert!(matches!(outcome, ScanOutcome::Unavailable));
    }

    #[test]
    fn semgrep_tool_is_always_applicable() {
        assert!(SemgrepTool.is_applicable(&[]));
        assert!(SemgrepTool.is_applicable(&["README.md".to_owned()]));
    }

    #[test]
    fn parse_semgrep_json_degrades_to_empty_on_malformed_input() {
        assert!(parse_semgrep_json(b"not json").is_empty());
        assert!(parse_semgrep_json(b"").is_empty());
    }

    /// Schema-accurate representative fixture (gitleaks v8 `--report-format
    /// json`) — see module docs' Fixture note.
    ///
    /// Uses `AKIAIOSFODNN7EXAMPLE`, AWS's own published documentation example
    /// key. It is recognised as a non-secret by gitleaks itself, so the
    /// fixture can read naturally instead of being spliced or built at runtime
    /// to dodge this repo's pre-commit secret scan.
    const GITLEAKS_FIXTURE: &str = r#"[
        {
            "Description": "AWS Access Key",
            "StartLine": 4,
            "EndLine": 4,
            "File": "infra/deploy.sh",
            "RuleID": "aws-access-key",
            "Match": "AKIAIOSFODNN7EXAMPLE",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Fingerprint": "infra/deploy.sh:aws-access-key:4"
        }
    ]"#;

    #[tokio::test]
    async fn gitleaks_tool_parses_a_captured_fixture() {
        let runner = FakeRunner::ok(true, GITLEAKS_FIXTURE.as_bytes());
        let outcome = GitleaksTool
            .scan(Path::new("/tmp"), &runner)
            .await
            .unwrap_or_else(|e| panic!("scan: {e}"));
        let ScanOutcome::Findings(findings) = outcome else {
            panic!("expected Findings outcome");
        };
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "secret");
        assert_eq!(findings[0].tool, "gitleaks");
        assert_eq!(findings[0].severity, "critical");
        assert_eq!(findings[0].rule_id, "aws-access-key");
        assert_eq!(findings[0].file_path.as_deref(), Some("infra/deploy.sh"));
        assert_eq!(findings[0].line, Some(4));
    }

    #[tokio::test]
    async fn gitleaks_tool_reports_unavailable_when_binary_missing() {
        let runner = FakeRunner::ok(false, b"");
        let outcome = GitleaksTool
            .scan(Path::new("/tmp"), &runner)
            .await
            .unwrap_or_else(|e| panic!("scan: {e}"));
        assert!(matches!(outcome, ScanOutcome::Unavailable));
    }

    #[test]
    fn parse_gitleaks_json_degrades_to_empty_on_malformed_input() {
        assert!(parse_gitleaks_json(b"{not even an array}").is_empty());
        assert!(parse_gitleaks_json(b"[]").is_empty());
    }

    // Schema-accurate representative fixture (trivy `fs --scanners
    // misconfig --format json`) — see module docs' Fixture note.
    const TRIVY_FIXTURE: &str = r#"{
        "Results": [
            {
                "Target": "k8s/deployment.yaml",
                "Class": "config",
                "Type": "kubernetes",
                "MisconfSummary": {"Successes": 10, "Failures": 1},
                "Misconfigurations": [
                    {
                        "Type": "Kubernetes Security Check",
                        "ID": "KSV012",
                        "Title": "Container should not run as root",
                        "Description": "runAsNonRoot is not set",
                        "Severity": "HIGH",
                        "Status": "FAIL",
                        "CauseMetadata": {"StartLine": 5, "EndLine": 8}
                    }
                ]
            }
        ]
    }"#;

    #[tokio::test]
    async fn trivy_config_tool_parses_a_captured_fixture() {
        let runner = FakeRunner::ok(true, TRIVY_FIXTURE.as_bytes());
        let outcome = TrivyConfigTool
            .scan(Path::new("/tmp"), &runner)
            .await
            .unwrap_or_else(|e| panic!("scan: {e}"));
        let ScanOutcome::Findings(findings) = outcome else {
            panic!("expected Findings outcome");
        };
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "iac");
        assert_eq!(findings[0].tool, "trivy");
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[0].rule_id, "KSV012");
        assert_eq!(
            findings[0].file_path.as_deref(),
            Some("k8s/deployment.yaml")
        );
        assert_eq!(findings[0].line, Some(5));
    }

    #[tokio::test]
    async fn trivy_config_tool_reports_unavailable_when_binary_missing() {
        let runner = FakeRunner::ok(false, b"");
        let outcome = TrivyConfigTool
            .scan(Path::new("/tmp"), &runner)
            .await
            .unwrap_or_else(|e| panic!("scan: {e}"));
        assert!(matches!(outcome, ScanOutcome::Unavailable));
    }

    #[test]
    fn trivy_config_tool_is_applicable_only_with_dockerfiles_or_yaml() {
        assert!(TrivyConfigTool.is_applicable(&["Dockerfile".to_owned()]));
        assert!(TrivyConfigTool.is_applicable(&["services/api/Dockerfile.prod".to_owned()]));
        assert!(TrivyConfigTool.is_applicable(&["k8s/deploy.yaml".to_owned()]));
        assert!(TrivyConfigTool.is_applicable(&["k8s/deploy.yml".to_owned()]));
        assert!(
            !TrivyConfigTool.is_applicable(&["README.md".to_owned(), "src/main.rs".to_owned()])
        );
        assert!(!TrivyConfigTool.is_applicable(&[]));
    }

    #[test]
    fn parse_trivy_config_json_degrades_to_empty_on_malformed_input() {
        assert!(parse_trivy_config_json(b"nope").is_empty());
    }

    // Schema-accurate representative fixture (syft `-o cyclonedx-json`) —
    // see module docs' Fixture note.
    const SYFT_FIXTURE: &str = r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
        "version": 1,
        "metadata": {
            "timestamp": "2026-08-22T00:00:00Z",
            "tools": [{"vendor": "anchore", "name": "syft", "version": "1.51.0"}]
        },
        "components": [
            {"type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}
        ]
    }"#;

    #[tokio::test]
    async fn syft_tool_produces_an_sbom_document_for_valid_json() {
        let runner = FakeRunner::ok(true, SYFT_FIXTURE.as_bytes());
        let outcome = SyftTool
            .scan(Path::new("/tmp"), &runner)
            .await
            .unwrap_or_else(|e| panic!("scan: {e}"));
        let ScanOutcome::Sbom(doc) = outcome else {
            panic!("expected Sbom outcome");
        };
        assert_eq!(doc.format, "cyclonedx-json");
        assert_eq!(doc.content, SYFT_FIXTURE.as_bytes());
    }

    #[tokio::test]
    async fn syft_tool_reports_unavailable_when_binary_missing() {
        let runner = FakeRunner::ok(false, b"");
        let outcome = SyftTool
            .scan(Path::new("/tmp"), &runner)
            .await
            .unwrap_or_else(|e| panic!("scan: {e}"));
        assert!(matches!(outcome, ScanOutcome::Unavailable));
    }

    #[tokio::test]
    async fn syft_tool_degrades_to_no_sbom_on_malformed_output() {
        let runner = FakeRunner::ok(true, b"not json at all");
        let outcome = SyftTool
            .scan(Path::new("/tmp"), &runner)
            .await
            .unwrap_or_else(|e| panic!("scan: {e}"));
        let ScanOutcome::Findings(findings) = outcome else {
            panic!("expected an empty Findings fallback, not Sbom");
        };
        assert!(findings.is_empty());
    }

    #[test]
    fn fingerprint_is_deterministic_and_distinguishes_findings() {
        let base = ToolFinding {
            kind: "sast",
            tool: "semgrep",
            rule_id: "rule-a".to_owned(),
            severity: "high".to_owned(),
            file_path: Some("app.py".to_owned()),
            line: Some(10),
            title: "x".to_owned(),
        };
        // Severity/title changing must not change identity — the
        // fingerprint is a dedupe key, not a full-row hash.
        let mut same_identity = base.clone();
        same_identity.severity = "medium".to_owned();
        same_identity.title = "different title".to_owned();

        let mut different_line = base.clone();
        different_line.line = Some(11);

        assert_eq!(base.fingerprint(), same_identity.fingerprint());
        assert_ne!(base.fingerprint(), different_line.fingerprint());
        assert_eq!(
            base.fingerprint().len(),
            64,
            "sha256 hex digest is 64 chars"
        );
    }

    #[test]
    fn default_registry_includes_every_tool_exactly_once() {
        let registry = default_registry();
        assert_eq!(registry.len(), 4);
        let mut names: Vec<&str> = registry.iter().map(|t| t.name()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["gitleaks", "semgrep", "syft", "trivy"]);
    }

    #[tokio::test]
    async fn tokio_process_runner_reports_not_found_for_a_nonexistent_binary() {
        let out = TokioProcessRunner
            .run("definitely-not-a-real-binary-xyz123", &[], Path::new("."))
            .await
            .unwrap_or_else(|e| panic!("run: {e}"));
        assert!(!out.found);
    }

    #[tokio::test]
    async fn tokio_process_runner_captures_stdout_for_a_real_binary() {
        let out = TokioProcessRunner
            .run("echo", &["hello"], Path::new("."))
            .await
            .unwrap_or_else(|e| panic!("run: {e}"));
        assert!(out.found);
        assert!(out.success);
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
    }
}
