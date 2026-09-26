//! The unified scan engine: ClamAV (INSTREAM) + YARA-X, run together when
//! both are configured, either alone when only one is — the DRY foundation
//! `docs/v2-port/v2.1-depgate.md` §3 calls for. `s3scan` and `scanner` each
//! adopt this instead of hand-rolling their own clamav/yara plumbing;
//! DepGate and Sentinel are the net-new consumers this was built for.

use std::time::Duration;

use crate::clamav::{self, ClamdTransport};
use crate::hashing::{self, Hashes};
use crate::verdict::Verdict;
use crate::yara::{YaraMatch, YaraScanner};

/// Configuration for building a [`ScanEngine`].
///
/// At most one of `clamd_socket`/`clamd_tcp` should be set (Unix wins if
/// both are); leaving both `None` disables ClamAV entirely. Leaving
/// `yara_rules_path` `None` disables YARA entirely — either engine may run
/// alone.
#[derive(Debug, Clone)]
pub struct ScanEngineConfig {
    /// Unix-socket path to clamd (`s3scan`'s deployment shape,
    /// `CLAMD_SOCKET`).
    pub clamd_socket: Option<String>,
    /// TCP `(host, port)` to clamd (`scanner`'s deployment shape,
    /// `CLAMAV_HOST`/`CLAMAV_PORT`).
    pub clamd_tcp: Option<(String, u16)>,
    /// Per-scan clamd timeout. Ignored when ClamAV is not configured.
    pub clamd_timeout: Duration,
    /// Directory or single-file path to YARA rules. `None` disables YARA.
    pub yara_rules_path: Option<String>,
}

/// Resolved, connected-lazily ClamAV endpoint.
#[derive(Debug, Clone)]
struct ClamdEndpoint {
    transport: ClamdTransport,
    timeout: Duration,
}

/// Failed to build a [`ScanEngine`].
#[derive(Debug, thiserror::Error)]
pub enum ScanEngineError {
    /// YARA rule compilation failed — see [`YaraScanner::load`].
    #[error("failed to load YARA rules from {path}: {source}")]
    YaraLoad {
        /// The configured rules path.
        path: String,
        /// The underlying compile/IO error.
        #[source]
        source: anyhow::Error,
    },
}

/// A scan-time failure. Unlike a ClamAV daemon simply being unreachable
/// (which degrades to a clean verdict — see module docs), this is a real
/// scan-execution failure the caller must handle.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// The YARA-X scan itself failed (not a load/compile failure — that
    /// happens earlier, in [`ScanEngine::new`]).
    #[error("yara scan failed: {0}")]
    Yara(String),
}

/// Per-call control over which configured engines actually run. Both
/// default to `true` — "run everything this engine has configured" — with
/// `s3scan`'s per-bucket/per-task YARA toggle and `scanner`'s
/// per-message `scan_type` dispatch as the two reasons a caller narrows it.
#[derive(Debug, Clone, Copy)]
pub struct ScanOptions {
    /// Run ClamAV for this call, if configured.
    pub run_clamav: bool,
    /// Run YARA for this call, if configured.
    pub run_yara: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            run_clamav: true,
            run_yara: true,
        }
    }
}

/// Which engines actually executed for one [`ScanEngine::scan_bytes`] call
/// — distinct from "configured": a configured engine might still not run
/// because [`ScanOptions`] excluded it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EnginesRun {
    /// ClamAV executed.
    pub clamav: bool,
    /// YARA-X executed.
    pub yara: bool,
}

/// The full result of one [`ScanEngine::scan_bytes`] call.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    /// The canonical verdict (see [`Verdict`]).
    pub verdict: Verdict,
    /// Any configured/run engine reported malware.
    pub is_malware: bool,
    /// Any configured/run engine reported a PUP.
    pub is_pup: bool,
    /// `is_malware || is_pup`.
    pub is_threat: bool,
    /// Threat/signature/rule names from every engine that ran. YARA entries
    /// are prefixed `YARA.<rule_name>` so the two engines' contributions
    /// stay distinguishable in a flat list.
    pub threat_names: Vec<String>,
    /// Detected MIME type.
    pub file_type: String,
    /// MD5/SHA1/SHA256 of the scanned bytes.
    pub hashes: Hashes,
    /// ClamAV's raw result as JSON (`{"is_malware","is_pup","threats"}`),
    /// matching `s3scan`'s pre-extraction shape exactly. `None` when ClamAV
    /// did not run or the daemon was unreachable.
    pub clamav_result: Option<serde_json::Value>,
    /// Raw YARA-X matches, for callers that want rule-level detail (e.g.
    /// `scanner`'s "yara" scan-type findings payload).
    pub yara_matches: Vec<YaraMatch>,
    /// Which engines actually executed for this call.
    pub engines_run: EnginesRun,
    /// Wall-clock time spent inside this call (engine time only — excludes
    /// any download/IO the caller did before invoking it).
    pub scan_time_ms: i64,
}

/// Runs ClamAV and/or YARA-X against in-memory bytes. Build once per
/// process (YARA rule compilation is not cheap) and reuse across scans.
#[derive(Debug)]
pub struct ScanEngine {
    clamd: Option<ClamdEndpoint>,
    yara: Option<YaraScanner>,
}

impl ScanEngine {
    /// Builds an engine from `config`, compiling YARA rules up front when
    /// `yara_rules_path` is set. Performs no ClamAV I/O at construction —
    /// clamd is only contacted per-scan, so a down daemon never fails this.
    ///
    /// # Errors
    /// Returns [`ScanEngineError::YaraLoad`] when `yara_rules_path` is set
    /// but the rules fail to load/compile.
    pub async fn new(config: ScanEngineConfig) -> Result<Self, ScanEngineError> {
        let yara =
            match &config.yara_rules_path {
                Some(path) => Some(YaraScanner::load(path).await.map_err(|source| {
                    ScanEngineError::YaraLoad {
                        path: path.clone(),
                        source,
                    }
                })?),
                None => None,
            };
        Ok(Self {
            clamd: resolve_clamd(&config),
            yara,
        })
    }

    /// Builds a ClamAV-only engine (no YARA). Infallible — no rule
    /// compilation is performed. Intended for callers that want to degrade
    /// gracefully after a [`ScanEngine::new`] YARA-load failure, mirroring
    /// `services/scanner`'s existing "log and continue without YARA"
    /// behavior rather than a hard boot-time failure.
    #[must_use]
    pub fn clamav_only(config: &ScanEngineConfig) -> Self {
        Self {
            clamd: resolve_clamd(config),
            yara: None,
        }
    }

    /// Whether ClamAV is configured on this engine.
    #[must_use]
    pub const fn clamav_enabled(&self) -> bool {
        self.clamd.is_some()
    }

    /// Whether YARA rules are loaded on this engine.
    #[must_use]
    pub const fn yara_enabled(&self) -> bool {
        self.yara.is_some()
    }

    /// Scans `data` with every configured engine (`ScanOptions::default()`).
    ///
    /// # Errors
    /// Returns [`ScanError`] if a configured, requested YARA scan itself
    /// fails. ClamAV daemon failures degrade to "clean" rather than erroring
    /// — see the module docs.
    pub async fn scan_bytes(&self, data: &[u8]) -> Result<ScanOutcome, ScanError> {
        self.scan_bytes_with_options(data, ScanOptions::default())
            .await
    }

    /// Scans `data`, running only the engines both configured on this
    /// engine and requested by `options`.
    ///
    /// # Errors
    /// Returns [`ScanError`] if a requested, configured YARA scan itself
    /// fails.
    pub async fn scan_bytes_with_options(
        &self,
        data: &[u8],
        options: ScanOptions,
    ) -> Result<ScanOutcome, ScanError> {
        let start = std::time::Instant::now();
        let file_type = hashing::detect_file_type(data);
        let hashes = hashing::compute_hashes(data);

        let mut is_malware = false;
        let mut is_pup = false;
        let mut threat_names = Vec::new();
        let mut clamav_result = None;
        let mut engines_run = EnginesRun::default();

        if options.run_clamav
            && let Some(clamd) = &self.clamd
        {
            engines_run.clamav = true;
            match clamav::scan_bytes(&clamd.transport, clamd.timeout, data).await {
                Ok(v) => {
                    clamav_result = Some(serde_json::json!({
                        "is_malware": v.is_malware,
                        "is_pup": v.is_pup,
                        "threats": v.threat_names,
                    }));
                    is_malware |= v.is_malware;
                    is_pup |= v.is_pup;
                    threat_names.extend(v.threat_names);
                }
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        "ClamAV unavailable — scanning skipped (clean)"
                    );
                }
            }
        }

        let mut yara_matches = Vec::new();
        if options.run_yara
            && let Some(scanner) = &self.yara
        {
            engines_run.yara = true;
            let matches = scanner
                .scan_bytes(data)
                .map_err(|e| ScanError::Yara(e.to_string()))?;
            for m in &matches {
                // A rule tagged `pup` mirrors ClamAV's PUP/PUA substring
                // heuristic; everything else is treated as malware.
                if m.tags.iter().any(|t| t.eq_ignore_ascii_case("pup")) {
                    is_pup = true;
                } else {
                    is_malware = true;
                }
                threat_names.push(format!("YARA.{}", m.rule_name));
            }
            yara_matches = matches;
        }

        let is_threat = is_malware || is_pup;
        let verdict = Verdict::from_malware_pup(is_malware, is_pup);
        let scan_time_ms = i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX);

        Ok(ScanOutcome {
            verdict,
            is_malware,
            is_pup,
            is_threat,
            threat_names,
            file_type,
            hashes,
            clamav_result,
            yara_matches,
            engines_run,
            scan_time_ms,
        })
    }
}

/// Resolves the configured ClamAV transport: Unix socket wins if both are
/// somehow set, else TCP, else `None` (ClamAV disabled).
fn resolve_clamd(config: &ScanEngineConfig) -> Option<ClamdEndpoint> {
    if let Some(socket) = &config.clamd_socket {
        Some(ClamdEndpoint {
            transport: ClamdTransport::Unix(socket.clone()),
            timeout: config.clamd_timeout,
        })
    } else {
        config.clamd_tcp.clone().map(|(host, port)| ClamdEndpoint {
            transport: ClamdTransport::Tcp(host, port),
            timeout: config.clamd_timeout,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    fn no_engines_config() -> ScanEngineConfig {
        ScanEngineConfig {
            clamd_socket: None,
            clamd_tcp: None,
            clamd_timeout: Duration::from_secs(1),
            yara_rules_path: None,
        }
    }

    fn yara_rules_path() -> String {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/yara_rules").to_owned()
    }

    const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    #[tokio::test]
    async fn no_engines_configured_yields_clean_with_neither_running() {
        let engine = ScanEngine::new(no_engines_config())
            .await
            .expect("infallible with no yara path");
        assert!(!engine.clamav_enabled());
        assert!(!engine.yara_enabled());

        let outcome = engine.scan_bytes(b"hello").await.expect("scan");
        assert_eq!(outcome.verdict, Verdict::Clean);
        assert!(!outcome.is_malware);
        assert!(!outcome.is_pup);
        assert!(outcome.threat_names.is_empty());
        assert_eq!(outcome.engines_run, EnginesRun::default());
    }

    #[tokio::test]
    async fn clamav_unreachable_degrades_to_clean_not_error() {
        let config = ScanEngineConfig {
            clamd_socket: Some("/nonexistent/scan-core-engine-test.sock".to_owned()),
            clamd_tcp: None,
            clamd_timeout: Duration::from_millis(500),
            yara_rules_path: None,
        };
        let engine = ScanEngine::new(config).await.expect("no yara configured");
        assert!(engine.clamav_enabled());

        let outcome = engine.scan_bytes(EICAR).await.expect("scan");
        assert_eq!(outcome.verdict, Verdict::Clean);
        assert!(outcome.clamav_result.is_none());
        assert!(outcome.engines_run.clamav, "clamav was attempted");
    }

    #[tokio::test]
    async fn yara_only_engine_detects_eicar_as_malware() {
        let config = ScanEngineConfig {
            clamd_socket: None,
            clamd_tcp: None,
            clamd_timeout: Duration::from_secs(1),
            yara_rules_path: Some(yara_rules_path()),
        };
        let engine = ScanEngine::new(config).await.expect("corpus loads");
        assert!(engine.yara_enabled());
        assert!(!engine.clamav_enabled());

        let outcome = engine.scan_bytes(EICAR).await.expect("scan");
        assert_eq!(outcome.verdict, Verdict::Infected);
        assert!(outcome.is_malware);
        assert!(!engine.clamav_enabled());
        assert!(!outcome.engines_run.clamav);
        assert!(outcome.engines_run.yara);
        assert!(
            outcome
                .threat_names
                .iter()
                .any(|n| n == "YARA.EICAR_Test_File")
        );
        assert!(
            outcome
                .yara_matches
                .iter()
                .any(|m| m.rule_name == "EICAR_Test_File")
        );
        // ClamAV never ran — its JSON blob must stay absent.
        assert!(outcome.clamav_result.is_none());
    }

    #[tokio::test]
    async fn yara_only_engine_benign_content_is_clean() {
        let config = ScanEngineConfig {
            clamd_socket: None,
            clamd_tcp: None,
            clamd_timeout: Duration::from_secs(1),
            yara_rules_path: Some(yara_rules_path()),
        };
        let engine = ScanEngine::new(config).await.expect("corpus loads");
        let outcome = engine
            .scan_bytes(b"nothing suspicious here")
            .await
            .expect("scan");
        assert_eq!(outcome.verdict, Verdict::Clean);
        assert!(outcome.yara_matches.is_empty());
    }

    #[tokio::test]
    async fn run_yara_false_skips_yara_even_when_configured() {
        let config = ScanEngineConfig {
            clamd_socket: None,
            clamd_tcp: None,
            clamd_timeout: Duration::from_secs(1),
            yara_rules_path: Some(yara_rules_path()),
        };
        let engine = ScanEngine::new(config).await.expect("corpus loads");
        let outcome = engine
            .scan_bytes_with_options(
                EICAR,
                ScanOptions {
                    run_clamav: false,
                    run_yara: false,
                },
            )
            .await
            .expect("scan");
        assert_eq!(outcome.verdict, Verdict::Clean);
        assert!(!outcome.engines_run.yara, "yara must not have run");
        assert!(outcome.yara_matches.is_empty());
    }

    #[tokio::test]
    async fn new_fails_loudly_on_bad_yara_rules_path() {
        let config = ScanEngineConfig {
            clamd_socket: None,
            clamd_tcp: None,
            clamd_timeout: Duration::from_secs(1),
            yara_rules_path: Some("/nonexistent/rules".to_owned()),
        };
        let err = ScanEngine::new(config)
            .await
            .expect_err("bad path must fail construction");
        assert!(matches!(err, ScanEngineError::YaraLoad { .. }));
        assert!(err.to_string().contains("/nonexistent/rules"));
    }

    #[tokio::test]
    async fn clamav_only_fallback_is_infallible_and_disables_yara() {
        let config = ScanEngineConfig {
            clamd_socket: Some("/nonexistent/fallback-test.sock".to_owned()),
            clamd_tcp: None,
            clamd_timeout: Duration::from_millis(200),
            yara_rules_path: Some("/nonexistent/rules".to_owned()),
        };
        // Simulates the "YARA failed to load" recovery path: build the
        // clamav-only engine directly from the same config, ignoring the
        // (still present, but now unused) yara_rules_path.
        let engine = ScanEngine::clamav_only(&config);
        assert!(engine.clamav_enabled());
        assert!(!engine.yara_enabled());
    }

    #[tokio::test]
    async fn tcp_transport_is_selected_when_socket_unset() {
        let config = ScanEngineConfig {
            clamd_socket: None,
            clamd_tcp: Some(("127.0.0.1".to_owned(), 1)),
            clamd_timeout: Duration::from_millis(200),
            yara_rules_path: None,
        };
        let engine = ScanEngine::new(config).await.expect("infallible");
        assert!(engine.clamav_enabled());
        // Port 1 on loopback: nothing listens there — must degrade to clean.
        let outcome = engine.scan_bytes(b"x").await.expect("scan");
        assert_eq!(outcome.verdict, Verdict::Clean);
        assert!(outcome.engines_run.clamav);
    }

    #[tokio::test]
    async fn unix_socket_wins_when_both_transports_configured() {
        let config = ScanEngineConfig {
            clamd_socket: Some("/nonexistent/unix-wins.sock".to_owned()),
            clamd_tcp: Some(("127.0.0.1".to_owned(), 1)),
            clamd_timeout: Duration::from_millis(200),
            yara_rules_path: None,
        };
        let engine = ScanEngine::new(config).await.expect("infallible");
        assert!(engine.clamav_enabled());
        // Both are unreachable, so this only proves resolve_clamd doesn't
        // panic/misconfigure when both are set — the precedence itself is
        // documented behavior, exercised indirectly here.
        let outcome = engine.scan_bytes(b"x").await.expect("scan");
        assert_eq!(outcome.verdict, Verdict::Clean);
    }
}
