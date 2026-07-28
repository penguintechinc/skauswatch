//! Scan orchestration — dispatches to YARA, ClamAV, or ASM tools.

use crate::message::ScannerResult;
use chrono::Utc;
use serde_json::json;
use std::time::Instant;

/// Executes the appropriate scan based on scan_type.
#[allow(clippy::too_many_arguments)]
pub async fn execute_scan(
    scan_type: &str,
    target: &str,
    file_path: Option<&str>,
    _params: &serde_json::Value,
    yara_scanner: Option<&crate::yara::YaraScanner>,
    clamav_host: Option<&str>,
    clamav_port: Option<u16>,
    clamav_timeout: std::time::Duration,
) -> anyhow::Result<ScannerResult> {
    let start = Instant::now();

    let (findings, findings_count, error_message) = match scan_type {
        "yara" => match yara_scanner {
            Some(scanner) => {
                if let Some(fpath) = file_path {
                    match scanner.scan_file(fpath).await {
                        Ok(matches) => {
                            let count = matches.len();
                            (json!({"matches": matches}), count, None)
                        }
                        Err(e) => {
                            tracing::error!("YARA scan error: {}", e);
                            (json!({}), 0, Some(e.to_string()))
                        }
                    }
                } else {
                    let err_msg = "no file_path provided for YARA scan".to_string();
                    (json!({}), 0, Some(err_msg))
                }
            }
            None => {
                let err_msg = "YARA scanner not initialized".to_string();
                (json!({}), 0, Some(err_msg))
            }
        },
        "clamav" => {
            if let (Some(host), Some(port)) = (clamav_host, clamav_port) {
                if let Some(fpath) = file_path {
                    match tokio::fs::read(fpath).await {
                        Ok(data) => {
                            match crate::clamav::scan_bytes(host, port, clamav_timeout, &data).await
                            {
                                Ok(verdict) => {
                                    let count = if verdict.is_malware { 1 } else { 0 };
                                    (
                                        json!({
                                            "is_malware": verdict.is_malware,
                                            "is_pup": verdict.is_pup,
                                            "threat_names": verdict.threat_names,
                                        }),
                                        count,
                                        None,
                                    )
                                }
                                Err(e) => {
                                    // Degrade to "clean" when clamd is
                                    // unreachable/erroring — matches the
                                    // documented contract in
                                    // `crate::clamav` (v1 parity: v1 set
                                    // `clamav_scanner = None` and skipped
                                    // scanning when clamd was down) and the
                                    // sibling `s3scan` service's identical
                                    // handling. Treating this as a
                                    // scan-level `status: "error"` (as
                                    // written before this fix) diverged
                                    // from that contract.
                                    tracing::debug!(error = %e, "ClamAV unavailable — scanning skipped (clean)");
                                    (
                                        json!({
                                            "is_malware": false,
                                            "is_pup": false,
                                            "threat_names": Vec::<String>::new(),
                                        }),
                                        0,
                                        None,
                                    )
                                }
                            }
                        }
                        Err(e) => {
                            let err = format!("failed to read file: {}", e);
                            (json!({}), 0, Some(err))
                        }
                    }
                } else {
                    let err = "no file_path provided for ClamAV scan".to_string();
                    (json!({}), 0, Some(err))
                }
            } else {
                let err = "ClamAV not configured".to_string();
                (json!({}), 0, Some(err))
            }
        }
        "nuclei" | "zap" | "openvas" => {
            // ASM tool orchestration — placeholder for Phase 3
            let err = format!("{} scanning not yet implemented", scan_type);
            (json!({}), 0, Some(err))
        }
        _ => {
            let err = format!("unknown scan type: {}", scan_type);
            (json!({}), 0, Some(err))
        }
    };

    let duration = start.elapsed().as_secs_f64();
    let status = if error_message.is_none() {
        "success"
    } else {
        "error"
    };

    Ok(ScannerResult {
        job_id: target.to_string(), // placeholder — will be set by handler
        scan_type: scan_type.to_string(),
        findings_count,
        findings,
        duration_sec: duration,
        status: status.to_string(),
        error_message,
        timestamp: Utc::now().to_rfc3339(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;
    use crate::clamav::spawn_fake_clamd;
    use crate::yara::YaraScanner;
    use std::time::Duration;

    fn yara_rules_path() -> &'static str {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/yara_rules")
    }

    async fn loaded_yara_scanner() -> YaraScanner {
        YaraScanner::load(yara_rules_path())
            .await
            .expect("yara corpus loads")
    }

    fn temp_file_with(contents: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        std::io::Write::write_all(&mut f, contents).expect("write tempfile");
        f
    }

    #[tokio::test]
    async fn yara_scan_matches_eicar() {
        let scanner = loaded_yara_scanner().await;
        const EICAR: &[u8] =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let f = temp_file_with(EICAR);
        let path = f.path().to_str().expect("utf8 path").to_owned();

        let result = execute_scan(
            "yara",
            "target",
            Some(&path),
            &json!({}),
            Some(&scanner),
            None,
            None,
            Duration::from_secs(1),
        )
        .await
        .expect("execute_scan ok");

        assert_eq!(result.status, "success");
        assert_eq!(result.scan_type, "yara");
        assert!(result.findings_count >= 1);
        assert!(result.error_message.is_none());
    }

    #[tokio::test]
    async fn yara_scan_benign_content_has_no_findings() {
        let scanner = loaded_yara_scanner().await;
        let f = temp_file_with(b"nothing malicious in this plain text file at all");
        let path = f.path().to_str().expect("utf8 path").to_owned();

        let result = execute_scan(
            "yara",
            "target",
            Some(&path),
            &json!({}),
            Some(&scanner),
            None,
            None,
            Duration::from_secs(1),
        )
        .await
        .expect("execute_scan ok");

        assert_eq!(result.status, "success");
        assert_eq!(result.findings_count, 0);
    }

    #[tokio::test]
    async fn yara_scan_without_file_path_errors() {
        let scanner = loaded_yara_scanner().await;
        let result = execute_scan(
            "yara",
            "target",
            None,
            &json!({}),
            Some(&scanner),
            None,
            None,
            Duration::from_secs(1),
        )
        .await
        .expect("execute_scan ok even on scan-level failure");
        assert_eq!(result.status, "error");
        assert_eq!(result.findings_count, 0);
        assert_eq!(
            result.error_message.as_deref(),
            Some("no file_path provided for YARA scan")
        );
    }

    #[tokio::test]
    async fn yara_scan_without_scanner_errors() {
        let result = execute_scan(
            "yara",
            "target",
            Some("/tmp/whatever"),
            &json!({}),
            None,
            None,
            None,
            Duration::from_secs(1),
        )
        .await
        .expect("execute_scan ok");
        assert_eq!(result.status, "error");
        assert_eq!(
            result.error_message.as_deref(),
            Some("YARA scanner not initialized")
        );
    }

    #[tokio::test]
    async fn clamav_scan_clean_verdict_is_success() {
        let addr = spawn_fake_clamd(b"stream: OK\0").await;
        let f = temp_file_with(b"benign content");
        let path = f.path().to_str().expect("utf8 path").to_owned();

        let result = execute_scan(
            "clamav",
            "target",
            Some(&path),
            &json!({}),
            None,
            Some(&addr.ip().to_string()),
            Some(addr.port()),
            Duration::from_secs(2),
        )
        .await
        .expect("execute_scan ok");

        assert_eq!(result.status, "success");
        assert_eq!(result.findings_count, 0);
        assert_eq!(result.findings["is_malware"].as_bool(), Some(false));
    }

    #[tokio::test]
    async fn clamav_scan_found_verdict_reports_one_finding() {
        let addr = spawn_fake_clamd(b"stream: Win.Test.EICAR_HDB-1 FOUND\0").await;
        let f = temp_file_with(b"eicar-ish payload");
        let path = f.path().to_str().expect("utf8 path").to_owned();

        let result = execute_scan(
            "clamav",
            "target",
            Some(&path),
            &json!({}),
            None,
            Some(&addr.ip().to_string()),
            Some(addr.port()),
            Duration::from_secs(2),
        )
        .await
        .expect("execute_scan ok");

        assert_eq!(result.status, "success");
        assert_eq!(result.findings_count, 1);
        assert_eq!(result.findings["is_malware"].as_bool(), Some(true));
    }

    #[tokio::test]
    async fn clamav_scan_unreachable_daemon_degrades_to_clean() {
        // Regression for the parity bug fixed alongside this test suite:
        // an unreachable clamd must produce a clean "success" verdict, not
        // a scan-level "error" (see `crate::clamav` module doc +
        // `services/s3scan/src/clamav.rs`'s identical handling).
        let f = temp_file_with(b"whatever");
        let path = f.path().to_str().expect("utf8 path").to_owned();

        let result = execute_scan(
            "clamav",
            "target",
            Some(&path),
            &json!({}),
            None,
            Some("127.0.0.1"),
            Some(1), // nothing listens on this privileged port
            Duration::from_millis(500),
        )
        .await
        .expect("execute_scan ok");

        assert_eq!(result.status, "success");
        assert_eq!(result.findings_count, 0);
        assert!(result.error_message.is_none());
        assert_eq!(result.findings["is_malware"].as_bool(), Some(false));
    }

    #[tokio::test]
    async fn clamav_scan_without_file_path_errors() {
        let result = execute_scan(
            "clamav",
            "target",
            None,
            &json!({}),
            None,
            Some("127.0.0.1"),
            Some(3310),
            Duration::from_secs(1),
        )
        .await
        .expect("execute_scan ok");
        assert_eq!(result.status, "error");
        assert_eq!(
            result.error_message.as_deref(),
            Some("no file_path provided for ClamAV scan")
        );
    }

    #[tokio::test]
    async fn clamav_scan_missing_host_config_errors() {
        let result = execute_scan(
            "clamav",
            "target",
            Some("/tmp/x"),
            &json!({}),
            None,
            None,
            None,
            Duration::from_secs(1),
        )
        .await
        .expect("execute_scan ok");
        assert_eq!(result.status, "error");
        assert_eq!(
            result.error_message.as_deref(),
            Some("ClamAV not configured")
        );
    }

    #[tokio::test]
    async fn clamav_scan_unreadable_file_errors() {
        let result = execute_scan(
            "clamav",
            "target",
            Some("/nonexistent/path/to/file"),
            &json!({}),
            None,
            Some("127.0.0.1"),
            Some(3310),
            Duration::from_secs(1),
        )
        .await
        .expect("execute_scan ok");
        assert_eq!(result.status, "error");
        let msg = result.error_message.expect("error message present");
        assert!(msg.starts_with("failed to read file:"));
    }

    #[tokio::test]
    async fn asm_scan_types_report_not_yet_implemented() {
        for scan_type in ["nuclei", "zap", "openvas"] {
            let result = execute_scan(
                scan_type,
                "target",
                None,
                &json!({}),
                None,
                None,
                None,
                Duration::from_secs(1),
            )
            .await
            .expect("execute_scan ok");
            assert_eq!(result.status, "error");
            assert_eq!(
                result.error_message,
                Some(format!("{scan_type} scanning not yet implemented"))
            );
        }
    }

    #[tokio::test]
    async fn unknown_scan_type_reports_error() {
        let result = execute_scan(
            "bogus",
            "target",
            None,
            &json!({}),
            None,
            None,
            None,
            Duration::from_secs(1),
        )
        .await
        .expect("execute_scan ok");
        assert_eq!(result.status, "error");
        assert_eq!(
            result.error_message.as_deref(),
            Some("unknown scan type: bogus")
        );
    }

    #[tokio::test]
    async fn result_job_id_is_target_placeholder_until_handler_overwrites_it() {
        // `execute_scan` stamps `job_id = target` as a placeholder; the
        // real job id is set by the caller (`ScannerHandler::handle`)
        // afterward — see handler.rs.
        let result = execute_scan(
            "bogus",
            "the-target",
            None,
            &json!({}),
            None,
            None,
            None,
            Duration::from_secs(1),
        )
        .await
        .expect("execute_scan ok");
        assert_eq!(result.job_id, "the-target");
    }
}
