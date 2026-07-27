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
                                    tracing::error!("ClamAV scan error: {}", e);
                                    (json!({}), 0, Some(e.to_string()))
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
