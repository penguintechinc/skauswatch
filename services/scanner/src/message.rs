//! Stream message types for scanner tasks and results.

use serde::{Deserialize, Serialize};
use skauswatch_streams::EntryFields;

/// Scanner task message from the manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ScannerTask {
    /// Unique job ID.
    pub job_id: String,
    /// Target (URL/host/file path).
    pub target: String,
    /// Scan type: "yara" | "clamav" | "nuclei" | "zap" | "openvas".
    pub scan_type: String,
    /// File path (for local file scans) or URL (for network scans).
    pub file_path: Option<String>,
    /// Additional scan parameters.
    pub params: serde_json::Value,
    /// Timestamp of task submission.
    pub submitted_at: String,
}

/// Scanner result message to publish onward.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerResult {
    /// Unique job ID (matches the task).
    pub job_id: String,
    /// Scan type.
    pub scan_type: String,
    /// Number of findings/detections.
    pub findings_count: usize,
    /// Serialized findings (JSON).
    pub findings: serde_json::Value,
    /// Scan duration in seconds.
    pub duration_sec: f64,
    /// Status: "success" | "error".
    pub status: String,
    /// Error message if status is "error".
    pub error_message: Option<String>,
    /// Result timestamp.
    pub timestamp: String,
}

impl ScannerResult {
    /// Converts the result into stream entry fields for publishing.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_entry_fields(self) -> EntryFields {
        vec![
            ("job_id".into(), self.job_id),
            ("scan_type".into(), self.scan_type),
            ("findings_count".into(), self.findings_count.to_string()),
            (
                "findings".into(),
                serde_json::to_string(&self.findings).unwrap_or_default(),
            ),
            ("duration_sec".into(), self.duration_sec.to_string()),
            ("status".into(), self.status),
            (
                "error_message".into(),
                self.error_message.unwrap_or_default(),
            ),
            ("timestamp".into(), self.timestamp),
        ]
    }
}
