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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    fn sample(error_message: Option<&str>) -> ScannerResult {
        ScannerResult {
            job_id: "job-1".to_owned(),
            scan_type: "yara".to_owned(),
            findings_count: 2,
            findings: serde_json::json!({"matches": ["rule_a"]}),
            duration_sec: 1.25,
            status: "success".to_owned(),
            error_message: error_message.map(str::to_owned),
            timestamp: "2026-07-28T00:00:00+00:00".to_owned(),
        }
    }

    #[test]
    fn to_entry_fields_preserves_order_and_values() {
        let fields = sample(None).to_entry_fields();
        assert_eq!(
            fields,
            vec![
                ("job_id".to_owned(), "job-1".to_owned()),
                ("scan_type".to_owned(), "yara".to_owned()),
                ("findings_count".to_owned(), "2".to_owned()),
                (
                    "findings".to_owned(),
                    serde_json::to_string(&serde_json::json!({"matches": ["rule_a"]}))
                        .expect("serialize")
                ),
                ("duration_sec".to_owned(), "1.25".to_owned()),
                ("status".to_owned(), "success".to_owned()),
                ("error_message".to_owned(), String::new()),
                (
                    "timestamp".to_owned(),
                    "2026-07-28T00:00:00+00:00".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn to_entry_fields_renders_some_error_message_verbatim() {
        let fields = sample(Some("boom")).to_entry_fields();
        let (_, error_field) = fields
            .into_iter()
            .find(|(k, _)| k == "error_message")
            .expect("error_message field present");
        assert_eq!(error_field, "boom");
    }

    #[test]
    fn scanner_task_roundtrips_through_json() {
        let task = ScannerTask {
            job_id: "job-2".to_owned(),
            target: "/tmp/file".to_owned(),
            scan_type: "clamav".to_owned(),
            file_path: Some("/tmp/file".to_owned()),
            params: serde_json::json!({}),
            submitted_at: "2026-07-28T00:00:00+00:00".to_owned(),
        };
        let encoded = serde_json::to_string(&task).expect("encode");
        let decoded: ScannerTask = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded.job_id, "job-2");
        assert_eq!(decoded.scan_type, "clamav");
        assert_eq!(decoded.file_path.as_deref(), Some("/tmp/file"));
    }
}
