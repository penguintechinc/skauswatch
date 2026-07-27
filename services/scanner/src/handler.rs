//! Stream consumer handler for scanner tasks.

use crate::config::WorkerConfig;
use crate::message::ScannerResult;
use crate::yara::YaraScanner;
use skauswatch_streams::{
    HandlerError, STREAM_SCANNER_RESULTS, StreamEntry, StreamHandler, StreamProducer,
};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// Handler for scanner stream entries.
pub struct ScannerHandler {
    pool: PgPool,
    producer: StreamProducer,
    config: WorkerConfig,
    yara_scanner: Option<Arc<YaraScanner>>,
}

impl ScannerHandler {
    /// Creates a new scanner handler.
    pub fn new(pool: PgPool, producer: StreamProducer, config: WorkerConfig) -> Self {
        let yara_scanner = if config.yara_enabled {
            match futures::executor::block_on(YaraScanner::load(&config.yara_rules_path)) {
                Ok(scanner) => {
                    info!("YARA scanner loaded successfully");
                    Some(Arc::new(scanner))
                }
                Err(e) => {
                    error!("failed to load YARA scanner: {}", e);
                    None
                }
            }
        } else {
            info!("YARA scanning disabled");
            None
        };

        Self {
            pool,
            producer,
            config,
            yara_scanner,
        }
    }
}

#[async_trait::async_trait]
impl StreamHandler for ScannerHandler {
    async fn handle(&self, entry: &StreamEntry) -> Result<(), HandlerError> {
        let fields = &entry.fields;

        // Parse task message from stream entry.
        let job_id = fields.get("job_id").map(|s| s.to_string());
        let scan_type = fields.get("scan_type").map(|s| s.to_string());
        let target = fields.get("target").map(|s| s.to_string());
        let file_path = fields.get("file_path").map(|s| s.to_string());
        let params_json = fields
            .get("params")
            .cloned()
            .unwrap_or_else(|| "{}".to_string());
        let params: serde_json::Value =
            serde_json::from_str(&params_json).unwrap_or_else(|_| serde_json::json!({}));

        let job_id = match job_id {
            Some(id) if !id.is_empty() => id,
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing or empty job_id",
                )));
            }
        };

        let scan_type = match scan_type {
            Some(st) if !st.is_empty() => st,
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing or empty scan_type",
                )));
            }
        };

        let target = match target {
            Some(t) if !t.is_empty() => t,
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing or empty target",
                )));
            }
        };

        info!(job_id = %job_id, scan_type = %scan_type, target = %target, "processing scanner task");

        // Execute the appropriate scan.
        let clamav_timeout = Duration::from_secs(self.config.clamav_timeout_sec);
        let result = match crate::scan::execute_scan(
            &scan_type,
            &target,
            file_path.as_deref(),
            &params,
            self.yara_scanner.as_deref(),
            if self.config.clamav_enabled {
                Some(&self.config.clamav_host)
            } else {
                None
            },
            if self.config.clamav_enabled {
                Some(self.config.clamav_port)
            } else {
                None
            },
            clamav_timeout,
        )
        .await
        {
            Ok(mut r) => {
                r.job_id = job_id.clone();
                r
            }
            Err(e) => {
                error!(job_id = %job_id, error = %e, "scan execution failed");
                ScannerResult {
                    job_id: job_id.clone(),
                    scan_type: scan_type.clone(),
                    findings_count: 0,
                    findings: serde_json::json!({}),
                    duration_sec: 0.0,
                    status: "error".to_string(),
                    error_message: Some(e.to_string()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }
            }
        };

        // Write result to database.
        if let Err(e) = crate::db::insert_scan_result(
            &self.pool,
            &result.job_id,
            &result.scan_type,
            &target,
            result.findings_count as i32,
            &serde_json::to_string(&result.findings).unwrap_or_default(),
            result.duration_sec,
            &result.status,
            result.error_message.as_deref(),
        )
        .await
        {
            error!(job_id = %job_id, error = %e, "failed to write result to database");
            // Don't fail the message — it's already computed; ack it.
        }

        // Publish result to onward stream.
        if let Err(e) = self
            .producer
            .publish(STREAM_SCANNER_RESULTS, result.to_entry_fields())
            .await
        {
            error!(job_id = %job_id, error = %e, "failed to publish result to stream");
            // Don't fail — result is in DB, stream publish is nice-to-have.
        } else {
            info!(job_id = %job_id, "result published to scanner results stream");
        }

        metrics::counter!("scanner_tasks_processed_total", "scan_type" => scan_type).increment(1);
        Ok(())
    }
}
