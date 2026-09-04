//! Runtime configuration, preserving the v1 `LogReceiverConfig` env-var names,
//! defaults, and validation.
//!
//! Only the variables the ported HTTP→OpenSearch path consumes are read here:
//! `OPENSEARCH_URL`, `LOG_RETENTION_DAYS`, `HTTP_PORT`. The v1 variables for the
//! deferred sinks/sources — `S3_ENDPOINT_URL`, `S3_REGION`, `S3_ACCESS_KEY`,
//! `S3_SECRET_KEY`, `S3_SIEM_BUCKET`, `REDIS_URL`, `SYSLOG_UDP_PORT` — remain
//! valid in the environment and are simply ignored until those paths land (see
//! docs/v2-port/logs-contract.md). Present-but-unused env vars do not
//! affect startup.

/// Default OpenSearch endpoint (v1 default).
const DEFAULT_OPENSEARCH_URL: &str = "http://localhost:9200";
/// Default log retention in days (v1 default).
const DEFAULT_RETENTION_DAYS: i64 = 90;
/// Default HTTP ingest port (v1 default; the `LOGS_URL` the manager
/// proxies to is `http://logs:5010`).
const DEFAULT_HTTP_PORT: u16 = 5010;

/// Loaded configuration for the ported ingest path.
#[derive(Debug, Clone)]
pub struct Config {
    /// OpenSearch base URL (`OPENSEARCH_URL`).
    pub opensearch_url: String,
    /// Retention window in days (`LOG_RETENTION_DAYS`, validated 1..=400).
    pub log_retention_days: i64,
    /// HTTP ingest port (`HTTP_PORT`) serving `/ingest`, `/healthz`, and
    /// `/readyz`.
    pub http_port: u16,
}

impl Config {
    /// Loads configuration from the environment with the v1 defaults.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when `LOG_RETENTION_DAYS`/`HTTP_PORT` are not
    /// integers (v1 `int(...)` raised) or when retention is outside 1..=400
    /// (v1 `__post_init__` raised `ValueError`).
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_values(
            std::env::var("OPENSEARCH_URL").ok().as_deref(),
            std::env::var("LOG_RETENTION_DAYS").ok().as_deref(),
            std::env::var("HTTP_PORT").ok().as_deref(),
        )
    }

    /// Pure constructor mirroring v1 `LogReceiverConfig` field resolution;
    /// factored out so the parsing/validation rules are unit-testable.
    fn from_values(
        opensearch_url: Option<&str>,
        retention_days: Option<&str>,
        http_port: Option<&str>,
    ) -> Result<Self, ConfigError> {
        let opensearch_url = opensearch_url
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_OPENSEARCH_URL)
            .to_owned();

        let log_retention_days = match retention_days.filter(|s| !s.is_empty()) {
            None => DEFAULT_RETENTION_DAYS,
            Some(raw) => parse_py_int(raw).ok_or(ConfigError::Int("LOG_RETENTION_DAYS"))?,
        };
        if !(1..=400).contains(&log_retention_days) {
            return Err(ConfigError::Retention(log_retention_days));
        }

        let http_port = match http_port.filter(|s| !s.is_empty()) {
            None => DEFAULT_HTTP_PORT,
            Some(raw) => {
                let n = parse_py_int(raw).ok_or(ConfigError::Int("HTTP_PORT"))?;
                u16::try_from(n).map_err(|_| ConfigError::Int("HTTP_PORT"))?
            }
        };

        Ok(Self {
            opensearch_url,
            log_retention_days,
            http_port,
        })
    }
}

/// Approximates Python `int(str)`: surrounding whitespace tolerated, optional
/// sign, base-10 only.
fn parse_py_int(s: &str) -> Option<i64> {
    s.trim().parse::<i64>().ok()
}

/// Errors raised while loading [`Config`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A numeric env var was not a base-10 integer (v1 `int(...)` raised).
    #[error("{0} must be an integer")]
    Int(&'static str),
    /// Retention was outside the v1-permitted 1..=400 range.
    #[error("log_retention_days must be 1–400, got {0}")]
    Retention(i64),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_v1() {
        let cfg = Config::from_values(None, None, None).unwrap();
        assert_eq!(cfg.opensearch_url, "http://localhost:9200");
        assert_eq!(cfg.log_retention_days, 90);
        assert_eq!(cfg.http_port, 5010);
    }

    #[test]
    fn values_are_parsed() {
        let cfg = Config::from_values(Some("http://os:9200"), Some("30"), Some("5010")).unwrap();
        assert_eq!(cfg.opensearch_url, "http://os:9200");
        assert_eq!(cfg.log_retention_days, 30);
        assert_eq!(cfg.http_port, 5010);
    }

    #[test]
    fn retention_bounds_match_v1() {
        assert!(Config::from_values(None, Some("1"), None).is_ok());
        assert!(Config::from_values(None, Some("400"), None).is_ok());
        assert!(matches!(
            Config::from_values(None, Some("0"), None),
            Err(ConfigError::Retention(0))
        ));
        assert!(matches!(
            Config::from_values(None, Some("401"), None),
            Err(ConfigError::Retention(401))
        ));
    }

    #[test]
    fn unparsable_ints_are_errors() {
        assert!(matches!(
            Config::from_values(None, Some("abc"), None),
            Err(ConfigError::Int("LOG_RETENTION_DAYS"))
        ));
        assert!(matches!(
            Config::from_values(None, None, Some("notaport")),
            Err(ConfigError::Int("HTTP_PORT"))
        ));
        assert!(matches!(
            Config::from_values(None, None, Some("70000")),
            Err(ConfigError::Int("HTTP_PORT"))
        ));
    }
}
