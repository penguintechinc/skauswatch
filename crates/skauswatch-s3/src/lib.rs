//! S3/MinIO client construction shared by the scan pipeline. Supports both
//! AWS-native endpoints and MinIO via `S3_ENDPOINT_URL` override with
//! path-style addressing, matching the v1 deployment topology.

use serde::Deserialize;

/// S3 connection settings, from `S3_*` env vars.
#[derive(Debug, Clone, Deserialize)]
pub struct S3Config {
    /// Optional custom endpoint (MinIO); AWS default endpoints when unset.
    #[serde(default)]
    pub endpoint_url: Option<String>,
    /// Region; MinIO accepts any value.
    #[serde(default = "default_region")]
    pub region: String,
    /// Use path-style addressing (required for MinIO).
    #[serde(default = "default_force_path_style")]
    pub force_path_style: bool,
}

fn default_region() -> String {
    "us-east-1".to_owned()
}
fn default_force_path_style() -> bool {
    true
}

impl S3Config {
    /// Loads config from the standard `S3_*` environment variables.
    pub fn from_env() -> Result<Self, skauswatch_common::Error> {
        skauswatch_common::load_config("S3_")
    }
}

/// Builds an S3 client honoring the MinIO endpoint/path-style settings.
/// Credentials resolve through the standard AWS provider chain (env vars,
/// IRSA, profile) — never hardcoded.
pub async fn client(cfg: &S3Config) -> aws_sdk_s3::Client {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(cfg.region.clone()));
    if let Some(endpoint) = &cfg.endpoint_url {
        loader = loader.endpoint_url(endpoint);
    }
    let shared = loader.load().await;
    let s3_cfg = aws_sdk_s3::config::Builder::from(&shared)
        .force_path_style(cfg.force_path_style)
        .build();
    aws_sdk_s3::Client::from_conf(s3_cfg)
}
