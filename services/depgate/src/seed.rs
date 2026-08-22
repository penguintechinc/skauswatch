//! `skauswatch-depgate seed` — warm-starts the vetted cache from a seed
//! manifest (`docs/v2-port/v2.1-depgate.md` §2/§9). Pulls, scans, tags, and
//! pins every listed image ahead of demand.

use serde::Deserialize;
use uuid::Uuid;

use crate::scanpipe::ScanPipeline;
use crate::state::AppState;

/// System-attributed tenant for seed-triggered ingestion — no end-user
/// request initiates this, so there is no caller tenant claim to attribute
/// to. Matches the workspace-wide bootstrap-tenant literal seeded by
/// manager's own migrations (`docs/v2-port/tenancy-model.md`).
pub const BOOTSTRAP_TENANT: &str = "00000000-0000-0000-0000-000000000001";

/// One entry in a seed manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct SeedImage {
    /// Repository name (e.g. `library/nginx`).
    pub name: String,
    /// Tag or digest to seed.
    pub reference: String,
}

/// A seed manifest file (see `seeds/penguintech.yaml`).
#[derive(Debug, Clone, Deserialize)]
pub struct SeedManifest {
    /// Images to warm-start.
    pub images: Vec<SeedImage>,
}

impl SeedManifest {
    /// Parses a manifest from its raw YAML contents.
    ///
    /// # Errors
    /// Returns a `serde_yaml::Error` on malformed YAML.
    pub fn parse(raw: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(raw)
    }
}

/// Runs the seed manifest at `manifest_path` against `state`, logging a
/// per-image outcome and continuing past individual failures (one bad
/// upstream image must not abort the whole warm-start run).
///
/// # Errors
/// Returns an error only for a manifest-level failure (file unreadable, not
/// valid YAML) — per-image scan/fetch failures are logged and skipped.
pub async fn run(state: &AppState, manifest_path: &str) -> anyhow::Result<()> {
    let raw = tokio::fs::read_to_string(manifest_path)
        .await
        .map_err(|e| anyhow::anyhow!("read seed manifest {manifest_path}: {e}"))?;
    let manifest = SeedManifest::parse(&raw)
        .map_err(|e| anyhow::anyhow!("parse seed manifest {manifest_path}: {e}"))?;

    let tenant_id: Uuid = BOOTSTRAP_TENANT
        .parse()
        .map_err(|e| anyhow::anyhow!("bootstrap tenant literal is not a valid UUID: {e}"))?;

    let pipeline = ScanPipeline {
        upstream: &state.upstream,
        s3: &state.s3,
        bucket: &state.cfg.cache_bucket,
        cache_prefix: &state.cfg.cache_prefix,
        quarantine_prefix: &state.cfg.quarantine_prefix,
        scan_engine: &state.scan_engine,
        db: &state.db,
        max_artifact_bytes: state.cfg.max_artifact_bytes,
        cache_stats: &state.cache_stats,
    };

    let mut seeded = 0usize;
    let mut failed = 0usize;
    for image in &manifest.images {
        match pipeline
            .seed_manifest(&image.name, &image.reference, tenant_id)
            .await
        {
            Ok(artifact) => {
                seeded += 1;
                tracing::info!(
                    name = %image.name,
                    reference = %image.reference,
                    sha256 = %artifact.sha256,
                    "seeded artifact"
                );
            }
            Err(e) => {
                failed += 1;
                tracing::error!(
                    name = %image.name,
                    reference = %image.reference,
                    error = %e,
                    "seed failed for image"
                );
            }
        }
    }
    tracing::info!(
        seeded,
        failed,
        total = manifest.images.len(),
        "seed run complete"
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn parses_the_shipped_manifest_shape() {
        let raw = "images:\n  - name: library/nginx\n    reference: latest\n  - name: library/redis\n    reference: \"7\"\n";
        let manifest = SeedManifest::parse(raw).expect("parse");
        assert_eq!(manifest.images.len(), 2);
        assert_eq!(manifest.images[0].name, "library/nginx");
        assert_eq!(manifest.images[0].reference, "latest");
        assert_eq!(manifest.images[1].reference, "7");
    }

    #[test]
    fn rejects_malformed_yaml() {
        assert!(SeedManifest::parse("not: [valid").is_err());
    }

    #[test]
    fn bootstrap_tenant_is_a_valid_uuid() {
        assert!(Uuid::parse_str(BOOTSTRAP_TENANT).is_ok());
    }
}
