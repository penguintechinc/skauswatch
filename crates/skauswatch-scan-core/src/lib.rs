//! Shared, byte-oriented malware-scan engine: ClamAV (INSTREAM, Unix socket
//! or TCP) + YARA-X, run together or independently, plus the hashing/typing
//! primitives and S3-tag-set builder every consumer needs. Extracted so
//! `services/s3scan` and `services/scanner` stop maintaining parallel
//! copies, and so DepGate/Sentinel (`docs/v2-port/v2.1-depgate.md`) get a
//! ready-made foundation instead of a third one.
//!
//! Recon at extraction time (release/v2.0.x): `s3scan` ran ClamAV only via
//! `clamav.rs::scan_bytes` over a Unix socket, with a `yara_enabled` config
//! flag plumbed through end-to-end but never invoked; `scanner` had the only
//! working YARA-X integration (`yara.rs`) plus its own TCP-based ClamAV
//! client. Both sets of scan primitives were already byte-oriented and
//! S3/stream-agnostic — this crate is that code, unified, with a real
//! [`Verdict`] enum in place of ad hoc string literals.
//!
//! No AWS SDK dependency, no database dependency: this crate scans bytes and
//! builds a tag list. Callers own persistence and object storage.

pub mod clamav;
pub mod engine;
pub mod hashing;
pub mod tags;
pub mod verdict;
pub mod yara;

pub use clamav::{ClamError, ClamVerdict, ClamdTransport};
pub use engine::{
    EnginesRun, ScanEngine, ScanEngineConfig, ScanEngineError, ScanError, ScanOptions, ScanOutcome,
};
pub use hashing::{Hashes, UNKNOWN_MIME, compute_hashes, detect_file_type};
pub use tags::{SCANNER_VERSION, threat_label, verdict_tags};
pub use verdict::{ParseVerdictError, Verdict};
pub use yara::{YaraMatch, YaraScanner};
