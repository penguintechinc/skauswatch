//! `YaraScanner` moved to `skauswatch-scan-core::yara` (shared with
//! `s3scan`, which previously had a `yara_enabled` config flag plumbed
//! through end-to-end but never invoked it) — see
//! `docs/v2-port/v2.1-depgate.md` §3. Re-exported here so every existing
//! `crate::yara::YaraScanner` call site in this crate (`handler.rs`,
//! `scan.rs`) keeps working unchanged; the implementation and its test
//! suite (corpus load, EICAR match, benign no-false-positive, single-file
//! vs. directory loading, missing/invalid-rules error paths) now live in
//! `skauswatch-scan-core` instead of being duplicated here.

pub use skauswatch_scan_core::YaraScanner;
