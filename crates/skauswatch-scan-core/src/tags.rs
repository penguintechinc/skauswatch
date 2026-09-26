//! The tag-set builder: turns a [`ScanOutcome`] into the object-tag schema
//! `s3scan` already writes to S3 objects (`s3scan/src/scan.rs::scan_tags`,
//! itself a port of v1 `S3Tagger.apply_scan_tags`) — `malware`, `pup`,
//! `threat`, `scanTime`, `fileType` — plus `scannerVersion` so a re-scan
//! sweep (`docs/v2-port/v2.1-depgate.md` §6) can tell which engine build
//! produced a given verdict. No AWS SDK dependency here: this crate only
//! builds the tag list, callers (s3scan today; DepGate's registry proxy
//! later) are the ones that actually call `PutObjectTagging`.

use crate::engine::ScanOutcome;

/// This crate's own version, embedded as the `scannerVersion` tag value.
pub const SCANNER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// v1/`s3scan` threat label: `malware`, `pup`, or `clean` — infected takes
/// precedence over pup, matching [`crate::Verdict::from_malware_pup`].
#[must_use]
pub fn threat_label(is_malware: bool, is_pup: bool) -> &'static str {
    if is_malware {
        "malware"
    } else if is_pup {
        "pup"
    } else {
        "clean"
    }
}

/// Builds the tag set for `outcome`, matching `s3scan`'s exact schema plus
/// `scannerVersion`. `scanTime` is `outcome.scan_time_ms` (engine time only,
/// see [`ScanOutcome`] docs) rendered as a decimal string.
#[must_use]
pub fn verdict_tags(outcome: &ScanOutcome) -> Vec<(String, String)> {
    let b = |v: bool| if v { "true" } else { "false" }.to_owned();
    vec![
        ("malware".to_owned(), b(outcome.is_malware)),
        ("pup".to_owned(), b(outcome.is_pup)),
        (
            "threat".to_owned(),
            threat_label(outcome.is_malware, outcome.is_pup).to_owned(),
        ),
        ("scanTime".to_owned(), outcome.scan_time_ms.to_string()),
        ("fileType".to_owned(), outcome.file_type.clone()),
        ("scannerVersion".to_owned(), SCANNER_VERSION.to_owned()),
    ]
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;
    use crate::engine::EnginesRun;
    use crate::hashing::Hashes;
    use crate::verdict::Verdict;

    fn outcome(is_malware: bool, is_pup: bool) -> ScanOutcome {
        ScanOutcome {
            verdict: Verdict::from_malware_pup(is_malware, is_pup),
            is_malware,
            is_pup,
            is_threat: is_malware || is_pup,
            threat_names: Vec::new(),
            file_type: "application/pdf".to_owned(),
            hashes: Hashes::default(),
            clamav_result: None,
            yara_matches: Vec::new(),
            engines_run: EnginesRun::default(),
            scan_time_ms: 1234,
        }
    }

    #[test]
    fn threat_label_precedence() {
        assert_eq!(threat_label(true, true), "malware");
        assert_eq!(threat_label(false, true), "pup");
        assert_eq!(threat_label(false, false), "clean");
    }

    #[test]
    fn tags_shape_matches_s3scan_schema_plus_scanner_version() {
        let tags = verdict_tags(&outcome(false, false));
        assert_eq!(tags.len(), 6);
        assert_eq!(tags[0], ("malware".to_owned(), "false".to_owned()));
        assert_eq!(tags[1], ("pup".to_owned(), "false".to_owned()));
        assert_eq!(tags[2], ("threat".to_owned(), "clean".to_owned()));
        assert_eq!(tags[3], ("scanTime".to_owned(), "1234".to_owned()));
        assert_eq!(
            tags[4],
            ("fileType".to_owned(), "application/pdf".to_owned())
        );
        assert_eq!(tags[5].0, "scannerVersion");
        assert_eq!(tags[5].1, SCANNER_VERSION);
    }

    #[test]
    fn tags_reflect_malware_verdict() {
        let tags = verdict_tags(&outcome(true, false));
        assert_eq!(tags[0], ("malware".to_owned(), "true".to_owned()));
        assert_eq!(tags[2], ("threat".to_owned(), "malware".to_owned()));
    }

    #[test]
    fn tags_reflect_pup_verdict() {
        let tags = verdict_tags(&outcome(false, true));
        assert_eq!(tags[1], ("pup".to_owned(), "true".to_owned()));
        assert_eq!(tags[2], ("threat".to_owned(), "pup".to_owned()));
    }
}
