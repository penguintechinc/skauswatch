//! The canonical scan verdict shared by every scan-core consumer, promoting
//! the loose `scan_status VARCHAR(20)` string literals (enforced only in
//! Rust today — see `services/s3scan/src/db.rs::scan_status_for`) to a real
//! enum, per the hardening note in `docs/v2-port/v2.1-depgate.md` §3.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A scan outcome, one of the six states s3scan/scanner/DepGate/Sentinel all
/// agree on. `as_str`/`from_str` round-trip the exact string literals
/// s3scan's `scan_status` columns already store (`clean`, `infected`, `pup`,
/// `error`, `skipped`), plus the new `quarantined` state DepGate introduces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No detection from any configured engine.
    Clean,
    /// A malware signature/rule matched.
    Infected,
    /// A potentially-unwanted-program signature/rule matched.
    Pup,
    /// Scanning itself failed (not a content verdict).
    Error,
    /// Scanning was not attempted (e.g. object too large).
    Skipped,
    /// Flagged and held in a quarantine prefix/table pending disposition —
    /// DepGate's addition to the enum (`docs/v2-port/v2.1-depgate.md` §6).
    Quarantined,
}

impl Verdict {
    /// Renders the canonical lowercase string stored in `scan_status`
    /// columns and used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Infected => "infected",
            Verdict::Pup => "pup",
            Verdict::Error => "error",
            Verdict::Skipped => "skipped",
            Verdict::Quarantined => "quarantined",
        }
    }

    /// Derives a verdict from the two booleans every scan engine in this
    /// workspace already reports, with the same infected-over-pup-over-clean
    /// precedence as the pre-extraction `scan_status_for` helper.
    #[must_use]
    pub const fn from_malware_pup(is_malware: bool, is_pup: bool) -> Self {
        if is_malware {
            Verdict::Infected
        } else if is_pup {
            Verdict::Pup
        } else {
            Verdict::Clean
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A string did not match any [`Verdict`] variant.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[error("unrecognized scan verdict: {0:?}")]
pub struct ParseVerdictError(String);

impl FromStr for Verdict {
    type Err = ParseVerdictError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "clean" => Ok(Verdict::Clean),
            "infected" => Ok(Verdict::Infected),
            "pup" => Ok(Verdict::Pup),
            "error" => Ok(Verdict::Error),
            "skipped" => Ok(Verdict::Skipped),
            "quarantined" => Ok(Verdict::Quarantined),
            other => Err(ParseVerdictError(other.to_owned())),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_variant() {
        let all = [
            Verdict::Clean,
            Verdict::Infected,
            Verdict::Pup,
            Verdict::Error,
            Verdict::Skipped,
            Verdict::Quarantined,
        ];
        for v in all {
            let s = v.as_str();
            assert_eq!(s.parse::<Verdict>().expect("round trip"), v);
            assert_eq!(v.to_string(), s);
        }
    }

    #[test]
    fn matches_existing_scan_status_string_literals() {
        // Exact strings `s3scan/src/db.rs::scan_status_for` already writes
        // to `scan_status` columns — must not drift.
        assert_eq!(Verdict::Clean.as_str(), "clean");
        assert_eq!(Verdict::Infected.as_str(), "infected");
        assert_eq!(Verdict::Pup.as_str(), "pup");
    }

    #[test]
    fn from_malware_pup_precedence() {
        assert_eq!(Verdict::from_malware_pup(true, true), Verdict::Infected);
        assert_eq!(Verdict::from_malware_pup(true, false), Verdict::Infected);
        assert_eq!(Verdict::from_malware_pup(false, true), Verdict::Pup);
        assert_eq!(Verdict::from_malware_pup(false, false), Verdict::Clean);
    }

    #[test]
    fn from_str_rejects_unknown_value() {
        let err = "bogus".parse::<Verdict>().expect_err("must reject");
        assert_eq!(err.to_string(), "unrecognized scan verdict: \"bogus\"");
    }

    #[test]
    fn serde_uses_lowercase_variant_names() {
        let json = serde_json::to_string(&Verdict::Quarantined).expect("serialize");
        assert_eq!(json, "\"quarantined\"");
        let back: Verdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, Verdict::Quarantined);
    }
}
