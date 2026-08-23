//! Pure npm registry request-path parsing (P2, `docs/v2-port/v2.1-depgate.md`
//! §4). Mirrors `src/oci_path.rs`'s split: axum's wildcard route captures the
//! full remainder after `/npm/` as one segment (a scoped package name itself
//! contains a `/` — `@scope/name` — so it cannot be a single path
//! parameter), and this module does the actual parse. Kept free of any
//! axum/HTTP types so it is trivially unit-testable.

/// A parsed npm registry request, minus the leading `/npm/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NpmRequest<'a> {
    /// `GET /npm/{package}` or `GET /npm/@{scope}/{package}` — the
    /// packument (package metadata document).
    Packument {
        /// Package name, e.g. `left-pad` or `@types/node`.
        name: &'a str,
    },
    /// `GET /npm/{package}/-/{filename}.tgz` (+ scoped form) — the tarball.
    Tarball {
        /// Package name.
        name: &'a str,
        /// Tarball filename (e.g. `left-pad-1.3.0.tgz`).
        filename: &'a str,
    },
}

const TARBALL_SEP: &str = "/-/";

/// Parses the path remainder after `/npm/` into an [`NpmRequest`]. Returns
/// `None` for an empty name or a malformed tarball path (missing filename).
#[must_use]
pub fn parse(rest: &str) -> Option<NpmRequest<'_>> {
    if let Some(idx) = rest.find(TARBALL_SEP) {
        let name = &rest[..idx];
        let filename = &rest[idx + TARBALL_SEP.len()..];
        return match (non_empty(name), non_empty(filename)) {
            (Some(name), Some(filename)) => Some(NpmRequest::Tarball { name, filename }),
            _ => None,
        };
    }
    non_empty(rest).map(|name| NpmRequest::Packument { name })
}

fn non_empty(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unscoped_packument() {
        assert_eq!(
            parse("left-pad"),
            Some(NpmRequest::Packument { name: "left-pad" })
        );
    }

    #[test]
    fn parses_scoped_packument() {
        assert_eq!(
            parse("@types/node"),
            Some(NpmRequest::Packument {
                name: "@types/node"
            })
        );
    }

    #[test]
    fn parses_unscoped_tarball() {
        assert_eq!(
            parse("left-pad/-/left-pad-1.3.0.tgz"),
            Some(NpmRequest::Tarball {
                name: "left-pad",
                filename: "left-pad-1.3.0.tgz",
            })
        );
    }

    #[test]
    fn parses_scoped_tarball() {
        assert_eq!(
            parse("@types/node/-/node-20.0.0.tgz"),
            Some(NpmRequest::Tarball {
                name: "@types/node",
                filename: "node-20.0.0.tgz",
            })
        );
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(parse(""), None);
    }

    #[test]
    fn rejects_tarball_with_missing_filename() {
        assert_eq!(parse("left-pad/-/"), None);
    }

    #[test]
    fn rejects_tarball_with_missing_name() {
        assert_eq!(parse("/-/left-pad-1.3.0.tgz"), None);
    }
}
