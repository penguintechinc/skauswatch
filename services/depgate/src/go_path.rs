//! Pure Go module proxy (`GOPROXY` protocol) request-path parsing (P4,
//! `docs/v2-port/v2.1-depgate.md` §4/§9). Mirrors `src/npm_path.rs`/
//! `src/oci_path.rs`'s split: axum's wildcard route captures the full
//! `{module}/@v/...` remainder of a `/go/` request as one segment (a Go
//! module path itself contains any number of `/`s — `github.com/user/repo`),
//! and this module does the actual parse. Kept free of any axum/HTTP types
//! so it is trivially unit-testable.
//!
//! Also implements the GOPROXY spec's module-path escaping (`golang.org/x/
//! mod/module` §Escaped paths): every uppercase letter is replaced with `!`
//! followed by its lowercase form, so the proxy protocol's paths are
//! case-insensitive-filesystem-safe. Requests already arrive pre-escaped
//! (the `go` tool escapes before requesting) — DepGate proxies the escaped
//! path straight through to the upstream unchanged; [`unescape_module_path`]
//! is used only to recover a human-readable module name for
//! `depgate_artifacts`/policy purposes.

/// A parsed Go module proxy request, minus the leading `/go/`. Every variant
/// carries the module path EXACTLY as escaped in the request (see module
/// docs) — callers needing the human-readable form use
/// [`unescape_module_path`] separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoRequest<'a> {
    /// `GET /go/{module}/@v/list` — newline-separated known versions.
    List {
        /// Escaped module path.
        module: &'a str,
    },
    /// `GET /go/{module}/@v/{version}.info` — `{Version, Time}` JSON.
    Info {
        /// Escaped module path.
        module: &'a str,
        /// Escaped version.
        version: &'a str,
    },
    /// `GET /go/{module}/@v/{version}.mod` — that version's `go.mod` file.
    Mod {
        /// Escaped module path.
        module: &'a str,
        /// Escaped version.
        version: &'a str,
    },
    /// `GET /go/{module}/@v/{version}.zip` — that version's full source zip.
    Zip {
        /// Escaped module path.
        module: &'a str,
        /// Escaped version.
        version: &'a str,
    },
}

const AT_V_SEP: &str = "/@v/";
const LIST_TAIL: &str = "list";

/// Parses the path remainder after `/go/` into a [`GoRequest`]. Returns
/// `None` for anything this proxy doesn't support (`/@latest`, `/@v/list`
/// with an empty module, a `{version}` file with an unrecognized
/// extension).
#[must_use]
pub fn parse(rest: &str) -> Option<GoRequest<'_>> {
    let idx = rest.find(AT_V_SEP)?;
    let module = &rest[..idx];
    let tail = &rest[idx + AT_V_SEP.len()..];
    if module.is_empty() || tail.is_empty() {
        return None;
    }

    // `AT_V_SEP` ("/@v/") already consumes the slash before "list" -- `tail`
    // here is the bare `"list"`, not `"/list"`, so this is an exact match,
    // not a suffix strip (unlike the `.info`/`.mod`/`.zip` cases below,
    // where the dot genuinely is part of `tail`, not part of the preceding
    // separator).
    if tail == LIST_TAIL {
        return Some(GoRequest::List { module });
    }
    if let Some(version) = tail.strip_suffix(".info") {
        return non_empty(version).map(|version| GoRequest::Info { module, version });
    }
    if let Some(version) = tail.strip_suffix(".mod") {
        return non_empty(version).map(|version| GoRequest::Mod { module, version });
    }
    if let Some(version) = tail.strip_suffix(".zip") {
        return non_empty(version).map(|version| GoRequest::Zip { module, version });
    }
    None
}

fn non_empty(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

/// Escapes a module path per the GOPROXY spec: every uppercase ASCII letter
/// becomes `!` followed by its lowercase form (e.g. `BurntSushi` ->
/// `!burnt!sushi`). Non-uppercase bytes pass through unchanged.
#[must_use]
pub fn escape_module_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Reverses [`escape_module_path`]. `None` for malformed escaping (a
/// trailing bare `!`, or `!` followed by a non-lowercase-letter) — never
/// panics on attacker-influenced input.
#[must_use]
pub fn unescape_module_path(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '!' {
            let next = chars.next()?;
            if !next.is_ascii_lowercase() {
                return None;
            }
            out.push(next.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list_request() {
        assert_eq!(
            parse("github.com/pkg/errors/@v/list"),
            Some(GoRequest::List {
                module: "github.com/pkg/errors"
            })
        );
    }

    #[test]
    fn parses_info_request() {
        assert_eq!(
            parse("github.com/pkg/errors/@v/v0.9.1.info"),
            Some(GoRequest::Info {
                module: "github.com/pkg/errors",
                version: "v0.9.1",
            })
        );
    }

    #[test]
    fn parses_mod_request() {
        assert_eq!(
            parse("github.com/pkg/errors/@v/v0.9.1.mod"),
            Some(GoRequest::Mod {
                module: "github.com/pkg/errors",
                version: "v0.9.1",
            })
        );
    }

    #[test]
    fn parses_zip_request() {
        assert_eq!(
            parse("github.com/pkg/errors/@v/v0.9.1.zip"),
            Some(GoRequest::Zip {
                module: "github.com/pkg/errors",
                version: "v0.9.1",
            })
        );
    }

    #[test]
    fn parses_an_escaped_module_path_verbatim() {
        assert_eq!(
            parse("github.com/!burnt!sushi/toml/@v/v1.3.2.zip"),
            Some(GoRequest::Zip {
                module: "github.com/!burnt!sushi/toml",
                version: "v1.3.2",
            })
        );
    }

    #[test]
    fn rejects_missing_at_v_separator() {
        assert_eq!(parse("github.com/pkg/errors"), None);
    }

    #[test]
    fn rejects_empty_module() {
        assert_eq!(parse("/@v/list"), None);
    }

    #[test]
    fn rejects_unrecognized_extension() {
        assert_eq!(parse("github.com/pkg/errors/@v/v0.9.1.txt"), None);
    }

    #[test]
    fn rejects_empty_version() {
        assert_eq!(parse("github.com/pkg/errors/@v/.zip"), None);
    }

    #[test]
    fn escape_module_path_escapes_every_uppercase_letter() {
        assert_eq!(escape_module_path("BurntSushi"), "!burnt!sushi");
        assert_eq!(
            escape_module_path("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );
    }

    #[test]
    fn escape_module_path_is_a_no_op_for_already_lowercase_paths() {
        assert_eq!(
            escape_module_path("github.com/pkg/errors"),
            "github.com/pkg/errors"
        );
    }

    #[test]
    fn escape_then_unescape_round_trips() {
        for module in [
            "github.com/BurntSushi/toml",
            "github.com/pkg/errors",
            "golang.org/x/mod",
        ] {
            let escaped = escape_module_path(module);
            assert_eq!(unescape_module_path(&escaped).as_deref(), Some(module));
        }
    }

    #[test]
    fn unescape_rejects_a_trailing_bare_bang() {
        assert_eq!(unescape_module_path("burnt!"), None);
    }

    #[test]
    fn unescape_rejects_bang_followed_by_non_lowercase() {
        assert_eq!(unescape_module_path("burnt!S"), None);
        assert_eq!(unescape_module_path("burnt!1"), None);
    }
}
