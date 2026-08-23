//! Minimal, formatting-preserving dependency-version edits for CodeScan
//! Sentinel's grouped auto-fix (P4, docs/v2-port/v2.1-codescan-sentinel.md
//! §7). Reuses `license_scan`'s per-ecosystem line parsers to *find* the
//! declaration, then rewrites only the version substring of that one
//! line — no reserialization of the file, so indentation, key order,
//! comments, and every other dependency are untouched byte-for-byte.
//!
//! A version specifier that isn't a single, unambiguous pinned/ranged
//! version (a compound range, a workspace/git/path dependency, an npm
//! `workspace:`/`file:` protocol) is deliberately left alone — [`EditOutcome::Skipped`]
//! carries a human-readable reason rather than guessing at a rewrite that
//! could silently produce an invalid or wrong manifest.

use crate::license_scan::{self, Ecosystem};

/// Result of attempting to bump one dependency's version within a whole
/// manifest file's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditOutcome {
    /// The full new file content, with only the target dependency's
    /// version substring changed.
    Edited(String),
    /// Left untouched — the reason is surfaced to the caller
    /// (`fix.rs`) to record against the finding (spec: "skip ... with a
    /// recorded reason rather than guessing").
    Skipped(String),
}

/// Rejoins `lines` with `\n`, preserving the original content's trailing
/// newline (or lack of one) — `str::lines` strips line terminators, so this
/// is the one place that has to put the convention back.
fn reconstruct(original: &str, lines: Vec<String>) -> String {
    let mut out = lines.join("\n");
    if original.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Attempts to bump `package_name` to `new_version` within `content`
/// (`file_name`'s basename determines which ecosystem's line grammar
/// applies — same dispatch as `sentinel::extract_manifest_dependencies`).
pub fn edit_dependency_version(
    file_name: &str,
    content: &str,
    package_name: &str,
    new_version: &str,
) -> EditOutcome {
    let Some(eco) = license_scan::ecosystem_for_file(file_name) else {
        return EditOutcome::Skipped(format!("unrecognized manifest file: {file_name}"));
    };
    match eco {
        Ecosystem::Npm => edit_npm(content, package_name, new_version),
        Ecosystem::PyPi => edit_pypi(content, package_name, new_version),
        Ecosystem::Crates => edit_cargo(content, package_name, new_version),
        Ecosystem::Go => edit_go_mod(content, package_name, new_version),
    }
}

/// Computes the replacement value for an npm version string, or `None` when
/// it isn't a single simple pinned/ranged semver (a `workspace:`/`file:`
/// protocol, a compound range with a space or `||`, or no digit at all —
/// e.g. `"*"`/`"latest"`).
fn npm_bump(val: &str, new_version: &str) -> Option<String> {
    if val.starts_with("workspace:") || val.starts_with("file:") {
        return None;
    }
    if val.contains(' ') || val.contains("||") {
        return None;
    }
    let prefix_len = val.find(|c: char| c.is_ascii_digit())?;
    let prefix = &val[..prefix_len];
    if !prefix
        .chars()
        .all(|c| matches!(c, '^' | '~' | '=' | '>' | '<'))
    {
        return None;
    }
    Some(format!("{prefix}{new_version}"))
}

fn edit_npm(content: &str, package_name: &str, new_version: &str) -> EditOutcome {
    let mut out = Vec::with_capacity(content.lines().count());
    let mut found = false;
    let mut skip_reason = None;
    for line in content.lines() {
        if !found
            && let Some((name, val)) = license_scan::parse_npm_dep_line(line)
            && name == package_name
        {
            found = true;
            match npm_bump(&val, new_version) {
                Some(new_val) => {
                    let old_quoted = format!("\"{val}\"");
                    let new_quoted = format!("\"{new_val}\"");
                    out.push(line.replacen(&old_quoted, &new_quoted, 1));
                    continue;
                }
                None => {
                    skip_reason = Some(format!(
                        "npm: version spec '{val}' for {package_name} is not a simple \
                         pinned/ranged semver, not mechanically editable"
                    ));
                }
            }
        }
        out.push(line.to_owned());
    }
    if let Some(reason) = skip_reason {
        return EditOutcome::Skipped(reason);
    }
    if !found {
        return EditOutcome::Skipped(format!(
            "{package_name}: dependency line not found in manifest at current ref"
        ));
    }
    EditOutcome::Edited(reconstruct(content, out))
}

/// Rewrites one `requirements.txt` line's version token in place, or
/// `None` when a second comma-separated constraint follows the matched
/// separator (`flask>=1.0,<2.0`) — editing only the first token would leave
/// a now-inconsistent second constraint behind. `!=` is deliberately
/// excluded (an exclusion is not "the current pinned version").
fn pypi_bump(line: &str, new_version: &str) -> Option<String> {
    let trimmed_end = line.trim_end();
    for sep in ["==", ">=", "<=", "~="] {
        let Some(idx) = trimmed_end.find(sep) else {
            continue;
        };
        let after = &trimmed_end[idx + sep.len()..];
        let version_end = after.find([',', ';', ' ', '#']).unwrap_or(after.len());
        let version_token = &after[..version_end];
        if version_token.is_empty() {
            return None;
        }
        let rest_after_version = &after[version_end..];
        if rest_after_version.trim_start().starts_with(',') {
            // Compound requirement (`flask>=1.0,<2.0`) — not mechanically
            // editable in isolation.
            return None;
        }
        return Some(format!(
            "{}{}{}{}",
            &trimmed_end[..idx],
            sep,
            new_version,
            rest_after_version
        ));
    }
    None
}

fn edit_pypi(content: &str, package_name: &str, new_version: &str) -> EditOutcome {
    let mut out = Vec::with_capacity(content.lines().count());
    let mut found = false;
    let mut skip_reason = None;
    for line in content.lines() {
        if !found
            && let Some((name, _val)) = license_scan::parse_pypi_dep_line(line)
            && name == package_name
        {
            found = true;
            match pypi_bump(line, new_version) {
                Some(new_line) => {
                    out.push(new_line);
                    continue;
                }
                None => {
                    skip_reason = Some(format!(
                        "pypi: requirement line for {package_name} is a compound or \
                         non-pinned specifier, not mechanically editable"
                    ));
                }
            }
        }
        out.push(line.to_owned());
    }
    if let Some(reason) = skip_reason {
        return EditOutcome::Skipped(reason);
    }
    if !found {
        return EditOutcome::Skipped(format!(
            "{package_name}: dependency line not found in manifest at current ref"
        ));
    }
    EditOutcome::Edited(reconstruct(content, out))
}

/// Rewrites one `Cargo.toml` dependency line's version, or `None` when the
/// entry is a `git`/`path`/`workspace` dependency (spec: "workspace
/// inheritance, vendored path" must be skipped, not guessed at).
fn cargo_bump(line: &str, new_version: &str) -> Option<String> {
    let content_trimmed = line.trim();
    let (_key_part, rest) = content_trimmed.split_once('=')?;
    let rest_trimmed = rest.trim();
    if let Some(v) = rest_trimmed.strip_prefix('"') {
        let old_val = v.split('"').next()?;
        let old_quoted = format!("\"{old_val}\"");
        let new_quoted = format!("\"{new_version}\"");
        return Some(line.replacen(&old_quoted, &new_quoted, 1));
    }
    if rest_trimmed.starts_with('{') {
        if rest_trimmed.contains("git")
            || rest_trimmed.contains("path")
            || rest_trimmed.contains("workspace")
        {
            return None;
        }
        let version_pos = line.find("version")?;
        let (before, after_version) = line.split_at(version_pos);
        let (_, after_key) = after_version.split_once('"')?;
        let old_val = after_key.split('"').next()?;
        let old_quoted = format!("\"{old_val}\"");
        let new_quoted = format!("\"{new_version}\"");
        let replaced_after = after_version.replacen(&old_quoted, &new_quoted, 1);
        return Some(format!("{before}{replaced_after}"));
    }
    None
}

fn edit_cargo(content: &str, package_name: &str, new_version: &str) -> EditOutcome {
    let mut out = Vec::with_capacity(content.lines().count());
    let mut found = false;
    let mut skip_reason = None;
    for line in content.lines() {
        if !found
            && let Some((name, _val)) = license_scan::parse_cargo_dep_line(line)
            && name == package_name
        {
            found = true;
            match cargo_bump(line, new_version) {
                Some(new_line) => {
                    out.push(new_line);
                    continue;
                }
                None => {
                    skip_reason = Some(format!(
                        "cargo: {package_name} is a git/path/workspace dependency, not \
                         mechanically editable"
                    ));
                }
            }
        }
        out.push(line.to_owned());
    }
    if let Some(reason) = skip_reason {
        return EditOutcome::Skipped(reason);
    }
    if !found {
        return EditOutcome::Skipped(format!(
            "{package_name}: dependency line not found in manifest at current ref"
        ));
    }
    EditOutcome::Edited(reconstruct(content, out))
}

fn edit_go_mod(content: &str, package_name: &str, new_version: &str) -> EditOutcome {
    let normalized_new = if new_version.starts_with('v') {
        new_version.to_owned()
    } else {
        format!("v{new_version}")
    };
    let mut out = Vec::with_capacity(content.lines().count());
    let mut found = false;
    for line in content.lines() {
        if !found
            && let Some((module, old_version)) = license_scan::parse_go_mod_dep_line(line)
            && module == package_name
        {
            found = true;
            out.push(line.replacen(&old_version, &normalized_new, 1));
            continue;
        }
        out.push(line.to_owned());
    }
    if !found {
        return EditOutcome::Skipped(format!(
            "{package_name}: dependency line not found in go.mod at current ref"
        ));
    }
    EditOutcome::Edited(reconstruct(content, out))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn npm_caret_range_is_bumped_preserving_prefix() {
        let content = "{\n  \"dependencies\": {\n    \"left-pad\": \"^1.3.0\",\n    \"axios\": \"1.7.0\"\n  }\n}\n";
        let result = edit_dependency_version("package.json", content, "left-pad", "1.3.1");
        assert_eq!(
            result,
            EditOutcome::Edited(
                "{\n  \"dependencies\": {\n    \"left-pad\": \"^1.3.1\",\n    \"axios\": \"1.7.0\"\n  }\n}\n"
                    .to_owned()
            )
        );
    }

    #[test]
    fn npm_workspace_protocol_is_skipped() {
        let content = "{\n  \"dependencies\": {\n    \"@acme/shared\": \"workspace:*\"\n  }\n}\n";
        let result = edit_dependency_version("package.json", content, "@acme/shared", "2.0.0");
        assert!(matches!(result, EditOutcome::Skipped(_)));
    }

    #[test]
    fn npm_missing_dependency_is_skipped_with_not_found_reason() {
        let content = "{\n  \"dependencies\": {\n    \"axios\": \"1.7.0\"\n  }\n}\n";
        let result = edit_dependency_version("package.json", content, "left-pad", "1.3.1");
        match result {
            EditOutcome::Skipped(reason) => assert!(reason.contains("not found")),
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    #[test]
    fn pypi_exact_pin_is_bumped() {
        let content = "flask==2.0.0\nrequests==2.28.0\n";
        let result = edit_dependency_version("requirements.txt", content, "flask", "2.3.2");
        assert_eq!(
            result,
            EditOutcome::Edited("flask==2.3.2\nrequests==2.28.0\n".to_owned())
        );
    }

    #[test]
    fn pypi_preserves_environment_marker_tail() {
        let content = "flask>=2.0.0 ; python_version>='3.8'\n";
        let result = edit_dependency_version("requirements.txt", content, "flask", "2.3.2");
        assert_eq!(
            result,
            EditOutcome::Edited("flask>=2.3.2 ; python_version>='3.8'\n".to_owned())
        );
    }

    #[test]
    fn pypi_compound_range_is_skipped() {
        let content = "flask>=1.0.0,<2.0.0\n";
        let result = edit_dependency_version("requirements.txt", content, "flask", "2.3.2");
        assert!(matches!(result, EditOutcome::Skipped(_)));
    }

    #[test]
    fn cargo_simple_string_version_is_bumped() {
        let content = "[dependencies]\nserde = \"1.0.150\"\ntokio = \"1.35.0\"\n";
        let result = edit_dependency_version("Cargo.toml", content, "serde", "1.0.160");
        assert_eq!(
            result,
            EditOutcome::Edited(
                "[dependencies]\nserde = \"1.0.160\"\ntokio = \"1.35.0\"\n".to_owned()
            )
        );
    }

    #[test]
    fn cargo_inline_table_version_is_bumped_preserving_features() {
        let content =
            "[dependencies]\nserde = { version = \"1.0.150\", features = [\"derive\"] }\n";
        let result = edit_dependency_version("Cargo.toml", content, "serde", "1.0.160");
        assert_eq!(
            result,
            EditOutcome::Edited(
                "[dependencies]\nserde = { version = \"1.0.160\", features = [\"derive\"] }\n"
                    .to_owned()
            )
        );
    }

    #[test]
    fn cargo_workspace_inherited_dependency_is_skipped() {
        let content = "[dependencies]\nserde = { workspace = true }\n";
        // `parse_cargo_dep_line` itself won't match a bare `{ workspace = true }`
        // (no "version" key to find) — this asserts the not-found path, which
        // is the correct outcome (the finding for this package should never
        // have been generated by `sentinel::extract_manifest_dependencies` in
        // the first place, since the same parser drives both).
        let result = edit_dependency_version("Cargo.toml", content, "serde", "1.0.160");
        assert!(matches!(result, EditOutcome::Skipped(_)));
    }

    #[test]
    fn cargo_git_dependency_with_a_version_key_is_skipped() {
        let content = "[dependencies]\nserde = { git = \"https://example.com/serde\", version = \"1.0.150\" }\n";
        let result = edit_dependency_version("Cargo.toml", content, "serde", "1.0.160");
        match result {
            EditOutcome::Skipped(reason) => assert!(reason.contains("git/path/workspace")),
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    #[test]
    fn go_mod_direct_dependency_is_bumped() {
        let content = "module example.com/app\n\nrequire github.com/pkg/errors v0.9.0\n";
        let result = edit_dependency_version("go.mod", content, "github.com/pkg/errors", "0.9.1");
        assert_eq!(
            result,
            EditOutcome::Edited(
                "module example.com/app\n\nrequire github.com/pkg/errors v0.9.1\n".to_owned()
            )
        );
    }

    #[test]
    fn go_mod_indirect_comment_is_preserved() {
        let content = "require (\n\tgithub.com/pkg/errors v0.9.0 // indirect\n)\n";
        let result = edit_dependency_version("go.mod", content, "github.com/pkg/errors", "0.9.1");
        assert_eq!(
            result,
            EditOutcome::Edited(
                "require (\n\tgithub.com/pkg/errors v0.9.1 // indirect\n)\n".to_owned()
            )
        );
    }

    #[test]
    fn unrecognized_manifest_file_is_skipped() {
        let result = edit_dependency_version("README.md", "left-pad ^1.3.0", "left-pad", "1.3.1");
        assert!(matches!(result, EditOutcome::Skipped(_)));
    }
}
