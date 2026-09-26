//! Static reachability prefilter (P3, docs/v2-port/v2.1-codescan-sentinel.md
//! §5 point 1): for each dependency-derived finding (kind `sca`/`cve`),
//! determines whether the affected package is even imported anywhere in the
//! fetched branch tree and, best-effort, whether an advisory-named symbol is
//! referenced. This is the cheap, deterministic pass that runs before any
//! AI spend — "unused packages are the cheap win" per the phase brief: a
//! package with zero textual references short-circuits straight to a
//! `document`-only policy outcome (`crate::policy`) without ever calling
//! WaddleAI.
//!
//! **What this honestly is**: per-ecosystem regex text matching against
//! source file contents (Rust `use`/`extern crate` + `Cargo.toml`; Python
//! `import`/`from`; JS/TS `import`/`require`; Go quoted import paths), plus
//! a best-effort scan for backtick-quoted identifiers pulled out of the
//! advisory's free-text summary. It is deliberately "AST-lite": no real
//! parser, no scope resolution, no call graph. A match inside a comment or
//! string literal still counts as "used"; a symbol name that collides with
//! an unrelated identifier still counts as "referenced".
//!
//! **What this is NOT, and never claims to be**: a call graph, taint
//! analysis, or AST walk. It cannot tell whether an `import` is dead code,
//! whether a call site is behind an `if false`, or resolve re-exports/
//! aliases. That judgment is exactly what AI triage (`crate::triage`)
//! exists for on findings that survive this filter. An unrecognized
//! ecosystem fails *open* (`used = true`) rather than asserting "not used"
//! from ignorance — a false "not used" would wrongly suppress review of a
//! genuinely reachable vulnerability, which this design never risks; the
//! only thing this filter is confident asserting is a positive match.

use std::path::Path;

use regex::{Regex, RegexBuilder};

/// One matched location backing a [`PrefilterResult`] verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub file: String,
    pub line: Option<u32>,
}

/// Static prefilter verdict for one (package, advisory) pair against one
/// fetched branch tree.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrefilterResult {
    /// `true` when the package is imported/required anywhere in the tree
    /// (or, for Rust, declared in `Cargo.toml` — see module docs). `false`
    /// means "no textual reference found in a recognized ecosystem" — the
    /// high-confidence "not used" signal that short-circuits before AI
    /// spend. Always `true` for an ecosystem this module doesn't recognize
    /// (fail open — see module docs).
    pub used: bool,
    /// `None` when the advisory text named no extractable symbol candidate
    /// (nothing to check); `Some(true)`/`Some(false)` otherwise.
    pub symbol_referenced: Option<bool>,
    pub evidence: Vec<Evidence>,
}

/// Cap on evidence lines returned to the caller (and forwarded into the AI
/// triage prompt) — keeps the prompt small and the finding row's stored
/// evidence bounded.
const MAX_EVIDENCE: usize = 5;
/// Skip source files above this size — an import statement lives in the
/// first few KB of any real file; this bounds worst-case scan cost on a
/// monorepo without materially affecting accuracy.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// Hard cap on files inspected per ecosystem/symbol pass, independent of
/// [`crate::tree_fetch`]'s own extracted-size cap — bounds CPU time on a
/// tree with an enormous number of small files.
const MAX_FILES_SCANNED: usize = 20_000;

fn esc(s: &str) -> String {
    regex::escape(s)
}

fn build_regexes(pats: &[String]) -> Vec<Regex> {
    pats.iter()
        .filter_map(|p| {
            RegexBuilder::new(p)
                .multi_line(true)
                .build()
                .map_err(|e| tracing::warn!(pattern = %p, error = %e, "reachability: bad regex, skipping"))
                .ok()
        })
        .collect()
}

/// Per-ecosystem candidate source file extensions (without the leading
/// `.`) + the regex(es) that count as "this package is imported here".
/// `None` for an ecosystem this module doesn't (yet) speak.
fn import_patterns(
    ecosystem: &str,
    package_name: &str,
) -> Option<(&'static [&'static str], Vec<Regex>)> {
    match ecosystem {
        "cargo" => {
            // Rust `use`/`extern crate` paths spell a crate name with `_`
            // even when Cargo.toml spells it with `-`.
            let ident = esc(&package_name.replace('-', "_"));
            let raw = esc(package_name);
            let pats = vec![
                format!(r"^\s*(pub\s+)?use\s+{ident}(::|\s*;|\s+as\s)"),
                format!(r"^\s*(pub\s+)?extern\s+crate\s+{ident}\b"),
                // Cargo.toml `<name> = "..."` / `<name> = { ... }` dependency line.
                format!(r#"^\s*{raw}\s*="#),
            ];
            Some((&["rs", "toml"], build_regexes(&pats)))
        }
        "npm" => {
            let raw = esc(package_name);
            let pats = vec![
                format!(r#"require\(\s*['"]{raw}(?:['"/])"#),
                format!(r#"from\s+['"]{raw}(?:['"/])"#),
                format!(r#"import\s*\(\s*['"]{raw}(?:['"/])"#),
                format!(r#"import\s+['"]{raw}(?:['"/])"#),
            ];
            Some((
                &["js", "jsx", "ts", "tsx", "mjs", "cjs"],
                build_regexes(&pats),
            ))
        }
        "pypi" => {
            let raw = esc(package_name);
            let underscored = esc(&package_name.replace('-', "_"));
            let pats = vec![
                format!(r"^\s*import\s+{raw}\b"),
                format!(r"^\s*from\s+{raw}\b"),
                format!(r"^\s*import\s+{underscored}\b"),
                format!(r"^\s*from\s+{underscored}\b"),
            ];
            Some((&["py"], build_regexes(&pats)))
        }
        "go" => {
            let raw = esc(package_name);
            let pats = vec![format!(r#""{raw}(?:"|/)"#)];
            Some((&["go"], build_regexes(&pats)))
        }
        _ => None,
    }
}

fn has_extension(file: &str, extensions: &[&str]) -> bool {
    let lower = file.to_lowercase();
    extensions
        .iter()
        .any(|ext| lower.ends_with(&format!(".{ext}")))
        || (extensions.contains(&"toml") && lower.ends_with("cargo.toml"))
}

/// Scans `files` (relative to `root`) for the first line in each file
/// matching any of `patterns`, returning at most one [`Evidence`] entry per
/// file. Every I/O failure (missing file, oversized file, non-UTF8 content)
/// is skipped rather than propagated — a prefilter is advisory, never a
/// reason to fail the scan.
fn scan_files(root: &Path, files: &[&String], patterns: &[Regex]) -> Vec<Evidence> {
    if patterns.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for file in files.iter().take(MAX_FILES_SCANNED) {
        let full = root.join(file.as_str());
        let Ok(meta) = std::fs::metadata(&full) else {
            continue;
        };
        if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&full) else {
            continue;
        };
        for (idx, line) in content.lines().enumerate() {
            if patterns.iter().any(|re| re.is_match(line)) {
                out.push(Evidence {
                    file: (*file).clone(),
                    line: u32::try_from(idx + 1).ok(),
                });
                break;
            }
        }
        if out.len() >= MAX_EVIDENCE {
            break;
        }
    }
    out
}

/// Extracts backtick-quoted identifier-shaped tokens from an advisory's
/// free-text summary (e.g. `` the `parse_headers` function ``) — a
/// heuristic, not a structured advisory field (OSV/deps.dev don't publish
/// one). Empty when the summary is `None`, empty, or names nothing
/// identifier-shaped.
fn extract_symbol_candidates(summary: &str) -> Vec<String> {
    let Ok(re) = Regex::new(r"`([A-Za-z_][A-Za-z0-9_:.]{2,63})`") else {
        return Vec::new();
    };
    let mut seen = std::collections::BTreeSet::new();
    for cap in re.captures_iter(summary) {
        if let Some(m) = cap.get(1) {
            seen.insert(m.as_str().to_owned());
        }
    }
    seen.into_iter().collect()
}

/// Runs the static prefilter for one dependency-derived finding against a
/// fetched branch tree. `files` is `crate::tree_fetch::WorkingTree::files()`;
/// `root` is `WorkingTree::root()`. `advisory_summary` is the OSV advisory's
/// free-text summary, when the caller has one
/// (`license_scan::AdvisoryRef::summary`).
pub fn analyze(
    root: &Path,
    files: &[String],
    ecosystem: &str,
    package_name: &str,
    advisory_summary: Option<&str>,
) -> PrefilterResult {
    let Some((extensions, patterns)) = import_patterns(ecosystem, package_name) else {
        // Unrecognized ecosystem: never assert "not used" from ignorance —
        // see module docs' fail-open rationale.
        return PrefilterResult {
            used: true,
            symbol_referenced: None,
            evidence: Vec::new(),
        };
    };

    let candidate_files: Vec<&String> = files
        .iter()
        .filter(|f| has_extension(f, extensions))
        .collect();

    let mut evidence = scan_files(root, &candidate_files, &patterns);
    let used = !evidence.is_empty();
    evidence.truncate(MAX_EVIDENCE);

    let symbol_candidates = advisory_summary
        .map(extract_symbol_candidates)
        .unwrap_or_default();

    let symbol_referenced = if symbol_candidates.is_empty() {
        None
    } else {
        let symbol_patterns: Vec<Regex> = symbol_candidates
            .iter()
            .filter_map(|c| Regex::new(&format!(r"\b{}\b", esc(c))).ok())
            .collect();
        let all_files: Vec<&String> = files.iter().collect();
        let symbol_evidence = scan_files(root, &all_files, &symbol_patterns);
        let found = !symbol_evidence.is_empty();
        for e in symbol_evidence {
            if evidence.len() >= MAX_EVIDENCE {
                break;
            }
            if !evidence.contains(&e) {
                evidence.push(e);
            }
        }
        Some(found)
    };

    PrefilterResult {
        used,
        symbol_referenced,
        evidence,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn write_tree(entries: &[(&str, &str)]) -> (tempfile::TempDir, Vec<String>) {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let mut files = Vec::new();
        for (name, content) in entries {
            let path = dir.path().join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap_or_else(|e| panic!("mkdir: {e}"));
            }
            std::fs::write(&path, content).unwrap_or_else(|e| panic!("write: {e}"));
            files.push((*name).to_owned());
        }
        (dir, files)
    }

    #[test]
    fn rust_use_statement_marks_the_package_used() {
        let (dir, files) = write_tree(&[
            ("src/main.rs", "use left_pad::pad;\nfn main() {}\n"),
            ("Cargo.toml", "[dependencies]\n"),
        ]);
        let result = analyze(dir.path(), &files, "cargo", "left-pad", None);
        assert!(result.used);
        assert_eq!(result.evidence[0].file, "src/main.rs");
        assert_eq!(result.evidence[0].line, Some(1));
    }

    #[test]
    fn rust_cargo_toml_declaration_alone_marks_the_package_used() {
        let (dir, files) = write_tree(&[
            ("src/main.rs", "fn main() {}\n"),
            ("Cargo.toml", "[dependencies]\nleft-pad = \"1.0\"\n"),
        ]);
        let result = analyze(dir.path(), &files, "cargo", "left-pad", None);
        assert!(result.used);
        assert_eq!(result.evidence[0].file, "Cargo.toml");
    }

    #[test]
    fn rust_package_declared_but_never_used_is_not_used() {
        let (dir, files) = write_tree(&[("src/main.rs", "fn main() {}\n")]);
        let result = analyze(dir.path(), &files, "cargo", "left-pad", None);
        assert!(!result.used);
        assert!(result.evidence.is_empty());
    }

    #[test]
    fn npm_require_marks_the_package_used() {
        let (dir, files) = write_tree(&[("index.js", "const x = require('left-pad');\n")]);
        let result = analyze(dir.path(), &files, "npm", "left-pad", None);
        assert!(result.used);
    }

    #[test]
    fn npm_import_from_marks_the_package_used() {
        let (dir, files) = write_tree(&[("index.ts", "import { pad } from 'left-pad';\n")]);
        let result = analyze(dir.path(), &files, "npm", "left-pad", None);
        assert!(result.used);
    }

    #[test]
    fn npm_package_never_imported_is_not_used() {
        let (dir, files) = write_tree(&[("index.js", "console.log('hi');\n")]);
        let result = analyze(dir.path(), &files, "npm", "left-pad", None);
        assert!(!result.used);
    }

    #[test]
    fn python_import_marks_the_package_used() {
        let (dir, files) = write_tree(&[("app.py", "import flask\n")]);
        let result = analyze(dir.path(), &files, "pypi", "flask", None);
        assert!(result.used);
    }

    #[test]
    fn python_from_import_with_hyphenated_manifest_name_marks_used() {
        let (dir, files) = write_tree(&[("app.py", "from python_dateutil import parser\n")]);
        let result = analyze(dir.path(), &files, "pypi", "python-dateutil", None);
        assert!(result.used);
    }

    #[test]
    fn go_import_path_marks_the_package_used() {
        let (dir, files) = write_tree(&[(
            "main.go",
            "package main\nimport \"github.com/acme/widgets\"\n",
        )]);
        let result = analyze(dir.path(), &files, "go", "github.com/acme/widgets", None);
        assert!(result.used);
    }

    #[test]
    fn unrecognized_ecosystem_fails_open_to_used() {
        let (dir, files) = write_tree(&[("README.md", "nothing relevant\n")]);
        let result = analyze(dir.path(), &files, "nuget", "SomePackage", None);
        assert!(result.used, "unknown ecosystems must never assert not-used");
        assert_eq!(result.symbol_referenced, None);
    }

    #[test]
    fn no_advisory_summary_yields_no_symbol_verdict() {
        let (dir, files) = write_tree(&[("app.py", "import flask\n")]);
        let result = analyze(dir.path(), &files, "pypi", "flask", None);
        assert_eq!(result.symbol_referenced, None);
    }

    #[test]
    fn advisory_summary_with_no_backtick_symbol_yields_no_symbol_verdict() {
        let (dir, files) = write_tree(&[("app.py", "import flask\n")]);
        let result = analyze(
            dir.path(),
            &files,
            "pypi",
            "flask",
            Some("a generic denial of service issue"),
        );
        assert_eq!(result.symbol_referenced, None);
    }

    #[test]
    fn advisory_named_symbol_found_in_source_is_referenced() {
        let (dir, files) = write_tree(&[(
            "app.py",
            "import flask\n\ndef handler():\n    parse_headers(x)\n",
        )]);
        let result = analyze(
            dir.path(),
            &files,
            "pypi",
            "flask",
            Some("the `parse_headers` function is affected"),
        );
        assert_eq!(result.symbol_referenced, Some(true));
        assert!(
            result
                .evidence
                .iter()
                .any(|e| e.file == "app.py" && e.line == Some(4))
        );
    }

    #[test]
    fn advisory_named_symbol_absent_from_source_is_not_referenced() {
        let (dir, files) = write_tree(&[("app.py", "import flask\n")]);
        let result = analyze(
            dir.path(),
            &files,
            "pypi",
            "flask",
            Some("the `parse_headers` function is affected"),
        );
        assert_eq!(result.symbol_referenced, Some(false));
    }

    #[test]
    fn evidence_is_capped_at_max_evidence() {
        let entries: Vec<(String, String)> = (0..10)
            .map(|i| (format!("mod_{i}.py"), "import flask\n".to_owned()))
            .collect();
        let entry_refs: Vec<(&str, &str)> = entries
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let (dir, files) = write_tree(&entry_refs);
        let result = analyze(dir.path(), &files, "pypi", "flask", None);
        assert!(result.used);
        assert!(result.evidence.len() <= MAX_EVIDENCE);
    }

    #[test]
    fn oversized_file_is_skipped() {
        let huge = "x".repeat(usize::try_from(MAX_FILE_BYTES).unwrap_or(0) + 10);
        let content = format!("import flask\n{huge}\n");
        let (dir, files) = write_tree(&[("app.py", &content)]);
        let result = analyze(dir.path(), &files, "pypi", "flask", None);
        assert!(!result.used, "an oversized file must be skipped entirely");
    }
}
