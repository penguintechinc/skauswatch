//! Language/framework detection from a unified PR/MR diff — populates
//! `codescan_review_detections`. Net-new logic: v1's `create_detection()`
//! writer existed but had zero callers anywhere in the darwin tree (see
//! docs/v2-port/phase12-scope-codeai.md row 2), so there is no working
//! behavior to port. This is a diff-only heuristic (no full repo checkout
//! is available to this worker — see `git_provider`), not a byte-perfect
//! language classifier: it counts touched file extensions and flags a small
//! set of well-known framework manifests/dependencies.

use std::collections::{BTreeMap, BTreeSet};

/// One detected language or framework for a review.
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    /// `"language"` or `"framework"`.
    pub detection_type: &'static str,
    /// Display name (e.g. `"Rust"`, `"React"`).
    pub name: String,
    /// Heuristic confidence in `[0.0, 1.0]` — see module docs for how each
    /// detection type computes this.
    pub confidence: f64,
    /// Number of touched files that contributed to this detection.
    pub file_count: i32,
}

/// Extracts the set of touched file paths from a unified diff by scanning
/// `+++ b/...` / `--- a/...` header lines. A `BTreeSet` dedupes files that
/// appear twice (e.g. GitLab diff assembly synthesizes a header per hunk in
/// `git_provider::fetch_gitlab_diff`, which can coexist with a
/// already-embedded header in test fixtures / some API responses).
fn touched_files(diff: &str) -> BTreeSet<String> {
    let mut files = BTreeSet::new();
    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ b/") {
            files.insert(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("--- a/") {
            files.insert(path.trim().to_string());
        }
    }
    files
}

/// Maps a lowercase file extension to a display language name. Deliberately
/// a fixed, well-known-extension list rather than an exhaustive one — an
/// unrecognized extension is simply not counted, not mis-attributed.
fn language_for_extension(ext: &str) -> Option<&'static str> {
    match ext {
        "rs" => Some("Rust"),
        "py" | "pyi" => Some("Python"),
        "go" => Some("Go"),
        "js" | "jsx" | "mjs" | "cjs" => Some("JavaScript"),
        "ts" | "tsx" => Some("TypeScript"),
        "java" => Some("Java"),
        "rb" => Some("Ruby"),
        "php" => Some("PHP"),
        "c" | "h" => Some("C"),
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Some("C++"),
        "cs" => Some("C#"),
        "swift" => Some("Swift"),
        "kt" | "kts" => Some("Kotlin"),
        "scala" => Some("Scala"),
        "sh" | "bash" => Some("Shell"),
        "sql" => Some("SQL"),
        "yaml" | "yml" => Some("YAML"),
        "html" | "htm" => Some("HTML"),
        "css" | "scss" | "sass" => Some("CSS"),
        "dart" => Some("Dart"),
        "tf" => Some("Terraform"),
        _ => None,
    }
}

fn extension_of(path: &str) -> Option<&str> {
    path.rsplit('/').next().and_then(|filename| {
        filename
            .rsplit_once('.')
            .filter(|(stem, _)| !stem.is_empty())
            .map(|(_, ext)| ext)
    })
}

/// A manifest-file + dependency-name signal that implies a framework is in
/// use. `content_needle` is matched case-insensitively against the whole
/// diff text — a coarse heuristic (it does not distinguish an added line
/// from a removed one), acceptable for a "framework present in this diff"
/// signal rather than a precise dependency-change detector.
struct FrameworkSignal {
    filename_suffix: &'static str,
    content_needle: &'static str,
    name: &'static str,
}

const FRAMEWORK_SIGNALS: &[FrameworkSignal] = &[
    FrameworkSignal {
        filename_suffix: "package.json",
        content_needle: "\"react\"",
        name: "React",
    },
    FrameworkSignal {
        filename_suffix: "package.json",
        content_needle: "\"vue\"",
        name: "Vue",
    },
    FrameworkSignal {
        filename_suffix: "package.json",
        content_needle: "\"express\"",
        name: "Express",
    },
    FrameworkSignal {
        filename_suffix: "package.json",
        content_needle: "\"next\"",
        name: "Next.js",
    },
    FrameworkSignal {
        filename_suffix: "requirements.txt",
        content_needle: "django",
        name: "Django",
    },
    FrameworkSignal {
        filename_suffix: "requirements.txt",
        content_needle: "flask",
        name: "Flask",
    },
    FrameworkSignal {
        filename_suffix: "requirements.txt",
        content_needle: "quart",
        name: "Quart",
    },
    FrameworkSignal {
        filename_suffix: "pyproject.toml",
        content_needle: "fastapi",
        name: "FastAPI",
    },
    FrameworkSignal {
        filename_suffix: "go.mod",
        content_needle: "gin-gonic/gin",
        name: "Gin",
    },
    FrameworkSignal {
        filename_suffix: "go.mod",
        content_needle: "labstack/echo",
        name: "Echo",
    },
    FrameworkSignal {
        filename_suffix: "cargo.toml",
        content_needle: "axum",
        name: "Axum",
    },
    FrameworkSignal {
        filename_suffix: "cargo.toml",
        content_needle: "actix-web",
        name: "Actix Web",
    },
    FrameworkSignal {
        filename_suffix: "gemfile",
        content_needle: "rails",
        name: "Ruby on Rails",
    },
];

/// Framework-detection confidence: fixed and moderate, since this is a
/// coarse manifest-name + keyword heuristic rather than a resolved
/// dependency graph.
const FRAMEWORK_CONFIDENCE: f64 = 0.6;

/// Detects languages (by touched-file extension) and frameworks (by
/// manifest filename + dependency keyword) from a unified diff. Returns an
/// empty vec for an empty/header-less diff — callers should not write rows
/// for a diff with no recognizable content.
pub fn detect_from_diff(diff: &str) -> Vec<Detection> {
    let files = touched_files(diff);
    if files.is_empty() {
        return Vec::new();
    }

    let mut language_counts: BTreeMap<&'static str, i32> = BTreeMap::new();
    for file in &files {
        if let Some(lang) =
            extension_of(file).and_then(|ext| language_for_extension(&ext.to_lowercase()))
        {
            *language_counts.entry(lang).or_insert(0) += 1;
        }
    }
    let total_recognized: i32 = language_counts.values().sum();

    let mut detections: Vec<Detection> = language_counts
        .into_iter()
        .map(|(name, count)| Detection {
            detection_type: "language",
            name: name.to_string(),
            confidence: if total_recognized > 0 {
                f64::from(count) / f64::from(total_recognized)
            } else {
                0.0
            },
            file_count: count,
        })
        .collect();

    let diff_lower = diff.to_lowercase();
    let mut seen_frameworks = BTreeSet::new();
    for signal in FRAMEWORK_SIGNALS {
        let manifest_touched = files
            .iter()
            .any(|f| f.to_lowercase().ends_with(signal.filename_suffix));
        if manifest_touched
            && diff_lower.contains(signal.content_needle)
            && seen_frameworks.insert(signal.name)
        {
            detections.push(Detection {
                detection_type: "framework",
                name: signal.name.to_string(),
                confidence: FRAMEWORK_CONFIDENCE,
                file_count: 1,
            });
        }
    }

    detections
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_diff_yields_no_detections() {
        assert_eq!(detect_from_diff(""), Vec::new());
    }

    #[test]
    fn diff_with_no_recognizable_headers_yields_no_detections() {
        assert_eq!(
            detect_from_diff("just some text\nwith no diff headers\n"),
            Vec::new()
        );
    }

    #[test]
    fn detects_a_single_language_at_full_confidence() {
        let diff = "diff --git a/src/main.rs b/src/main.rs\n\
                     --- a/src/main.rs\n+++ b/src/main.rs\n@@ -1 +1 @@\n-old\n+new\n";
        let detections = detect_from_diff(diff);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].detection_type, "language");
        assert_eq!(detections[0].name, "Rust");
        assert!((detections[0].confidence - 1.0).abs() < f64::EPSILON);
        assert_eq!(detections[0].file_count, 1);
    }

    #[test]
    fn splits_confidence_across_multiple_languages() {
        let diff = "--- a/src/main.rs\n+++ b/src/main.rs\n@@ -1 +1 @@\n-x\n+y\n\
                     --- a/scripts/build.py\n+++ b/scripts/build.py\n@@ -1 +1 @@\n-x\n+y\n\
                     --- a/scripts/deploy.py\n+++ b/scripts/deploy.py\n@@ -1 +1 @@\n-x\n+y\n";
        let detections = detect_from_diff(diff);
        let rust = detections
            .iter()
            .find(|d| d.name == "Rust")
            .expect("rust detected");
        let python = detections
            .iter()
            .find(|d| d.name == "Python")
            .expect("python detected");
        assert!((rust.confidence - (1.0 / 3.0)).abs() < 1e-9);
        assert_eq!(rust.file_count, 1);
        assert!((python.confidence - (2.0 / 3.0)).abs() < 1e-9);
        assert_eq!(python.file_count, 2);
    }

    #[test]
    fn unrecognized_extensions_are_not_counted_but_do_not_panic() {
        let diff = "--- a/README\n+++ b/README\n@@ -1 +1 @@\n-x\n+y\n";
        assert_eq!(detect_from_diff(diff), Vec::new());
    }

    #[test]
    fn detects_react_from_package_json() {
        let diff = "--- a/package.json\n+++ b/package.json\n@@ -1,2 +1,3 @@\n \
                     {\n+  \"dependencies\": { \"react\": \"^18.2.0\" }\n }\n";
        let detections = detect_from_diff(diff);
        let framework = detections
            .iter()
            .find(|d| d.detection_type == "framework")
            .expect("framework detected");
        assert_eq!(framework.name, "React");
        assert!((framework.confidence - FRAMEWORK_CONFIDENCE).abs() < f64::EPSILON);
    }

    #[test]
    fn does_not_flag_a_framework_whose_manifest_was_not_touched() {
        // "react" appears in the diff body, but not inside a package.json path.
        let diff = "--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-x\n+react is great\n";
        let detections = detect_from_diff(diff);
        assert!(detections.iter().all(|d| d.detection_type != "framework"));
    }

    #[test]
    fn deduplicates_repeated_framework_signals() {
        let diff = "--- a/package.json\n+++ b/package.json\n@@ -1 +1 @@\n-x\n+\"react\": \"1\"\n\
                     --- a/package.json\n+++ b/package.json\n@@ -2 +2 @@\n-x\n+\"react\": \"2\"\n";
        let detections = detect_from_diff(diff);
        let react_count = detections.iter().filter(|d| d.name == "React").count();
        assert_eq!(react_count, 1);
    }

    #[test]
    fn detects_axum_from_cargo_toml_case_insensitively() {
        let diff = "--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1 +1 @@\n-x\n+axum = \"0.8\"\n";
        let detections = detect_from_diff(diff);
        assert!(detections.iter().any(|d| d.name == "Axum"));
    }
}
