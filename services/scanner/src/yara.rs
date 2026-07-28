//! YARA pattern-matching malware detection engine.
//! Ported from v1 scanner/yara_scanner.py using yara-x 1.19.0 (pure Rust, no C deps).

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::path::Path;
use yara_x::Compiler;

/// Compiled YARA scanner ready for scanning.
#[derive(Debug)]
pub struct YaraScanner {
    rules: yara_x::Rules,
}

/// One matched YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    /// Rule name.
    pub rule_name: String,
    /// Rule namespace.
    pub namespace: String,
    /// Rule tags.
    pub tags: Vec<String>,
    /// Matched strings (pattern identifiers).
    pub matched_strings: Vec<String>,
}

impl YaraScanner {
    /// Loads and compiles all YARA rules from a directory or single file.
    /// Fails loudly if rules cannot be compiled (unlike v1 which silently no-op'd).
    pub async fn load(rules_path: &str) -> anyhow::Result<Self> {
        let path = Path::new(rules_path);

        // Determine if it's a file or directory.
        let rule_files = if path.is_file() {
            vec![path.to_path_buf()]
        } else if path.is_dir() {
            // Glob *.yar and *.yara separately — the `glob` crate has no
            // `{a,b}` brace expansion, so a combined pattern matches nothing.
            let mut files = Vec::new();
            for ext in ["yar", "yara"] {
                let pattern = format!("{}/*.{}", path.display(), ext);
                for entry in glob::glob(&pattern)
                    .map_err(|e| anyhow!("failed to read rules directory: {e}"))?
                {
                    files.push(entry.map_err(|e| anyhow!("failed to glob rules files: {e}"))?);
                }
            }
            files
        } else {
            return Err(anyhow!("YARA rules path does not exist: {rules_path}"));
        };

        if rule_files.is_empty() {
            return Err(anyhow!("no YARA rule files found in {rules_path}"));
        }

        tracing::info!(
            "loading {} YARA rule files from {}",
            rule_files.len(),
            rules_path
        );

        // Compile rules (glob *.yar/*.yara, one add_source per file, FAIL LOUD on error).
        let mut compiler = Compiler::new();
        for file_path in &rule_files {
            let source = std::fs::read_to_string(file_path)
                .map_err(|e| anyhow!("failed to read rule file {}: {}", file_path.display(), e))?;
            compiler.add_source(source.as_str()).map_err(|e| {
                anyhow!("yara rule compile failed in {}: {}", file_path.display(), e)
            })?;
        }

        let rules = compiler.build();
        tracing::info!("YARA rules compiled successfully");
        Ok(Self { rules })
    }

    /// Scans file contents for YARA pattern matches.
    pub fn scan_bytes(&self, data: &[u8]) -> anyhow::Result<Vec<YaraMatch>> {
        // Scan bytes (create Scanner, call scan, map results inside scope to avoid borrow issues).
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner
            .scan(data)
            .map_err(|e| anyhow!("yara scan failed: {}", e))?;

        // Map matches to owned data INSIDE this scope (results borrows scanner).
        let matches: Vec<YaraMatch> = results
            .matching_rules()
            .map(|r| YaraMatch {
                rule_name: r.identifier().to_string(),
                namespace: r.namespace().to_string(),
                tags: r.tags().map(|t| t.identifier().to_string()).collect(),
                matched_strings: r
                    .patterns()
                    .map(|p| p.identifier().to_string())
                    .collect::<Vec<_>>(),
            })
            .collect();

        Ok(matches)
    }

    /// Scans a file by path.
    pub async fn scan_file(&self, file_path: &str) -> anyhow::Result<Vec<YaraMatch>> {
        let data = tokio::fs::read(file_path)
            .await
            .map_err(|e| anyhow!("failed to read file {}: {}", file_path, e))?;
        self.scan_bytes(&data)
    }
}

#[cfg(test)]
#[allow(
    unused_imports,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_yara_corpus_load_fails_loudly() {
        // Regression: v1 silently no-op'd when rule dir didn't exist.
        // v2 fails loudly.
        let result = YaraScanner::load("/nonexistent/rules").await;
        assert!(result.is_err(), "Loading nonexistent rules dir should fail");
        assert!(
            result.unwrap_err().to_string().contains("does not exist"),
            "Error should mention missing path"
        );
    }

    #[tokio::test]
    async fn test_yara_scanner_with_corporate_threats_corpus() {
        // Real integration test: load actual YARA rules from config/yara_rules/,
        // verify EICAR matches + benign doesn't false-positive.
        // This test proves v2 doesn't silently no-op like v1 did.

        // Absolute path via CARGO_MANIFEST_DIR so the corpus resolves
        // regardless of the test runner's CWD (it lives at repo-root/config).
        let rules_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/yara_rules");
        let scanner = YaraScanner::load(rules_path)
            .await
            .expect("corporate_threats.yar corpus must load (proves YARA is not a no-op)");

        // EICAR test file (canonical 68 bytes).
        const EICAR: &[u8] =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        // Scan EICAR — should match EICAR_Test_File rule.
        let eicar_matches = scanner.scan_bytes(EICAR).expect("EICAR scan failed");
        let eicar_rule_names: Vec<&str> =
            eicar_matches.iter().map(|m| m.rule_name.as_str()).collect();

        assert!(
            eicar_rule_names.contains(&"EICAR_Test_File"),
            "EICAR (68 bytes) should match EICAR_Test_File rule; got rules: {:?}",
            eicar_rule_names
        );
        eprintln!("✓ EICAR matched: rules={:?}", eicar_rule_names);

        // Scan benign content — should NOT match any rules (anti-regression for v1 false positives).
        let benign = b"This is a harmless document with no executable code or suspicious patterns whatsoever.";
        let benign_matches = scanner.scan_bytes(benign).expect("benign scan failed");

        assert!(
            benign_matches.is_empty(),
            "Benign content should not match any rules; got: {:?}",
            benign_matches
                .iter()
                .map(|m| &m.rule_name)
                .collect::<Vec<_>>()
        );
        eprintln!("✓ Benign content did not match (no false positives)");
    }

    #[tokio::test]
    async fn load_single_file_path_uses_the_is_file_branch() {
        // `load()` branches on `path.is_file()` vs `path.is_dir()`; the
        // directory branch is covered above — this exercises the single-
        // file branch by pointing directly at one `.yar` file.
        let rules_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/yara_rules/corporate_threats.yar"
        );
        let scanner = YaraScanner::load(rules_path)
            .await
            .expect("single-file load must succeed");

        const EICAR: &[u8] =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let matches = scanner.scan_bytes(EICAR).expect("scan succeeds");
        assert!(
            matches.iter().any(|m| m.rule_name == "EICAR_Test_File"),
            "single-file load should compile the same rule as the directory load"
        );
    }

    #[tokio::test]
    async fn load_empty_directory_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = YaraScanner::load(dir.path().to_str().expect("utf8 path")).await;
        let err = result.expect_err("empty rules directory must fail loudly, not silently no-op");
        assert!(err.to_string().contains("no YARA rule files found"));
    }

    #[tokio::test]
    async fn load_directory_with_invalid_rule_syntax_fails_loudly() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("broken.yar"),
            b"this is not valid YARA syntax {{{",
        )
        .expect("write broken rule file");
        let result = YaraScanner::load(dir.path().to_str().expect("utf8 path")).await;
        let err = result.expect_err("invalid rule syntax must fail compilation, not be ignored");
        assert!(err.to_string().contains("yara rule compile failed"));
    }

    #[tokio::test]
    async fn scan_file_reads_from_disk_and_matches_eicar() {
        let rules_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/yara_rules");
        let scanner = YaraScanner::load(rules_path).await.expect("corpus loads");

        const EICAR: &[u8] =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        std::io::Write::write_all(&mut f, EICAR).expect("write eicar to tempfile");

        let matches = scanner
            .scan_file(f.path().to_str().expect("utf8 path"))
            .await
            .expect("scan_file succeeds");
        assert!(matches.iter().any(|m| m.rule_name == "EICAR_Test_File"));
    }

    #[tokio::test]
    async fn scan_file_missing_path_errors() {
        let rules_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/yara_rules");
        let scanner = YaraScanner::load(rules_path).await.expect("corpus loads");

        let result = scanner.scan_file("/nonexistent/path/to/file").await;
        let err = result.expect_err("missing file must error");
        assert!(err.to_string().contains("failed to read file"));
    }
}
