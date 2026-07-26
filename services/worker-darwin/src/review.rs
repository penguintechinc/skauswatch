//! Code review engine leveraging the AI provider abstraction.

/// Comment finding from an AI review.
#[derive(Debug, Clone)]
pub struct ReviewComment {
    pub file_path: String,
    pub line_start: i64,
    pub _line_end: i64,
    pub severity: String,
    pub title: String,
    pub body: String,
}

/// Result of a review run.
#[derive(Debug, Clone)]
pub struct ReviewOutput {
    pub _files_reviewed: usize,
    pub comments: Vec<ReviewComment>,
    pub summary: String,
}

/// Parse findings from AI response as JSON array of comment objects.
pub fn parse_ai_response(response: &str) -> anyhow::Result<Vec<ReviewComment>> {
    // Try to extract JSON array from the response (AI may wrap it in markdown, etc.).
    let json_str = if response.contains("```json") {
        response
            .split("```json")
            .nth(1)
            .and_then(|s| s.split("```").next())
            .unwrap_or(response)
            .trim()
    } else if response.contains('[') && response.contains(']') {
        // Extract the JSON array.
        let start = response
            .find('[')
            .ok_or_else(|| anyhow::anyhow!("no JSON array found"))?;
        let end = response
            .rfind(']')
            .ok_or_else(|| anyhow::anyhow!("no JSON array found"))?
            + 1;
        &response[start..end]
    } else {
        // Try treating the whole response as JSON.
        response
    };

    let findings: Vec<serde_json::Value> = serde_json::from_str(json_str)?;

    let mut comments = Vec::new();
    for finding in findings {
        let obj = finding
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("finding not an object"))?;

        let line_start = obj.get("line_start").and_then(|v| v.as_i64()).unwrap_or(1);
        let line_end = obj
            .get("line_end")
            .and_then(|v| v.as_i64())
            .unwrap_or(line_start);

        let severity = obj
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("suggestion")
            .to_string();

        let title = obj
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Code Review Finding")
            .to_string();

        let body = obj
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        comments.push(ReviewComment {
            file_path: "diff".to_string(),
            line_start,
            _line_end: line_end,
            severity,
            title,
            body,
        });
    }

    Ok(comments)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ai_response_json_array() {
        let json = r#"[
            {
                "line_start": 10,
                "line_end": 12,
                "severity": "critical",
                "title": "SQL Injection",
                "body": "Unsanitized input"
            }
        ]"#;

        let findings = parse_ai_response(json).expect("parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "SQL Injection");
        assert_eq!(findings[0].severity, "critical");
    }

    #[test]
    fn test_parse_ai_response_markdown_wrapped() {
        let json = r#"```json
        [{"line_start": 5, "severity": "minor", "title": "Test", "body": "msg"}]
        ```"#;

        let findings = parse_ai_response(json).expect("parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Test");
    }

    #[test]
    fn test_parse_ai_response_empty_array() {
        let json = "[]";
        let findings = parse_ai_response(json).expect("parse");
        assert_eq!(findings.len(), 0);
    }
}
