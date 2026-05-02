"""Darwin Code Security Scanner Integration Bridge.

Darwin is a code security scanning tool that integrates with GitHub
to analyze pull requests for security vulnerabilities.

This bridge allows SkausWatch to leverage Darwin's scanning capabilities
for code review and security analysis.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger()

# Darwin submodule path
DARWIN_PATH = Path(__file__).parent / "darwin"


class DarwinBridge:
    """Bridge to Darwin code security scanner."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Darwin bridge.

        Args:
            config: Configuration dict with keys:
                - github_token: GitHub API token
                - ai_provider: 'ollama' or 'claude'
                - ollama_url: Ollama server URL (if using Ollama)
                - anthropic_api_key: Anthropic API key (if using Claude)
        """
        self.config = config
        self._darwin_available = False
        self._github_client = None
        self._ai_provider = None

        self._initialize()

    def _initialize(self) -> None:
        """Initialize Darwin integration."""
        # Check if Darwin submodule exists
        if not DARWIN_PATH.exists():
            logger.warning("Darwin submodule not found", path=str(DARWIN_PATH))
            return

        # Add Darwin to Python path
        darwin_backend = DARWIN_PATH / "services" / "flask_backend"
        if darwin_backend.exists():
            sys.path.insert(0, str(darwin_backend))
            self._darwin_available = True
            logger.info("Darwin integration initialized")
        else:
            logger.warning("Darwin backend not found", expected=str(darwin_backend))

    async def initialize_clients(self) -> None:
        """Initialize GitHub and AI clients."""
        if not self._darwin_available:
            return

        try:
            # Initialize GitHub client
            from app.integrations.github import GitHubClient

            github_token = self.config.get("github_token")
            if github_token:
                self._github_client = GitHubClient(github_token)
                logger.info("Darwin GitHub client initialized")

            # Initialize AI provider
            provider = self.config.get("ai_provider", "ollama")

            if provider == "claude":
                from app.providers.claude import ClaudeProvider

                self._ai_provider = ClaudeProvider(self.config)
            else:
                from app.providers.ollama import OllamaProvider

                self._ai_provider = OllamaProvider(self.config)

            logger.info("Darwin AI provider initialized", provider=provider)

        except ImportError as e:
            logger.error("Failed to import Darwin modules", error=str(e))
        except Exception as e:
            logger.error("Darwin initialization error", error=str(e))

    @property
    def is_available(self) -> bool:
        """Check if Darwin is available."""
        return self._darwin_available

    async def scan_pull_request(
        self, repo: str, pr_number: int, scan_types: List[str] = None
    ) -> Dict[str, Any]:
        """
        Scan a GitHub pull request for security issues.

        Args:
            repo: Repository name (owner/repo format)
            pr_number: Pull request number
            scan_types: Types of scans to perform (optional)

        Returns:
            Scan results with findings
        """
        if not self._darwin_available:
            return {
                "error": "Darwin not available",
                "repository": repo,
                "pr_number": pr_number,
            }

        if not self._github_client:
            return {
                "error": "GitHub client not initialized",
                "repository": repo,
                "pr_number": pr_number,
            }

        scan_types = scan_types or ["security", "code_quality", "secrets"]

        try:
            # Get PR data
            pr_data = await self._github_client.get_pull_request(repo, pr_number)
            files = await self._github_client.get_pr_files(repo, pr_number)

            findings = []
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }

            # Scan each file
            for file in files:
                if not self._is_scannable(file):
                    continue

                file_findings = await self._scan_file(file, scan_types)
                for finding in file_findings:
                    findings.append(finding)
                    severity = finding.get("severity", "info")
                    if severity in severity_counts:
                        severity_counts[severity] += 1

            return {
                "repository": repo,
                "pr_number": pr_number,
                "pr_title": pr_data.get("title"),
                "scan_types": scan_types,
                "findings": findings,
                "severity_counts": severity_counts,
                "total_findings": len(findings),
                "files_scanned": len([f for f in files if self._is_scannable(f)]),
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error("PR scan failed", repo=repo, pr_number=pr_number, error=str(e))
            return {
                "error": str(e),
                "repository": repo,
                "pr_number": pr_number,
            }

    async def scan_code(
        self,
        code: str,
        language: str,
        filename: str = "code.txt",
        scan_types: List[str] = None,
    ) -> Dict[str, Any]:
        """
        Scan code snippet for security issues.

        Args:
            code: Code content to scan
            language: Programming language
            filename: Optional filename for context
            scan_types: Types of scans to perform

        Returns:
            Scan results with findings
        """
        if not self._darwin_available:
            return {
                "error": "Darwin not available",
                "language": language,
            }

        scan_types = scan_types or ["security", "secrets"]

        try:
            findings = []

            # Run security analysis
            if "security" in scan_types and self._ai_provider:
                security_findings = await self._analyze_security(
                    code, language, filename
                )
                findings.extend(security_findings)

            # Check for secrets
            if "secrets" in scan_types:
                secret_findings = self._scan_for_secrets(code, filename)
                findings.extend(secret_findings)

            return {
                "language": language,
                "filename": filename,
                "scan_types": scan_types,
                "findings": findings,
                "total_findings": len(findings),
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error("Code scan failed", error=str(e))
            return {
                "error": str(e),
                "language": language,
            }

    async def _scan_file(
        self, file: Dict[str, Any], scan_types: List[str]
    ) -> List[Dict[str, Any]]:
        """Scan a single file."""
        findings = []
        filename = file.get("filename", "")
        patch = file.get("patch", "")

        if not patch:
            return findings

        # Determine language from extension
        language = self._detect_language(filename)

        # Extract added lines from patch
        added_code = self._extract_added_lines(patch)

        if not added_code:
            return findings

        # Security analysis
        if "security" in scan_types and self._ai_provider:
            security_findings = await self._analyze_security(
                added_code, language, filename
            )
            for finding in security_findings:
                finding["file"] = filename
            findings.extend(security_findings)

        # Secret scanning
        if "secrets" in scan_types:
            secret_findings = self._scan_for_secrets(added_code, filename)
            findings.extend(secret_findings)

        return findings

    async def _analyze_security(
        self, code: str, language: str, filename: str
    ) -> List[Dict[str, Any]]:
        """Use AI to analyze code for security issues."""
        if not self._ai_provider:
            return []

        try:
            prompt = f"""Analyze the following {language} code for security vulnerabilities.
Focus on:
- SQL injection
- XSS vulnerabilities
- Command injection
- Path traversal
- Insecure deserialization
- Hardcoded secrets
- Authentication issues
- Authorization flaws

Code from {filename}:
```{language}
{code}
```

For each issue found, provide:
1. Severity (critical/high/medium/low)
2. Issue type
3. Description
4. Line numbers if identifiable
5. Remediation suggestion

If no issues found, respond with "No security issues found."
"""

            response = await self._ai_provider.analyze(prompt)
            return self._parse_security_response(response, filename)

        except Exception as e:
            logger.error("Security analysis failed", error=str(e))
            return []

    def _parse_security_response(
        self, response: str, filename: str
    ) -> List[Dict[str, Any]]:
        """Parse AI security analysis response."""
        findings = []

        if "no security issues found" in response.lower():
            return findings

        # Basic parsing - in production, use more sophisticated parsing
        lines = response.split("\n")
        current_finding = None

        for line in lines:
            line = line.strip()
            if not line:
                if current_finding:
                    findings.append(current_finding)
                    current_finding = None
                continue

            # Look for severity indicators
            for severity in ["critical", "high", "medium", "low"]:
                if severity in line.lower():
                    if current_finding:
                        findings.append(current_finding)
                    current_finding = {
                        "severity": severity,
                        "file": filename,
                        "description": line,
                        "source": "darwin_ai",
                    }
                    break

        if current_finding:
            findings.append(current_finding)

        return findings

    def _scan_for_secrets(self, code: str, filename: str) -> List[Dict[str, Any]]:
        """Scan code for hardcoded secrets."""
        import re

        findings = []

        # Secret patterns to detect
        patterns = [
            (r'(?i)api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', "API Key"),
            (r'(?i)secret[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', "Secret Key"),
            (r'(?i)password\s*[=:]\s*["\']([^"\']+)["\']', "Password"),
            (r'(?i)token\s*[=:]\s*["\']([^"\']+)["\']', "Token"),
            (
                r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']?([A-Z0-9]{20})["\']?',
                "AWS Access Key",
            ),
            (
                r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
                "AWS Secret Key",
            ),
            (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
            (r"sk-[A-Za-z0-9]{48}", "OpenAI API Key"),
            (r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----", "Private Key"),
        ]

        for pattern, secret_type in patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                findings.append(
                    {
                        "severity": "critical",
                        "type": "hardcoded_secret",
                        "secret_type": secret_type,
                        "file": filename,
                        "line_content": match.group(0)[:50] + "...",
                        "description": f"Potential hardcoded {secret_type} detected",
                        "source": "darwin_secrets",
                    }
                )

        return findings

    def _is_scannable(self, file: Dict[str, Any]) -> bool:
        """Check if file should be scanned."""
        filename = file.get("filename", "")
        status = file.get("status", "")

        # Skip deleted files
        if status == "removed":
            return False

        # Scannable extensions
        scannable_exts = {
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".java",
            ".go",
            ".rb",
            ".php",
            ".c",
            ".cpp",
            ".h",
            ".hpp",
            ".cs",
            ".rs",
            ".swift",
            ".kt",
            ".sh",
            ".bash",
            ".yaml",
            ".yml",
            ".json",
            ".xml",
            ".sql",
        }

        ext = Path(filename).suffix.lower()
        return ext in scannable_exts

    def _detect_language(self, filename: str) -> str:
        """Detect programming language from filename."""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".c": "c",
            ".cpp": "cpp",
            ".h": "c",
            ".hpp": "cpp",
            ".cs": "csharp",
            ".rs": "rust",
            ".swift": "swift",
            ".kt": "kotlin",
            ".sh": "bash",
            ".bash": "bash",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".json": "json",
            ".xml": "xml",
            ".sql": "sql",
        }

        ext = Path(filename).suffix.lower()
        return ext_map.get(ext, "text")

    def _extract_added_lines(self, patch: str) -> str:
        """Extract added lines from a git patch."""
        added_lines = []
        for line in patch.split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])
        return "\n".join(added_lines)
