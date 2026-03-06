from dataclasses import dataclass, field
from pathlib import Path
import json
import re

@dataclass(slots=True)
class DetectionResult:
    languages: dict[str, float] = field(default_factory=dict)   # language -> confidence (0-1)
    frameworks: dict[str, float] = field(default_factory=dict)  # framework -> confidence
    iac_tools: list[str] = field(default_factory=list)          # detected IaC tools
    file_mapping: dict[str, str] = field(default_factory=dict)  # file -> language

class LanguageDetector:
    # File extension to language mapping
    LANGUAGE_EXTENSIONS: dict[str, str] = {
        ".py": "python",
        ".go": "go",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".rs": "rust",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".swift": "swift",
        ".kt": "kotlin",
        ".kts": "kotlin",
        ".scala": "scala",
        ".sh": "shell",
        ".bash": "shell",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".json": "json",
        ".tf": "terraform",
        ".hcl": "terraform",
        ".sql": "sql",
        ".md": "markdown",
        ".vue": "vue",
        ".svelte": "svelte",
    }

    # Framework detection patterns - file patterns and content patterns
    FRAMEWORK_INDICATORS: dict[str, list[dict]] = {
        "react": [
            {"file": "package.json", "content": '"react"'},
            {"file": "*.tsx", "exists": True},
            {"file": "*.jsx", "exists": True},
        ],
        "vue": [
            {"file": "package.json", "content": '"vue"'},
            {"file": "*.vue", "exists": True},
        ],
        "angular": [
            {"file": "angular.json", "exists": True},
            {"file": "package.json", "content": '"@angular/core"'},
        ],
        "django": [
            {"file": "manage.py", "exists": True},
            {"file": "settings.py", "content": "django"},
            {"file": "requirements.txt", "content": "django"},
        ],
        "flask": [
            {"file": "requirements.txt", "content": "flask"},
            {"file": "*.py", "content": "from flask import"},
        ],
        "fastapi": [
            {"file": "requirements.txt", "content": "fastapi"},
            {"file": "*.py", "content": "from fastapi import"},
        ],
        "express": [
            {"file": "package.json", "content": '"express"'},
        ],
        "nextjs": [
            {"file": "next.config.js", "exists": True},
            {"file": "next.config.mjs", "exists": True},
            {"file": "package.json", "content": '"next"'},
        ],
        "spring": [
            {"file": "pom.xml", "content": "spring"},
            {"file": "build.gradle", "content": "spring"},
        ],
        "rails": [
            {"file": "Gemfile", "content": "rails"},
            {"file": "config/routes.rb", "exists": True},
        ],
        "laravel": [
            {"file": "composer.json", "content": "laravel"},
            {"file": "artisan", "exists": True},
        ],
    }

    # IaC detection patterns
    IAC_INDICATORS: dict[str, list[dict]] = {
        "ansible": [
            {"file": "ansible.cfg", "exists": True},
            {"file": "playbook.yml", "exists": True},
            {"file": "playbook.yaml", "exists": True},
            {"file": "*.yml", "content": "hosts:"},
            {"file": "roles/*/tasks/main.yml", "exists": True},
        ],
        "terraform": [
            {"file": "*.tf", "exists": True},
            {"file": "terraform.tfstate", "exists": True},
            {"file": "*.tfvars", "exists": True},
        ],
        "github_actions": [
            {"file": ".github/workflows/*.yml", "exists": True},
            {"file": ".github/workflows/*.yaml", "exists": True},
        ],
        "kubernetes": [
            {"file": "*.yaml", "content": "apiVersion:"},
            {"file": "*.yaml", "content": "kind: Deployment"},
            {"file": "*.yaml", "content": "kind: Service"},
            {"file": "k8s/*.yaml", "exists": True},
        ],
        "cloudformation": [
            {"file": "*.yaml", "content": "AWSTemplateFormatVersion"},
            {"file": "*.json", "content": "AWSTemplateFormatVersion"},
        ],
        "docker": [
            {"file": "Dockerfile", "exists": True},
            {"file": "docker-compose.yml", "exists": True},
            {"file": "docker-compose.yaml", "exists": True},
        ],
    }

    def __init__(self):
        pass

    def detect_from_files(self, files: list[str]) -> DetectionResult:
        """Detect languages and frameworks from a list of file paths."""
        result = DetectionResult()

        # Count languages by extension
        lang_counts: dict[str, int] = {}
        for file_path in files:
            ext = Path(file_path).suffix.lower()
            if ext in self.LANGUAGE_EXTENSIONS:
                lang = self.LANGUAGE_EXTENSIONS[ext]
                lang_counts[lang] = lang_counts.get(lang, 0) + 1
                result.file_mapping[file_path] = lang

        # Calculate confidence based on file counts
        total_files = sum(lang_counts.values()) or 1
        for lang, count in lang_counts.items():
            result.languages[lang] = round(count / total_files, 3)

        return result

    def detect_from_directory(self, directory: Path,
                             file_contents: dict[str, str] | None = None) -> DetectionResult:
        """Detect languages, frameworks, and IaC from a directory."""
        # Get all files
        files = [str(f.relative_to(directory)) for f in directory.rglob("*") if f.is_file()]
        result = self.detect_from_files(files)

        # Detect frameworks
        result.frameworks = self._detect_frameworks(directory, files, file_contents or {})

        # Detect IaC tools
        result.iac_tools = self._detect_iac(directory, files, file_contents or {})

        return result

    def _detect_frameworks(self, directory: Path, files: list[str],
                          contents: dict[str, str]) -> dict[str, float]:
        """Detect frameworks based on indicator patterns."""
        frameworks: dict[str, float] = {}

        for framework, indicators in self.FRAMEWORK_INDICATORS.items():
            matches = 0
            for indicator in indicators:
                if self._check_indicator(directory, files, contents, indicator):
                    matches += 1

            if matches > 0:
                confidence = min(1.0, matches / len(indicators) + 0.3)
                frameworks[framework] = round(confidence, 2)

        return frameworks

    def _detect_iac(self, directory: Path, files: list[str],
                   contents: dict[str, str]) -> list[str]:
        """Detect IaC tools based on indicator patterns."""
        iac_tools: list[str] = []

        for tool, indicators in self.IAC_INDICATORS.items():
            for indicator in indicators:
                if self._check_indicator(directory, files, contents, indicator):
                    if tool not in iac_tools:
                        iac_tools.append(tool)
                    break

        return iac_tools

    def _check_indicator(self, directory: Path, files: list[str],
                        contents: dict[str, str], indicator: dict) -> bool:
        """Check if an indicator matches."""
        file_pattern = indicator.get("file", "")

        # Check for file existence with glob pattern
        if indicator.get("exists"):
            import fnmatch
            for f in files:
                if fnmatch.fnmatch(f, file_pattern):
                    return True
            return False

        # Check for content in file
        if "content" in indicator:
            import fnmatch
            search_text = indicator["content"].lower()
            for f in files:
                if fnmatch.fnmatch(f, file_pattern):
                    # Check cached content or try to read
                    content = contents.get(f, "").lower()
                    if search_text in content:
                        return True

        return False

    def get_primary_language(self, result: DetectionResult) -> str | None:
        """Get the primary language from detection result."""
        if not result.languages:
            return None
        return max(result.languages.items(), key=lambda x: x[1])[0]

    def get_linters_for_result(self, result: DetectionResult) -> list[str]:
        """Get list of linter names to run based on detection."""
        linters = []

        # Language-based linters
        lang_linter_map = {
            "python": "python",
            "go": "go",
            "javascript": "javascript",
            "typescript": "javascript",
            "java": "java",
            "ruby": "ruby",
            "php": "php",
            "rust": "rust",
            "c": "c",
            "cpp": "c",
        }

        for lang in result.languages:
            if lang in lang_linter_map:
                linter = lang_linter_map[lang]
                if linter not in linters:
                    linters.append(linter)

        # IaC linters
        iac_linter_map = {
            "ansible": "ansible",
            "terraform": "terraform",
            "github_actions": "gha",
            "kubernetes": "kubernetes",
            "docker": "docker",
        }

        for tool in result.iac_tools:
            if tool in iac_linter_map:
                linter = iac_linter_map[tool]
                if linter not in linters:
                    linters.append(linter)

        return linters
