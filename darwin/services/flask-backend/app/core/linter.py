from pathlib import Path
from dataclasses import dataclass, field
import asyncio
from ..linters import (
    BaseLinter,
    LintResult,
    LintIssue,
    PythonLinter,
    GoLinter,
    JavaScriptLinter,
    AnsibleLinter,
    TerraformLinter,
    GHALinter,
    SecurityLinter,
)
from .detector import DetectionResult


@dataclass(slots=True)
class OrchestratorResult:
    results: list[LintResult] = field(default_factory=list)
    total_issues: int = 0
    errors: int = 0
    warnings: int = 0


class LinterOrchestrator:
    LINTER_MAP: dict[str, type[BaseLinter]] = {
        "python": PythonLinter,
        "go": GoLinter,
        "javascript": JavaScriptLinter,
        "ansible": AnsibleLinter,
        "terraform": TerraformLinter,
        "gha": GHALinter,
        "security": SecurityLinter,
    }

    def __init__(self):
        self._linter_cache: dict[str, BaseLinter] = {}

    async def run_linters(
        self,
        path: Path,
        detection: DetectionResult,
        files: list[str] | None = None,
        include_security: bool = True,
    ) -> OrchestratorResult:
        """Run appropriate linters based on detection result."""
        result = OrchestratorResult()

        # Get linters to run based on detection
        linter_names = detection.get_linters_for_result(detection)
        if include_security and "security" not in linter_names:
            linter_names.append("security")

        # Run linters concurrently
        tasks = [
            self.run_single_linter(name, path, files)
            for name in linter_names
        ]
        lint_results = await asyncio.gather(*tasks)

        # Process results
        for lint_result in lint_results:
            result.results.append(lint_result)
            result.total_issues += len(lint_result.issues)

            for issue in lint_result.issues:
                if issue.severity == "error":
                    result.errors += 1
                elif issue.severity == "warning":
                    result.warnings += 1

        return result

    async def run_single_linter(
        self, linter_name: str, path: Path, files: list[str] | None = None
    ) -> LintResult:
        """Run a specific linter."""
        linter = self._get_linter(linter_name)
        if linter is None:
            return LintResult(
                linter=linter_name,
                success=False,
                error=f"Unknown linter: {linter_name}",
            )

        return await linter.lint(path, files)

    def _get_linter(self, name: str) -> BaseLinter | None:
        """Get or create linter instance."""
        if name in self._linter_cache:
            return self._linter_cache[name]

        if name not in self.LINTER_MAP:
            return None

        linter = self.LINTER_MAP[name]()
        self._linter_cache[name] = linter
        return linter
