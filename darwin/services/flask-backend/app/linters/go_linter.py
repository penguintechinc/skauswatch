from pathlib import Path
import json
import time
from .base import BaseLinter, LintResult, LintIssue


class GoLinter(BaseLinter):
    name = "go"
    languages = ["go"]

    async def is_available(self) -> bool:
        """Check if golangci-lint is installed."""
        _, stdout, _ = await self._run_command(["golangci-lint", "--version"], Path.cwd())
        return "golangci-lint" in stdout

    async def lint(self, path: Path, files: list[str] | None = None) -> LintResult:
        """Run golangci-lint on Go files."""
        result = LintResult(linter=self.name, success=False)
        start = time.time()

        try:
            if not await self.is_available():
                result.error = "golangci-lint not installed"
                return result

            cmd = ["golangci-lint", "run", "--out-format=json"]
            if files:
                cmd.extend(files)
            else:
                cmd.append(str(path))

            exit_code, stdout, stderr = await self._run_command(cmd, path.parent)
            result.execution_time_ms = int((time.time() - start) * 1000)

            if exit_code == -1:
                result.error = stderr or "Command execution failed"
                return result

            if stdout.strip():
                data = json.loads(stdout)
                for issue in data.get("Issues", []):
                    result.issues.append(
                        LintIssue(
                            file=issue.get("Pos", {}).get("Filename", ""),
                            line=issue.get("Pos", {}).get("Line", 0),
                            column=issue.get("Pos", {}).get("Column", 0),
                            severity=issue.get("Severity", "warning").lower(),
                            rule_id=issue.get("FromLinter", ""),
                            message=issue.get("Text", ""),
                        )
                    )

            result.success = exit_code == 0
            return result

        except Exception as e:
            result.error = str(e)
            result.execution_time_ms = int((time.time() - start) * 1000)
            return result
