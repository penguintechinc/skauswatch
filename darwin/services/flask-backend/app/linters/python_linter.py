from pathlib import Path
import json
import time
from .base import BaseLinter, LintResult, LintIssue


class PythonLinter(BaseLinter):
    name = "python"
    languages = ["python"]

    async def is_available(self) -> bool:
        """Check if flake8 is installed."""
        _, stdout, _ = await self._run_command(["flake8", "--version"], Path.cwd())
        return "flake8" in stdout

    async def lint(self, path: Path, files: list[str] | None = None) -> LintResult:
        """Run flake8 on Python files."""
        result = LintResult(linter=self.name, success=False)
        start = time.time()

        try:
            if not await self.is_available():
                result.error = "flake8 not installed"
                return result

            cmd = ["flake8", "--format=json"]
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
                issues = json.loads(stdout)
                for issue in issues:
                    result.issues.append(
                        LintIssue(
                            file=issue.get("filename", ""),
                            line=issue.get("line_number", 0),
                            column=issue.get("column_number", 0),
                            severity="error"
                            if issue.get("type") == "E"
                            else "warning",
                            rule_id=issue.get("code", ""),
                            message=issue.get("text", ""),
                        )
                    )

            result.success = exit_code == 0
            return result

        except Exception as e:
            result.error = str(e)
            result.execution_time_ms = int((time.time() - start) * 1000)
            return result
