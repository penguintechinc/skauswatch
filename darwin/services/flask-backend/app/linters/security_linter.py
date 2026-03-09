from pathlib import Path
import json
import time
from .base import BaseLinter, LintResult, LintIssue


class SecurityLinter(BaseLinter):
    name = "security"
    languages = ["all"]

    async def is_available(self) -> bool:
        """Check if gitleaks is installed."""
        _, stdout, _ = await self._run_command(["gitleaks", "version"], Path.cwd())
        return "gitleaks" in stdout or "version" in stdout

    async def lint(self, path: Path, files: list[str] | None = None) -> LintResult:
        """Run gitleaks for secrets detection."""
        result = LintResult(linter=self.name, success=False)
        start = time.time()

        try:
            if not await self.is_available():
                result.error = "gitleaks not installed"
                return result

            cmd = [
                "gitleaks",
                "detect",
                "--source",
                str(path),
                "--report-path=/tmp/gitleaks-report.json",
                "--verbose",
            ]

            exit_code, stdout, stderr = await self._run_command(cmd, path.parent)
            result.execution_time_ms = int((time.time() - start) * 1000)

            if exit_code == -1:
                result.error = stderr or "Command execution failed"
                return result

            try:
                with open("/tmp/gitleaks-report.json") as f:
                    data = json.load(f)
                    for leak in data.get("Leaks", []):
                        result.issues.append(
                            LintIssue(
                                file=leak.get("File", ""),
                                line=leak.get("StartLine", 0),
                                column=leak.get("StartColumn", 0),
                                severity="error",
                                rule_id=leak.get("RuleID", ""),
                                message=leak.get("Match", ""),
                            )
                        )
            except FileNotFoundError:
                pass

            result.success = exit_code == 0
            return result

        except Exception as e:
            result.error = str(e)
            result.execution_time_ms = int((time.time() - start) * 1000)
            return result
