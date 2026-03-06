from pathlib import Path
import time
from .base import BaseLinter, LintResult, LintIssue


class GHALinter(BaseLinter):
    name = "gha"
    languages = ["github-actions", "yaml"]

    async def is_available(self) -> bool:
        """Check if actionlint is installed."""
        _, stdout, _ = await self._run_command(["actionlint", "-version"], Path.cwd())
        return "actionlint" in stdout

    async def lint(self, path: Path, files: list[str] | None = None) -> LintResult:
        """Run actionlint on GitHub Actions workflows."""
        result = LintResult(linter=self.name, success=False)
        start = time.time()

        try:
            if not await self.is_available():
                result.error = "actionlint not installed"
                return result

            cmd = ["actionlint"]
            if files:
                cmd.extend(files)
            else:
                cmd.append(str(path))

            exit_code, stdout, stderr = await self._run_command(cmd, path.parent)
            result.execution_time_ms = int((time.time() - start) * 1000)

            if exit_code == -1:
                result.error = stderr or "Command execution failed"
                return result

            for line in stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split(":")
                if len(parts) >= 3:
                    try:
                        result.issues.append(
                            LintIssue(
                                file=parts[0],
                                line=int(parts[1]) if parts[1].isdigit() else 0,
                                column=int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                                severity="error",
                                rule_id="actionlint",
                                message=":".join(parts[3:]) if len(parts) > 3 else "",
                            )
                        )
                    except ValueError:
                        pass

            result.success = exit_code == 0
            return result

        except Exception as e:
            result.error = str(e)
            result.execution_time_ms = int((time.time() - start) * 1000)
            return result
