from pathlib import Path
import json
import time
from .base import BaseLinter, LintResult, LintIssue


class JavaScriptLinter(BaseLinter):
    name = "javascript"
    languages = ["javascript", "typescript"]

    async def is_available(self) -> bool:
        """Check if eslint is installed."""
        _, stdout, _ = await self._run_command(["eslint", "--version"], Path.cwd())
        return "v" in stdout

    async def lint(self, path: Path, files: list[str] | None = None) -> LintResult:
        """Run eslint on JS/TS files."""
        result = LintResult(linter=self.name, success=False)
        start = time.time()

        try:
            if not await self.is_available():
                result.error = "eslint not installed"
                return result

            cmd = ["eslint", "--format=json"]
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
                for file_result in data:
                    for message in file_result.get("messages", []):
                        result.issues.append(
                            LintIssue(
                                file=file_result.get("filePath", ""),
                                line=message.get("line", 0),
                                column=message.get("column", 0),
                                severity=message.get("severity", 1),
                                rule_id=message.get("ruleId", ""),
                                message=message.get("message", ""),
                            )
                        )

            result.success = len(result.issues) == 0
            return result

        except Exception as e:
            result.error = str(e)
            result.execution_time_ms = int((time.time() - start) * 1000)
            return result
