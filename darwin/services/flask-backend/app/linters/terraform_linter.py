from pathlib import Path
import json
import time
from .base import BaseLinter, LintResult, LintIssue


class TerraformLinter(BaseLinter):
    name = "terraform"
    languages = ["terraform", "hcl"]

    async def is_available(self) -> bool:
        """Check if tflint is installed."""
        _, stdout, _ = await self._run_command(["tflint", "--version"], Path.cwd())
        return "tflint" in stdout

    async def lint(self, path: Path, files: list[str] | None = None) -> LintResult:
        """Run tflint on Terraform files."""
        result = LintResult(linter=self.name, success=False)
        start = time.time()

        try:
            if not await self.is_available():
                result.error = "tflint not installed"
                return result

            cmd = ["tflint", "--format=json"]
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
                for issue in data.get("issues", []):
                    result.issues.append(
                        LintIssue(
                            file=issue.get("range", {}).get("filename", ""),
                            line=issue.get("range", {}).get("start", {}).get("line", 0),
                            column=issue.get("range", {}).get("start", {}).get("column", 0),
                            severity=issue.get("severity", "warning").lower(),
                            rule_id=issue.get("rule", {}).get("name", ""),
                            message=issue.get("message", ""),
                        )
                    )

            result.success = len(result.issues) == 0
            return result

        except Exception as e:
            result.error = str(e)
            result.execution_time_ms = int((time.time() - start) * 1000)
            return result
