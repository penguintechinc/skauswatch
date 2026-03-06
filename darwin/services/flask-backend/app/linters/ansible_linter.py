from pathlib import Path
import time
from .base import BaseLinter, LintResult, LintIssue


class AnsibleLinter(BaseLinter):
    name = "ansible"
    languages = ["ansible", "yaml"]

    async def is_available(self) -> bool:
        """Check if ansible-lint is installed."""
        _, stdout, _ = await self._run_command(["ansible-lint", "--version"], Path.cwd())
        return "ansible-lint" in stdout

    async def lint(self, path: Path, files: list[str] | None = None) -> LintResult:
        """Run ansible-lint on Ansible files."""
        result = LintResult(linter=self.name, success=False)
        start = time.time()

        try:
            if not await self.is_available():
                result.error = "ansible-lint not installed"
                return result

            cmd = ["ansible-lint", "-f", "parseable"]
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
                if len(parts) >= 4:
                    result.issues.append(
                        LintIssue(
                            file=parts[0],
                            line=int(parts[1]) if parts[1].isdigit() else 0,
                            column=int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                            severity="error" if "error" in line.lower() else "warning",
                            rule_id=parts[3].split()[0] if len(parts) > 3 else "",
                            message=":".join(parts[4:]) if len(parts) > 4 else "",
                        )
                    )

            result.success = exit_code == 0
            return result

        except Exception as e:
            result.error = str(e)
            result.execution_time_ms = int((time.time() - start) * 1000)
            return result
