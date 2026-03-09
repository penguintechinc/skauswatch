from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
import asyncio
import time


@dataclass(slots=True)
class LintIssue:
    file: str
    line: int
    column: int
    severity: str  # "error", "warning", "info"
    rule_id: str
    message: str
    suggestion: str | None = None


@dataclass(slots=True)
class LintResult:
    linter: str
    success: bool
    issues: list[LintIssue] = field(default_factory=list)
    error: str | None = None
    execution_time_ms: int = 0


class BaseLinter(ABC):
    name: str = ""
    languages: list[str] = []

    @abstractmethod
    async def lint(self, path: Path, files: list[str] | None = None) -> LintResult:
        """Run linter on path, optionally limiting to specific files."""
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if linter tool is installed."""
        pass

    async def _run_command(
        self, cmd: list[str], cwd: Path, timeout: int = 120
    ) -> tuple[int, str, str]:
        """Run command and return (exit_code, stdout, stderr)."""
        start = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(cwd),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode or 0, stdout.decode(), stderr.decode()
        except asyncio.TimeoutError:
            proc.kill()
            return -1, "", "Command timeout"
        except Exception as e:
            return -1, "", str(e)
