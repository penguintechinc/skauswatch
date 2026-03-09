"""Sandbox management for git operations."""

from __future__ import annotations

import asyncio
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Sandbox:
    """Isolated sandbox environment for git operations."""

    id: str  # UUID
    path: Path  # /tmp/pr-reviewer/{uuid}
    created_at: datetime
    expires_at: datetime


class SandboxManager:
    """Manages creation and cleanup of sandboxed directories."""

    def __init__(
        self, base_path: str = "/tmp/pr-reviewer", default_timeout: int = 3600
    ) -> None:
        """Initialize sandbox manager.

        Args:
            base_path: Base directory for all sandboxes
            default_timeout: Default sandbox lifetime in seconds
        """
        self.base_path = Path(base_path)
        self.default_timeout = default_timeout
        self.base_path.mkdir(parents=True, exist_ok=True)

    async def create(self, timeout: int | None = None) -> Sandbox:
        """Create new sandbox directory with UUID.

        Args:
            timeout: Sandbox lifetime in seconds (uses default if None)

        Returns:
            Created Sandbox instance
        """
        sandbox_id = str(uuid.uuid4())
        sandbox_path = self.base_path / sandbox_id

        # Create sandbox directory
        sandbox_path.mkdir(parents=True, exist_ok=True)

        # Set ownership and permissions
        sandbox_path.chmod(0o700)

        # Calculate expiration
        created_at = datetime.utcnow()
        expires_at = created_at + timedelta(
            seconds=timeout or self.default_timeout
        )

        return Sandbox(
            id=sandbox_id,
            path=sandbox_path,
            created_at=created_at,
            expires_at=expires_at,
        )

    async def cleanup(self, sandbox: Sandbox) -> bool:
        """Remove sandbox directory completely.

        Args:
            sandbox: Sandbox to clean up

        Returns:
            True if cleanup successful, False otherwise
        """
        try:
            if sandbox.path.exists():
                shutil.rmtree(sandbox.path, ignore_errors=False)
            return True
        except Exception as e:
            # Log error but don't raise
            print(f"Failed to cleanup sandbox {sandbox.id}: {e}")
            return False

    async def cleanup_expired(self) -> int:
        """Scan for expired sandboxes and clean them up.

        Returns:
            Count of cleaned up sandboxes
        """
        if not self.base_path.exists():
            return 0

        cleaned = 0
        now = datetime.utcnow()

        # Iterate through all directories in base path
        for sandbox_dir in self.base_path.iterdir():
            if not sandbox_dir.is_dir():
                continue

            try:
                # Check if directory name is a valid UUID
                sandbox_id = sandbox_dir.name
                uuid.UUID(sandbox_id)  # Validate UUID format

                # Get directory creation time
                stat = sandbox_dir.stat()
                created_at = datetime.fromtimestamp(stat.st_ctime)
                expires_at = created_at + timedelta(seconds=self.default_timeout)

                # Cleanup if expired
                if now >= expires_at:
                    sandbox = Sandbox(
                        id=sandbox_id,
                        path=sandbox_dir,
                        created_at=created_at,
                        expires_at=expires_at,
                    )
                    if await self.cleanup(sandbox):
                        cleaned += 1

            except (ValueError, OSError):
                # Skip invalid directories
                continue

        return cleaned

    def get_sandbox(self, sandbox_id: str) -> Sandbox | None:
        """Get sandbox by ID if it exists.

        Args:
            sandbox_id: Sandbox UUID

        Returns:
            Sandbox instance or None if not found
        """
        try:
            # Validate UUID format
            uuid.UUID(sandbox_id)
        except ValueError:
            return None

        sandbox_path = self.base_path / sandbox_id

        if not sandbox_path.exists() or not sandbox_path.is_dir():
            return None

        # Get directory creation time
        try:
            stat = sandbox_path.stat()
            created_at = datetime.fromtimestamp(stat.st_ctime)
            expires_at = created_at + timedelta(seconds=self.default_timeout)

            return Sandbox(
                id=sandbox_id,
                path=sandbox_path,
                created_at=created_at,
                expires_at=expires_at,
            )
        except OSError:
            return None

    async def run_in_sandbox(
        self,
        sandbox: Sandbox,
        command: list[str],
        env: dict[str, str] | None = None,
        timeout: int = 300,
    ) -> tuple[int, str, str]:
        """Run command in sandbox directory.

        Args:
            sandbox: Sandbox to run command in
            command: Command and arguments to execute
            env: Additional environment variables
            timeout: Command timeout in seconds

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        # Build environment
        process_env = {}
        if env:
            process_env.update(env)

        try:
            # Create subprocess
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(sandbox.path),
                env=process_env or None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait for completion with timeout
            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )

            return (
                process.returncode or 0,
                stdout_data.decode("utf-8", errors="replace"),
                stderr_data.decode("utf-8", errors="replace"),
            )

        except asyncio.TimeoutError:
            # Kill process on timeout
            if process:
                process.kill()
                await process.wait()
            return (-1, "", f"Command timed out after {timeout} seconds")

        except Exception as e:
            return (-1, "", f"Command execution failed: {str(e)}")
