"""Git clone operations with authentication."""

from __future__ import annotations

import asyncio
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .credentials import CredentialManager, GitCredential
from .sandbox import Sandbox, SandboxManager


@dataclass(slots=True)
class CloneResult:
    """Result of a git clone operation."""

    success: bool
    sandbox: Sandbox
    repo_path: Path
    error: str | None = None
    branch: str | None = None
    commit_sha: str | None = None


class GitCloner:
    """Handles git clone operations with various authentication methods."""

    def __init__(
        self,
        sandbox_manager: SandboxManager,
        credential_manager: CredentialManager,
    ) -> None:
        """Initialize git cloner.

        Args:
            sandbox_manager: Manager for sandboxed directories
            credential_manager: Manager for credential encryption
        """
        self.sandbox = sandbox_manager
        self.credentials = credential_manager

    async def clone(
        self,
        url: str,
        credential: GitCredential | None = None,
        branch: str | None = None,
        depth: int | None = 1,
        timeout: int = 300,
    ) -> CloneResult:
        """Clone repository to sandbox.

        Args:
            url: Git repository URL
            credential: Optional credential for authentication
            branch: Specific branch to clone
            depth: Clone depth (None for full clone)
            timeout: Operation timeout in seconds

        Returns:
            CloneResult with sandbox and repository information
        """
        # Create sandbox
        sandbox = await self.sandbox.create()

        # Build clone command
        cmd = ["git", "clone"]

        if depth is not None:
            cmd.extend(["--depth", str(depth)])

        if branch:
            cmd.extend(["--branch", branch])

        # Determine authentication method
        if credential:
            if credential.auth_type == "https_token":
                # Token will be embedded in URL
                # Note: Token retrieval from DB should be done by caller
                return await self._clone_error(
                    sandbox,
                    "https_token auth requires token to be provided via "
                    "clone_with_token()",
                )
            elif credential.auth_type == "ssh_key":
                # SSH key auth
                # Note: Key retrieval from DB should be done by caller
                return await self._clone_error(
                    sandbox,
                    "ssh_key auth requires key to be provided via "
                    "clone_with_ssh_key()",
                )

        # No authentication - public repository
        cmd.append(url)
        cmd.append("repo")  # Clone into 'repo' subdirectory

        # Execute clone
        exit_code, stdout, stderr = await self.sandbox.run_in_sandbox(
            sandbox, cmd, timeout=timeout
        )

        if exit_code != 0:
            return CloneResult(
                success=False,
                sandbox=sandbox,
                repo_path=sandbox.path / "repo",
                error=f"Git clone failed: {stderr}",
            )

        # Get commit info
        repo_path = sandbox.path / "repo"
        commit_info = await self.get_commit_info(repo_path)

        return CloneResult(
            success=True,
            sandbox=sandbox,
            repo_path=repo_path,
            branch=branch or commit_info.get("branch"),
            commit_sha=commit_info.get("sha"),
        )

    async def clone_with_token(
        self,
        url: str,
        token: str,
        sandbox: Sandbox,
        branch: str | None = None,
        depth: int | None = 1,
        timeout: int = 300,
    ) -> CloneResult:
        """Clone using HTTPS token authentication.

        Args:
            url: Git repository URL
            token: Authentication token
            sandbox: Sandbox to clone into
            branch: Specific branch to clone
            depth: Clone depth (None for full clone)
            timeout: Operation timeout in seconds

        Returns:
            CloneResult with repository information
        """
        # Build authenticated URL
        auth_url = self.credentials.build_auth_url(url, token)

        # Build clone command
        cmd = ["git", "clone"]

        if depth is not None:
            cmd.extend(["--depth", str(depth)])

        if branch:
            cmd.extend(["--branch", branch])

        cmd.append(auth_url)
        cmd.append("repo")

        # Execute clone (token will be hidden in logs)
        exit_code, stdout, stderr = await self.sandbox.run_in_sandbox(
            sandbox, cmd, timeout=timeout
        )

        if exit_code != 0:
            # Remove token from error message
            safe_stderr = stderr.replace(token, "***")
            return CloneResult(
                success=False,
                sandbox=sandbox,
                repo_path=sandbox.path / "repo",
                error=f"Git clone failed: {safe_stderr}",
            )

        # Get commit info
        repo_path = sandbox.path / "repo"
        commit_info = await self.get_commit_info(repo_path)

        return CloneResult(
            success=True,
            sandbox=sandbox,
            repo_path=repo_path,
            branch=branch or commit_info.get("branch"),
            commit_sha=commit_info.get("sha"),
        )

    async def clone_with_ssh_key(
        self,
        url: str,
        private_key: str,
        passphrase: str | None,
        sandbox: Sandbox,
        branch: str | None = None,
        depth: int | None = 1,
        timeout: int = 300,
    ) -> CloneResult:
        """Clone using SSH key authentication.

        Args:
            url: Git repository URL (SSH format)
            private_key: SSH private key content
            passphrase: Optional key passphrase
            sandbox: Sandbox to clone into
            branch: Specific branch to clone
            depth: Clone depth (None for full clone)
            timeout: Operation timeout in seconds

        Returns:
            CloneResult with repository information
        """
        # Write private key to temp file in sandbox
        key_path = sandbox.path / "ssh_key"
        try:
            key_path.write_text(private_key)
            key_path.chmod(0o600)

            # Build SSH command
            ssh_cmd = self.credentials.get_ssh_command(str(key_path), passphrase)

            # Build clone command
            cmd = ["git", "clone"]

            if depth is not None:
                cmd.extend(["--depth", str(depth)])

            if branch:
                cmd.extend(["--branch", branch])

            cmd.append(url)
            cmd.append("repo")

            # Execute clone with SSH command
            env = {"GIT_SSH_COMMAND": ssh_cmd}
            exit_code, stdout, stderr = await self.sandbox.run_in_sandbox(
                sandbox, cmd, env=env, timeout=timeout
            )

            if exit_code != 0:
                return CloneResult(
                    success=False,
                    sandbox=sandbox,
                    repo_path=sandbox.path / "repo",
                    error=f"Git clone failed: {stderr}",
                )

            # Get commit info
            repo_path = sandbox.path / "repo"
            commit_info = await self.get_commit_info(repo_path)

            return CloneResult(
                success=True,
                sandbox=sandbox,
                repo_path=repo_path,
                branch=branch or commit_info.get("branch"),
                commit_sha=commit_info.get("sha"),
            )

        finally:
            # Always cleanup SSH key
            try:
                if key_path.exists():
                    key_path.unlink()
            except Exception:
                pass

    async def get_commit_info(self, repo_path: Path) -> dict[str, str]:
        """Get current commit SHA, author, and message.

        Args:
            repo_path: Path to git repository

        Returns:
            Dictionary with commit information
        """
        info: dict[str, str] = {}

        # Get commit SHA
        cmd = ["git", "rev-parse", "HEAD"]
        exit_code, stdout, stderr = await self._run_git_command(repo_path, cmd)
        if exit_code == 0:
            info["sha"] = stdout.strip()

        # Get branch name
        cmd = ["git", "rev-parse", "--abbrev-ref", "HEAD"]
        exit_code, stdout, stderr = await self._run_git_command(repo_path, cmd)
        if exit_code == 0:
            info["branch"] = stdout.strip()

        # Get commit author
        cmd = ["git", "log", "-1", "--pretty=format:%an <%ae>"]
        exit_code, stdout, stderr = await self._run_git_command(repo_path, cmd)
        if exit_code == 0:
            info["author"] = stdout.strip()

        # Get commit message
        cmd = ["git", "log", "-1", "--pretty=format:%s"]
        exit_code, stdout, stderr = await self._run_git_command(repo_path, cmd)
        if exit_code == 0:
            info["message"] = stdout.strip()

        return info

    async def get_changed_files(
        self, repo_path: Path, base_ref: str, head_ref: str
    ) -> list[str]:
        """Get list of changed files between refs.

        Args:
            repo_path: Path to git repository
            base_ref: Base reference (e.g., 'main', commit SHA)
            head_ref: Head reference (e.g., 'feature-branch', commit SHA)

        Returns:
            List of changed file paths
        """
        cmd = ["git", "diff", "--name-only", f"{base_ref}...{head_ref}"]
        exit_code, stdout, stderr = await self._run_git_command(repo_path, cmd)

        if exit_code != 0:
            return []

        return [line.strip() for line in stdout.split("\n") if line.strip()]

    async def get_file_diff(
        self, repo_path: Path, base_ref: str, head_ref: str
    ) -> str:
        """Get unified diff between refs.

        Args:
            repo_path: Path to git repository
            base_ref: Base reference (e.g., 'main', commit SHA)
            head_ref: Head reference (e.g., 'feature-branch', commit SHA)

        Returns:
            Unified diff output
        """
        cmd = ["git", "diff", f"{base_ref}...{head_ref}"]
        exit_code, stdout, stderr = await self._run_git_command(repo_path, cmd)

        if exit_code != 0:
            return ""

        return stdout

    async def _run_git_command(
        self, repo_path: Path, cmd: list[str], timeout: int = 30
    ) -> tuple[int, str, str]:
        """Run git command in repository directory.

        Args:
            repo_path: Path to git repository
            cmd: Git command and arguments
            timeout: Command timeout in seconds

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(repo_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )

            return (
                process.returncode or 0,
                stdout_data.decode("utf-8", errors="replace"),
                stderr_data.decode("utf-8", errors="replace"),
            )

        except asyncio.TimeoutError:
            if process:
                process.kill()
                await process.wait()
            return (-1, "", f"Command timed out after {timeout} seconds")

        except Exception as e:
            return (-1, "", f"Command execution failed: {str(e)}")

    async def _clone_error(self, sandbox: Sandbox, error: str) -> CloneResult:
        """Create error CloneResult.

        Args:
            sandbox: Sandbox instance
            error: Error message

        Returns:
            CloneResult indicating failure
        """
        return CloneResult(
            success=False,
            sandbox=sandbox,
            repo_path=sandbox.path / "repo",
            error=error,
        )
