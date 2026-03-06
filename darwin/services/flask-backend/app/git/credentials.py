"""Git credential management with encryption."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass

from cryptography.fernet import Fernet


@dataclass(slots=True)
class GitCredential:
    """Git credential configuration."""

    id: int
    name: str
    url_pattern: str  # e.g., "github.com/*", "*.gitlab.mycompany.com/*"
    auth_type: str  # "https_token" or "ssh_key"
    # Note: credential itself is encrypted in DB


class CredentialManager:
    """Manages encryption and matching of git credentials."""

    def __init__(self, encryption_key: str | None = None) -> None:
        """Initialize credential manager.

        Args:
            encryption_key: Base64-encoded Fernet key. If None, uses
                           CREDENTIAL_ENCRYPTION_KEY from environment.
        """
        key = encryption_key or os.getenv("CREDENTIAL_ENCRYPTION_KEY")
        if not key:
            raise ValueError(
                "encryption_key must be provided or "
                "CREDENTIAL_ENCRYPTION_KEY must be set"
            )
        self.cipher = Fernet(key.encode() if isinstance(key, str) else key)

    def encrypt(self, data: str) -> bytes:
        """Encrypt credential for storage.

        Args:
            data: Plain text credential (token or private key)

        Returns:
            Encrypted credential bytes
        """
        return self.cipher.encrypt(data.encode())

    def decrypt(self, encrypted_data: bytes) -> str:
        """Decrypt credential for use.

        Args:
            encrypted_data: Encrypted credential bytes

        Returns:
            Decrypted plain text credential
        """
        return self.cipher.decrypt(encrypted_data).decode()

    def match_url(
        self, url: str, credentials: list[GitCredential]
    ) -> GitCredential | None:
        """Find matching credential for a git URL using fnmatch.

        Args:
            url: Git repository URL (https://github.com/owner/repo or
                 git@github.com:owner/repo)
            credentials: List of available credentials

        Returns:
            Matching GitCredential or None if no match found
        """
        # Extract host from URL
        host = self._extract_host(url)
        if not host:
            return None

        # Find matching credential
        for cred in credentials:
            pattern = cred.url_pattern
            # Match against full host/path or just host
            if fnmatch.fnmatch(host, pattern) or fnmatch.fnmatch(url, pattern):
                return cred

        return None

    def _extract_host(self, url: str) -> str | None:
        """Extract host from git URL.

        Args:
            url: Git repository URL

        Returns:
            Host portion of URL or None if extraction fails
        """
        # Handle SSH format: git@github.com:owner/repo
        if "@" in url and "://" not in url:
            try:
                parts = url.split("@")[1].split(":")
                return parts[0]
            except (IndexError, AttributeError):
                return None

        # Handle HTTPS format: https://github.com/owner/repo
        if "://" in url:
            try:
                parts = url.split("://")[1].split("/")
                return parts[0]
            except (IndexError, AttributeError):
                return None

        return None

    def build_auth_url(self, url: str, token: str) -> str:
        """Transform URL to include authentication token.

        Args:
            url: Original git URL (https://github.com/owner/repo)
            token: Authentication token

        Returns:
            URL with token embedded (https://token@github.com/owner/repo)
        """
        if "://" not in url:
            raise ValueError(f"Invalid HTTPS URL: {url}")

        protocol, rest = url.split("://", 1)
        return f"{protocol}://{token}@{rest}"

    def get_ssh_command(
        self, private_key_path: str, passphrase: str | None = None
    ) -> str:
        """Build GIT_SSH_COMMAND for SSH key authentication.

        Args:
            private_key_path: Path to SSH private key file
            passphrase: Optional passphrase for encrypted key

        Returns:
            Value for GIT_SSH_COMMAND environment variable
        """
        # Base SSH command with key
        cmd = f'ssh -i "{private_key_path}" -o StrictHostKeyChecking=no'

        # Note: passphrase is handled by ssh-agent or ssh-add,
        # not by GIT_SSH_COMMAND directly
        # For automated use, key should be unencrypted or use ssh-agent

        return cmd
