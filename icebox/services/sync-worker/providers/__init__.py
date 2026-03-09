"""Cloud provider base class and factory function."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SyncResult:
    """Result of a single secret sync operation."""

    secret_id: str
    external_ref: str
    success: bool
    error: str | None = None
    # One of: created, updated, synced, skipped, deleted
    action: str = "synced"


class CloudProvider(ABC):
    """Abstract base class for all cloud secret providers."""

    def __init__(
        self,
        credentials: dict[str, Any],
        config: dict[str, Any],
    ) -> None:
        self.credentials = credentials
        self.config = config

    @abstractmethod
    async def push_secret(
        self,
        name: str,
        value: str,
        secret_id: str,
        tags: dict[str, str] | None = None,
    ) -> SyncResult:
        """Push a secret value to the cloud provider.

        Args:
            name: Human-readable secret name.
            value: Decrypted secret plaintext.
            secret_id: IceBox UUID for this secret.
            tags: Optional key-value tags/labels for the cloud resource.

        Returns:
            SyncResult with external_ref (ARN / resource name / etc.).
        """

    @abstractmethod
    async def pull_secret(self, external_ref: str) -> str | None:
        """Pull a secret value from the cloud provider.

        Args:
            external_ref: Provider-specific resource identifier.

        Returns:
            Plaintext secret value, or None if not found.
        """

    @abstractmethod
    async def delete_secret(self, external_ref: str) -> bool:
        """Delete a secret from the cloud provider.

        Returns:
            True if deleted, False if not found.
        """

    @abstractmethod
    async def list_secrets(self) -> list[str]:
        """List all secret names/refs managed by IceBox in this provider.

        Returns:
            List of external_ref strings.
        """

    @abstractmethod
    async def close(self) -> None:
        """Release any open SDK clients or connection resources."""


def get_provider(
    provider_name: str,
    credentials: dict[str, Any],
    config: dict[str, Any],
) -> CloudProvider:
    """Factory: instantiate the correct CloudProvider implementation.

    Args:
        provider_name: One of aws | azure | gcp | oracle | kubernetes.
        credentials: Decrypted credentials dict from cloud_integrations.
        config: Provider config dict from cloud_integrations.config.

    Returns:
        Instantiated CloudProvider.

    Raises:
        ValueError: If provider_name is not recognised.
    """
    # Lazy imports to avoid loading all SDKs at startup
    from .aws import AwsProvider
    from .azure import AzureProvider
    from .gcp import GcpProvider
    from .kubernetes import KubernetesProvider
    from .oracle import OracleProvider

    mapping: dict[str, type[CloudProvider]] = {
        "aws": AwsProvider,
        "azure": AzureProvider,
        "gcp": GcpProvider,
        "oracle": OracleProvider,
        "kubernetes": KubernetesProvider,
    }
    cls = mapping.get(provider_name)
    if cls is None:
        raise ValueError(
            f"Unknown provider '{provider_name}'. "
            f"Valid options: {list(mapping)}"
        )
    return cls(credentials, config)
