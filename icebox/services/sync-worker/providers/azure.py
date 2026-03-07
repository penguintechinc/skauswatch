"""Azure Key Vault cloud provider."""
from __future__ import annotations

import logging
from typing import Any

from azure.core.exceptions import ResourceNotFoundError, ServiceRequestError
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from . import CloudProvider, SyncResult

logger = logging.getLogger(__name__)

# Tag applied to all secrets created by IceBox
ICEBOX_TAG = {"icebox-managed": "true"}


class AzureProvider(CloudProvider):
    """Sync secrets between IceBox and Azure Key Vault."""

    def __init__(
        self,
        credentials: dict[str, Any],
        config: dict[str, Any],
    ) -> None:
        super().__init__(credentials, config)
        vault_url: str = credentials["vault_url"]

        # Support service principal auth or DefaultAzureCredential (managed identity)
        tenant_id = credentials.get("tenant_id")
        client_id = credentials.get("client_id")
        client_secret = credentials.get("client_secret")

        if tenant_id and client_id and client_secret:
            az_cred = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        else:
            az_cred = DefaultAzureCredential()

        self._client = SecretClient(vault_url=vault_url, credential=az_cred)
        self._prefix: str = config.get("secret_prefix", "icebox-")

    def _secret_name(self, name: str) -> str:
        """Azure Key Vault names: alphanumeric + dashes only."""
        safe = name.replace("_", "-").replace("/", "-").replace(".", "-")
        return f"{self._prefix}{safe}"

    async def push_secret(
        self,
        name: str,
        value: str,
        secret_id: str,
        tags: dict[str, str] | None = None,
    ) -> SyncResult:
        """Create or update a secret in Azure Key Vault."""
        az_name = self._secret_name(name)
        combined_tags = dict(ICEBOX_TAG)
        combined_tags["icebox-secret-id"] = secret_id
        if tags:
            combined_tags.update(tags)
        try:
            bundle = self._client.set_secret(az_name, value, tags=combined_tags)
            version = bundle.properties.version
            action = "updated"
            logger.info(
                "azure: set secret %s version=%s (icebox_id=%s)",
                az_name,
                version,
                secret_id,
            )
            return SyncResult(
                secret_id=secret_id,
                external_ref=az_name,
                success=True,
                action=action,
            )
        except (ServiceRequestError, Exception) as exc:
            msg = str(exc)
            logger.error("azure: push failed for %s: %s", az_name, msg)
            return SyncResult(
                secret_id=secret_id,
                external_ref=az_name,
                success=False,
                error=msg,
            )

    async def pull_secret(self, external_ref: str) -> str | None:
        """Fetch the latest value of a secret from Azure Key Vault."""
        try:
            secret = self._client.get_secret(external_ref)
            return secret.value
        except ResourceNotFoundError:
            return None

    async def delete_secret(self, external_ref: str) -> bool:
        """Begin deletion of a secret (soft-delete enabled vaults)."""
        try:
            poller = self._client.begin_delete_secret(external_ref)
            poller.result()  # Wait for deletion
            logger.info("azure: deleted secret %s", external_ref)
            return True
        except ResourceNotFoundError:
            return False

    async def list_secrets(self) -> list[str]:
        """List all IceBox-managed secret names in this Key Vault."""
        names: list[str] = []
        for props in self._client.list_properties_of_secrets():
            # Filter by icebox-managed tag
            if props.tags and props.tags.get("icebox-managed") == "true":
                names.append(props.name)
        return names

    async def close(self) -> None:
        """Close the Azure SDK client."""
        self._client.close()
