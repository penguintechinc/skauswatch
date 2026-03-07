"""GCP Secret Manager cloud provider."""
from __future__ import annotations

import json
import logging
from typing import Any

from google.api_core.exceptions import AlreadyExists, NotFound, PermissionDenied
from google.cloud import secretmanager
from google.oauth2 import service_account

from . import CloudProvider, SyncResult

logger = logging.getLogger(__name__)

ICEBOX_LABEL_KEY = "icebox-managed"
ICEBOX_LABEL_VALUE = "true"


class GcpProvider(CloudProvider):
    """Sync secrets between IceBox and GCP Secret Manager."""

    def __init__(
        self,
        credentials: dict[str, Any],
        config: dict[str, Any],
    ) -> None:
        super().__init__(credentials, config)
        self._project_id: str = credentials["project_id"]

        # Support service account JSON key or ADC (Application Default Credentials)
        sa_json = credentials.get("service_account_json")
        if sa_json:
            if isinstance(sa_json, str):
                sa_info = json.loads(sa_json)
            else:
                sa_info = sa_json
            gcp_creds = service_account.Credentials.from_service_account_info(
                sa_info,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
            self._client = secretmanager.SecretManagerServiceClient(
                credentials=gcp_creds
            )
        else:
            # ADC — works on GKE with Workload Identity
            self._client = secretmanager.SecretManagerServiceClient()

        self._prefix: str = config.get("secret_prefix", "icebox_")

    def _secret_id(self, name: str) -> str:
        """GCP secret IDs: alphanumeric, dashes, underscores."""
        safe = name.replace("/", "_").replace(".", "_").replace("-", "_")
        return f"{self._prefix}{safe}"

    def _secret_path(self, secret_id: str) -> str:
        return f"projects/{self._project_id}/secrets/{secret_id}"

    def _version_path(self, secret_id: str, version: str = "latest") -> str:
        return f"{self._secret_path(secret_id)}/versions/{version}"

    async def push_secret(
        self,
        name: str,
        value: str,
        secret_id: str,
        tags: dict[str, str] | None = None,
    ) -> SyncResult:
        """Create (or add a version to) a secret in GCP Secret Manager."""
        gcp_id = self._secret_id(name)
        labels: dict[str, str] = {ICEBOX_LABEL_KEY: ICEBOX_LABEL_VALUE}
        if tags:
            # GCP labels must be lowercase, max 63 chars
            for k, v in tags.items():
                labels[k[:63].lower()] = v[:63].lower()

        parent = f"projects/{self._project_id}"
        # Ensure the secret resource exists
        try:
            self._client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": gcp_id,
                    "secret": {
                        "replication": {"automatic": {}},
                        "labels": labels,
                    },
                }
            )
            action = "created"
        except AlreadyExists:
            action = "updated"
        except Exception as exc:
            msg = str(exc)
            logger.error("gcp: create_secret failed for %s: %s", gcp_id, msg)
            return SyncResult(
                secret_id=secret_id,
                external_ref=gcp_id,
                success=False,
                error=msg,
            )

        # Add the secret version (payload)
        try:
            version_resp = self._client.add_secret_version(
                request={
                    "parent": self._secret_path(gcp_id),
                    "payload": {"data": value.encode("utf-8")},
                }
            )
            logger.info(
                "gcp: added version %s for secret %s (icebox_id=%s)",
                version_resp.name,
                gcp_id,
                secret_id,
            )
            return SyncResult(
                secret_id=secret_id,
                external_ref=gcp_id,
                success=True,
                action=action,
            )
        except Exception as exc:
            msg = str(exc)
            logger.error("gcp: add_secret_version failed for %s: %s", gcp_id, msg)
            return SyncResult(
                secret_id=secret_id,
                external_ref=gcp_id,
                success=False,
                error=msg,
            )

    async def pull_secret(self, external_ref: str) -> str | None:
        """Fetch the latest version of a secret from GCP Secret Manager."""
        try:
            resp = self._client.access_secret_version(
                request={"name": self._version_path(external_ref)}
            )
            return resp.payload.data.decode("utf-8")
        except NotFound:
            return None
        except PermissionDenied as exc:
            logger.error("gcp: permission denied reading %s: %s", external_ref, exc)
            raise

    async def delete_secret(self, external_ref: str) -> bool:
        """Delete all versions of a secret in GCP Secret Manager."""
        try:
            self._client.delete_secret(
                request={"name": self._secret_path(external_ref)}
            )
            logger.info("gcp: deleted secret %s", external_ref)
            return True
        except NotFound:
            return False

    async def list_secrets(self) -> list[str]:
        """List all IceBox-managed secret IDs in this GCP project."""
        ids: list[str] = []
        parent = f"projects/{self._project_id}"
        for secret in self._client.list_secrets(request={"parent": parent}):
            if secret.labels.get(ICEBOX_LABEL_KEY) == ICEBOX_LABEL_VALUE:
                # Return just the ID portion (last segment)
                ids.append(secret.name.split("/")[-1])
        return ids

    async def close(self) -> None:
        """GCP client manages its own transport — nothing to close."""
