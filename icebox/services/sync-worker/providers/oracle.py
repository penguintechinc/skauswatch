"""Oracle OCI Vault cloud provider."""
from __future__ import annotations

import logging
import base64
from typing import Any

import oci
from oci.exceptions import ServiceError
from oci.vault import VaultsClient
from oci.secrets import SecretsClient
from oci.vault.models import (
    CreateSecretDetails,
    Base64SecretContentDetails,
    UpdateSecretDetails,
)

from . import CloudProvider, SyncResult

logger = logging.getLogger(__name__)

ICEBOX_TAG_NS = "icebox"
ICEBOX_TAG_KEY = "managed"
ICEBOX_TAG_VALUE = "true"


class OracleProvider(CloudProvider):
    """Sync secrets between IceBox and Oracle OCI Vault."""

    def __init__(
        self,
        credentials: dict[str, Any],
        config: dict[str, Any],
    ) -> None:
        super().__init__(credentials, config)
        # Build OCI config dict from IceBox credentials
        oci_config = {
            "user": credentials["user"],
            "key_content": credentials["private_key_pem"],
            "fingerprint": credentials["fingerprint"],
            "tenancy": credentials["tenancy"],
            "region": credentials.get("region", "us-ashburn-1"),
        }
        # Passphrase is optional (if key is encrypted)
        if "private_key_passphrase" in credentials:
            oci_config["pass_phrase"] = credentials["private_key_passphrase"]

        self._compartment_id: str = credentials["compartment_id"]
        self._vault_id: str = credentials["vault_id"]
        self._vault_key_id: str = credentials["vault_key_id"]
        self._prefix: str = config.get("secret_prefix", "icebox-")

        self._vaults_client = VaultsClient(oci_config)
        self._secrets_client = SecretsClient(oci_config)

    def _secret_name(self, name: str) -> str:
        """OCI secret names: alphanumeric, dashes, underscores."""
        safe = name.replace("/", "-").replace(".", "-")
        return f"{self._prefix}{safe}"

    async def push_secret(
        self,
        name: str,
        value: str,
        secret_id: str,
        tags: dict[str, str] | None = None,
    ) -> SyncResult:
        """Create or update a secret in OCI Vault."""
        oci_name = self._secret_name(name)
        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        freeform_tags = {"icebox-managed": "true", "icebox-secret-id": secret_id}
        if tags:
            freeform_tags.update(tags)

        # Check if secret already exists
        existing_id: str | None = None
        try:
            resp = self._vaults_client.list_secrets(
                compartment_id=self._compartment_id,
                vault_id=self._vault_id,
                name=oci_name,
            )
            items = resp.data
            if items:
                existing_id = items[0].id
        except ServiceError as exc:
            if exc.status != 404:
                msg = str(exc)
                logger.error("oracle: list_secrets failed for %s: %s", oci_name, msg)
                return SyncResult(
                    secret_id=secret_id,
                    external_ref=oci_name,
                    success=False,
                    error=msg,
                )

        try:
            if existing_id:
                # Update existing secret with a new version
                details = UpdateSecretDetails(
                    secret_content=Base64SecretContentDetails(content=encoded),
                    freeform_tags=freeform_tags,
                )
                self._vaults_client.update_secret(
                    secret_id=existing_id,
                    update_secret_details=details,
                )
                logger.info(
                    "oracle: updated secret %s (icebox_id=%s)", oci_name, secret_id
                )
                return SyncResult(
                    secret_id=secret_id,
                    external_ref=existing_id,
                    success=True,
                    action="updated",
                )
            else:
                # Create new secret
                details = CreateSecretDetails(
                    compartment_id=self._compartment_id,
                    vault_id=self._vault_id,
                    key_id=self._vault_key_id,
                    secret_name=oci_name,
                    secret_content=Base64SecretContentDetails(content=encoded),
                    freeform_tags=freeform_tags,
                )
                resp = self._vaults_client.create_secret(
                    create_secret_details=details
                )
                oci_id: str = resp.data.id
                logger.info(
                    "oracle: created secret %s id=%s (icebox_id=%s)",
                    oci_name,
                    oci_id,
                    secret_id,
                )
                return SyncResult(
                    secret_id=secret_id,
                    external_ref=oci_id,
                    success=True,
                    action="created",
                )
        except ServiceError as exc:
            msg = str(exc)
            logger.error("oracle: push failed for %s: %s", oci_name, msg)
            return SyncResult(
                secret_id=secret_id,
                external_ref=oci_name,
                success=False,
                error=msg,
            )

    async def pull_secret(self, external_ref: str) -> str | None:
        """Fetch the current value of a secret from OCI Vault."""
        try:
            resp = self._secrets_client.get_secret_bundle(secret_id=external_ref)
            bundle = resp.data
            encoded: str = bundle.secret_bundle_content.content
            return base64.b64decode(encoded).decode("utf-8")
        except ServiceError as exc:
            if exc.status == 404:
                return None
            raise

    async def delete_secret(self, external_ref: str) -> bool:
        """Schedule deletion of a secret in OCI Vault."""
        try:
            from oci.vault.models import ScheduleSecretDeletionDetails
            import datetime

            details = ScheduleSecretDeletionDetails(
                time_of_deletion=datetime.datetime.utcnow()
                + datetime.timedelta(days=30)
            )
            self._vaults_client.schedule_secret_deletion(
                secret_id=external_ref,
                schedule_secret_deletion_details=details,
            )
            logger.info("oracle: scheduled deletion of secret %s", external_ref)
            return True
        except ServiceError as exc:
            if exc.status == 404:
                return False
            raise

    async def list_secrets(self) -> list[str]:
        """List all IceBox-managed secret IDs in this OCI compartment/vault."""
        ids: list[str] = []
        resp = self._vaults_client.list_secrets(
            compartment_id=self._compartment_id,
            vault_id=self._vault_id,
        )
        for item in resp.data:
            ft = item.freeform_tags or {}
            if ft.get("icebox-managed") == "true":
                ids.append(item.id)
        return ids

    async def close(self) -> None:
        """OCI SDK clients have no explicit close method."""
