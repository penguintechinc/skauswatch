"""AWS Secrets Manager cloud provider."""
from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from . import CloudProvider, SyncResult

logger = logging.getLogger(__name__)

# Tag applied to all secrets created by IceBox so we can list them
ICEBOX_TAG_KEY = "icebox:managed"
ICEBOX_TAG_VALUE = "true"


class AwsProvider(CloudProvider):
    """Sync secrets between IceBox and AWS Secrets Manager."""

    def __init__(
        self,
        credentials: dict[str, Any],
        config: dict[str, Any],
    ) -> None:
        super().__init__(credentials, config)
        region = credentials.get("region", config.get("region", "us-east-1"))
        self._client = boto3.client(
            "secretsmanager",
            region_name=region,
            aws_access_key_id=credentials.get("access_key_id"),
            aws_secret_access_key=credentials.get("secret_access_key"),
            aws_session_token=credentials.get("session_token"),
        )
        self._prefix: str = config.get("secret_prefix", "icebox/")

    async def push_secret(
        self,
        name: str,
        value: str,
        secret_id: str,
        tags: dict[str, str] | None = None,
    ) -> SyncResult:
        """Create or update a secret in AWS Secrets Manager."""
        secret_name = f"{self._prefix}{name}"
        aws_tags = [
            {"Key": ICEBOX_TAG_KEY, "Value": ICEBOX_TAG_VALUE},
            {"Key": "icebox:secret_id", "Value": secret_id},
        ]
        if tags:
            aws_tags.extend(
                {"Key": k, "Value": v} for k, v in tags.items()
            )
        try:
            # Try to update existing secret first
            self._client.put_secret_value(
                SecretId=secret_name,
                SecretString=value,
            )
            logger.info(
                "aws: updated secret %s (icebox_id=%s)", secret_name, secret_id
            )
            return SyncResult(
                secret_id=secret_id,
                external_ref=secret_name,
                success=True,
                action="updated",
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                # Secret doesn't exist yet — create it
                try:
                    resp = self._client.create_secret(
                        Name=secret_name,
                        SecretString=value,
                        Tags=aws_tags,
                    )
                    arn: str = resp["ARN"]
                    logger.info(
                        "aws: created secret %s arn=%s", secret_name, arn
                    )
                    return SyncResult(
                        secret_id=secret_id,
                        external_ref=arn,
                        success=True,
                        action="created",
                    )
                except ClientError as create_exc:
                    msg = str(create_exc)
                    logger.error("aws: create failed for %s: %s", secret_name, msg)
                    return SyncResult(
                        secret_id=secret_id,
                        external_ref=secret_name,
                        success=False,
                        error=msg,
                    )
            msg = str(exc)
            logger.error("aws: push failed for %s: %s", secret_name, msg)
            return SyncResult(
                secret_id=secret_id,
                external_ref=secret_name,
                success=False,
                error=msg,
            )

    async def pull_secret(self, external_ref: str) -> str | None:
        """Fetch the current value of a secret from AWS Secrets Manager."""
        try:
            resp = self._client.get_secret_value(SecretId=external_ref)
            return resp.get("SecretString") or resp.get("SecretBinary", b"").decode()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "InvalidRequestException"):
                return None
            raise

    async def delete_secret(self, external_ref: str) -> bool:
        """Delete a secret from AWS Secrets Manager (with recovery window)."""
        try:
            self._client.delete_secret(
                SecretId=external_ref,
                RecoveryWindowInDays=7,
            )
            logger.info("aws: scheduled deletion of %s", external_ref)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return False
            raise

    async def list_secrets(self) -> list[str]:
        """List all IceBox-managed secret ARNs in this AWS account/region."""
        arns: list[str] = []
        paginator = self._client.get_paginator("list_secrets")
        filter_tag = [
            {"Key": "tag-key", "Values": [ICEBOX_TAG_KEY]},
        ]
        for page in paginator.paginate(Filters=filter_tag):
            for secret in page.get("SecretList", []):
                arns.append(secret.get("ARN", secret["Name"]))
        return arns

    async def close(self) -> None:
        """No persistent connection to close for boto3."""
