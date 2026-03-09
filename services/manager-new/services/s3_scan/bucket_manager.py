"""
S3 Bucket Configuration Manager.

Handles CRUD operations for S3 bucket configurations with encrypted credential storage.
"""

import logging
import os
from typing import Dict, List, Optional, Tuple

from aiobotocore.session import get_session
from cryptography.fernet import Fernet
from pydal import DAL

logger = logging.getLogger(__name__)


class BucketConfigManager:
    """
    Manages S3 bucket configurations with encrypted credential storage.

    Features:
    - Encrypt access_key_id and secret_access_key before storing
    - Decrypt credentials for internal use
    - Mask credentials in API responses
    - Test S3 connections
    - Paginated listing
    """

    def __init__(self, db: DAL, encryption_key: str):
        """
        Initialize the bucket config manager.

        Args:
            db: PyDAL database instance
            encryption_key: Base64-encoded Fernet encryption key
        """
        self.db = db
        self.cipher = Fernet(
            encryption_key.encode()
            if isinstance(encryption_key, str)
            else encryption_key
        )

    def _encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string.

        Args:
            plaintext: String to encrypt

        Returns:
            Base64-encoded encrypted string
        """
        if not plaintext:
            return ""
        return self.cipher.encrypt(plaintext.encode()).decode()

    def _decrypt(self, ciphertext: str) -> str:
        """
        Decrypt a ciphertext string.

        Args:
            ciphertext: Base64-encoded encrypted string

        Returns:
            Decrypted plaintext string
        """
        if not ciphertext:
            return ""
        return self.cipher.decrypt(ciphertext.encode()).decode()

    def _mask_secret(self, secret: str) -> str:
        """
        Mask a secret string, showing only last 4 characters.

        Args:
            secret: Secret string to mask

        Returns:
            Masked string (e.g., "****ABCD")
        """
        if not secret or len(secret) < 4:
            return "****"
        return "*" * (len(secret) - 4) + secret[-4:]

    async def create_bucket_config(self, data: Dict, user_id: int) -> Dict:
        """
        Create a new S3 bucket configuration.

        Args:
            data: Configuration data containing:
                - name: Unique config name
                - endpoint_url: S3 endpoint URL
                - bucket_name: S3 bucket name
                - access_key_id: AWS access key ID
                - secret_access_key: AWS secret access key
                - region: Optional AWS region
                - use_ssl: Optional, default True
                - path_style: Optional, default False
                - prefix_filter: Optional path prefix filter
                - file_types_filter: Optional list of file extensions
                - max_file_size_mb: Optional, default 100
                - scan_enabled: Optional, default True
                - yara_enabled: Optional, default False
            user_id: User ID creating the config

        Returns:
            Created config record with masked credentials
        """
        # Encrypt credentials
        encrypted_access_key = self._encrypt(data["access_key_id"])
        encrypted_secret_key = self._encrypt(data["secret_access_key"])

        # Insert record
        config_id = self.db.s3_bucket_configs.insert(
            name=data["name"],
            endpoint_url=data["endpoint_url"],
            bucket_name=data["bucket_name"],
            access_key_id=encrypted_access_key,
            secret_access_key=encrypted_secret_key,
            region=data.get("region"),
            use_ssl=data.get("use_ssl", True),
            path_style=data.get("path_style", False),
            prefix_filter=data.get("prefix_filter"),
            file_types_filter=data.get("file_types_filter", []),
            max_file_size_mb=data.get("max_file_size_mb", 100),
            scan_enabled=data.get("scan_enabled", True),
            yara_enabled=data.get("yara_enabled", False),
            created_by=user_id,
        )
        self.db.commit()

        logger.info(f"Created S3 bucket config '{data['name']}' (ID: {config_id})")

        # Return with masked credentials
        return await self.get_bucket_config_masked(config_id)

    async def get_bucket_config(self, config_id: int) -> Optional[Dict]:
        """
        Get bucket config with decrypted credentials (for internal use).

        Args:
            config_id: Configuration ID

        Returns:
            Config record with decrypted credentials, or None if not found
        """
        row = self.db(self.db.s3_bucket_configs.id == config_id).select().first()
        if not row:
            return None

        config = row.as_dict()
        # Decrypt credentials
        config["access_key_id"] = self._decrypt(config["access_key_id"])
        config["secret_access_key"] = self._decrypt(config["secret_access_key"])
        return config

    async def get_bucket_config_masked(self, config_id: int) -> Optional[Dict]:
        """
        Get bucket config with masked credentials (for API responses).

        Args:
            config_id: Configuration ID

        Returns:
            Config record with masked secret_access_key, or None if not found
        """
        row = self.db(self.db.s3_bucket_configs.id == config_id).select().first()
        if not row:
            return None

        config = row.as_dict()
        # Decrypt to mask properly
        decrypted_secret = self._decrypt(config["secret_access_key"])
        config["secret_access_key"] = self._mask_secret(decrypted_secret)
        # Decrypt access key ID (not considered highly sensitive)
        config["access_key_id"] = self._decrypt(config["access_key_id"])
        return config

    async def list_bucket_configs(
        self,
        page: int = 1,
        per_page: int = 20,
        scan_enabled: Optional[bool] = None,
    ) -> Tuple[List[Dict], int]:
        """
        List bucket configs with pagination and masked credentials.

        Args:
            page: Page number (1-indexed)
            per_page: Items per page
            scan_enabled: Optional filter for scan_enabled field

        Returns:
            Tuple of (configs list, total count)
        """
        # Build query
        query = self.db.s3_bucket_configs.id > 0
        if scan_enabled is not None:
            query &= self.db.s3_bucket_configs.scan_enabled == scan_enabled

        # Get total count
        total = self.db(query).count()

        # Get paginated results
        offset = (page - 1) * per_page
        rows = self.db(query).select(
            orderby=~self.db.s3_bucket_configs.created_at,
            limitby=(offset, offset + per_page),
        )

        # Convert to dicts with masked credentials
        configs = []
        for row in rows:
            config = row.as_dict()
            decrypted_secret = self._decrypt(config["secret_access_key"])
            config["secret_access_key"] = self._mask_secret(decrypted_secret)
            config["access_key_id"] = self._decrypt(config["access_key_id"])
            configs.append(config)

        return configs, total

    async def update_bucket_config(self, config_id: int, data: Dict) -> Optional[Dict]:
        """
        Update a bucket configuration.

        Args:
            config_id: Configuration ID
            data: Fields to update (only provided fields will be updated)

        Returns:
            Updated config with masked credentials, or None if not found
        """
        # Check if config exists
        config = self.db(self.db.s3_bucket_configs.id == config_id).select().first()
        if not config:
            return None

        # Prepare update fields
        update_fields = {}

        # Handle credential encryption if provided
        if "access_key_id" in data:
            update_fields["access_key_id"] = self._encrypt(data["access_key_id"])
        if "secret_access_key" in data:
            update_fields["secret_access_key"] = self._encrypt(
                data["secret_access_key"]
            )

        # Handle other fields
        for field in [
            "name",
            "endpoint_url",
            "bucket_name",
            "region",
            "use_ssl",
            "path_style",
            "prefix_filter",
            "file_types_filter",
            "max_file_size_mb",
            "scan_enabled",
            "yara_enabled",
        ]:
            if field in data:
                update_fields[field] = data[field]

        # Update record
        self.db(self.db.s3_bucket_configs.id == config_id).update(**update_fields)
        self.db.commit()

        logger.info(f"Updated S3 bucket config ID {config_id}")

        # Return updated config with masked credentials
        return await self.get_bucket_config_masked(config_id)

    async def delete_bucket_config(self, config_id: int) -> bool:
        """
        Delete a bucket configuration and related schedules.

        Args:
            config_id: Configuration ID

        Returns:
            True if deleted, False if not found
        """
        # Check if exists
        config = self.db(self.db.s3_bucket_configs.id == config_id).select().first()
        if not config:
            return False

        # Delete related schedules
        self.db(self.db.s3_scan_schedules.bucket_config_id == config_id).delete()

        # Delete config
        self.db(self.db.s3_bucket_configs.id == config_id).delete()
        self.db.commit()

        logger.info(f"Deleted S3 bucket config ID {config_id}")
        return True

    async def test_connection(self, config_id: int) -> Dict:
        """
        Test S3 connection and list bucket contents.

        Args:
            config_id: Configuration ID

        Returns:
            Dict with test results:
                - success: bool
                - message: str
                - bucket_exists: bool
                - object_count: int (if successful)
        """
        # Get config with decrypted credentials
        config = await self.get_bucket_config(config_id)
        if not config:
            return {
                "success": False,
                "message": "Configuration not found",
                "bucket_exists": False,
                "object_count": 0,
            }

        # Test connection using aiobotocore
        session = get_session()

        try:
            async with session.create_client(
                "s3",
                endpoint_url=config["endpoint_url"],
                aws_access_key_id=config["access_key_id"],
                aws_secret_access_key=config["secret_access_key"],
                region_name=config.get("region"),
                use_ssl=config.get("use_ssl", True),
                config={
                    "s3": {
                        "addressing_style": (
                            "path" if config.get("path_style") else "auto"
                        )
                    }
                },
            ) as s3_client:
                # Test bucket access
                try:
                    response = await s3_client.head_bucket(Bucket=config["bucket_name"])
                    bucket_exists = True
                except Exception as e:
                    logger.warning(f"Bucket head failed: {e}")
                    bucket_exists = False

                # Try to list objects
                try:
                    paginator = s3_client.get_paginator("list_objects_v2")
                    object_count = 0

                    async for page in paginator.paginate(
                        Bucket=config["bucket_name"],
                        Prefix=config.get("prefix_filter", ""),
                        PaginationConfig={"MaxItems": 1000},
                    ):
                        object_count += page.get("KeyCount", 0)

                    return {
                        "success": True,
                        "message": "Connection successful",
                        "bucket_exists": bucket_exists,
                        "object_count": object_count,
                    }
                except Exception as e:
                    logger.error(f"Error listing objects: {e}")
                    return {
                        "success": False,
                        "message": f"Failed to list objects: {str(e)}",
                        "bucket_exists": bucket_exists,
                        "object_count": 0,
                    }

        except Exception as e:
            logger.error(f"S3 connection test failed: {e}")
            return {
                "success": False,
                "message": f"Connection failed: {str(e)}",
                "bucket_exists": False,
                "object_count": 0,
            }
