"""Async S3 client wrapper using aiobotocore."""

from typing import AsyncGenerator, Dict, Optional

import aiobotocore.session


class S3Client:
    """Async S3 client wrapper for object storage operations."""

    def __init__(
        self,
        endpoint_url: str,
        access_key: str,
        secret_key: str,
        region: str = "us-east-1",
        use_ssl: bool = True,
        path_style: bool = False,
    ) -> None:
        """Initialize S3 client with configuration.

        Args:
            endpoint_url: S3-compatible endpoint URL
            access_key: AWS/S3 access key ID
            secret_key: AWS/S3 secret access key
            region: AWS region (default: us-east-1)
            use_ssl: Whether to use SSL/TLS (default: True)
            path_style: Whether to use path-style addressing (default: False)
        """
        self.endpoint_url = endpoint_url
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.use_ssl = use_ssl
        self.path_style = path_style
        self.session = aiobotocore.session.get_session()

    async def list_objects(
        self, bucket: str, prefix: Optional[str] = None
    ) -> AsyncGenerator[Dict, None]:
        """List objects in S3 bucket with optional prefix.

        Args:
            bucket: S3 bucket name
            prefix: Optional prefix to filter objects

        Yields:
            Dictionary containing object metadata (Key, Size, LastModified, etc.)
        """
        async with self.session.client(
            "s3",
            endpoint_url=self.endpoint_url,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region,
            use_ssl=self.use_ssl,
        ) as client:
            paginator = client.get_paginator("list_objects_v2")
            page_iterator = paginator.paginate(
                Bucket=bucket,
                **({"Prefix": prefix} if prefix else {}),
            )

            async for page in page_iterator:
                if "Contents" in page:
                    for obj in page["Contents"]:
                        yield obj

    async def get_object_metadata(self, bucket: str, key: str) -> Dict:
        """Get object metadata without downloading content.

        Args:
            bucket: S3 bucket name
            key: Object key/path

        Returns:
            Dictionary with object metadata (ContentLength, LastModified, etc.)
        """
        async with self.session.client(
            "s3",
            endpoint_url=self.endpoint_url,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region,
            use_ssl=self.use_ssl,
        ) as client:
            response = await client.head_object(Bucket=bucket, Key=key)
            return {
                "ContentLength": response.get("ContentLength", 0),
                "LastModified": response.get("LastModified"),
                "ETag": response.get("ETag"),
                "ContentType": response.get("ContentType"),
                "Metadata": response.get("Metadata", {}),
            }

    async def download_to_file(self, bucket: str, key: str, local_path: str) -> int:
        """Download S3 object to local file.

        Args:
            bucket: S3 bucket name
            key: Object key/path
            local_path: Local file path to write to

        Returns:
            Number of bytes downloaded
        """
        bytes_downloaded = 0

        async with self.session.client(
            "s3",
            endpoint_url=self.endpoint_url,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region,
            use_ssl=self.use_ssl,
        ) as client:
            response = await client.get_object(Bucket=bucket, Key=key)

            async with response["Body"] as stream:
                with open(local_path, "wb") as f:
                    async for chunk in stream.iter_chunks():
                        if chunk:
                            f.write(chunk)
                            bytes_downloaded += len(chunk)

        return bytes_downloaded
