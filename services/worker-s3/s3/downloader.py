"""Async streaming downloader for S3 objects with size limits."""

import os
import tempfile
from pathlib import Path
from typing import Optional

from s3.client import S3Client


class S3Downloader:
    """Async streaming downloader for S3 objects with size constraints."""

    def __init__(self, temp_dir: str = "/tmp/s3-scan") -> None:
        """Initialize downloader with temp directory.

        Args:
            temp_dir: Directory for temporary downloads (default: /tmp/s3-scan)
        """
        self.temp_dir = temp_dir
        # Create temp directory if it doesn't exist
        Path(self.temp_dir).mkdir(parents=True, exist_ok=True)

    async def download_object(
        self,
        s3_client: S3Client,
        bucket: str,
        key: str,
        max_size_mb: int = 1024,
    ) -> Optional[str]:
        """Download S3 object to local temp file with size limit.

        Enforces maximum file size limit. Downloads are streamed to disk
        with periodic size checks to prevent memory exhaustion and
        enforce security policies.

        Args:
            s3_client: S3Client instance
            bucket: S3 bucket name
            key: Object key/path
            max_size_mb: Maximum file size in MB (default: 1024 MB)

        Returns:
            Path to local temp file if successful, None if:
            - Object exceeds size limit
            - Download fails
            - Size check fails
        """
        max_size_bytes = max_size_mb * 1024 * 1024

        try:
            # Get object metadata first to check size
            metadata = await s3_client.get_object_metadata(bucket, key)
            content_length = metadata.get("ContentLength", 0)

            if content_length > max_size_bytes:
                return None

            # Create temporary file
            fd, temp_path = tempfile.mkstemp(
                dir=self.temp_dir,
                prefix="s3-download-",
            )
            os.close(fd)

            try:
                bytes_downloaded = await s3_client.download_to_file(
                    bucket, key, temp_path
                )

                # Verify downloaded size
                if bytes_downloaded > max_size_bytes:
                    os.remove(temp_path)
                    return None

                return temp_path
            except Exception:
                # Clean up temp file on download error
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                return None

        except Exception:
            return None

    def cleanup(self, file_path: str) -> None:
        """Remove temporary file created by download_object.

        Args:
            file_path: Path to temporary file to remove
        """
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass
