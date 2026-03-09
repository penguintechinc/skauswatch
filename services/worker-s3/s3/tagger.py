"""Async S3 tag writer for scan results."""

from typing import Dict

import aiobotocore.session


class S3Tagger:
    """Write scan results as S3 object tags."""

    def __init__(self, session: aiobotocore.session.AioSession) -> None:
        """Initialize tagger with aiobotocore session.

        Args:
            session: aiobotocore session instance
        """
        self.session = session

    async def apply_scan_tags(
        self,
        bucket: str,
        key: str,
        is_malware: bool,
        is_pup: bool,
        file_type: str,
        scan_time: int,
    ) -> bool:
        """Apply scan result tags to S3 object.

        Tags applied:
        - malware: "true" or "false"
        - pup: "true" or "false" (potentially unwanted program)
        - threat: "malware" or "pup" or "clean"
        - scanTime: Unix timestamp in milliseconds
        - fileType: File type/extension

        Args:
            bucket: S3 bucket name
            key: Object key/path
            is_malware: Whether object contains malware
            is_pup: Whether object is potentially unwanted program
            file_type: File type/extension
            scan_time: Scan timestamp in milliseconds

        Returns:
            True if tags applied successfully, False otherwise
        """
        try:
            # Determine threat level
            if is_malware:
                threat = "malware"
            elif is_pup:
                threat = "pup"
            else:
                threat = "clean"

            # Build tag set
            tags = {
                "malware": "true" if is_malware else "false",
                "pup": "true" if is_pup else "false",
                "threat": threat,
                "scanTime": str(scan_time),
                "fileType": file_type,
            }

            async with self.session.client("s3") as client:
                tag_set = [{"Key": k, "Value": v} for k, v in tags.items()]
                await client.put_object_tagging(
                    Bucket=bucket,
                    Key=key,
                    Tagging={"TagSet": tag_set},
                )

            return True
        except Exception:
            return False

    async def get_tags(self, bucket: str, key: str) -> Dict[str, str]:
        """Retrieve tags from S3 object.

        Args:
            bucket: S3 bucket name
            key: Object key/path

        Returns:
            Dictionary of tag key-value pairs
        """
        try:
            async with self.session.client("s3") as client:
                response = await client.get_object_tagging(Bucket=bucket, Key=key)
                return {tag["Key"]: tag["Value"] for tag in response["TagSet"]}
        except Exception:
            return {}
