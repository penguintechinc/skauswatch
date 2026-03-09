"""
Ad-hoc S3 Scan Manager

Manages ad-hoc file scanning operations where users upload files directly
for scanning through the web UI or API.
"""

import io
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class AdhocScanManager:
    """Manages ad-hoc file scanning operations"""

    def __init__(self, db, minio_client, scan_service):
        """
        Initialize the ad-hoc scan manager

        Args:
            db: PyDAL database instance
            minio_client: Minio client for file storage
            scan_service: S3 scan service instance for performing scans
        """
        self.db = db
        self.minio_client = minio_client
        self.scan_service = scan_service
        self.adhoc_bucket = "adhoc-scans"

        # Ensure the adhoc bucket exists
        self._ensure_bucket_exists()

    def _ensure_bucket_exists(self):
        """Ensure the ad-hoc scans bucket exists"""
        try:
            if not self.minio_client.bucket_exists(self.adhoc_bucket):
                self.minio_client.make_bucket(self.adhoc_bucket)
                logger.info(f"Created ad-hoc scans bucket: {self.adhoc_bucket}")
        except Exception as e:
            logger.error(f"Error ensuring ad-hoc bucket exists: {str(e)}")

    async def upload_and_scan(
        self, file_content: bytes, filename: str, user_id: int
    ) -> dict:
        """
        Upload a file and initiate a scan

        Args:
            file_content: File content as bytes
            filename: Original filename
            user_id: ID of the user uploading the file

        Returns:
            Dictionary containing scan_id, status, and filename
        """
        try:
            # Generate unique scan ID
            scan_id = str(uuid.uuid4())

            # Construct object key
            object_key = f"{scan_id}/{filename}"

            # Upload file to Minio
            file_size = len(file_content)
            file_stream = io.BytesIO(file_content)

            self.minio_client.put_object(
                self.adhoc_bucket, object_key, file_stream, file_size
            )

            logger.info(
                f"Uploaded ad-hoc scan file: {object_key} "
                f"({file_size} bytes) for user {user_id}"
            )

            # Create database record
            record_id = self.db.adhoc_scan_results.insert(
                scan_id=scan_id,
                user_id=user_id,
                filename=filename,
                object_key=object_key,
                file_size=file_size,
                scan_status="pending",
                uploaded_at=datetime.utcnow(),
            )
            self.db.commit()

            logger.info(
                f"Created ad-hoc scan record {record_id} with scan_id {scan_id}"
            )

            # Trigger scan asynchronously
            try:
                scan_result = await self.scan_service.scan_s3_object(
                    self.adhoc_bucket, object_key, file_size
                )

                # Update the scan result
                await self.update_scan_result(scan_id, scan_result)

            except Exception as scan_error:
                logger.error(f"Error scanning ad-hoc file {scan_id}: {str(scan_error)}")
                # Update status to failed
                self.db(self.db.adhoc_scan_results.scan_id == scan_id).update(
                    scan_status="failed", error_message=str(scan_error)
                )
                self.db.commit()

            # Return initial response
            return {
                "scan_id": scan_id,
                "status": "pending",
                "filename": filename,
                "file_size": file_size,
            }

        except Exception as e:
            logger.error(f"Error in upload_and_scan: {str(e)}")
            self.db.rollback()
            raise

    async def get_scan_result(self, scan_id: str) -> Optional[dict]:
        """
        Fetch an ad-hoc scan result by scan ID

        Args:
            scan_id: Scan ID (UUID)

        Returns:
            Dictionary containing scan result, or None if not found
        """
        try:
            row = (
                self.db(self.db.adhoc_scan_results.scan_id == scan_id).select().first()
            )

            if not row:
                return None

            return row.as_dict()

        except Exception as e:
            logger.error(f"Error fetching ad-hoc scan result {scan_id}: {str(e)}")
            raise

    async def list_user_scans(
        self, user_id: int, page: int = 1, per_page: int = 20
    ) -> Tuple[List[dict], int]:
        """
        List a user's ad-hoc scans with pagination

        Args:
            user_id: ID of the user
            page: Page number (1-indexed)
            per_page: Number of results per page

        Returns:
            Tuple of (list of scan dictionaries, total count)
        """
        try:
            query = self.db.adhoc_scan_results.user_id == user_id

            # Get total count
            total_count = self.db(query).count()

            # Calculate pagination
            offset = (page - 1) * per_page

            # Fetch results
            rows = self.db(query).select(
                orderby=~self.db.adhoc_scan_results.uploaded_at,
                limitby=(offset, offset + per_page),
            )

            results = [row.as_dict() for row in rows]

            logger.debug(
                f"Listed ad-hoc scans for user {user_id}: "
                f"{len(results)} results, total {total_count}, page {page}"
            )

            return results, total_count

        except Exception as e:
            logger.error(f"Error listing ad-hoc scans for user {user_id}: {str(e)}")
            raise

    async def update_scan_result(self, scan_id: str, result: dict) -> None:
        """
        Update an ad-hoc scan result with scan data

        Args:
            scan_id: Scan ID (UUID)
            result: Dictionary containing scan result data
        """
        try:
            # Prepare update data
            update_data = {
                "scan_status": result.get("status", "completed"),
                "scanned_at": datetime.utcnow(),
            }

            # Add optional fields if present
            optional_fields = [
                "scan_engine",
                "engine_version",
                "file_hash",
                "detected_file_type",
                "is_malware",
                "is_pup",
                "is_threat",
                "threat_details",
                "scan_duration_ms",
                "error_message",
            ]

            for field in optional_fields:
                if field in result:
                    update_data[field] = result[field]

            # Handle status mapping
            if result.get("infected", False):
                update_data["is_malware"] = True
                update_data["is_threat"] = True

            # Update the record
            updated = self.db(self.db.adhoc_scan_results.scan_id == scan_id).update(
                **update_data
            )

            self.db.commit()

            if updated:
                logger.info(f"Updated ad-hoc scan result for {scan_id}")
            else:
                logger.warning(f"No ad-hoc scan result found for {scan_id}")

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error updating ad-hoc scan result {scan_id}: {str(e)}")
            raise

    async def delete_scan(self, scan_id: str) -> bool:
        """
        Delete an ad-hoc scan and its associated file

        Args:
            scan_id: Scan ID (UUID)

        Returns:
            True if deleted successfully, False if not found
        """
        try:
            # Fetch the scan record
            scan = (
                self.db(self.db.adhoc_scan_results.scan_id == scan_id).select().first()
            )

            if not scan:
                return False

            object_key = scan.object_key

            # Delete from Minio
            try:
                self.minio_client.remove_object(self.adhoc_bucket, object_key)
                logger.info(f"Deleted ad-hoc scan object: {object_key}")
            except Exception as minio_error:
                logger.warning(f"Error deleting object from Minio: {str(minio_error)}")

            # Delete from database
            self.db(self.db.adhoc_scan_results.scan_id == scan_id).delete()
            self.db.commit()

            logger.info(f"Deleted ad-hoc scan {scan_id} from database")

            return True

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error deleting ad-hoc scan {scan_id}: {str(e)}")
            raise

    async def cleanup_old_scans(self, days: int = 30) -> int:
        """
        Clean up ad-hoc scans older than specified days

        Args:
            days: Number of days to keep scans (default: 30)

        Returns:
            Number of scans cleaned up
        """
        try:
            from datetime import timedelta

            cutoff_date = datetime.utcnow() - timedelta(days=days)

            # Find old scans
            query = self.db.adhoc_scan_results.uploaded_at < cutoff_date
            old_scans = self.db(query).select()

            count = 0
            for scan in old_scans:
                try:
                    # Delete from Minio
                    self.minio_client.remove_object(self.adhoc_bucket, scan.object_key)
                    count += 1
                except Exception as minio_error:
                    logger.warning(
                        f"Error deleting old object {scan.object_key}: "
                        f"{str(minio_error)}"
                    )

            # Delete from database
            deleted = self.db(query).delete()
            self.db.commit()

            logger.info(
                f"Cleaned up {deleted} ad-hoc scans older than {days} days "
                f"({count} objects deleted from Minio)"
            )

            return deleted

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error cleaning up old ad-hoc scans: {str(e)}")
            raise

    async def get_user_quota(self, user_id: int) -> dict:
        """
        Get quota information for a user's ad-hoc scans

        Args:
            user_id: ID of the user

        Returns:
            Dictionary containing quota information:
                - total_scans: Total number of scans
                - scans_today: Number of scans today
                - total_bytes: Total bytes uploaded
                - bytes_today: Bytes uploaded today
        """
        try:
            from datetime import timedelta

            # Total scans for user
            total_scans = self.db(self.db.adhoc_scan_results.user_id == user_id).count()

            # Total bytes for user
            rows = self.db(self.db.adhoc_scan_results.user_id == user_id).select(
                self.db.adhoc_scan_results.file_size.sum()
            )

            total_bytes = rows[0]["_extra"]["SUM(adhoc_scan_results.file_size)"] or 0

            # Scans today
            today_start = datetime.utcnow().replace(
                hour=0, minute=0, second=0, microsecond=0
            )

            scans_today = self.db(
                (self.db.adhoc_scan_results.user_id == user_id)
                & (self.db.adhoc_scan_results.uploaded_at >= today_start)
            ).count()

            # Bytes today
            rows = self.db(
                (self.db.adhoc_scan_results.user_id == user_id)
                & (self.db.adhoc_scan_results.uploaded_at >= today_start)
            ).select(self.db.adhoc_scan_results.file_size.sum())

            bytes_today = rows[0]["_extra"]["SUM(adhoc_scan_results.file_size)"] or 0

            quota = {
                "total_scans": total_scans,
                "scans_today": scans_today,
                "total_bytes": total_bytes,
                "bytes_today": bytes_today,
            }

            logger.debug(f"User {user_id} quota: {quota}")

            return quota

        except Exception as e:
            logger.error(f"Error getting user quota for {user_id}: {str(e)}")
            raise
