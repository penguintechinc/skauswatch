"""
S3 Scan Results Manager

Manages scan results from S3 bucket scans, including storage, retrieval,
querying, and statistics generation.
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ScanResultsManager:
    """Manages scan results for S3 bucket scans"""

    def __init__(self, db):
        """
        Initialize the scan results manager

        Args:
            db: PyDAL database instance
        """
        self.db = db

    async def save_scan_result(self, result: dict) -> int:
        """
        Save a scan result to the database

        Args:
            result: Dictionary containing scan result data
                Required fields: bucket_config_id, object_key, scan_status
                Optional fields: job_id, scan_engine, engine_version, file_size,
                               file_hash, detected_file_type, is_malware, is_pup,
                               is_threat, threat_details, scan_duration_ms, error_message

        Returns:
            ID of the inserted scan result
        """
        try:
            # Prepare record data
            record_data = {
                'bucket_config_id': result['bucket_config_id'],
                'object_key': result['object_key'],
                'scan_status': result['scan_status'],
                'scanned_at': datetime.utcnow()
            }

            # Add optional fields if present
            optional_fields = [
                'job_id', 'scan_engine', 'engine_version', 'file_size',
                'file_hash', 'detected_file_type', 'is_malware', 'is_pup',
                'is_threat', 'threat_details', 'scan_duration_ms', 'error_message'
            ]

            for field in optional_fields:
                if field in result:
                    record_data[field] = result[field]

            # Insert the record
            result_id = self.db.s3_scan_results.insert(**record_data)
            self.db.commit()

            logger.info(
                f"Saved scan result {result_id} for object {result['object_key']} "
                f"in bucket config {result['bucket_config_id']}"
            )

            return result_id

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error saving scan result: {str(e)}")
            raise

    async def get_result(self, result_id: int) -> Optional[dict]:
        """
        Fetch a single scan result by ID

        Args:
            result_id: ID of the scan result

        Returns:
            Dictionary containing scan result data, or None if not found
        """
        try:
            row = self.db(self.db.s3_scan_results.id == result_id).select().first()

            if not row:
                return None

            return row.as_dict()

        except Exception as e:
            logger.error(f"Error fetching scan result {result_id}: {str(e)}")
            raise

    async def get_result_by_object(
        self,
        bucket_config_id: int,
        object_key: str
    ) -> Optional[dict]:
        """
        Fetch the most recent scan result for a specific object

        Args:
            bucket_config_id: ID of the bucket configuration
            object_key: S3 object key

        Returns:
            Dictionary containing the most recent scan result, or None if not found
        """
        try:
            query = (
                (self.db.s3_scan_results.bucket_config_id == bucket_config_id) &
                (self.db.s3_scan_results.object_key == object_key)
            )

            row = self.db(query).select(
                orderby=~self.db.s3_scan_results.scanned_at,
                limitby=(0, 1)
            ).first()

            if not row:
                return None

            return row.as_dict()

        except Exception as e:
            logger.error(
                f"Error fetching result for object {object_key} "
                f"in bucket config {bucket_config_id}: {str(e)}"
            )
            raise

    async def query_results(
        self,
        filters: dict,
        page: int = 1,
        per_page: int = 50
    ) -> Tuple[List[dict], int]:
        """
        Query scan results with filters and pagination

        Args:
            filters: Dictionary of filters to apply
                Supported filters:
                - bucket_config_id: int
                - scan_status: str
                - is_malware: bool
                - is_pup: bool
                - is_threat: bool
                - detected_file_type: str
                - date_from: datetime
                - date_to: datetime
                - job_id: str
            page: Page number (1-indexed)
            per_page: Number of results per page

        Returns:
            Tuple of (list of result dictionaries, total count)
        """
        try:
            # Build query from filters
            query_conditions = []

            if 'bucket_config_id' in filters:
                query_conditions.append(
                    self.db.s3_scan_results.bucket_config_id == filters['bucket_config_id']
                )

            if 'scan_status' in filters:
                query_conditions.append(
                    self.db.s3_scan_results.scan_status == filters['scan_status']
                )

            if 'is_malware' in filters:
                query_conditions.append(
                    self.db.s3_scan_results.is_malware == filters['is_malware']
                )

            if 'is_pup' in filters:
                query_conditions.append(
                    self.db.s3_scan_results.is_pup == filters['is_pup']
                )

            if 'is_threat' in filters:
                query_conditions.append(
                    self.db.s3_scan_results.is_threat == filters['is_threat']
                )

            if 'detected_file_type' in filters:
                query_conditions.append(
                    self.db.s3_scan_results.detected_file_type == filters['detected_file_type']
                )

            if 'date_from' in filters:
                query_conditions.append(
                    self.db.s3_scan_results.scanned_at >= filters['date_from']
                )

            if 'date_to' in filters:
                query_conditions.append(
                    self.db.s3_scan_results.scanned_at <= filters['date_to']
                )

            if 'job_id' in filters:
                query_conditions.append(
                    self.db.s3_scan_results.job_id == filters['job_id']
                )

            # Combine conditions
            if query_conditions:
                query = query_conditions[0]
                for condition in query_conditions[1:]:
                    query &= condition
            else:
                query = self.db.s3_scan_results.id > 0

            # Get total count
            total_count = self.db(query).count()

            # Calculate pagination
            offset = (page - 1) * per_page

            # Fetch results
            rows = self.db(query).select(
                orderby=~self.db.s3_scan_results.scanned_at,
                limitby=(offset, offset + per_page)
            )

            results = [row.as_dict() for row in rows]

            logger.debug(
                f"Queried scan results: {len(results)} results, "
                f"total {total_count}, page {page}"
            )

            return results, total_count

        except Exception as e:
            logger.error(f"Error querying scan results: {str(e)}")
            raise

    async def get_statistics(self, bucket_config_id: int = None) -> dict:
        """
        Get aggregate statistics for scan results

        Args:
            bucket_config_id: Optional bucket config ID to filter by

        Returns:
            Dictionary containing statistics:
                - total_scanned: Total number of scans
                - total_infected: Number of infected files
                - total_pup: Number of PUPs
                - total_clean: Number of clean files
                - total_error: Number of scan errors
                - by_file_type: Dictionary of {mime_type: count}
                - by_bucket: Dictionary of {bucket_name: {total, infected, clean}}
        """
        try:
            # Base query
            if bucket_config_id:
                query = self.db.s3_scan_results.bucket_config_id == bucket_config_id
            else:
                query = self.db.s3_scan_results.id > 0

            # Get total counts
            total_scanned = self.db(query).count()

            total_infected = self.db(
                query & (self.db.s3_scan_results.is_malware == True)
            ).count()

            total_pup = self.db(
                query & (self.db.s3_scan_results.is_pup == True)
            ).count()

            total_clean = self.db(
                query &
                (self.db.s3_scan_results.scan_status == 'completed') &
                (self.db.s3_scan_results.is_threat == False)
            ).count()

            total_error = self.db(
                query & (self.db.s3_scan_results.scan_status == 'failed')
            ).count()

            # Get file type distribution
            by_file_type = {}
            file_type_rows = self.db(query).select(
                self.db.s3_scan_results.detected_file_type,
                self.db.s3_scan_results.id.count(),
                groupby=self.db.s3_scan_results.detected_file_type
            )

            for row in file_type_rows:
                file_type = row.s3_scan_results.detected_file_type
                if file_type:
                    by_file_type[file_type] = row['_extra']['COUNT(s3_scan_results.id)']

            # Get bucket distribution (if not filtered by bucket)
            by_bucket = {}
            if not bucket_config_id:
                bucket_rows = self.db(query).select(
                    self.db.s3_scan_results.bucket_config_id,
                    self.db.s3_scan_results.id.count(),
                    groupby=self.db.s3_scan_results.bucket_config_id
                )

                for row in bucket_rows:
                    config_id = row.s3_scan_results.bucket_config_id
                    if config_id:
                        # Get bucket name
                        config = self.db(
                            self.db.s3_bucket_configs.id == config_id
                        ).select().first()

                        if config:
                            bucket_name = config.bucket_name
                            total = row['_extra']['COUNT(s3_scan_results.id)']

                            # Get infected count for this bucket
                            infected = self.db(
                                (self.db.s3_scan_results.bucket_config_id == config_id) &
                                (self.db.s3_scan_results.is_malware == True)
                            ).count()

                            # Get clean count for this bucket
                            clean = self.db(
                                (self.db.s3_scan_results.bucket_config_id == config_id) &
                                (self.db.s3_scan_results.scan_status == 'completed') &
                                (self.db.s3_scan_results.is_threat == False)
                            ).count()

                            by_bucket[bucket_name] = {
                                'total': total,
                                'infected': infected,
                                'clean': clean
                            }

            statistics = {
                'total_scanned': total_scanned,
                'total_infected': total_infected,
                'total_pup': total_pup,
                'total_clean': total_clean,
                'total_error': total_error,
                'by_file_type': by_file_type,
                'by_bucket': by_bucket
            }

            logger.debug(f"Generated statistics: {statistics}")

            return statistics

        except Exception as e:
            logger.error(f"Error generating statistics: {str(e)}")
            raise

    async def delete_results_for_job(self, job_id: str) -> int:
        """
        Delete all scan results for a specific job

        Args:
            job_id: Job ID to delete results for

        Returns:
            Number of results deleted
        """
        try:
            query = self.db.s3_scan_results.job_id == job_id
            count = self.db(query).count()

            self.db(query).delete()
            self.db.commit()

            logger.info(f"Deleted {count} scan results for job {job_id}")

            return count

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error deleting results for job {job_id}: {str(e)}")
            raise
