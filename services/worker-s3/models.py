"""
Pydantic models for worker-s3 gRPC/stream message validation.

This module defines the data models for task messages consumed from Redis Streams
and result messages published back to the system. All fields are validated using
Pydantic BaseModel with appropriate constraints and type checking.
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class ScanTaskMessage(BaseModel):
    """Task message for S3 object scanning.

    Represents a scan task consumed from Redis Streams containing S3 object
    location, credentials, and scan parameters.

    Attributes:
        task_id: Unique identifier for this scan task
        job_id: Parent job identifier for correlation
        bucket_config_id: Reference to bucket configuration
        object_key: S3 object key/path to scan
        object_size: Size of object in bytes
        endpoint_url: S3-compatible endpoint URL
        bucket_name: S3 bucket name
        access_key: S3 access key ID
        secret_key: S3 secret access key
        region: AWS region (default: us-east-1)
        use_ssl: Whether to use SSL/TLS (default: True)
        path_style: Whether to use path-style addressing (default: False)
        yara_enabled: Whether to enable YARA rule scanning
    """

    task_id: str = Field(..., description="Unique task identifier")
    job_id: str = Field(..., description="Parent job identifier")
    bucket_config_id: str = Field(..., description="Bucket configuration reference")
    object_key: str = Field(..., description="S3 object key/path")
    object_size: int = Field(..., ge=0, description="Object size in bytes")
    endpoint_url: str = Field(..., description="S3-compatible endpoint URL")
    bucket_name: str = Field(..., description="S3 bucket name")
    access_key: str = Field(..., description="S3 access key ID")
    secret_key: str = Field(..., description="S3 secret access key")
    region: str = Field(default="us-east-1", description="AWS region")
    use_ssl: bool = Field(default=True, description="Use SSL/TLS")
    path_style: bool = Field(default=False, description="Use path-style addressing")
    yara_enabled: bool = Field(default=False, description="Enable YARA scanning")

    class Config:
        """Pydantic configuration."""

        schema_extra = {
            "example": {
                "task_id": "task-001",
                "job_id": "job-001",
                "bucket_config_id": "config-001",
                "object_key": "uploads/malware.exe",
                "object_size": 1024000,
                "endpoint_url": "https://s3.amazonaws.com",
                "bucket_name": "scan-bucket",
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-east-1",
                "use_ssl": True,
                "path_style": False,
                "yara_enabled": True,
            }
        }


class ScanResultMessage(BaseModel):
    """Result message for completed scan operation.

    Represents the complete scan results for an S3 object including malware
    detection, hashes, threat intelligence enrichment, and tags applied.

    Attributes:
        task_id: Task identifier (matches ScanTaskMessage)
        job_id: Job identifier (matches ScanTaskMessage)
        object_key: S3 object key that was scanned
        scan_status: Status of scan (completed, failed, timeout, skipped)
        is_malware: Whether malware was detected
        is_pup: Whether PUP (Potentially Unwanted Program) was detected
        is_threat: Whether any threat (malware or PUP) was detected
        detected_file_type: MIME type of scanned file
        threat_names: List of detected threat names from ClamAV/YARA
        file_md5: MD5 hash of file
        file_sha1: SHA1 hash of file
        file_sha256: SHA256 hash of file
        clamav_result: ClamAV scan result dictionary (optional)
        yara_matches: List of YARA rule matches (optional)
        ti_enrichment: Threat intelligence enrichment data (optional)
        scan_duration_ms: Scan duration in milliseconds
        tags_applied: Tags successfully applied to S3 object
        error_message: Error message if scan failed (optional)
    """

    task_id: str = Field(..., description="Task identifier")
    job_id: str = Field(..., description="Job identifier")
    object_key: str = Field(..., description="S3 object key")
    scan_status: str = Field(
        ...,
        description="Scan status",
        pattern="^(completed|failed|timeout|skipped)$",
    )
    is_malware: bool = Field(..., description="Malware detected")
    is_pup: bool = Field(..., description="PUP detected")
    is_threat: bool = Field(..., description="Any threat detected")
    detected_file_type: str = Field(..., description="Detected MIME type")
    threat_names: List[str] = Field(default_factory=list, description="Threat names")
    file_md5: str = Field(..., description="MD5 hash")
    file_sha1: str = Field(..., description="SHA1 hash")
    file_sha256: str = Field(..., description="SHA256 hash")
    clamav_result: Optional[Dict] = Field(default=None, description="ClamAV result")
    yara_matches: Optional[List[Dict]] = Field(default=None, description="YARA matches")
    ti_enrichment: Optional[Dict] = Field(default=None, description="TI enrichment")
    scan_duration_ms: int = Field(..., ge=0, description="Scan duration in ms")
    tags_applied: List[str] = Field(default_factory=list, description="Tags applied")
    error_message: Optional[str] = Field(
        default=None, description="Error message if failed"
    )

    class Config:
        """Pydantic configuration."""

        schema_extra = {
            "example": {
                "task_id": "task-001",
                "job_id": "job-001",
                "object_key": "uploads/clean.pdf",
                "scan_status": "completed",
                "is_malware": False,
                "is_pup": False,
                "is_threat": False,
                "detected_file_type": "application/pdf",
                "threat_names": [],
                "file_md5": "5d41402abc4b2a76b9719d911017c592",
                "file_sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                "file_sha256": (
                    "2c26b46911185131006cff7ee3b3f78b9"
                    "2d5529ce8cac75070d6d4e8b13c5d6a8"
                ),
                "clamav_result": None,
                "yara_matches": [],
                "ti_enrichment": {
                    "vt_score": 0,
                    "severity": "unknown",
                    "threat_family": None,
                },
                "scan_duration_ms": 1234,
                "tags_applied": ["malware=false", "pup=false", "threat=clean"],
                "error_message": None,
            }
        }
