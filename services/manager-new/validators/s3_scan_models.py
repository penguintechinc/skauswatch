"""
Pydantic models for S3 malware scanning request/response validation.

Includes models for bucket configuration, scan jobs, results, and scheduling.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator

# ============================================
# Enums
# ============================================


class S3ScanJobType(str, Enum):
    """S3 scan job types."""

    SCHEDULED = "scheduled"
    MANUAL = "manual"
    REALTIME = "realtime"


class S3ScanJobStatus(str, Enum):
    """S3 scan job status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class S3ScanStatus(str, Enum):
    """S3 file scan status."""

    CLEAN = "clean"
    INFECTED = "infected"
    PUP = "pup"
    ERROR = "error"
    SKIPPED = "skipped"


class SandboxStatus(str, Enum):
    """Sandbox execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ============================================
# Bucket Configuration Models
# ============================================


class BucketConfigCreateRequest(BaseModel):
    """Bucket configuration creation request model."""

    name: str = Field(..., min_length=1, max_length=255)
    endpoint_url: str = Field(..., max_length=500)
    bucket_name: str = Field(..., min_length=1, max_length=255)
    access_key_id: str = Field(..., min_length=1, max_length=255)
    secret_access_key: str = Field(..., min_length=1, max_length=500)
    region: str = Field(default="us-east-1", max_length=50)
    use_ssl: bool = Field(default=True)
    path_style: bool = Field(default=True)
    prefix_filter: Optional[str] = Field(None, max_length=500)
    file_types_filter: Optional[List[str]] = Field(None, max_items=50)
    max_file_size_mb: int = Field(default=100, ge=1, le=500)
    scan_enabled: bool = Field(default=True)
    yara_enabled: bool = Field(default=False)

    @validator("endpoint_url")
    def validate_endpoint_url(cls, v):
        """Validate S3 endpoint URL format."""
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("Endpoint URL must start with http:// or https://")
        return v

    @validator("file_types_filter", each_item=True)
    def validate_file_types(cls, v):
        """Validate file type filters."""
        v = v.strip().lower()
        if not v.startswith("."):
            v = "." + v
        return v


class BucketConfigUpdateRequest(BaseModel):
    """Bucket configuration update request model."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    endpoint_url: Optional[str] = Field(None, max_length=500)
    bucket_name: Optional[str] = Field(None, min_length=1, max_length=255)
    access_key_id: Optional[str] = Field(None, min_length=1, max_length=255)
    secret_access_key: Optional[str] = Field(None, min_length=1, max_length=500)
    region: Optional[str] = Field(None, max_length=50)
    use_ssl: Optional[bool] = None
    path_style: Optional[bool] = None
    prefix_filter: Optional[str] = Field(None, max_length=500)
    file_types_filter: Optional[List[str]] = Field(None, max_items=50)
    max_file_size_mb: Optional[int] = Field(None, ge=1, le=500)
    scan_enabled: Optional[bool] = None
    yara_enabled: Optional[bool] = None

    @validator("endpoint_url")
    def validate_endpoint_url(cls, v):
        """Validate S3 endpoint URL format."""
        if v is None:
            return v
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("Endpoint URL must start with http:// or https://")
        return v

    @validator("file_types_filter", each_item=True)
    def validate_file_types(cls, v):
        """Validate file type filters."""
        v = v.strip().lower()
        if not v.startswith("."):
            v = "." + v
        return v


class BucketConfigResponse(BaseModel):
    """Bucket configuration response model."""

    id: int
    name: str
    endpoint_url: str
    bucket_name: str
    access_key_id: str
    secret_access_key: str = Field(...)  # Will be masked in service layer
    region: str
    use_ssl: bool
    path_style: bool
    prefix_filter: Optional[str]
    file_types_filter: Optional[List[str]] = []
    max_file_size_mb: int
    scan_enabled: bool
    yara_enabled: bool
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

    @property
    def masked_secret(self) -> str:
        """Return masked secret access key."""
        if len(self.secret_access_key) <= 4:
            return "****"
        return (
            self.secret_access_key[:4]
            + "*" * (len(self.secret_access_key) - 8)
            + self.secret_access_key[-4:]
        )


# ============================================
# Scan Request Models
# ============================================


class TriggerScanRequest(BaseModel):
    """Trigger S3 scan request model."""

    prefix_filter: Optional[str] = Field(None, max_length=500)
    force_rescan: bool = Field(default=False)


class ScanResultsQueryRequest(BaseModel):
    """Query scan results request model."""

    bucket_config_id: Optional[int] = None
    scan_status: Optional[List[S3ScanStatus]] = None
    is_malware: Optional[bool] = None
    is_pup: Optional[bool] = None
    is_threat: Optional[bool] = None
    file_type: Optional[str] = Field(None, max_length=50)
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=50, ge=1, le=500)

    @validator("file_type")
    def validate_file_type(cls, v):
        """Validate file type format."""
        if v is None:
            return v
        v = v.strip().lower()
        if not v.startswith("."):
            v = "." + v
        return v


class ScheduleSetRequest(BaseModel):
    """Set scan schedule request model."""

    cron_expression: str = Field(..., max_length=255)
    timezone: str = Field(default="UTC", max_length=50)
    enabled: bool = Field(default=True)

    @validator("cron_expression")
    def validate_cron_expression(cls, v):
        """Validate cron expression format."""
        v = v.strip()
        parts = v.split()
        if len(parts) not in (5, 6):
            raise ValueError(
                "Cron expression must have 5 or 6 parts (minute hour day month dow [year])"
            )

        # Validate each part has valid characters
        allowed_chars = set("0123456789,-/*L?WC# ")
        if not all(c in allowed_chars for c in v):
            raise ValueError("Cron expression contains invalid characters")

        return v


class FileUploadScanRequest(BaseModel):
    """File upload scan request model (file comes via multipart)."""

    pass


class HashLookupRequest(BaseModel):
    """Hash lookup request model."""

    hash_value: str = Field(..., min_length=32, max_length=256)

    @validator("hash_value")
    def validate_hash_value(cls, v):
        """Validate hash value format (SHA256 or MD5)."""
        v = v.strip().upper()

        # Check if valid hex
        if not all(c in "0123456789ABCDEF" for c in v):
            raise ValueError("Hash must be valid hexadecimal")

        # Check length for MD5 (32) or SHA256 (64)
        if len(v) not in (32, 64):
            raise ValueError("Hash must be MD5 (32 chars) or SHA256 (64 chars)")

        return v


# ============================================
# Response Models
# ============================================


class ScanJobResponse(BaseModel):
    """Scan job response model."""

    id: int
    bucket_config_id: int
    job_type: S3ScanJobType
    status: S3ScanJobStatus
    files_scanned: int = 0
    files_infected: int = 0
    files_pup: int = 0
    files_error: int = 0
    files_skipped: int = 0
    prefix_filter: Optional[str]
    force_rescan: bool
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class ScanResultResponse(BaseModel):
    """Scan result response model."""

    id: int
    scan_job_id: int
    bucket_config_id: int
    file_key: str
    file_size: int
    file_type: str
    scan_status: S3ScanStatus
    is_malware: bool
    is_pup: bool
    is_threat: bool
    threat_names: List[str] = []
    yara_matches: List[str] = []
    sandbox_status: Optional[SandboxStatus]
    sandbox_report: Optional[Dict[str, Any]]
    scan_engine: Optional[str]
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    error_message: Optional[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)
    scanned_at: datetime
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class AdhocScanResponse(BaseModel):
    """Adhoc scan result response model."""

    id: int
    filename: str
    file_size: int
    scan_status: S3ScanStatus
    is_malware: bool
    is_pup: bool
    is_threat: bool
    threat_names: List[str] = []
    yara_matches: List[str] = []
    sandbox_status: Optional[SandboxStatus]
    sandbox_report: Optional[Dict[str, Any]]
    scan_engine: Optional[str]
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    file_hash_md5: Optional[str]
    file_hash_sha256: Optional[str]
    error_message: Optional[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)
    scanned_at: datetime
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class ScheduleResponse(BaseModel):
    """Scan schedule response model."""

    id: int
    bucket_config_id: int
    cron_expression: str
    timezone: str
    enabled: bool
    last_triggered_at: Optional[datetime]
    next_trigger_at: Optional[datetime]
    error_count: int = 0
    last_error_message: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============================================
# Statistics Models
# ============================================


class ScanStatisticsResponse(BaseModel):
    """Scan statistics response model."""

    total_scanned: int
    total_infected: int
    total_pup: int
    total_clean: int
    total_error: int
    total_skipped: int
    by_file_type: Dict[str, int] = Field(default_factory=dict)
    by_bucket: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    average_scan_time_ms: Optional[float] = None
    last_scan_at: Optional[datetime]
    scan_period_days: int = 30


# ============================================
# Common Pagination Models
# ============================================


class PaginatedScanJobResponse(BaseModel):
    """Paginated scan job response model."""

    items: List[ScanJobResponse]
    total: int
    page: int
    per_page: int
    pages: int


class PaginatedScanResultResponse(BaseModel):
    """Paginated scan result response model."""

    items: List[ScanResultResponse]
    total: int
    page: int
    per_page: int
    pages: int


class PaginatedBucketConfigResponse(BaseModel):
    """Paginated bucket config response model."""

    items: List[BucketConfigResponse]
    total: int
    page: int
    per_page: int
    pages: int
