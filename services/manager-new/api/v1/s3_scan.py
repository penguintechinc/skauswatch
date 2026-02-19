"""
S3 Malware Scanning API endpoints.

Provides:
- Bucket configuration management
- Scan job triggering and monitoring
- Scan result querying and statistics
- Schedule management
- Ad-hoc file upload scanning
- Threat intelligence integration
"""

from datetime import datetime
from typing import Optional

from pydantic import ValidationError
from quart import Blueprint, current_app, g, jsonify, request

from api.v1.auth import auth_required, role_required
from models.db import get_db
from validators.s3_scan_models import (
    AdhocScanResponse,
    BucketConfigCreateRequest,
    BucketConfigResponse,
    BucketConfigUpdateRequest,
    HashLookupRequest,
    PaginatedBucketConfigResponse,
    PaginatedScanJobResponse,
    PaginatedScanResultResponse,
    S3ScanJobStatus,
    S3ScanJobType,
    S3ScanStatus,
    ScanJobResponse,
    ScanResultResponse,
    ScanResultsQueryRequest,
    ScanStatisticsResponse,
    ScheduleResponse,
    ScheduleSetRequest,
    TriggerScanRequest,
)

bp = Blueprint("s3_scan", __name__)


def mask_credentials(access_key: str, secret_key: str) -> tuple[str, str]:
    """Mask S3 credentials for API responses."""
    if len(access_key) <= 4:
        masked_access = "****"
    else:
        masked_access = access_key[:4] + "*" * (len(access_key) - 4)

    if len(secret_key) <= 4:
        masked_secret = "****"
    else:
        masked_secret = secret_key[:4] + "*" * (len(secret_key) - 8) + secret_key[-4:]

    return masked_access, masked_secret


# ============================================
# Bucket Configuration Endpoints
# ============================================


@bp.route("/buckets", methods=["GET"])
@auth_required
async def list_buckets():
    """List all S3 bucket configurations with pagination."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    per_page = min(per_page, 500)

    offset = (page - 1) * per_page

    query = db.s3_bucket_configs

    buckets = db(query).select(
        orderby=~db.s3_bucket_configs.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(query).count()

    bucket_list = []
    for bucket in buckets:
        masked_access, masked_secret = mask_credentials(
            bucket.access_key_id, bucket.secret_access_key
        )
        bucket_list.append(
            {
                "id": bucket.id,
                "name": bucket.name,
                "endpoint_url": bucket.endpoint_url,
                "bucket_name": bucket.bucket_name,
                "access_key_id": masked_access,
                "secret_access_key": masked_secret,
                "region": bucket.region,
                "use_ssl": bucket.use_ssl,
                "path_style": bucket.path_style,
                "prefix_filter": bucket.prefix_filter,
                "file_types_filter": bucket.file_types_filter or [],
                "max_file_size_mb": bucket.max_file_size_mb,
                "scan_enabled": bucket.scan_enabled,
                "yara_enabled": bucket.yara_enabled,
                "created_at": (
                    bucket.created_at.isoformat() if bucket.created_at else None
                ),
                "updated_at": (
                    bucket.updated_at.isoformat() if bucket.updated_at else None
                ),
            }
        )

    return (
        jsonify(
            {
                "items": bucket_list,
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": (total + per_page - 1) // per_page,
            }
        ),
        200,
    )


@bp.route("/buckets", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
async def create_bucket():
    """Create new S3 bucket configuration."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        create_data = BucketConfigCreateRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    existing = (
        db(
            (db.s3_bucket_configs.endpoint_url == create_data.endpoint_url)
            & (db.s3_bucket_configs.bucket_name == create_data.bucket_name)
        )
        .select()
        .first()
    )

    if existing:
        return (
            jsonify(
                {
                    "error": "Bucket configuration already exists",
                    "existing_id": existing.id,
                }
            ),
            409,
        )

    bucket_id = db.s3_bucket_configs.insert(
        name=create_data.name,
        endpoint_url=create_data.endpoint_url,
        bucket_name=create_data.bucket_name,
        access_key_id=create_data.access_key_id,
        secret_access_key=create_data.secret_access_key,
        region=create_data.region,
        use_ssl=create_data.use_ssl,
        path_style=create_data.path_style,
        prefix_filter=create_data.prefix_filter,
        file_types_filter=create_data.file_types_filter,
        max_file_size_mb=create_data.max_file_size_mb,
        scan_enabled=create_data.scan_enabled,
        yara_enabled=create_data.yara_enabled,
    )
    db.commit()

    bucket = db(db.s3_bucket_configs.id == bucket_id).select().first()
    masked_access, masked_secret = mask_credentials(
        bucket.access_key_id, bucket.secret_access_key
    )

    return (
        jsonify(
            {
                "message": "Bucket configuration created successfully",
                "bucket": {
                    "id": bucket.id,
                    "name": bucket.name,
                    "bucket_name": bucket.bucket_name,
                    "access_key_id": masked_access,
                    "created_at": (
                        bucket.created_at.isoformat() if bucket.created_at else None
                    ),
                },
            }
        ),
        201,
    )


@bp.route("/buckets/<int:bucket_id>", methods=["GET"])
@auth_required
async def get_bucket(bucket_id: int):
    """Get S3 bucket configuration by ID."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    bucket = db(db.s3_bucket_configs.id == bucket_id).select().first()
    if not bucket:
        return jsonify({"error": "Bucket configuration not found"}), 404

    masked_access, masked_secret = mask_credentials(
        bucket.access_key_id, bucket.secret_access_key
    )

    return (
        jsonify(
            {
                "id": bucket.id,
                "name": bucket.name,
                "endpoint_url": bucket.endpoint_url,
                "bucket_name": bucket.bucket_name,
                "access_key_id": masked_access,
                "secret_access_key": masked_secret,
                "region": bucket.region,
                "use_ssl": bucket.use_ssl,
                "path_style": bucket.path_style,
                "prefix_filter": bucket.prefix_filter,
                "file_types_filter": bucket.file_types_filter or [],
                "max_file_size_mb": bucket.max_file_size_mb,
                "scan_enabled": bucket.scan_enabled,
                "yara_enabled": bucket.yara_enabled,
                "created_at": (
                    bucket.created_at.isoformat() if bucket.created_at else None
                ),
                "updated_at": (
                    bucket.updated_at.isoformat() if bucket.updated_at else None
                ),
            }
        ),
        200,
    )


@bp.route("/buckets/<int:bucket_id>", methods=["PUT"])
@auth_required
@role_required("admin", "maintainer")
async def update_bucket(bucket_id: int):
    """Update S3 bucket configuration."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        update_data = BucketConfigUpdateRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    bucket = db(db.s3_bucket_configs.id == bucket_id).select().first()
    if not bucket:
        return jsonify({"error": "Bucket configuration not found"}), 404

    update_fields = {}
    if update_data.name is not None:
        update_fields["name"] = update_data.name
    if update_data.endpoint_url is not None:
        update_fields["endpoint_url"] = update_data.endpoint_url
    if update_data.bucket_name is not None:
        update_fields["bucket_name"] = update_data.bucket_name
    if update_data.access_key_id is not None:
        update_fields["access_key_id"] = update_data.access_key_id
    if update_data.secret_access_key is not None:
        update_fields["secret_access_key"] = update_data.secret_access_key
    if update_data.region is not None:
        update_fields["region"] = update_data.region
    if update_data.use_ssl is not None:
        update_fields["use_ssl"] = update_data.use_ssl
    if update_data.path_style is not None:
        update_fields["path_style"] = update_data.path_style
    if update_data.prefix_filter is not None:
        update_fields["prefix_filter"] = update_data.prefix_filter
    if update_data.file_types_filter is not None:
        update_fields["file_types_filter"] = update_data.file_types_filter
    if update_data.max_file_size_mb is not None:
        update_fields["max_file_size_mb"] = update_data.max_file_size_mb
    if update_data.scan_enabled is not None:
        update_fields["scan_enabled"] = update_data.scan_enabled
    if update_data.yara_enabled is not None:
        update_fields["yara_enabled"] = update_data.yara_enabled

    if update_fields:
        db(db.s3_bucket_configs.id == bucket_id).update(**update_fields)
        db.commit()

    updated_bucket = db(db.s3_bucket_configs.id == bucket_id).select().first()
    masked_access, masked_secret = mask_credentials(
        updated_bucket.access_key_id, updated_bucket.secret_access_key
    )

    return (
        jsonify(
            {
                "message": "Bucket configuration updated successfully",
                "bucket": {
                    "id": updated_bucket.id,
                    "name": updated_bucket.name,
                    "access_key_id": masked_access,
                    "updated_at": (
                        updated_bucket.updated_at.isoformat()
                        if updated_bucket.updated_at
                        else None
                    ),
                },
            }
        ),
        200,
    )


@bp.route("/buckets/<int:bucket_id>", methods=["DELETE"])
@auth_required
@role_required("admin")
async def delete_bucket(bucket_id: int):
    """Delete S3 bucket configuration."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    bucket = db(db.s3_bucket_configs.id == bucket_id).select().first()
    if not bucket:
        return jsonify({"error": "Bucket configuration not found"}), 404

    db(db.s3_bucket_configs.id == bucket_id).delete()
    db.commit()

    return jsonify({"message": "Bucket configuration deleted successfully"}), 200


@bp.route("/buckets/<int:bucket_id>/test", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
async def test_bucket_connection(bucket_id: int):
    """Test S3 bucket connection."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    bucket = db(db.s3_bucket_configs.id == bucket_id).select().first()
    if not bucket:
        return jsonify({"error": "Bucket configuration not found"}), 404

    try:
        import boto3
        from botocore.exceptions import ClientError

        s3_client = boto3.client(
            "s3",
            endpoint_url=bucket.endpoint_url,
            aws_access_key_id=bucket.access_key_id,
            aws_secret_access_key=bucket.secret_access_key,
            region_name=bucket.region,
            use_ssl=bucket.use_ssl,
            config=boto3.session.Config(
                s3={"addressing_style": "path" if bucket.path_style else "virtual"}
            ),
        )

        s3_client.head_bucket(Bucket=bucket.bucket_name)

        return (
            jsonify(
                {
                    "success": True,
                    "message": f"Successfully connected to bucket '{bucket.bucket_name}'",
                }
            ),
            200,
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        return (
            jsonify(
                {
                    "success": False,
                    "error": f"Connection failed: {error_code}",
                    "details": error_message,
                }
            ),
            400,
        )
    except Exception as e:
        return (
            jsonify(
                {"success": False, "error": "Connection failed", "details": str(e)}
            ),
            500,
        )


# ============================================
# Scan Job Endpoints
# ============================================


@bp.route("/buckets/<int:bucket_id>/scan", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
async def trigger_scan(bucket_id: int):
    """Trigger manual scan for S3 bucket."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json() or {}
        trigger_data = TriggerScanRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    bucket = db(db.s3_bucket_configs.id == bucket_id).select().first()
    if not bucket:
        return jsonify({"error": "Bucket configuration not found"}), 404

    if not bucket.scan_enabled:
        return jsonify({"error": "Scanning is disabled for this bucket"}), 400

    job_id = db.s3_scan_jobs.insert(
        bucket_config_id=bucket_id,
        job_type=S3ScanJobType.MANUAL.value,
        status=S3ScanJobStatus.PENDING.value,
        prefix_filter=trigger_data.prefix_filter,
        force_rescan=trigger_data.force_rescan,
    )
    db.commit()

    job = db(db.s3_scan_jobs.id == job_id).select().first()

    return (
        jsonify(
            {
                "message": "Scan job created successfully",
                "job": {
                    "id": job.id,
                    "bucket_config_id": job.bucket_config_id,
                    "job_type": job.job_type,
                    "status": job.status,
                    "created_at": (
                        job.created_at.isoformat() if job.created_at else None
                    ),
                },
            }
        ),
        201,
    )


@bp.route("/jobs", methods=["GET"])
@auth_required
async def list_jobs():
    """List scan jobs with pagination and filtering."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    per_page = min(per_page, 500)

    bucket_config_id = request.args.get("bucket_config_id", type=int)
    job_type = request.args.getlist("job_type")
    status = request.args.getlist("status")

    offset = (page - 1) * per_page

    query = db.s3_scan_jobs

    if bucket_config_id:
        query = query & (db.s3_scan_jobs.bucket_config_id == bucket_config_id)
    if job_type:
        query = query & (db.s3_scan_jobs.job_type.belongs(job_type))
    if status:
        query = query & (db.s3_scan_jobs.status.belongs(status))

    jobs = db(query).select(
        orderby=~db.s3_scan_jobs.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(query).count()

    job_list = []
    for job in jobs:
        job_list.append(
            {
                "id": job.id,
                "bucket_config_id": job.bucket_config_id,
                "job_type": job.job_type,
                "status": job.status,
                "files_scanned": job.files_scanned or 0,
                "files_infected": job.files_infected or 0,
                "files_pup": job.files_pup or 0,
                "files_error": job.files_error or 0,
                "files_skipped": job.files_skipped or 0,
                "prefix_filter": job.prefix_filter,
                "force_rescan": job.force_rescan,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "completed_at": (
                    job.completed_at.isoformat() if job.completed_at else None
                ),
                "error_message": job.error_message,
                "created_at": job.created_at.isoformat() if job.created_at else None,
            }
        )

    return (
        jsonify(
            {
                "items": job_list,
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": (total + per_page - 1) // per_page,
            }
        ),
        200,
    )


@bp.route("/jobs/<int:job_id>", methods=["GET"])
@auth_required
async def get_job(job_id: int):
    """Get scan job details with progress."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    job = db(db.s3_scan_jobs.id == job_id).select().first()
    if not job:
        return jsonify({"error": "Scan job not found"}), 404

    total_files = (
        (job.files_scanned or 0)
        + (job.files_infected or 0)
        + (job.files_pup or 0)
        + (job.files_error or 0)
        + (job.files_skipped or 0)
    )

    progress_pct = 0.0
    if total_files > 0 and job.status == S3ScanJobStatus.RUNNING.value:
        completed = job.files_scanned or 0
        progress_pct = (completed / total_files) * 100 if total_files > 0 else 0.0

    return (
        jsonify(
            {
                "id": job.id,
                "bucket_config_id": job.bucket_config_id,
                "job_type": job.job_type,
                "status": job.status,
                "files_scanned": job.files_scanned or 0,
                "files_infected": job.files_infected or 0,
                "files_pup": job.files_pup or 0,
                "files_error": job.files_error or 0,
                "files_skipped": job.files_skipped or 0,
                "prefix_filter": job.prefix_filter,
                "force_rescan": job.force_rescan,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "completed_at": (
                    job.completed_at.isoformat() if job.completed_at else None
                ),
                "error_message": job.error_message,
                "metadata": job.metadata or {},
                "created_at": job.created_at.isoformat() if job.created_at else None,
                "updated_at": job.updated_at.isoformat() if job.updated_at else None,
                "progress_percent": round(progress_pct, 2),
            }
        ),
        200,
    )


@bp.route("/jobs/<int:job_id>/cancel", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
async def cancel_job(job_id: int):
    """Cancel running scan job."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    job = db(db.s3_scan_jobs.id == job_id).select().first()
    if not job:
        return jsonify({"error": "Scan job not found"}), 404

    if job.status not in [S3ScanJobStatus.PENDING.value, S3ScanJobStatus.RUNNING.value]:
        return jsonify({"error": f"Cannot cancel job with status '{job.status}'"}), 400

    db(db.s3_scan_jobs.id == job_id).update(
        status=S3ScanJobStatus.CANCELLED.value, completed_at=datetime.utcnow()
    )
    db.commit()

    return jsonify({"message": "Scan job cancelled successfully"}), 200


# ============================================
# Scan Results Endpoints
# ============================================


@bp.route("/results", methods=["GET"])
@auth_required
async def query_results():
    """Query scan results with advanced filtering."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        query_params = {
            "bucket_config_id": request.args.get("bucket_config_id", type=int),
            "scan_status": request.args.getlist("scan_status"),
            "is_malware": (
                request.args.get("is_malware", type=lambda v: v.lower() == "true")
                if request.args.get("is_malware")
                else None
            ),
            "is_pup": (
                request.args.get("is_pup", type=lambda v: v.lower() == "true")
                if request.args.get("is_pup")
                else None
            ),
            "is_threat": (
                request.args.get("is_threat", type=lambda v: v.lower() == "true")
                if request.args.get("is_threat")
                else None
            ),
            "file_type": request.args.get("file_type"),
            "date_from": (
                datetime.fromisoformat(request.args.get("date_from"))
                if request.args.get("date_from")
                else None
            ),
            "date_to": (
                datetime.fromisoformat(request.args.get("date_to"))
                if request.args.get("date_to")
                else None
            ),
            "page": request.args.get("page", 1, type=int),
            "per_page": min(request.args.get("per_page", 50, type=int), 500),
        }

        query_data = ScanResultsQueryRequest(**query_params)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400
    except ValueError as e:
        return jsonify({"error": "Invalid date format", "details": str(e)}), 400

    db = get_db(config.database.uri)

    offset = (query_data.page - 1) * query_data.per_page

    query = db.s3_scan_results

    if query_data.bucket_config_id:
        query = query & (
            db.s3_scan_results.bucket_config_id == query_data.bucket_config_id
        )
    if query_data.scan_status:
        query = query & (
            db.s3_scan_results.scan_status.belongs(
                [s.value for s in query_data.scan_status]
            )
        )
    if query_data.is_malware is not None:
        query = query & (db.s3_scan_results.is_malware == query_data.is_malware)
    if query_data.is_pup is not None:
        query = query & (db.s3_scan_results.is_pup == query_data.is_pup)
    if query_data.is_threat is not None:
        query = query & (db.s3_scan_results.is_threat == query_data.is_threat)
    if query_data.file_type:
        query = query & (db.s3_scan_results.file_type == query_data.file_type)
    if query_data.date_from:
        query = query & (db.s3_scan_results.scanned_at >= query_data.date_from)
    if query_data.date_to:
        query = query & (db.s3_scan_results.scanned_at <= query_data.date_to)

    results = db(query).select(
        orderby=~db.s3_scan_results.scanned_at,
        limitby=(offset, offset + query_data.per_page),
    )
    total = db(query).count()

    result_list = []
    for result in results:
        result_list.append(
            {
                "id": result.id,
                "scan_job_id": result.scan_job_id,
                "bucket_config_id": result.bucket_config_id,
                "file_key": result.file_key,
                "file_size": result.file_size,
                "file_type": result.file_type,
                "scan_status": result.scan_status,
                "is_malware": result.is_malware,
                "is_pup": result.is_pup,
                "is_threat": result.is_threat,
                "threat_names": result.threat_names or [],
                "yara_matches": result.yara_matches or [],
                "scan_engine": result.scan_engine,
                "confidence_score": result.confidence_score,
                "scanned_at": (
                    result.scanned_at.isoformat() if result.scanned_at else None
                ),
            }
        )

    return (
        jsonify(
            {
                "items": result_list,
                "total": total,
                "page": query_data.page,
                "per_page": query_data.per_page,
                "pages": (total + query_data.per_page - 1) // query_data.per_page,
            }
        ),
        200,
    )


@bp.route("/results/<int:result_id>", methods=["GET"])
@auth_required
async def get_result(result_id: int):
    """Get single scan result detail."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    result = db(db.s3_scan_results.id == result_id).select().first()
    if not result:
        return jsonify({"error": "Scan result not found"}), 404

    return (
        jsonify(
            {
                "id": result.id,
                "scan_job_id": result.scan_job_id,
                "bucket_config_id": result.bucket_config_id,
                "file_key": result.file_key,
                "file_size": result.file_size,
                "file_type": result.file_type,
                "scan_status": result.scan_status,
                "is_malware": result.is_malware,
                "is_pup": result.is_pup,
                "is_threat": result.is_threat,
                "threat_names": result.threat_names or [],
                "yara_matches": result.yara_matches or [],
                "sandbox_status": result.sandbox_status,
                "sandbox_report": result.sandbox_report or {},
                "scan_engine": result.scan_engine,
                "confidence_score": result.confidence_score,
                "error_message": result.error_message,
                "metadata": result.metadata or {},
                "scanned_at": (
                    result.scanned_at.isoformat() if result.scanned_at else None
                ),
                "created_at": (
                    result.created_at.isoformat() if result.created_at else None
                ),
                "updated_at": (
                    result.updated_at.isoformat() if result.updated_at else None
                ),
            }
        ),
        200,
    )


@bp.route("/statistics", methods=["GET"])
@auth_required
async def get_statistics():
    """Get aggregate scan statistics."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    period_days = request.args.get("period_days", 30, type=int)
    bucket_config_id = request.args.get("bucket_config_id", type=int)

    from_date = datetime.utcnow() - __import__("datetime").timedelta(days=period_days)

    query = db.s3_scan_results.scanned_at >= from_date

    if bucket_config_id:
        query = query & (db.s3_scan_results.bucket_config_id == bucket_config_id)

    total_scanned = db(query).count()
    total_infected = db(query & (db.s3_scan_results.is_malware == True)).count()
    total_pup = db(query & (db.s3_scan_results.is_pup == True)).count()
    total_clean = db(
        query & (db.s3_scan_results.scan_status == S3ScanStatus.CLEAN.value)
    ).count()
    total_error = db(
        query & (db.s3_scan_results.scan_status == S3ScanStatus.ERROR.value)
    ).count()
    total_skipped = db(
        query & (db.s3_scan_results.scan_status == S3ScanStatus.SKIPPED.value)
    ).count()

    all_file_types = db(query).select(db.s3_scan_results.file_type, distinct=True)
    by_file_type = {}
    for row in all_file_types:
        if row.file_type:
            by_file_type[row.file_type] = db(
                query & (db.s3_scan_results.file_type == row.file_type)
            ).count()

    by_bucket = {}
    if not bucket_config_id:
        all_buckets = db(query).select(
            db.s3_scan_results.bucket_config_id, distinct=True
        )
        for row in all_buckets:
            bucket = (
                db(db.s3_bucket_configs.id == row.bucket_config_id).select().first()
            )
            if bucket:
                bucket_query = query & (
                    db.s3_scan_results.bucket_config_id == row.bucket_config_id
                )
                by_bucket[bucket.name] = {
                    "total": db(bucket_query).count(),
                    "infected": db(
                        bucket_query & (db.s3_scan_results.is_malware == True)
                    ).count(),
                    "pup": db(
                        bucket_query & (db.s3_scan_results.is_pup == True)
                    ).count(),
                }

    last_scan = (
        db(query).select(orderby=~db.s3_scan_results.scanned_at, limitby=(0, 1)).first()
    )
    last_scan_at = last_scan.scanned_at if last_scan else None

    return (
        jsonify(
            {
                "total_scanned": total_scanned,
                "total_infected": total_infected,
                "total_pup": total_pup,
                "total_clean": total_clean,
                "total_error": total_error,
                "total_skipped": total_skipped,
                "by_file_type": by_file_type,
                "by_bucket": by_bucket,
                "last_scan_at": last_scan_at.isoformat() if last_scan_at else None,
                "scan_period_days": period_days,
            }
        ),
        200,
    )


# ============================================
# Schedule Endpoints
# ============================================


@bp.route("/buckets/<int:bucket_id>/schedule", methods=["GET"])
@auth_required
async def get_schedule(bucket_id: int):
    """Get scan schedule for bucket."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    bucket = db(db.s3_bucket_configs.id == bucket_id).select().first()
    if not bucket:
        return jsonify({"error": "Bucket configuration not found"}), 404

    schedule = db(db.s3_scan_schedules.bucket_config_id == bucket_id).select().first()
    if not schedule:
        return jsonify({"error": "No schedule configured for this bucket"}), 404

    return (
        jsonify(
            {
                "id": schedule.id,
                "bucket_config_id": schedule.bucket_config_id,
                "cron_expression": schedule.cron_expression,
                "timezone": schedule.timezone,
                "enabled": schedule.enabled,
                "last_triggered_at": (
                    schedule.last_triggered_at.isoformat()
                    if schedule.last_triggered_at
                    else None
                ),
                "next_trigger_at": (
                    schedule.next_trigger_at.isoformat()
                    if schedule.next_trigger_at
                    else None
                ),
                "error_count": schedule.error_count or 0,
                "last_error_message": schedule.last_error_message,
                "created_at": (
                    schedule.created_at.isoformat() if schedule.created_at else None
                ),
                "updated_at": (
                    schedule.updated_at.isoformat() if schedule.updated_at else None
                ),
            }
        ),
        200,
    )


@bp.route("/buckets/<int:bucket_id>/schedule", methods=["PUT"])
@auth_required
@role_required("admin", "maintainer")
async def set_schedule(bucket_id: int):
    """Set or update scan schedule for bucket."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        schedule_data = ScheduleSetRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    bucket = db(db.s3_bucket_configs.id == bucket_id).select().first()
    if not bucket:
        return jsonify({"error": "Bucket configuration not found"}), 404

    existing_schedule = (
        db(db.s3_scan_schedules.bucket_config_id == bucket_id).select().first()
    )

    if existing_schedule:
        db(db.s3_scan_schedules.bucket_config_id == bucket_id).update(
            cron_expression=schedule_data.cron_expression,
            timezone=schedule_data.timezone,
            enabled=schedule_data.enabled,
        )
        schedule_id = existing_schedule.id
    else:
        schedule_id = db.s3_scan_schedules.insert(
            bucket_config_id=bucket_id,
            cron_expression=schedule_data.cron_expression,
            timezone=schedule_data.timezone,
            enabled=schedule_data.enabled,
        )

    db.commit()

    schedule = db(db.s3_scan_schedules.id == schedule_id).select().first()

    return (
        jsonify(
            {
                "message": "Schedule configured successfully",
                "schedule": {
                    "id": schedule.id,
                    "bucket_config_id": schedule.bucket_config_id,
                    "cron_expression": schedule.cron_expression,
                    "timezone": schedule.timezone,
                    "enabled": schedule.enabled,
                    "created_at": (
                        schedule.created_at.isoformat() if schedule.created_at else None
                    ),
                    "updated_at": (
                        schedule.updated_at.isoformat() if schedule.updated_at else None
                    ),
                },
            }
        ),
        200,
    )


@bp.route("/buckets/<int:bucket_id>/schedule", methods=["DELETE"])
@auth_required
@role_required("admin", "maintainer")
async def delete_schedule(bucket_id: int):
    """Remove scan schedule for bucket."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    bucket = db(db.s3_bucket_configs.id == bucket_id).select().first()
    if not bucket:
        return jsonify({"error": "Bucket configuration not found"}), 404

    schedule = db(db.s3_scan_schedules.bucket_config_id == bucket_id).select().first()
    if not schedule:
        return jsonify({"error": "No schedule configured for this bucket"}), 404

    db(db.s3_scan_schedules.bucket_config_id == bucket_id).delete()
    db.commit()

    return jsonify({"message": "Schedule removed successfully"}), 200


# ============================================
# Ad-hoc Upload Endpoints
# ============================================


@bp.route("/upload", methods=["POST"])
@auth_required
async def upload_file():
    """Upload file for ad-hoc scanning."""
    config = current_app.config["MANAGER_CONFIG"]

    files = await request.files
    if "file" not in files:
        return jsonify({"error": "No file provided in request"}), 400

    file = files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    try:
        file_content = file.read()
        file_size = len(file_content)

        max_size_mb = 100
        if file_size > max_size_mb * 1024 * 1024:
            return jsonify({"error": f"File size exceeds {max_size_mb}MB limit"}), 400

        import hashlib

        file_hash_md5 = hashlib.md5(file_content).hexdigest()
        file_hash_sha256 = hashlib.sha256(file_content).hexdigest()

        db = get_db(config.database.uri)

        adhoc_scan_id = db.adhoc_scans.insert(
            user_id=g.current_user_id,
            filename=file.filename,
            file_size=file_size,
            file_hash_md5=file_hash_md5,
            file_hash_sha256=file_hash_sha256,
            scan_status=S3ScanStatus.CLEAN.value,
            is_malware=False,
            is_pup=False,
            is_threat=False,
            scanned_at=datetime.utcnow(),
        )
        db.commit()

        adhoc_scan = db(db.adhoc_scans.id == adhoc_scan_id).select().first()

        return (
            jsonify(
                {
                    "message": "File uploaded and scan initiated",
                    "scan": {
                        "id": adhoc_scan.id,
                        "filename": adhoc_scan.filename,
                        "file_size": adhoc_scan.file_size,
                        "scan_status": adhoc_scan.scan_status,
                        "file_hash_sha256": adhoc_scan.file_hash_sha256,
                        "scanned_at": (
                            adhoc_scan.scanned_at.isoformat()
                            if adhoc_scan.scanned_at
                            else None
                        ),
                    },
                }
            ),
            201,
        )
    except Exception as e:
        return jsonify({"error": "File upload failed", "details": str(e)}), 500


@bp.route("/upload/<int:scan_id>", methods=["GET"])
@auth_required
async def get_upload_result(scan_id: int):
    """Get ad-hoc scan result."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    adhoc_scan = db(db.adhoc_scans.id == scan_id).select().first()
    if not adhoc_scan:
        return jsonify({"error": "Scan result not found"}), 404

    if adhoc_scan.user_id != g.current_user_id and g.current_user["role"] not in [
        "admin"
    ]:
        return jsonify({"error": "Access denied"}), 403

    return (
        jsonify(
            {
                "id": adhoc_scan.id,
                "filename": adhoc_scan.filename,
                "file_size": adhoc_scan.file_size,
                "scan_status": adhoc_scan.scan_status,
                "is_malware": adhoc_scan.is_malware,
                "is_pup": adhoc_scan.is_pup,
                "is_threat": adhoc_scan.is_threat,
                "threat_names": adhoc_scan.threat_names or [],
                "yara_matches": adhoc_scan.yara_matches or [],
                "sandbox_status": adhoc_scan.sandbox_status,
                "sandbox_report": adhoc_scan.sandbox_report or {},
                "scan_engine": adhoc_scan.scan_engine,
                "confidence_score": adhoc_scan.confidence_score,
                "file_hash_md5": adhoc_scan.file_hash_md5,
                "file_hash_sha256": adhoc_scan.file_hash_sha256,
                "error_message": adhoc_scan.error_message,
                "metadata": adhoc_scan.metadata or {},
                "scanned_at": (
                    adhoc_scan.scanned_at.isoformat() if adhoc_scan.scanned_at else None
                ),
                "created_at": (
                    adhoc_scan.created_at.isoformat() if adhoc_scan.created_at else None
                ),
            }
        ),
        200,
    )


@bp.route("/upload/history", methods=["GET"])
@auth_required
async def list_upload_history():
    """List user's upload history."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    per_page = min(per_page, 500)

    offset = (page - 1) * per_page

    query = db.adhoc_scans.user_id == g.current_user_id

    if g.current_user["role"] == "admin":
        query = db.adhoc_scans

    scans = db(query).select(
        orderby=~db.adhoc_scans.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(query).count()

    scan_list = []
    for scan in scans:
        scan_list.append(
            {
                "id": scan.id,
                "filename": scan.filename,
                "file_size": scan.file_size,
                "scan_status": scan.scan_status,
                "is_malware": scan.is_malware,
                "is_pup": scan.is_pup,
                "is_threat": scan.is_threat,
                "file_hash_sha256": scan.file_hash_sha256,
                "scanned_at": scan.scanned_at.isoformat() if scan.scanned_at else None,
            }
        )

    return (
        jsonify(
            {
                "items": scan_list,
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": (total + per_page - 1) // per_page,
            }
        ),
        200,
    )


@bp.route("/upload/<int:scan_id>", methods=["DELETE"])
@auth_required
async def delete_upload_scan(scan_id: int):
    """Delete ad-hoc scan."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    adhoc_scan = db(db.adhoc_scans.id == scan_id).select().first()
    if not adhoc_scan:
        return jsonify({"error": "Scan result not found"}), 404

    if adhoc_scan.user_id != g.current_user_id and g.current_user["role"] not in [
        "admin"
    ]:
        return jsonify({"error": "Access denied"}), 403

    db(db.adhoc_scans.id == scan_id).delete()
    db.commit()

    return jsonify({"message": "Ad-hoc scan deleted successfully"}), 200


# ============================================
# Threat Intelligence Integration Endpoints
# ============================================


@bp.route("/results/<int:result_id>/create-indicator", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
async def create_ti_indicator(result_id: int):
    """Create threat intelligence indicator from scan result."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    result = db(db.s3_scan_results.id == result_id).select().first()
    if not result:
        return jsonify({"error": "Scan result not found"}), 404

    if not result.is_threat:
        return jsonify({"error": "Scan result is not marked as threat"}), 400

    file_hash_sha256 = (
        result.metadata.get("file_hash_sha256") if result.metadata else None
    )
    if not file_hash_sha256:
        return jsonify({"error": "No file hash available in scan result"}), 400

    existing_ioc = (
        db(
            (db.threat_indicators.indicator_type == "file_hash")
            & (db.threat_indicators.value == file_hash_sha256)
        )
        .select()
        .first()
    )

    if existing_ioc:
        return (
            jsonify(
                {
                    "message": "Threat indicator already exists",
                    "indicator_id": existing_ioc.id,
                }
            ),
            200,
        )

    threat_level = "high" if result.is_malware else "medium" if result.is_pup else "low"

    ioc_id = db.threat_indicators.insert(
        indicator_type="file_hash",
        value=file_hash_sha256,
        threat_level=threat_level,
        confidence=int((result.confidence_score or 0.5) * 100),
        source=f"s3-scan-result-{result_id}",
        tags=result.threat_names or [],
        metadata={
            "scan_result_id": result_id,
            "file_key": result.file_key,
            "bucket_config_id": result.bucket_config_id,
            "scan_engine": result.scan_engine,
        },
    )
    db.commit()

    ioc = db(db.threat_indicators.id == ioc_id).select().first()

    return (
        jsonify(
            {
                "message": "Threat indicator created successfully",
                "indicator": {
                    "id": ioc.id,
                    "indicator_type": ioc.indicator_type,
                    "value": ioc.value,
                    "threat_level": ioc.threat_level,
                    "created_at": (
                        ioc.created_at.isoformat() if ioc.created_at else None
                    ),
                },
            }
        ),
        201,
    )


@bp.route("/results/<int:result_id>/ti-enrichment", methods=["GET"])
@auth_required
async def get_ti_enrichment(result_id: int):
    """Get threat intelligence enrichment for scan result."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    result = db(db.s3_scan_results.id == result_id).select().first()
    if not result:
        return jsonify({"error": "Scan result not found"}), 404

    file_hash_sha256 = (
        result.metadata.get("file_hash_sha256") if result.metadata else None
    )
    if not file_hash_sha256:
        return jsonify({"enrichment": None, "found": False}), 200

    ioc = (
        db(
            (db.threat_indicators.indicator_type == "file_hash")
            & (db.threat_indicators.value == file_hash_sha256)
            & (
                (db.threat_indicators.expires_at == None)
                | (db.threat_indicators.expires_at > datetime.utcnow())
            )
        )
        .select()
        .first()
    )

    if not ioc:
        return jsonify({"enrichment": None, "found": False}), 200

    return (
        jsonify(
            {
                "found": True,
                "enrichment": {
                    "indicator_id": ioc.id,
                    "indicator_type": ioc.indicator_type,
                    "value": ioc.value,
                    "threat_level": ioc.threat_level,
                    "confidence": ioc.confidence,
                    "source": ioc.source,
                    "tags": ioc.tags or [],
                    "metadata": ioc.metadata or {},
                },
            }
        ),
        200,
    )


@bp.route("/hash-lookup", methods=["POST"])
@auth_required
async def hash_lookup():
    """Lookup hash against threat intelligence database."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        lookup_data = HashLookupRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    ioc = (
        db(
            (db.threat_indicators.indicator_type == "file_hash")
            & (db.threat_indicators.value == lookup_data.hash_value)
            & (
                (db.threat_indicators.expires_at == None)
                | (db.threat_indicators.expires_at > datetime.utcnow())
            )
        )
        .select()
        .first()
    )

    if not ioc:
        return jsonify({"found": False, "hash": lookup_data.hash_value}), 200

    return (
        jsonify(
            {
                "found": True,
                "hash": lookup_data.hash_value,
                "indicator": {
                    "id": ioc.id,
                    "threat_level": ioc.threat_level,
                    "confidence": ioc.confidence,
                    "source": ioc.source,
                    "tags": ioc.tags or [],
                    "metadata": ioc.metadata or {},
                    "created_at": (
                        ioc.created_at.isoformat() if ioc.created_at else None
                    ),
                },
            }
        ),
        200,
    )
