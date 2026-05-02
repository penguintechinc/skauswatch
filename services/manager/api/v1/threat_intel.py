"""
Threat Intelligence API endpoints.

Provides:
- IOC (Indicators of Compromise) management
- Threat feed management
- IOC lookup/enrichment
"""

from datetime import datetime
from typing import List, Optional

from api.v1.auth import auth_required, role_required
from models.db import get_db
from pydantic import ValidationError
from quart import Blueprint, current_app, g, jsonify, request
from validators.pydantic_models import (
    IndicatorType,
    IOCBulkCreateRequest,
    IOCCreateRequest,
    IOCResponse,
    IOCSearchRequest,
    ThreatLevel,
)

bp = Blueprint("threat_intel", __name__)


@bp.route("/iocs", methods=["GET"])
@auth_required
async def list_iocs():
    """List IOCs with pagination and filtering."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    # Get pagination params
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    per_page = min(per_page, 500)

    # Get filter params
    indicator_type = request.args.getlist("type")
    threat_level = request.args.getlist("threat_level")
    source = request.args.get("source")
    include_expired = request.args.get("include_expired", "false").lower() == "true"

    offset = (page - 1) * per_page

    # Build query
    query = db.threat_indicators

    if indicator_type:
        query = query & (db.threat_indicators.indicator_type.belongs(indicator_type))
    if threat_level:
        query = query & (db.threat_indicators.threat_level.belongs(threat_level))
    if source:
        query = query & (db.threat_indicators.source == source)
    if not include_expired:
        query = query & (
            (db.threat_indicators.expires_at == None)
            | (db.threat_indicators.expires_at > datetime.utcnow())
        )

    # Execute query
    iocs = db(query).select(
        orderby=~db.threat_indicators.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(query).count()

    # Convert to response format
    ioc_list = []
    for ioc in iocs:
        ioc_list.append(
            {
                "id": ioc.id,
                "indicator_type": ioc.indicator_type,
                "value": ioc.value,
                "threat_level": ioc.threat_level,
                "confidence": ioc.confidence,
                "source": ioc.source,
                "tags": ioc.tags or [],
                "metadata": ioc.metadata or {},
                "expires_at": ioc.expires_at.isoformat() if ioc.expires_at else None,
                "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
            }
        )

    return (
        jsonify(
            {
                "items": ioc_list,
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": (total + per_page - 1) // per_page,
            }
        ),
        200,
    )


@bp.route("/iocs/<int:ioc_id>", methods=["GET"])
@auth_required
async def get_ioc(ioc_id: int):
    """Get IOC by ID."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    ioc = db(db.threat_indicators.id == ioc_id).select().first()
    if not ioc:
        return jsonify({"error": "IOC not found"}), 404

    return (
        jsonify(
            {
                "id": ioc.id,
                "indicator_type": ioc.indicator_type,
                "value": ioc.value,
                "threat_level": ioc.threat_level,
                "confidence": ioc.confidence,
                "source": ioc.source,
                "tags": ioc.tags or [],
                "metadata": ioc.metadata or {},
                "expires_at": ioc.expires_at.isoformat() if ioc.expires_at else None,
                "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
                "updated_at": ioc.updated_at.isoformat() if ioc.updated_at else None,
            }
        ),
        200,
    )


@bp.route("/iocs", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
async def create_ioc():
    """Create a new IOC."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        create_data = IOCCreateRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    # Check for duplicate
    existing = (
        db(
            (db.threat_indicators.indicator_type == create_data.indicator_type.value)
            & (db.threat_indicators.value == create_data.value)
        )
        .select()
        .first()
    )

    if existing:
        return jsonify({"error": "IOC already exists", "existing_id": existing.id}), 409

    # Create IOC
    ioc_id = db.threat_indicators.insert(
        indicator_type=create_data.indicator_type.value,
        value=create_data.value,
        threat_level=create_data.threat_level.value,
        confidence=create_data.confidence,
        source=create_data.source,
        tags=create_data.tags,
        metadata=create_data.metadata,
        expires_at=create_data.expires_at,
    )
    db.commit()

    ioc = db(db.threat_indicators.id == ioc_id).select().first()

    return (
        jsonify(
            {
                "message": "IOC created successfully",
                "ioc": {
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


@bp.route("/iocs/bulk", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
async def bulk_create_iocs():
    """Bulk create IOCs."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        bulk_data = IOCBulkCreateRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    created_count = 0
    updated_count = 0
    errors = []

    for idx, ioc_data in enumerate(bulk_data.indicators):
        try:
            # Check for existing
            existing = (
                db(
                    (
                        db.threat_indicators.indicator_type
                        == ioc_data.indicator_type.value
                    )
                    & (db.threat_indicators.value == ioc_data.value)
                )
                .select()
                .first()
            )

            if existing:
                # Update existing
                db(db.threat_indicators.id == existing.id).update(
                    threat_level=ioc_data.threat_level.value,
                    confidence=ioc_data.confidence,
                    source=ioc_data.source,
                    tags=ioc_data.tags,
                    metadata=ioc_data.metadata,
                    expires_at=ioc_data.expires_at,
                )
                updated_count += 1
            else:
                # Create new
                db.threat_indicators.insert(
                    indicator_type=ioc_data.indicator_type.value,
                    value=ioc_data.value,
                    threat_level=ioc_data.threat_level.value,
                    confidence=ioc_data.confidence,
                    source=ioc_data.source,
                    tags=ioc_data.tags,
                    metadata=ioc_data.metadata,
                    expires_at=ioc_data.expires_at,
                )
                created_count += 1
        except Exception as e:
            errors.append({"index": idx, "error": str(e)})

    db.commit()

    return (
        jsonify(
            {
                "success": True,
                "created_count": created_count,
                "updated_count": updated_count,
                "error_count": len(errors),
                "errors": errors[:10],  # Return first 10 errors
            }
        ),
        201,
    )


@bp.route("/iocs/<int:ioc_id>", methods=["DELETE"])
@auth_required
@role_required("admin")
async def delete_ioc(ioc_id: int):
    """Delete an IOC."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    ioc = db(db.threat_indicators.id == ioc_id).select().first()
    if not ioc:
        return jsonify({"error": "IOC not found"}), 404

    db(db.threat_indicators.id == ioc_id).delete()
    db.commit()

    return jsonify({"message": "IOC deleted successfully"}), 200


@bp.route("/iocs/search", methods=["POST"])
@auth_required
async def search_iocs():
    """Search IOCs with advanced filtering."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        search_data = IOCSearchRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    offset = (search_data.page - 1) * search_data.per_page

    # Build query
    query = db.threat_indicators

    if search_data.query:
        query = query & (db.threat_indicators.value.contains(search_data.query))
    if search_data.indicator_type:
        query = query & (
            db.threat_indicators.indicator_type.belongs(
                [t.value for t in search_data.indicator_type]
            )
        )
    if search_data.threat_level:
        query = query & (
            db.threat_indicators.threat_level.belongs(
                [t.value for t in search_data.threat_level]
            )
        )
    if search_data.source:
        query = query & (db.threat_indicators.source == search_data.source)
    if search_data.confidence_min:
        query = query & (db.threat_indicators.confidence >= search_data.confidence_min)
    if not search_data.include_expired:
        query = query & (
            (db.threat_indicators.expires_at == None)
            | (db.threat_indicators.expires_at > datetime.utcnow())
        )

    # Execute query
    iocs = db(query).select(
        orderby=~db.threat_indicators.created_at,
        limitby=(offset, offset + search_data.per_page),
    )
    total = db(query).count()

    # Convert to response format
    ioc_list = []
    for ioc in iocs:
        ioc_list.append(
            {
                "id": ioc.id,
                "indicator_type": ioc.indicator_type,
                "value": ioc.value,
                "threat_level": ioc.threat_level,
                "confidence": ioc.confidence,
                "source": ioc.source,
                "tags": ioc.tags or [],
                "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
            }
        )

    return (
        jsonify(
            {
                "items": ioc_list,
                "total": total,
                "page": search_data.page,
                "per_page": search_data.per_page,
                "pages": (total + search_data.per_page - 1) // search_data.per_page,
            }
        ),
        200,
    )


@bp.route("/iocs/lookup", methods=["POST"])
@auth_required
async def lookup_ioc():
    """Lookup an indicator to check if it matches any IOCs."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    data = await request.get_json()
    indicator_type = data.get("type")
    value = data.get("value")

    if not indicator_type or not value:
        return jsonify({"error": "Both 'type' and 'value' are required"}), 400

    # Search for matching IOC
    ioc = (
        db(
            (db.threat_indicators.indicator_type == indicator_type)
            & (db.threat_indicators.value == value)
            & (
                (db.threat_indicators.expires_at == None)
                | (db.threat_indicators.expires_at > datetime.utcnow())
            )
        )
        .select()
        .first()
    )

    if ioc:
        return (
            jsonify(
                {
                    "found": True,
                    "ioc": {
                        "id": ioc.id,
                        "indicator_type": ioc.indicator_type,
                        "value": ioc.value,
                        "threat_level": ioc.threat_level,
                        "confidence": ioc.confidence,
                        "source": ioc.source,
                        "tags": ioc.tags or [],
                    },
                }
            ),
            200,
        )

    return (
        jsonify(
            {
                "found": False,
                "indicator_type": indicator_type,
                "value": value,
            }
        ),
        200,
    )


@bp.route("/statistics", methods=["GET"])
@auth_required
async def get_statistics():
    """Get threat intelligence statistics."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    # Count by type
    type_counts = {}
    for ioc_type in IndicatorType:
        count = db(db.threat_indicators.indicator_type == ioc_type.value).count()
        type_counts[ioc_type.value] = count

    # Count by threat level
    level_counts = {}
    for level in ThreatLevel:
        count = db(db.threat_indicators.threat_level == level.value).count()
        level_counts[level.value] = count

    # Count by source (top 10)
    # Note: PyDAL doesn't support GROUP BY directly in select, so we do it differently
    all_sources = db(db.threat_indicators).select(
        db.threat_indicators.source, distinct=True
    )
    source_counts = {}
    for row in all_sources:
        if row.source:
            source_counts[row.source] = db(
                db.threat_indicators.source == row.source
            ).count()

    # Sort and take top 10
    top_sources = dict(
        sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    )

    # Count expired
    expired_count = db(
        (db.threat_indicators.expires_at != None)
        & (db.threat_indicators.expires_at <= datetime.utcnow())
    ).count()

    return (
        jsonify(
            {
                "total": db(db.threat_indicators).count(),
                "by_type": type_counts,
                "by_threat_level": level_counts,
                "top_sources": top_sources,
                "expired": expired_count,
            }
        ),
        200,
    )


@bp.route("/feeds", methods=["GET"])
@auth_required
async def list_feeds():
    """List configured threat feeds."""
    config = current_app.config["MANAGER_CONFIG"]

    feeds = []

    # DNS Blacklist
    if config.threat_intel.dns_blacklist_enabled:
        feeds.append(
            {
                "id": "dns_blacklist",
                "name": "DNS Blacklists",
                "type": "dns",
                "enabled": True,
                "description": "SpamHaus, SpamCop, SORBS DNS blacklists",
            }
        )

    # IP Blacklist
    if config.threat_intel.ip_blacklist_enabled:
        feeds.append(
            {
                "id": "ip_blacklist",
                "name": "IP Blacklists",
                "type": "ip",
                "enabled": True,
                "description": "Known malicious IP address lists",
            }
        )

    # AlienVault OTX
    feeds.append(
        {
            "id": "otx",
            "name": "AlienVault OTX",
            "type": "api",
            "enabled": config.threat_intel.otx_enabled,
            "configured": bool(config.threat_intel.otx_api_key),
            "description": "Open Threat Exchange threat intelligence",
        }
    )

    # VirusTotal
    feeds.append(
        {
            "id": "virustotal",
            "name": "VirusTotal",
            "type": "api",
            "enabled": config.threat_intel.virustotal_enabled,
            "configured": bool(config.threat_intel.virustotal_api_key),
            "description": "VirusTotal file and URL analysis",
        }
    )

    # STIX/TAXII
    feeds.append(
        {
            "id": "taxii",
            "name": "STIX/TAXII",
            "type": "taxii",
            "enabled": config.threat_intel.taxii_enabled,
            "servers": len(config.threat_intel.taxii_servers),
            "description": "STIX/TAXII 2.1 threat feeds",
        }
    )

    return jsonify({"feeds": feeds}), 200
