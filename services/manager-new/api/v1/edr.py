"""
EDR (Endpoint Detection and Response) Agent API endpoints.

Provides REST API for external EDR agents to:
- Register with the Manager
- Send heartbeats
- Report security events
- Get configuration updates
"""

from datetime import datetime, timedelta
from typing import Optional

from pydantic import ValidationError
from quart import Blueprint, current_app, g, jsonify, request

from ...models.db import get_db
from ...validators.pydantic_models import (
    EDRAgentRegisterRequest,
    EDRAgentResponse,
    EDRAgentStatus,
    EDREventRequest,
    EDREventResponse,
    EDRHeartbeatRequest,
)

bp = Blueprint("edr", __name__)


def verify_api_key(f):
    """Decorator to verify EDR agent API key."""
    from functools import wraps

    @wraps(f)
    async def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        agent_id = request.headers.get("X-Agent-ID")

        if not api_key:
            return jsonify({"error": "Missing API key"}), 401

        # TODO: Implement proper API key validation
        # For now, accept any non-empty key
        if len(api_key) < 10:
            return jsonify({"error": "Invalid API key"}), 401

        g.agent_id = agent_id
        return await f(*args, **kwargs)

    return decorated


@bp.route("/register", methods=["POST"])
@verify_api_key
async def register_agent():
    """Register a new EDR agent."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        register_data = EDRAgentRegisterRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    # Check if agent already exists
    existing = db(db.edr_agents.agent_id == register_data.agent_id).select().first()

    if existing:
        # Update existing agent
        db(db.edr_agents.agent_id == register_data.agent_id).update(
            hostname=register_data.hostname,
            ip_address=register_data.ip_address,
            os_type=register_data.os_type,
            os_version=register_data.os_version,
            agent_version=register_data.agent_version,
            status="active",
            last_heartbeat=datetime.utcnow(),
            metadata=register_data.metadata,
        )
        db.commit()

        return jsonify({
            "message": "Agent re-registered",
            "agent_id": register_data.agent_id,
            "status": "active",
        }), 200

    # Create new agent
    db.edr_agents.insert(
        agent_id=register_data.agent_id,
        hostname=register_data.hostname,
        ip_address=register_data.ip_address,
        os_type=register_data.os_type,
        os_version=register_data.os_version,
        agent_version=register_data.agent_version,
        status="active",
        last_heartbeat=datetime.utcnow(),
        metadata=register_data.metadata,
    )
    db.commit()

    return jsonify({
        "message": "Agent registered successfully",
        "agent_id": register_data.agent_id,
        "status": "active",
    }), 201


@bp.route("/heartbeat", methods=["POST"])
@verify_api_key
async def heartbeat():
    """Receive heartbeat from an EDR agent."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        heartbeat_data = EDRHeartbeatRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    # Find agent
    agent = db(db.edr_agents.agent_id == heartbeat_data.agent_id).select().first()
    if not agent:
        return jsonify({"error": "Agent not registered"}), 404

    # Update heartbeat
    db(db.edr_agents.agent_id == heartbeat_data.agent_id).update(
        status=heartbeat_data.status.value,
        last_heartbeat=datetime.utcnow(),
        metadata={**(agent.metadata or {}), **(heartbeat_data.metadata or {})},
    )
    db.commit()

    return jsonify({
        "status": "ok",
        "agent_id": heartbeat_data.agent_id,
        "timestamp": datetime.utcnow().isoformat(),
    }), 200


@bp.route("/events", methods=["POST"])
@verify_api_key
async def report_events():
    """Report security events from an EDR agent."""
    config = current_app.config["MANAGER_CONFIG"]

    data = await request.get_json()

    # Handle single event or batch
    events = data if isinstance(data, list) else [data]

    if len(events) > 100:
        return jsonify({"error": "Maximum 100 events per request"}), 400

    db = get_db(config.database.uri)
    created_count = 0
    errors = []

    for idx, event_data in enumerate(events):
        try:
            event = EDREventRequest(**event_data)

            # Verify agent exists
            agent = db(db.edr_agents.agent_id == event.agent_id).select().first()
            if not agent:
                errors.append({"index": idx, "error": "Agent not registered"})
                continue

            # Store event
            db.edr_events.insert(
                agent_id=event.agent_id,
                event_type=event.event_type,
                severity=event.severity.value if event.severity else None,
                process_name=event.process_name,
                process_path=event.process_path,
                process_hash=event.process_hash,
                parent_process=event.parent_process,
                command_line=event.command_line,
                network_connections=event.network_connections,
                file_operations=event.file_operations,
                registry_operations=event.registry_operations,
                details=event.details,
            )
            created_count += 1

        except ValidationError as e:
            errors.append({"index": idx, "error": str(e)})
        except Exception as e:
            errors.append({"index": idx, "error": str(e)})

    db.commit()

    # TODO: Publish events to Redis Stream for processing

    return jsonify({
        "status": "accepted",
        "events_received": len(events),
        "events_stored": created_count,
        "errors": errors[:10] if errors else [],
    }), 202


@bp.route("/config", methods=["GET"])
@verify_api_key
async def get_agent_config():
    """Get configuration for an EDR agent."""
    config = current_app.config["MANAGER_CONFIG"]
    agent_id = request.headers.get("X-Agent-ID")

    if not agent_id:
        return jsonify({"error": "Agent ID required"}), 400

    db = get_db(config.database.uri)

    agent = db(db.edr_agents.agent_id == agent_id).select().first()
    if not agent:
        return jsonify({"error": "Agent not registered"}), 404

    # Return agent configuration
    # TODO: Implement configurable agent settings
    return jsonify({
        "agent_id": agent_id,
        "config": {
            "reporting_interval": 60,  # seconds
            "heartbeat_interval": 30,  # seconds
            "event_batch_size": 50,
            "enabled_collectors": [
                "process",
                "network",
                "file",
            ],
            "severity_threshold": "low",
        },
    }), 200


# Admin endpoints (require authentication)

from .auth import auth_required, role_required


@bp.route("/agents", methods=["GET"])
@auth_required
@role_required("admin", "maintainer")
async def list_agents():
    """List all registered EDR agents."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    # Get pagination params
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    per_page = min(per_page, 100)

    # Get filter params
    status = request.args.getlist("status")
    os_type = request.args.get("os_type")

    offset = (page - 1) * per_page

    # Build query
    query = db.edr_agents

    if status:
        query = query & (db.edr_agents.status.belongs(status))
    if os_type:
        query = query & (db.edr_agents.os_type == os_type)

    # Execute query
    agents = db(query).select(
        orderby=~db.edr_agents.last_heartbeat,
        limitby=(offset, offset + per_page),
    )
    total = db(query).count()

    # Convert to response format
    agent_list = []
    for agent in agents:
        agent_list.append({
            "id": agent.id,
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
            "ip_address": agent.ip_address,
            "os_type": agent.os_type,
            "os_version": agent.os_version,
            "agent_version": agent.agent_version,
            "status": agent.status,
            "last_heartbeat": agent.last_heartbeat.isoformat() if agent.last_heartbeat else None,
            "created_at": agent.created_at.isoformat() if agent.created_at else None,
        })

    return jsonify({
        "items": agent_list,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    }), 200


@bp.route("/agents/<agent_id>", methods=["GET"])
@auth_required
async def get_agent(agent_id: str):
    """Get EDR agent details."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    agent = db(db.edr_agents.agent_id == agent_id).select().first()
    if not agent:
        return jsonify({"error": "Agent not found"}), 404

    return jsonify({
        "id": agent.id,
        "agent_id": agent.agent_id,
        "hostname": agent.hostname,
        "ip_address": agent.ip_address,
        "os_type": agent.os_type,
        "os_version": agent.os_version,
        "agent_version": agent.agent_version,
        "status": agent.status,
        "last_heartbeat": agent.last_heartbeat.isoformat() if agent.last_heartbeat else None,
        "metadata": agent.metadata or {},
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
        "updated_at": agent.updated_at.isoformat() if agent.updated_at else None,
    }), 200


@bp.route("/agents/<agent_id>/events", methods=["GET"])
@auth_required
async def get_agent_events(agent_id: str):
    """Get events from a specific agent."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    # Verify agent exists
    agent = db(db.edr_agents.agent_id == agent_id).select().first()
    if not agent:
        return jsonify({"error": "Agent not found"}), 404

    # Get pagination params
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    per_page = min(per_page, 200)

    offset = (page - 1) * per_page

    # Get events
    events = db(db.edr_events.agent_id == agent_id).select(
        orderby=~db.edr_events.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(db.edr_events.agent_id == agent_id).count()

    event_list = []
    for event in events:
        event_list.append({
            "id": event.id,
            "event_type": event.event_type,
            "severity": event.severity,
            "process_name": event.process_name,
            "process_path": event.process_path,
            "command_line": event.command_line,
            "created_at": event.created_at.isoformat() if event.created_at else None,
        })

    return jsonify({
        "items": event_list,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    }), 200


@bp.route("/agents/<agent_id>/deactivate", methods=["POST"])
@auth_required
@role_required("admin")
async def deactivate_agent(agent_id: str):
    """Deactivate an EDR agent."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    agent = db(db.edr_agents.agent_id == agent_id).select().first()
    if not agent:
        return jsonify({"error": "Agent not found"}), 404

    db(db.edr_agents.agent_id == agent_id).update(status="inactive")
    db.commit()

    return jsonify({"message": "Agent deactivated", "agent_id": agent_id}), 200


@bp.route("/statistics", methods=["GET"])
@auth_required
async def get_statistics():
    """Get EDR statistics."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    # Agent counts by status
    status_counts = {}
    for status in EDRAgentStatus:
        count = db(db.edr_agents.status == status.value).count()
        status_counts[status.value] = count

    # Agent counts by OS
    os_counts = {}
    all_os = db(db.edr_agents).select(db.edr_agents.os_type, distinct=True)
    for row in all_os:
        if row.os_type:
            os_counts[row.os_type] = db(db.edr_agents.os_type == row.os_type).count()

    # Event counts (last 24 hours)
    yesterday = datetime.utcnow() - timedelta(days=1)
    recent_events = db(db.edr_events.created_at >= yesterday).count()

    # Stale agents (no heartbeat in last 5 minutes)
    stale_threshold = datetime.utcnow() - timedelta(minutes=5)
    stale_count = db(
        (db.edr_agents.status == "active") &
        (db.edr_agents.last_heartbeat < stale_threshold)
    ).count()

    return jsonify({
        "total_agents": db(db.edr_agents).count(),
        "agents_by_status": status_counts,
        "agents_by_os": os_counts,
        "stale_agents": stale_count,
        "total_events": db(db.edr_events).count(),
        "events_last_24h": recent_events,
    }), 200
