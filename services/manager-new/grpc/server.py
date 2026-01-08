"""
gRPC Server for Manager Service.

Provides internal gRPC API for inter-service communication.
"""

import asyncio
import logging
from concurrent import futures
from datetime import datetime
from typing import Optional

import grpc
from google.protobuf import empty_pb2, timestamp_pb2

from ..config import ManagerConfig
from ..models.db import get_db

logger = logging.getLogger(__name__)

# Note: Generated stubs will be in ./generated/ after running protoc
# For now, we define a placeholder implementation


class ManagerServiceServicer:
    """
    gRPC servicer implementation for Manager Service.

    This implements the ManagerService defined in manager.proto.
    """

    def __init__(self, config: ManagerConfig):
        self.config = config

    async def HealthCheck(self, request, context):
        """Health check endpoint."""
        from .generated import manager_pb2

        try:
            db = get_db(self.config.database.uri)
            db.executesql("SELECT 1")
            db_status = "connected"
        except Exception as e:
            db_status = f"error: {str(e)}"

        response = manager_pb2.HealthResponse(
            status="healthy" if db_status == "connected" else "unhealthy",
            version="1.0.0",
            database=db_status,
            redis="connected",
        )
        response.timestamp.FromDatetime(datetime.utcnow())

        return response

    async def CreateAlert(self, request, context):
        """Create a new alert."""
        from .generated import manager_pb2

        db = get_db(self.config.database.uri)

        # Map severity enum to string
        severity_map = {
            manager_pb2.SEVERITY_INFO: "info",
            manager_pb2.SEVERITY_LOW: "low",
            manager_pb2.SEVERITY_MEDIUM: "medium",
            manager_pb2.SEVERITY_HIGH: "high",
            manager_pb2.SEVERITY_CRITICAL: "critical",
        }

        alert_id = db.alerts.insert(
            title=request.title,
            description=request.description,
            severity=severity_map.get(request.severity, "medium"),
            status="pending",
            source=request.source,
            indicators=list(request.indicators),
        )
        db.commit()

        alert = db(db.alerts.id == alert_id).select().first()

        response = manager_pb2.AlertResponse(
            id=alert.id,
            title=alert.title,
            description=alert.description or "",
            severity=request.severity,
            status=manager_pb2.STATUS_PENDING,
            source=alert.source or "",
            indicators=alert.indicators or [],
        )
        response.created_at.FromDatetime(alert.created_at)

        return response

    async def GetAlert(self, request, context):
        """Get alert by ID."""
        from .generated import manager_pb2

        db = get_db(self.config.database.uri)

        alert = db(db.alerts.id == request.alert_id).select().first()
        if not alert:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Alert not found")
            return manager_pb2.AlertResponse()

        # Map status string to enum
        status_map = {
            "pending": manager_pb2.STATUS_PENDING,
            "in_progress": manager_pb2.STATUS_IN_PROGRESS,
            "resolved": manager_pb2.STATUS_RESOLVED,
            "false_positive": manager_pb2.STATUS_FALSE_POSITIVE,
            "escalated": manager_pb2.STATUS_ESCALATED,
        }

        severity_map = {
            "info": manager_pb2.SEVERITY_INFO,
            "low": manager_pb2.SEVERITY_LOW,
            "medium": manager_pb2.SEVERITY_MEDIUM,
            "high": manager_pb2.SEVERITY_HIGH,
            "critical": manager_pb2.SEVERITY_CRITICAL,
        }

        response = manager_pb2.AlertResponse(
            id=alert.id,
            title=alert.title,
            description=alert.description or "",
            severity=severity_map.get(alert.severity, manager_pb2.SEVERITY_MEDIUM),
            status=status_map.get(alert.status, manager_pb2.STATUS_PENDING),
            source=alert.source or "",
            indicators=alert.indicators or [],
        )
        response.created_at.FromDatetime(alert.created_at)
        if alert.updated_at:
            response.updated_at.FromDatetime(alert.updated_at)

        return response

    async def UpdateAlertStatus(self, request, context):
        """Update alert status."""
        from .generated import manager_pb2

        db = get_db(self.config.database.uri)

        alert = db(db.alerts.id == request.alert_id).select().first()
        if not alert:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Alert not found")
            return manager_pb2.AlertResponse()

        # Map status enum to string
        status_map = {
            manager_pb2.STATUS_PENDING: "pending",
            manager_pb2.STATUS_IN_PROGRESS: "in_progress",
            manager_pb2.STATUS_RESOLVED: "resolved",
            manager_pb2.STATUS_FALSE_POSITIVE: "false_positive",
            manager_pb2.STATUS_ESCALATED: "escalated",
        }

        updates = {"status": status_map.get(request.new_status, "pending")}
        if request.resolution_notes:
            updates["resolution_notes"] = request.resolution_notes
        if request.new_status == manager_pb2.STATUS_RESOLVED:
            updates["resolved_at"] = datetime.utcnow()

        db(db.alerts.id == request.alert_id).update(**updates)
        db.commit()

        # Return updated alert
        return await self.GetAlert(
            manager_pb2.AlertQuery(alert_id=request.alert_id),
            context,
        )

    async def CreateIOC(self, request, context):
        """Create a new IOC."""
        from .generated import manager_pb2

        db = get_db(self.config.database.uri)

        # Map enums to strings
        type_map = {
            manager_pb2.INDICATOR_IP: "ip",
            manager_pb2.INDICATOR_DOMAIN: "domain",
            manager_pb2.INDICATOR_HASH: "hash",
            manager_pb2.INDICATOR_URL: "url",
            manager_pb2.INDICATOR_EMAIL: "email",
            manager_pb2.INDICATOR_FILE: "file",
        }

        level_map = {
            manager_pb2.THREAT_INFO: "info",
            manager_pb2.THREAT_LOW: "low",
            manager_pb2.THREAT_MEDIUM: "medium",
            manager_pb2.THREAT_HIGH: "high",
            manager_pb2.THREAT_CRITICAL: "critical",
        }

        ioc_id = db.threat_indicators.insert(
            indicator_type=type_map.get(request.indicator_type, "ip"),
            value=request.value,
            threat_level=level_map.get(request.threat_level, "medium"),
            confidence=request.confidence,
            source=request.source,
            tags=list(request.tags),
            metadata=dict(request.metadata),
        )
        db.commit()

        ioc = db(db.threat_indicators.id == ioc_id).select().first()

        response = manager_pb2.IOCResponse(
            id=ioc.id,
            indicator_type=request.indicator_type,
            value=ioc.value,
            threat_level=request.threat_level,
            confidence=ioc.confidence,
            source=ioc.source,
            tags=ioc.tags or [],
        )
        response.created_at.FromDatetime(ioc.created_at)

        return response

    async def LookupIndicator(self, request, context):
        """Lookup an indicator in the IOC database."""
        from .generated import manager_pb2

        db = get_db(self.config.database.uri)

        type_map = {
            manager_pb2.INDICATOR_IP: "ip",
            manager_pb2.INDICATOR_DOMAIN: "domain",
            manager_pb2.INDICATOR_HASH: "hash",
            manager_pb2.INDICATOR_URL: "url",
            manager_pb2.INDICATOR_EMAIL: "email",
            manager_pb2.INDICATOR_FILE: "file",
        }

        indicator_type = type_map.get(request.type, "ip")

        ioc = db(
            (db.threat_indicators.indicator_type == indicator_type) &
            (db.threat_indicators.value == request.value)
        ).select().first()

        if ioc:
            # Reverse type map
            type_reverse = {v: k for k, v in type_map.items()}
            level_map = {
                "info": manager_pb2.THREAT_INFO,
                "low": manager_pb2.THREAT_LOW,
                "medium": manager_pb2.THREAT_MEDIUM,
                "high": manager_pb2.THREAT_HIGH,
                "critical": manager_pb2.THREAT_CRITICAL,
            }

            ioc_response = manager_pb2.IOCResponse(
                id=ioc.id,
                indicator_type=type_reverse.get(ioc.indicator_type, manager_pb2.INDICATOR_IP),
                value=ioc.value,
                threat_level=level_map.get(ioc.threat_level, manager_pb2.THREAT_MEDIUM),
                confidence=ioc.confidence or 0.5,
                source=ioc.source or "",
                tags=ioc.tags or [],
            )
            ioc_response.created_at.FromDatetime(ioc.created_at)

            return manager_pb2.IndicatorMatch(found=True, ioc=ioc_response)

        return manager_pb2.IndicatorMatch(found=False)

    async def LogAuditEvent(self, request, context):
        """Log an audit event."""
        from .generated import manager_pb2

        db = get_db(self.config.database.uri)

        db.audit_logs.insert(
            event_type=request.event_type,
            action=request.action,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            user_id=request.user_id if request.user_id else None,
            ip_address=request.ip_address,
            success=request.success,
            details=dict(request.details),
            severity=request.severity or "info",
        )
        db.commit()

        response = manager_pb2.AuditResponse(
            event_id=f"audit-{datetime.utcnow().timestamp()}",
            success=True,
        )
        response.timestamp.FromDatetime(datetime.utcnow())

        return response


async def serve(config: ManagerConfig) -> None:
    """Start the gRPC server."""
    try:
        from .generated import manager_pb2_grpc
    except ImportError:
        logger.warning(
            "gRPC stubs not generated. Run: "
            "python -m grpc_tools.protoc -I./grpc/protos "
            "--python_out=./grpc/generated --grpc_python_out=./grpc/generated "
            "./grpc/protos/*.proto"
        )
        return

    server = grpc.aio.server(
        futures.ThreadPoolExecutor(max_workers=config.grpc.max_workers),
        options=[
            ("grpc.max_send_message_length", config.grpc.max_message_length),
            ("grpc.max_receive_message_length", config.grpc.max_message_length),
        ],
    )

    manager_pb2_grpc.add_ManagerServiceServicer_to_server(
        ManagerServiceServicer(config),
        server,
    )

    listen_addr = f"{config.grpc.host}:{config.grpc.port}"
    server.add_insecure_port(listen_addr)

    logger.info(f"Starting gRPC server on {listen_addr}")
    await server.start()

    try:
        await server.wait_for_termination()
    except asyncio.CancelledError:
        logger.info("gRPC server shutting down...")
        await server.stop(grace=5)
