"""
SkausWatch AAA Monitor Service - Main Application

FastAPI-based AAA monitoring service providing comprehensive log collection
from Kubernetes, LXC/LXD, and auditd, with integrated threat intelligence
and AI-powered security analysis.
"""

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
import structlog
import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

# AI Integration imports
from .ai_integration.ai_provider import (
    AIAnalysisRequest,
    AIAnalysisResponse,
    AIAnalysisType,
    AIProviderManager,
)
from .ai_integration.analysis_engine import AIAnalysisEngine
from .ai_integration.prompt_templates import PromptTemplateManager
from .alert_manager import AlertManager
from .analysis_engine import AnalysisEngine
from .anomaly_detector import AnomalyDetector
from .buffer_manager import BufferManager
from .collectors.auditd_collector import AuditdCollector
from .collectors.database_collector import DatabaseCollector
from .collectors.file_collector import FileCollector
from .collectors.journald_collector import JournaldCollector

# Collector imports
from .collectors.kubernetes_collector import KubernetesCollector
from .collectors.lxc_collector import LXCCollector
from .collectors.syslog_collector import SyslogCollector
from .config import AAAMonitorConfig
from .escalation import EscalationManager
from .event_classifier import EventClassifier
from .health import HealthChecker
from .log_processor import LogProcessor
from .models import *
from .pattern_detector import PatternDetector
from .threat_intel.indicator_matcher import IndicatorMatcher
from .threat_intel.stix_parser import STIXParser

# Threat Intelligence imports
from .threat_intel.taxii_client import TAXIIClient
from .threat_intel.threat_database import ThreatDatabase
from .utils import get_version, setup_logging

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Global instances
config: Optional[AAAMonitorConfig] = None
redis_client: Optional[redis.Redis] = None

# Core components
log_processor: Optional[LogProcessor] = None
event_classifier: Optional[EventClassifier] = None
buffer_manager: Optional[BufferManager] = None
analysis_engine: Optional[AnalysisEngine] = None
pattern_detector: Optional[PatternDetector] = None
anomaly_detector: Optional[AnomalyDetector] = None
alert_manager: Optional[AlertManager] = None
escalation_manager: Optional[EscalationManager] = None
health_checker: Optional[HealthChecker] = None

# Log collectors
kubernetes_collector: Optional[KubernetesCollector] = None
lxc_collector: Optional[LXCCollector] = None
auditd_collector: Optional[AuditdCollector] = None
syslog_collector: Optional[SyslogCollector] = None
journald_collector: Optional[JournaldCollector] = None
file_collector: Optional[FileCollector] = None
database_collector: Optional[DatabaseCollector] = None

# Threat intelligence
taxii_client: Optional[TAXIIClient] = None
stix_parser: Optional[STIXParser] = None
indicator_matcher: Optional[IndicatorMatcher] = None
threat_database: Optional[ThreatDatabase] = None

# AI Integration components
ai_provider_manager: Optional[AIProviderManager] = None
ai_analysis_engine: Optional[AIAnalysisEngine] = None
ai_prompt_manager: Optional[PromptTemplateManager] = None

# Rate limiter
limiter = Limiter(key_func=get_remote_address)
security = HTTPBearer()

# Background tasks
background_tasks: List[asyncio.Task] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting AAA Monitor Service...")
    await startup()

    yield

    # Shutdown
    logger.info("Shutting down AAA Monitor Service...")
    await shutdown()


async def startup():
    """Application startup"""
    global config, redis_client, log_processor, event_classifier, buffer_manager, analysis_engine, pattern_detector, anomaly_detector, alert_manager, escalation_manager, health_checker, kubernetes_collector, lxc_collector, auditd_collector, syslog_collector, journald_collector, file_collector, database_collector, taxii_client, stix_parser, indicator_matcher, threat_database, ai_provider_manager, ai_analysis_engine, ai_prompt_manager

    try:
        # Initialize Redis connection
        if config.redis.enabled:
            redis_client = redis.from_url(
                config.redis.url,
                decode_responses=True,
                retry_on_timeout=True,
                health_check_interval=30,
            )
            await redis_client.ping()
            logger.info("Redis connection established")

        # Initialize threat intelligence components
        await _init_threat_intelligence()

        # Initialize AI providers
        await _init_ai_providers()

        # Initialize core processing components
        await _init_core_components()

        # Initialize log collectors
        await _init_log_collectors()

        # Initialize health checker
        health_checker = HealthChecker(
            config.health_check,
            redis_client,
            {
                "log_processor": log_processor,
                "kubernetes_collector": kubernetes_collector,
                "lxc_collector": lxc_collector,
                "auditd_collector": auditd_collector,
                "syslog_collector": syslog_collector,
                "journald_collector": journald_collector,
                "file_collector": file_collector,
                "database_collector": database_collector,
                "threat_database": threat_database,
                "ai_provider_manager": ai_provider_manager,
                "ai_analysis_engine": ai_analysis_engine,
            },
        )

        # Start background services
        await _start_background_services()

        logger.info("AAA Monitor Service startup completed successfully")

    except Exception as e:
        logger.error("Failed to start AAA Monitor Service", error=str(e), exc_info=True)
        raise


async def shutdown():
    """Application shutdown"""
    global background_tasks

    try:
        # Stop background tasks
        logger.info("Stopping background tasks...")
        for task in background_tasks:
            task.cancel()

        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)

        # Stop collectors
        if kubernetes_collector:
            await kubernetes_collector.stop()
        if lxc_collector:
            await lxc_collector.stop()
        if auditd_collector:
            await auditd_collector.stop()

        # Stop threat intelligence services
        if taxii_client:
            await taxii_client.stop()

        # Close connections
        if redis_client:
            await redis_client.close()

        # Cleanup components
        if health_checker:
            await health_checker.close()

        if buffer_manager:
            await buffer_manager.flush_all()

        logger.info("AAA Monitor Service shutdown completed")

    except Exception as e:
        logger.error("Error during AAA Monitor Service shutdown", error=str(e))


async def _init_threat_intelligence():
    """Initialize threat intelligence components"""
    global threat_database, stix_parser, indicator_matcher, taxii_client

    # Initialize threat database
    threat_database = ThreatDatabase(config.threat_intel.database_path, redis_client)
    await threat_database.initialize()

    # Initialize STIX parser
    stix_parser = STIXParser()

    # Initialize indicator matcher
    indicator_matcher = IndicatorMatcher(threat_database, config.threat_intel)

    # Initialize TAXII client
    if config.threat_intel.taxii.enabled:
        taxii_client = TAXIIClient(
            config.threat_intel.taxii, stix_parser, threat_database
        )
        await taxii_client.initialize()


async def _init_ai_providers():
    """Initialize AI integration components"""
    global ai_provider_manager, ai_analysis_engine, ai_prompt_manager

    if not config.ai.enabled:
        logger.info("AI integration disabled")
        return

    try:
        # Initialize AI provider manager
        ai_provider_manager = AIProviderManager(config.ai.__dict__, redis_client)
        await ai_provider_manager.initialize()

        # Initialize prompt template manager
        ai_prompt_manager = PromptTemplateManager()

        # Initialize AI analysis engine
        ai_analysis_engine = AIAnalysisEngine(
            config.analysis.__dict__, ai_provider_manager, redis_client
        )
        await ai_analysis_engine.initialize()

        logger.info("AI integration components initialized successfully")

    except Exception as e:
        logger.error("Failed to initialize AI components", error=str(e))
        # Don't fail startup if AI is not available
        ai_provider_manager = None
        ai_analysis_engine = None
        ai_prompt_manager = None


async def _init_core_components():
    """Initialize core processing components"""
    global log_processor, event_classifier, buffer_manager, analysis_engine, pattern_detector, anomaly_detector, alert_manager, escalation_manager

    # Initialize buffer manager
    buffer_manager = BufferManager(config.buffer, redis_client)

    # Initialize event classifier
    event_classifier = EventClassifier(config.classification)

    # Initialize log processor with AI integration
    log_processor = LogProcessor(
        config.log_processing.__dict__,
        event_classifier,
        buffer_manager,
        indicator_matcher,
        ai_analysis_engine,
    )

    # Initialize pattern detector
    pattern_detector = PatternDetector(config.pattern_detection)

    # Initialize anomaly detector
    anomaly_detector = AnomalyDetector(config.anomaly_detection, redis_client)

    # Initialize alert manager
    alert_manager = AlertManager(config.alerting, redis_client)

    # Initialize escalation manager
    escalation_manager = EscalationManager(config.escalation, alert_manager)

    # Initialize analysis engine
    analysis_engine = AnalysisEngine(
        config.analysis, pattern_detector, anomaly_detector, alert_manager, ai_provider
    )


async def _init_log_collectors():
    """Initialize log collectors"""
    global kubernetes_collector, lxc_collector, auditd_collector, syslog_collector, journald_collector, file_collector, database_collector

    # Initialize Kubernetes collector
    if config.collectors.kubernetes.enabled:
        kubernetes_collector = KubernetesCollector(
            config.collectors.kubernetes, log_processor, analysis_engine
        )
        await kubernetes_collector.initialize()

    # Initialize LXC/LXD collector
    if config.collectors.lxc_lxd.enabled:
        lxc_collector = LXCCollector(
            config.collectors.lxc_lxd, log_processor, analysis_engine
        )
        await lxc_collector.initialize()

    # Initialize auditd collector
    if config.collectors.auditd.enabled:
        auditd_collector = AuditdCollector(
            config.collectors.auditd, log_processor, analysis_engine
        )
        await auditd_collector.initialize()

    # Initialize syslog collector
    if config.collectors.syslog.enabled:
        syslog_collector = SyslogCollector(
            config.collectors.syslog, log_processor, analysis_engine
        )
        await syslog_collector.initialize()

    # Initialize journald collector
    if config.collectors.journald.enabled:
        journald_collector = JournaldCollector(
            config.collectors.journald, log_processor, analysis_engine
        )
        await journald_collector.initialize()

    # Initialize file collector
    if config.collectors.file.enabled:
        file_collector = FileCollector(
            config.collectors.file, log_processor, analysis_engine
        )
        await file_collector.initialize()

    # Initialize database collector
    if config.collectors.database.enabled:
        database_collector = DatabaseCollector(
            config.collectors.database, log_processor, analysis_engine
        )
        await database_collector.initialize()


async def _start_background_services():
    """Start background services"""
    global background_tasks

    # Start log collectors
    if kubernetes_collector:
        task = asyncio.create_task(kubernetes_collector.start_collection())
        background_tasks.append(task)

    if lxc_collector:
        task = asyncio.create_task(lxc_collector.start_collection())
        background_tasks.append(task)

    if auditd_collector:
        task = asyncio.create_task(auditd_collector.start_collection())
        background_tasks.append(task)

    if syslog_collector:
        task = asyncio.create_task(syslog_collector.start_collection())
        background_tasks.append(task)

    if journald_collector:
        task = asyncio.create_task(journald_collector.start_collection())
        background_tasks.append(task)

    if file_collector:
        task = asyncio.create_task(file_collector.start_collection())
        background_tasks.append(task)

    if database_collector:
        task = asyncio.create_task(database_collector.start_collection())
        background_tasks.append(task)

    # Start threat intelligence updates
    if taxii_client:
        task = asyncio.create_task(taxii_client.start_feed_updates())
        background_tasks.append(task)

    # Start analysis engine
    task = asyncio.create_task(analysis_engine.start_processing())
    background_tasks.append(task)

    # Start buffer manager
    task = asyncio.create_task(buffer_manager.start_processing())
    background_tasks.append(task)

    # Start alert processing
    task = asyncio.create_task(alert_manager.start_processing())
    background_tasks.append(task)

    # Start health monitoring
    if health_checker:
        task = asyncio.create_task(health_checker.start_monitoring())
        background_tasks.append(task)


def create_app(config_path: Optional[str] = None) -> FastAPI:
    """Create and configure the AAA Monitor FastAPI application"""
    global config

    # Load configuration
    config = AAAMonitorConfig(config_path)

    # Setup logging
    setup_logging(config.logging)

    # Create FastAPI app
    app = FastAPI(
        title="SkausWatch AAA Monitor Service",
        description="Authentication, Authorization, and Accounting monitoring with threat intelligence and AI analysis",
        version=get_version(),
        docs_url="/docs" if config.api.docs_enabled else None,
        redoc_url="/redoc" if config.api.docs_enabled else None,
        lifespan=lifespan,
    )

    # Add middleware
    _add_middleware(app)

    # Add routes
    _add_routes(app)

    # Add exception handlers
    _add_exception_handlers(app)

    return app


def _add_middleware(app: FastAPI):
    """Add middleware to the FastAPI app"""
    # Rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # CORS
    if config.api.cors_enabled:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.api.cors_origins,
            allow_credentials=True,
            allow_methods=config.api.cors_methods,
            allow_headers=config.api.cors_headers,
        )

    # Trusted hosts
    if config.security.trusted_hosts:
        app.add_middleware(
            TrustedHostMiddleware, allowed_hosts=config.security.trusted_hosts
        )


def _add_routes(app: FastAPI):
    """Add routes to the FastAPI app"""

    # Health and status endpoints
    @app.get("/health", response_model=HealthStatus)
    async def health_check():
        """Health check endpoint"""
        try:
            health_status = await health_checker.check_all()
            status_code = 200 if health_status["status"] == "healthy" else 503

            return JSONResponse(content=health_status, status_code=status_code)
        except Exception as e:
            logger.error("Health check failed", error=str(e))
            return JSONResponse(
                content={"status": "error", "error": str(e), "version": get_version()},
                status_code=500,
            )

    @app.get("/version")
    async def version_info():
        """Version information endpoint"""
        return {
            "name": "SkausWatch AAA Monitor Service",
            "version": get_version(),
            "status": "running",
        }

    @app.get("/metrics/dashboard", response_model=DashboardMetrics)
    @limiter.limit("30/minute")
    async def get_dashboard_metrics(request):
        """Get dashboard metrics"""
        try:
            metrics = await analysis_engine.get_dashboard_metrics()
            return metrics
        except Exception as e:
            logger.error("Failed to get dashboard metrics", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to retrieve metrics")

    # Event management endpoints
    @app.post("/events/search", response_model=EventSearchResponse)
    @limiter.limit("60/minute")
    async def search_events(request: EventSearchRequest):
        """Search events"""
        try:
            response = await log_processor.search_events(request)
            return response
        except Exception as e:
            logger.error("Failed to search events", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to search events")

    @app.get("/events/{event_id}")
    @limiter.limit("100/minute")
    async def get_event(event_id: str):
        """Get event by ID"""
        try:
            event = await log_processor.get_event_by_id(event_id)
            if not event:
                raise HTTPException(status_code=404, detail="Event not found")
            return event
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to get event", error=str(e), event_id=event_id)
            raise HTTPException(status_code=500, detail="Failed to retrieve event")

    @app.get("/events/stream")
    async def stream_events(
        sources: Optional[List[LogSource]] = Query(None),
        event_types: Optional[List[EventType]] = Query(None),
        severities: Optional[List[Severity]] = Query(None),
    ):
        """Stream real-time events"""
        try:

            async def event_generator():
                async for event in log_processor.stream_events(
                    sources, event_types, severities
                ):
                    yield f"data: {event.json()}\n\n"

            return StreamingResponse(
                event_generator(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                },
            )
        except Exception as e:
            logger.error("Failed to stream events", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to stream events")

    # Alert management endpoints
    @app.post("/alerts/search", response_model=AlertSearchResponse)
    @limiter.limit("60/minute")
    async def search_alerts(request: AlertSearchRequest):
        """Search alerts"""
        try:
            response = await alert_manager.search_alerts(request)
            return response
        except Exception as e:
            logger.error("Failed to search alerts", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to search alerts")

    @app.get("/alerts/{alert_id}")
    @limiter.limit("100/minute")
    async def get_alert(alert_id: str):
        """Get alert by ID"""
        try:
            alert = await alert_manager.get_alert_by_id(alert_id)
            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")
            return alert
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to get alert", error=str(e), alert_id=alert_id)
            raise HTTPException(status_code=500, detail="Failed to retrieve alert")

    @app.put("/alerts/{alert_id}/status")
    @limiter.limit("30/minute")
    async def update_alert_status(
        alert_id: str,
        status: AlertStatus,
        background_tasks: BackgroundTasks,
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        """Update alert status"""
        try:
            # TODO: Validate authentication
            user_info = {"user": "authenticated_user"}  # Placeholder

            await alert_manager.update_alert_status(alert_id, status, user_info)

            # Handle escalation
            background_tasks.add_task(
                escalation_manager.handle_status_change, alert_id, status
            )

            return {"status": "updated", "alert_id": alert_id, "new_status": status}
        except Exception as e:
            logger.error(
                "Failed to update alert status", error=str(e), alert_id=alert_id
            )
            raise HTTPException(status_code=500, detail="Failed to update alert status")

    # Enhanced Threat Intelligence Management Endpoints

    @app.get("/threat-intel/iocs")
    @limiter.limit("30/minute")
    async def get_iocs(
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        threat_level: Optional[ThreatLevel] = None,
        ioc_type: Optional[str] = Query(None),
        source: Optional[str] = Query(None),
        confidence_min: Optional[float] = Query(None, ge=0.0, le=1.0),
        tags: Optional[List[str]] = Query(None),
        created_since: Optional[datetime] = Query(None),
        include_expired: bool = Query(False),
    ):
        """Get indicators of compromise with advanced filtering"""
        try:
            filters = {
                "threat_level": threat_level,
                "ioc_type": ioc_type,
                "source": source,
                "confidence_min": confidence_min,
                "tags": tags,
                "created_since": created_since,
                "include_expired": include_expired,
            }

            iocs = await threat_database.get_iocs_advanced(limit, offset, filters)
            return iocs
        except Exception as e:
            logger.error("Failed to get IOCs", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to retrieve IOCs")

    @app.post("/threat-intel/iocs")
    @limiter.limit("10/minute")
    async def create_ioc(
        ioc: IOC, credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        """Create a new IOC"""
        try:
            # TODO: Validate authentication and permissions
            created_ioc = await threat_database.add_ioc(ioc)
            return created_ioc
        except Exception as e:
            logger.error("Failed to create IOC", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to create IOC")

    @app.get("/threat-intel/iocs/{ioc_id}")
    @limiter.limit("60/minute")
    async def get_ioc(ioc_id: str):
        """Get specific IOC by ID"""
        try:
            ioc = await threat_database.get_ioc_by_id(ioc_id)
            if not ioc:
                raise HTTPException(status_code=404, detail="IOC not found")
            return ioc
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to get IOC", error=str(e), ioc_id=ioc_id)
            raise HTTPException(status_code=500, detail="Failed to retrieve IOC")

    @app.post("/threat-intel/iocs/search")
    @limiter.limit("20/minute")
    async def search_iocs(search_request: Dict[str, Any]):
        """Advanced IOC search with complex queries"""
        try:
            results = await threat_database.search_iocs_advanced(search_request)
            return results
        except Exception as e:
            logger.error("Failed to search IOCs", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to search IOCs")

    @app.post("/threat-intel/iocs/bulk")
    @limiter.limit("5/minute")
    async def bulk_create_iocs(
        iocs: List[IOC], credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        """Bulk create IOCs"""
        try:
            # TODO: Validate authentication and permissions
            if len(iocs) > 1000:
                raise HTTPException(
                    status_code=400, detail="Maximum 1000 IOCs per bulk operation"
                )

            results = await threat_database.bulk_add_iocs(iocs)
            return {
                "success": True,
                "created_count": results.get("created", 0),
                "updated_count": results.get("updated", 0),
                "errors": results.get("errors", []),
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to bulk create IOCs", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to bulk create IOCs")

    @app.get("/threat-intel/statistics")
    @limiter.limit("30/minute")
    async def get_threat_statistics():
        """Get comprehensive threat intelligence statistics"""
        try:
            stats = await threat_database.get_enhanced_statistics()
            return stats
        except Exception as e:
            logger.error("Failed to get threat statistics", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to retrieve statistics")

    @app.get("/threat-intel/matches/{event_id}")
    @limiter.limit("60/minute")
    async def get_event_matches(event_id: str):
        """Get threat matches for a specific event"""
        try:
            matches = await threat_database.get_matches_by_event(event_id)
            return matches
        except Exception as e:
            logger.error("Failed to get event matches", error=str(e), event_id=event_id)
            raise HTTPException(status_code=500, detail="Failed to retrieve matches")

    @app.post("/threat-intel/database/optimize")
    @limiter.limit("2/hour")
    async def optimize_database(
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        """Manually trigger database optimization"""
        try:
            # TODO: Validate authentication and admin permissions
            result = await threat_database.optimize_database()
            return result
        except Exception as e:
            logger.error("Failed to optimize database", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to optimize database")

    @app.get("/threat-intel/feeds")
    @limiter.limit("20/minute")
    async def get_threat_feeds(
        include_stats: bool = Query(True), enabled_only: bool = Query(False)
    ):
        """Get threat feeds with quality assessment"""
        try:
            feeds = await threat_database.get_feed_status_enhanced(
                include_stats, enabled_only
            )
            return feeds
        except Exception as e:
            logger.error("Failed to get threat feeds", error=str(e))
            raise HTTPException(
                status_code=500, detail="Failed to retrieve threat feeds"
            )

    @app.post("/threat-intel/feeds")
    @limiter.limit("5/minute")
    async def create_threat_feed(
        feed: ThreatFeed, credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        """Create a new threat feed"""
        try:
            # TODO: Validate authentication and permissions
            created_feed = await threat_database.add_feed(feed)

            # Register with TAXII client if enabled
            if created_feed.enabled and taxii_client:
                await taxii_client.add_feed(created_feed)

            return created_feed
        except Exception as e:
            logger.error("Failed to create threat feed", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to create threat feed")

    @app.get("/threat-intel/feeds/{feed_id}")
    @limiter.limit("30/minute")
    async def get_threat_feed(feed_id: str):
        """Get specific threat feed"""
        try:
            feed = await threat_database.get_feed_by_id(feed_id)
            if not feed:
                raise HTTPException(status_code=404, detail="Feed not found")
            return feed
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to get threat feed", error=str(e), feed_id=feed_id)
            raise HTTPException(status_code=500, detail="Failed to retrieve feed")

    @app.put("/threat-intel/feeds/{feed_id}")
    @limiter.limit("5/minute")
    async def update_threat_feed_config(
        feed_id: str,
        feed_update: ThreatFeed,
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        """Update threat feed configuration"""
        try:
            # TODO: Validate authentication and permissions
            updated_feed = await threat_database.update_feed(feed_id, feed_update)
            if not updated_feed:
                raise HTTPException(status_code=404, detail="Feed not found")

            # Update TAXII client configuration
            if taxii_client:
                await taxii_client.update_feed_config(feed_id, updated_feed)

            return updated_feed
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to update threat feed", error=str(e), feed_id=feed_id)
            raise HTTPException(status_code=500, detail="Failed to update feed")

    @app.post("/threat-intel/feeds/{feed_id}/update")
    @limiter.limit("5/minute")
    async def trigger_feed_update(
        feed_id: str,
        background_tasks: BackgroundTasks,
        force: bool = Query(False),
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        """Manually trigger threat feed update"""
        try:
            # TODO: Validate authentication

            if taxii_client:
                background_tasks.add_task(taxii_client.update_feed, feed_id, force)
                return {"status": "update_scheduled", "feed_id": feed_id}
            else:
                raise HTTPException(
                    status_code=503, detail="TAXII client not available"
                )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "Failed to schedule threat feed update", error=str(e), feed_id=feed_id
            )
            raise HTTPException(
                status_code=500, detail="Failed to schedule feed update"
            )

    @app.get("/threat-intel/feeds/{feed_id}/quality")
    @limiter.limit("30/minute")
    async def get_feed_quality(feed_id: str):
        """Get feed quality assessment"""
        try:
            if not taxii_client:
                raise HTTPException(
                    status_code=503, detail="TAXII client not available"
                )

            quality = taxii_client.feed_quality_manager.get_feed_quality(feed_id)
            return quality
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to get feed quality", error=str(e), feed_id=feed_id)
            raise HTTPException(
                status_code=500, detail="Failed to retrieve feed quality"
            )

    @app.get("/threat-intel/feeds/quality/top")
    @limiter.limit("20/minute")
    async def get_top_quality_feeds(limit: int = Query(10, ge=1, le=50)):
        """Get top quality threat feeds"""
        try:
            if not taxii_client:
                raise HTTPException(
                    status_code=503, detail="TAXII client not available"
                )

            top_feeds = taxii_client.feed_quality_manager.get_top_quality_feeds(limit)
            return {"top_feeds": top_feeds}
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to get top quality feeds", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to retrieve top feeds")

    # Production Monitoring and Management Endpoints

    @app.get("/monitor/threat-intel/performance")
    @limiter.limit("30/minute")
    async def get_threat_intel_performance():
        """Get comprehensive threat intelligence performance metrics"""
        try:
            metrics = {
                "database_performance": await threat_database.get_enhanced_statistics(),
                "taxii_client_stats": (
                    taxii_client.get_comprehensive_statistics() if taxii_client else {}
                ),
                "stix_parser_stats": stix_parser.get_parsing_statistics(),
                "indicator_matcher_stats": indicator_matcher.get_statistics(),
                "system_health": {
                    "timestamp": datetime.utcnow().isoformat(),
                    "service_uptime": (
                        datetime.utcnow() - datetime.utcnow()
                    ).total_seconds(),  # Placeholder
                    "memory_usage": "Available through health endpoint",
                },
            }
            return metrics
        except Exception as e:
            logger.error("Failed to get threat intel performance metrics", error=str(e))
            raise HTTPException(
                status_code=500, detail="Failed to retrieve performance metrics"
            )

    @app.post("/monitor/threat-intel/diagnostics")
    @limiter.limit("10/minute")
    async def run_threat_intel_diagnostics(
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        """Run comprehensive threat intelligence diagnostics"""
        try:
            # TODO: Validate authentication and admin permissions

            diagnostics = {
                "database_health": await threat_database.get_health_status(),
                "feed_connectivity": {},
                "parser_validation": {},
                "matching_performance": {},
                "cache_status": threat_database.cache.get_stats(),
                "recommendations": [],
            }

            # Test feed connectivity
            if taxii_client:
                diagnostics["feed_connectivity"] = await taxii_client.test_all_feeds()

            # Test parser with sample data
            try:
                sample_stix = '{"type": "indicator", "id": "indicator--test", "pattern": "[file:hashes.MD5 = \'d41d8cd98f00b204e9800998ecf8427e\']", "labels": ["malicious-activity"]}'
                test_results = await stix_parser.parse_content(sample_stix)
                diagnostics["parser_validation"] = {
                    "status": "healthy" if test_results else "warning",
                    "test_indicators_parsed": len(test_results) if test_results else 0,
                }
            except Exception as e:
                diagnostics["parser_validation"] = {"status": "error", "error": str(e)}

            # Performance recommendations
            recommendations = []

            # Database performance recommendations
            db_stats = diagnostics["database_health"]
            if db_stats.get("cache_hit_ratio", 0) < 0.8:
                recommendations.append(
                    "Consider increasing cache size for better performance"
                )

            if db_stats.get("database_size_mb", 0) > 1000:
                recommendations.append(
                    "Database size is large, consider archiving old indicators"
                )

            # Feed quality recommendations
            if taxii_client:
                poor_quality_feeds = [
                    feed_id
                    for feed_id, quality in taxii_client.feed_quality_manager.quality_scores.items()
                    if quality.get("overall", 0) < 0.5
                ]
                if poor_quality_feeds:
                    recommendations.append(
                        f"Review {len(poor_quality_feeds)} feeds with poor quality scores"
                    )

            diagnostics["recommendations"] = recommendations

            return diagnostics
        except Exception as e:
            logger.error("Failed to run threat intel diagnostics", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to run diagnostics")

    @app.post("/monitor/threat-intel/maintenance")
    @limiter.limit("5/minute")
    async def perform_maintenance(
        background_tasks: BackgroundTasks,
        maintenance_type: str = Query(..., regex="^(cleanup|optimize|reindex|vacuum)$"),
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        """Perform threat intelligence maintenance operations"""
        try:
            # TODO: Validate authentication and admin permissions

            if maintenance_type == "cleanup":
                background_tasks.add_task(threat_database.cleanup_expired_indicators)
                message = "Cleanup task scheduled"
            elif maintenance_type == "optimize":
                background_tasks.add_task(threat_database.optimize_database)
                message = "Database optimization scheduled"
            elif maintenance_type == "reindex":
                background_tasks.add_task(threat_database._create_performance_indexes)
                message = "Index rebuild scheduled"
            elif maintenance_type == "vacuum":
                background_tasks.add_task(threat_database.vacuum_database)
                message = "Database vacuum scheduled"

            return {
                "status": "scheduled",
                "maintenance_type": maintenance_type,
                "message": message,
                "scheduled_at": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.error(
                "Failed to schedule maintenance",
                error=str(e),
                maintenance_type=maintenance_type,
            )
            raise HTTPException(
                status_code=500, detail="Failed to schedule maintenance"
            )

    @app.get("/monitor/threat-intel/alerts")
    @limiter.limit("30/minute")
    async def get_threat_intel_alerts():
        """Get threat intelligence system alerts and warnings"""
        try:
            alerts = []

            # Database alerts
            db_stats = await threat_database.get_enhanced_statistics()

            if db_stats.get("cache_hit_ratio", 1.0) < 0.5:
                alerts.append(
                    {
                        "type": "performance",
                        "severity": "warning",
                        "component": "database_cache",
                        "message": f"Low cache hit ratio: {db_stats.get('cache_hit_ratio', 0):.2f}",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )

            if db_stats.get("database_size", 0) > 5 * 1024 * 1024 * 1024:  # 5GB
                alerts.append(
                    {
                        "type": "storage",
                        "severity": "warning",
                        "component": "database",
                        "message": f"Large database size: {db_stats.get('database_size', 0) / (1024**3):.1f}GB",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )

            # Feed quality alerts
            if taxii_client:
                for (
                    feed_id,
                    quality,
                ) in taxii_client.feed_quality_manager.quality_scores.items():
                    if quality.get("overall", 0) < 0.3:
                        alerts.append(
                            {
                                "type": "quality",
                                "severity": "error",
                                "component": "feed",
                                "message": f"Feed {feed_id} has poor quality score: {quality.get('overall', 0):.2f}",
                                "timestamp": datetime.utcnow().isoformat(),
                            }
                        )

            # Parser alerts
            parser_stats = stix_parser.get_parsing_statistics()
            error_rate = parser_stats.get("parsing_errors", 0) / max(
                parser_stats.get("objects_parsed", 1), 1
            )
            if error_rate > 0.1:  # 10% error rate
                alerts.append(
                    {
                        "type": "parsing",
                        "severity": "warning",
                        "component": "stix_parser",
                        "message": f"High parsing error rate: {error_rate:.1%}",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )

            return {
                "alerts": alerts,
                "alert_count": len(alerts),
                "last_check": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.error("Failed to get threat intel alerts", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to retrieve alerts")

    @app.get("/monitor/threat-intel/export")
    @limiter.limit("5/minute")
    async def export_threat_data(
        export_format: str = Query("json", regex="^(json|csv|stix)$"),
        threat_level: Optional[ThreatLevel] = None,
        limit: int = Query(1000, ge=1, le=10000),
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        """Export threat intelligence data"""
        try:
            # TODO: Validate authentication and permissions

            if export_format == "stix":
                # Export as STIX 2.1 bundle
                iocs = await threat_database.get_iocs_advanced(
                    limit, 0, {"threat_level": threat_level}
                )
                stix_bundle = {
                    "type": "bundle",
                    "id": f"bundle--{uuid.uuid4()}",
                    "objects": [
                        ioc.to_stix() for ioc in iocs if hasattr(ioc, "to_stix")
                    ],
                }
                return JSONResponse(
                    content=stix_bundle,
                    headers={
                        "Content-Disposition": f"attachment; filename=threat-intel-export-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
                    },
                )
            else:
                # JSON or CSV export
                iocs = await threat_database.get_iocs_advanced(
                    limit, 0, {"threat_level": threat_level}
                )

                if export_format == "json":
                    return JSONResponse(
                        content=[ioc.dict() for ioc in iocs],
                        headers={
                            "Content-Disposition": f"attachment; filename=threat-intel-export-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
                        },
                    )
                else:  # CSV
                    # Convert to CSV format
                    import csv
                    import io

                    output = io.StringIO()
                    if iocs:
                        fieldnames = list(iocs[0].dict().keys())
                        writer = csv.DictWriter(output, fieldnames=fieldnames)
                        writer.writeheader()
                        for ioc in iocs:
                            writer.writerow(ioc.dict())

                    return StreamingResponse(
                        io.BytesIO(output.getvalue().encode()),
                        media_type="text/csv",
                        headers={
                            "Content-Disposition": f"attachment; filename=threat-intel-export-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
                        },
                    )
        except Exception as e:
            logger.error("Failed to export threat data", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to export data")

    # AI Analysis and Management Endpoints

    @app.get("/ai/status")
    @limiter.limit("60/minute")
    async def get_ai_status():
        """Get AI integration status and provider health"""
        try:
            if not ai_provider_manager:
                return {
                    "enabled": False,
                    "status": "disabled",
                    "message": "AI integration is not enabled",
                }

            provider_status = await ai_provider_manager.get_provider_status()

            engine_stats = None
            if ai_analysis_engine:
                engine_stats = await ai_analysis_engine.get_statistics()

            return {
                "enabled": True,
                "status": "active",
                "providers": provider_status,
                "analysis_engine": engine_stats,
                "prompt_templates": (
                    len(ai_prompt_manager.templates) if ai_prompt_manager else 0
                ),
            }
        except Exception as e:
            logger.error("Failed to get AI status", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to retrieve AI status")

    @app.post("/ai/analyze/events", response_model=Dict[str, Any])
    @limiter.limit("20/minute")
    async def analyze_events_ai(
        events: List[BaseEvent],
        analysis_type: AIAnalysisType,
        priority: int = Query(1, ge=1, le=5),
        template_name: Optional[str] = None,
        custom_context: Optional[Dict[str, Any]] = None,
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        """Submit events for AI analysis"""
        try:
            if not ai_analysis_engine:
                raise HTTPException(
                    status_code=503, detail="AI analysis engine not available"
                )

            if len(events) > 50:
                raise HTTPException(
                    status_code=400, detail="Maximum 50 events per analysis request"
                )

            # Submit for real-time analysis
            job_id = await ai_analysis_engine.analyze_real_time(
                events=events,
                analysis_type=analysis_type,
                priority=priority,
                context=custom_context or {},
                template_name=template_name,
            )

            return {
                "status": "analysis_submitted",
                "job_id": job_id,
                "analysis_type": analysis_type.value,
                "events_count": len(events),
                "priority": priority,
                "submitted_at": datetime.utcnow().isoformat(),
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to submit AI analysis", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to submit analysis")

    @app.post("/ai/analyze/text", response_model=Dict[str, Any])
    @limiter.limit("30/minute")
    async def analyze_text_ai(
        text: str,
        analysis_type: AIAnalysisType,
        priority: int = Query(1, ge=1, le=5),
        template_name: Optional[str] = None,
        custom_context: Optional[Dict[str, Any]] = None,
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        """Submit text for AI analysis"""
        try:
            if not ai_analysis_engine:
                raise HTTPException(
                    status_code=503, detail="AI analysis engine not available"
                )

            if len(text) > 10000:
                raise HTTPException(
                    status_code=400, detail="Text too long (max 10,000 characters)"
                )

            # Create a synthetic event from the text
            synthetic_event = BaseEvent(
                source=LogSource.SYSTEM,
                event_type=EventType.SECURITY_VIOLATION,
                severity=Severity.MEDIUM,
                message=text,
                raw_data={"user_submitted_text": True},
            )

            job_id = await ai_analysis_engine.analyze_real_time(
                events=[synthetic_event],
                analysis_type=analysis_type,
                priority=priority,
                context=custom_context or {"text_analysis": True},
                template_name=template_name,
            )

            return {
                "status": "analysis_submitted",
                "job_id": job_id,
                "analysis_type": analysis_type.value,
                "text_length": len(text),
                "priority": priority,
                "submitted_at": datetime.utcnow().isoformat(),
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to submit text analysis", error=str(e))
            raise HTTPException(
                status_code=500, detail="Failed to submit text analysis"
            )

    @app.get("/ai/analysis/{job_id}", response_model=Dict[str, Any])
    @limiter.limit("100/minute")
    async def get_ai_analysis_result(job_id: str):
        """Get AI analysis result by job ID"""
        try:
            if not ai_analysis_engine:
                raise HTTPException(
                    status_code=503, detail="AI analysis engine not available"
                )

            # Get job status first
            job_status = await ai_analysis_engine.get_job_status(job_id)
            if not job_status:
                raise HTTPException(status_code=404, detail="Analysis job not found")

            # Get result if completed
            result = await ai_analysis_engine.get_analysis_result(job_id)

            response = {
                "job_id": job_id,
                "status": job_status.get("status", "unknown"),
                **job_status,
            }

            if result:
                response["result"] = {
                    "analysis_type": result.analysis_type.value,
                    "confidence_score": result.confidence_score,
                    "threat_level": result.threat_level.value,
                    "events_analyzed": result.events_analyzed,
                    "processing_time": result.processing_time,
                    "recommendations": result.recommendations,
                    "iocs": result.iocs,
                    "key_findings": getattr(result, "key_findings", []),
                    "providers_used": result.metadata.get("providers_used", []),
                    "consensus_response": (
                        result.consensus_response.response_text
                        if result.consensus_response
                        else None
                    ),
                    "timestamp": result.timestamp.isoformat(),
                }

            return response
        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "Failed to get AI analysis result", error=str(e), job_id=job_id
            )
            raise HTTPException(
                status_code=500, detail="Failed to retrieve analysis result"
            )

    @app.get("/ai/analysis", response_model=Dict[str, Any])
    @limiter.limit("30/minute")
    async def list_ai_analyses(
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
        status: Optional[str] = Query(None),
        analysis_type: Optional[AIAnalysisType] = Query(None),
        since: Optional[datetime] = Query(None),
    ):
        """List AI analysis jobs with filtering"""
        try:
            if not ai_analysis_engine:
                raise HTTPException(
                    status_code=503, detail="AI analysis engine not available"
                )

            # This would need to be implemented in the analysis engine
            # For now, return basic statistics
            stats = await ai_analysis_engine.get_statistics()

            return {
                "message": "Analysis listing not fully implemented yet",
                "statistics": stats,
                "active_jobs": stats.get("active_jobs", 0),
                "completed_jobs": stats.get("completed_jobs", 0),
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to list AI analyses", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to list analyses")

    @app.get("/ai/templates", response_model=List[Dict[str, Any]])
    @limiter.limit("60/minute")
    async def get_ai_templates(
        category: Optional[str] = Query(None),
        analysis_type: Optional[AIAnalysisType] = Query(None),
        complexity: Optional[str] = Query(None),
    ):
        """Get available AI analysis templates"""
        try:
            if not ai_prompt_manager:
                raise HTTPException(
                    status_code=503, detail="AI prompt manager not available"
                )

            # Convert enum parameters
            from .ai_integration.prompt_templates import (
                PromptCategory,
                PromptComplexity,
            )

            category_enum = None
            if category:
                try:
                    category_enum = PromptCategory(category)
                except ValueError:
                    pass

            complexity_enum = None
            if complexity:
                try:
                    complexity_enum = PromptComplexity(complexity)
                except ValueError:
                    pass

            templates = ai_prompt_manager.list_templates(
                category=category_enum,
                analysis_type=analysis_type,
                complexity=complexity_enum,
            )

            return [
                {
                    "name": template.name,
                    "category": template.category.value,
                    "analysis_type": template.analysis_type.value,
                    "complexity": template.complexity.value,
                    "description": template.description,
                    "required_fields": template.required_fields,
                    "optional_fields": template.optional_fields,
                    "example_context": template.example_context,
                }
                for template in templates
            ]
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to get AI templates", error=str(e))
            raise HTTPException(status_code=500, detail="Failed to retrieve templates")

    @app.post("/ai/templates/format", response_model=Dict[str, str])
    @limiter.limit("30/minute")
    async def format_ai_template(
        template_name: str, data: Dict[str, Any], validate_fields: bool = Query(True)
    ):
        """Format an AI prompt template with provided data"""
        try:
            if not ai_prompt_manager:
                raise HTTPException(
                    status_code=503, detail="AI prompt manager not available"
                )

            try:
                formatted_prompt = ai_prompt_manager.format_prompt(
                    template_name=template_name,
                    data=data,
                    validate_fields=validate_fields,
                )

                return {
                    "template_name": template_name,
                    "formatted_prompt": formatted_prompt,
                    "data_fields_used": list(data.keys()),
                }
            except KeyError as e:
                raise HTTPException(
                    status_code=400, detail=f"Missing required fields: {str(e)}"
                )
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "Failed to format AI template",
                error=str(e),
                template_name=template_name,
            )
            raise HTTPException(status_code=500, detail="Failed to format template")

    @app.post("/ai/templates/suggest", response_model=List[str])
    @limiter.limit("30/minute")
    async def suggest_ai_templates(
        analysis_type: AIAnalysisType,
        data_characteristics: Optional[Dict[str, Any]] = None,
    ):
        """Get template suggestions based on analysis type and data characteristics"""
        try:
            if not ai_prompt_manager:
                raise HTTPException(
                    status_code=503, detail="AI prompt manager not available"
                )

            suggestions = ai_prompt_manager.suggest_template(
                analysis_type=analysis_type, data_characteristics=data_characteristics
            )

            return suggestions
        except Exception as e:
            logger.error("Failed to get template suggestions", error=str(e))
            raise HTTPException(
                status_code=500, detail="Failed to get template suggestions"
            )

    @app.get("/ai/statistics", response_model=Dict[str, Any])
    @limiter.limit("60/minute")
    async def get_ai_statistics():
        """Get comprehensive AI analysis statistics"""
        try:
            stats = {}

            if ai_provider_manager:
                provider_status = await ai_provider_manager.get_provider_status()
                stats["providers"] = provider_status

            if ai_analysis_engine:
                engine_stats = await ai_analysis_engine.get_statistics()
                stats["analysis_engine"] = engine_stats

            if ai_prompt_manager:
                stats["templates"] = {
                    "total_templates": len(ai_prompt_manager.templates),
                    "templates_by_category": {},
                    "templates_by_analysis_type": {},
                    "templates_by_complexity": {},
                }

                # Count templates by different attributes
                for template in ai_prompt_manager.templates.values():
                    category = template.category.value
                    analysis_type = template.analysis_type.value
                    complexity = template.complexity.value

                    stats["templates"]["templates_by_category"][category] = (
                        stats["templates"]["templates_by_category"].get(category, 0) + 1
                    )
                    stats["templates"]["templates_by_analysis_type"][analysis_type] = (
                        stats["templates"]["templates_by_analysis_type"].get(
                            analysis_type, 0
                        )
                        + 1
                    )
                    stats["templates"]["templates_by_complexity"][complexity] = (
                        stats["templates"]["templates_by_complexity"].get(complexity, 0)
                        + 1
                    )

            # Add log processor AI stats if available
            if log_processor:
                processor_stats = await log_processor.get_processing_stats()
                if "ai_analysis" in processor_stats:
                    stats["log_processor_integration"] = processor_stats["ai_analysis"]

            stats["timestamp"] = datetime.utcnow().isoformat()

            return stats
        except Exception as e:
            logger.error("Failed to get AI statistics", error=str(e))
            raise HTTPException(
                status_code=500, detail="Failed to retrieve AI statistics"
            )

    @app.post("/ai/providers/{provider_name}/test")
    @limiter.limit("10/minute")
    async def test_ai_provider(
        provider_name: str,
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        """Test a specific AI provider"""
        try:
            if not ai_provider_manager:
                raise HTTPException(
                    status_code=503, detail="AI provider manager not available"
                )

            # Validate provider name
            from ..models import AIProvider as AIProviderEnum

            try:
                provider_enum = AIProviderEnum(provider_name)
            except ValueError:
                raise HTTPException(
                    status_code=400, detail=f"Unknown provider: {provider_name}"
                )

            if provider_enum not in ai_provider_manager.providers:
                raise HTTPException(
                    status_code=404, detail=f"Provider {provider_name} not configured"
                )

            provider = ai_provider_manager.providers[provider_enum]

            # Perform health check
            health_ok = await provider.health_check()

            # Get provider metrics
            metrics = {
                "provider_name": provider_name,
                "health_check": health_ok,
                "status": provider.health_metrics.status.value,
                "enabled": provider.enabled,
                "total_requests": provider.health_metrics.total_requests,
                "successful_requests": provider.health_metrics.successful_requests,
                "failed_requests": provider.health_metrics.failed_requests,
                "error_rate": provider.health_metrics.error_rate,
                "average_response_time": provider.health_metrics.average_response_time,
                "last_success_time": (
                    provider.health_metrics.last_success_time.isoformat()
                    if provider.health_metrics.last_success_time
                    else None
                ),
                "circuit_breaker_open": await provider.is_circuit_breaker_open(),
                "rate_limited": await provider.is_rate_limited(),
            }

            return metrics
        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "Failed to test AI provider", error=str(e), provider=provider_name
            )
            raise HTTPException(status_code=500, detail="Failed to test provider")


def _add_exception_handlers(app: FastAPI):
    """Add exception handlers"""

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request, exc):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.detail,
                "status_code": exc.status_code,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request, exc):
        logger.error("Unhandled exception", error=str(exc), exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "status_code": 500,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )


class AAAMonitorApp:
    """Main AAA Monitor Application class"""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize AAA Monitor application"""
        self.app = create_app(config_path)
        self.config = config

    def run(self, host: str = "0.0.0.0", port: int = 8003, **kwargs):
        """Run the AAA Monitor Service"""
        uvicorn.run(
            self.app,
            host=host,
            port=port,
            log_config=None,  # We handle logging ourselves
            **kwargs,
        )


# Global app instance
app_instance: Optional[AAAMonitorApp] = None


def create_aaa_monitor_app(config_path: Optional[str] = None) -> AAAMonitorApp:
    """Create AAA Monitor application instance"""
    global app_instance

    if app_instance is None:
        app_instance = AAAMonitorApp(config_path)

    return app_instance


def get_aaa_monitor_app() -> AAAMonitorApp:
    """Get current AAA Monitor application instance"""
    global app_instance

    if app_instance is None:
        raise RuntimeError(
            "AAA Monitor application not initialized. Call create_aaa_monitor_app() first."
        )

    return app_instance


def main():
    """Main entry point for the AAA Monitor Service"""
    import argparse

    parser = argparse.ArgumentParser(description="SkausWatch AAA Monitor Service")
    parser.add_argument("--config", "-c", type=str, help="Configuration file path")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", "-p", type=int, default=8003, help="Port to bind to")
    parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload for development"
    )
    parser.add_argument(
        "--workers", type=int, default=1, help="Number of worker processes"
    )

    args = parser.parse_args()

    try:
        app = create_aaa_monitor_app(args.config)
        app.run(
            host=args.host, port=args.port, reload=args.reload, workers=args.workers
        )
    except KeyboardInterrupt:
        logger.info("Shutting down AAA Monitor Service...")
    except Exception as e:
        logger.error("Failed to start AAA Monitor Service", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
