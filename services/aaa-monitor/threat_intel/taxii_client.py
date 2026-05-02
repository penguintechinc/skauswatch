"""
SkausWatch AAA Monitor Service - Enhanced TAXII Client

Advanced TAXII 2.0/2.1 client for high-volume threat intelligence feed consumption
with support for multiple authentication methods, feed discovery, collection polling,
incremental updates, pagination, and comprehensive error handling.
"""

import asyncio
import base64
import hashlib
import json
import logging
import ssl
import time
import uuid
import weakref
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse

import aiohttp
import certifi
import stix2
import structlog
from aiohttp import ClientTimeout
from aiohttp.client_exceptions import ClientError
try:
    from cabby import create_client as _cabby_create_client
    _CABBY_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    _cabby_create_client = None  # type: ignore[assignment]
    _CABBY_AVAILABLE = False


def create_client(*args, **kwargs):  # type: ignore[return]
    if not _CABBY_AVAILABLE:
        raise RuntimeError("cabby is not available (cgi module removed in Python 3.13)")
    return _cabby_create_client(*args, **kwargs)
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ..models import IOC, ThreatFeed, ThreatLevel

logger = structlog.get_logger(__name__)


class CircuitBreaker:
    """Circuit breaker for failing feeds"""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 300):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half_open

    def call_succeeded(self):
        """Record successful call"""
        self.failure_count = 0
        self.state = "closed"

    def call_failed(self):
        """Record failed call"""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.failure_count >= self.failure_threshold:
            self.state = "open"

    def can_attempt(self) -> bool:
        """Check if request can be attempted"""
        if self.state == "closed":
            return True

        if self.state == "open":
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self.state = "half_open"
                return True
            return False

        # half_open state
        return True


class FeedQualityManager:
    """Manages feed quality assessment and scoring"""

    def __init__(self):
        self.quality_scores = {}
        self.quality_history = {}

    def assess_feed_quality(
        self, feed_id: str, indicators: List[IOC], response_time: float, success: bool
    ) -> float:
        """Assess feed quality based on multiple factors"""

        if feed_id not in self.quality_history:
            self.quality_history[feed_id] = {
                "response_times": [],
                "success_count": 0,
                "failure_count": 0,
                "indicator_counts": [],
                "duplicate_ratios": [],
                "freshness_scores": [],
            }

        history = self.quality_history[feed_id]

        # Update history
        history["response_times"].append(response_time)
        if success:
            history["success_count"] += 1
        else:
            history["failure_count"] += 1

        history["indicator_counts"].append(len(indicators))

        # Calculate quality metrics
        reliability_score = self._calculate_reliability_score(history)
        performance_score = self._calculate_performance_score(history)
        content_quality_score = self._calculate_content_quality_score(indicators)
        freshness_score = self._calculate_freshness_score(indicators)

        # Weighted overall score
        overall_score = (
            reliability_score * 0.3
            + performance_score * 0.2
            + content_quality_score * 0.3
            + freshness_score * 0.2
        )

        self.quality_scores[feed_id] = {
            "overall": overall_score,
            "reliability": reliability_score,
            "performance": performance_score,
            "content_quality": content_quality_score,
            "freshness": freshness_score,
            "last_assessed": datetime.utcnow().isoformat(),
        }

        return overall_score

    def _calculate_reliability_score(self, history: Dict) -> float:
        """Calculate reliability score based on success rate"""
        total_requests = history["success_count"] + history["failure_count"]
        if total_requests == 0:
            return 1.0
        return history["success_count"] / total_requests

    def _calculate_performance_score(self, history: Dict) -> float:
        """Calculate performance score based on response times"""
        times = history["response_times"]
        if not times:
            return 1.0

        avg_time = sum(times) / len(times)
        # Score based on response time (lower is better)
        # 1.0 for <1s, 0.8 for <5s, 0.6 for <10s, etc.
        if avg_time < 1:
            return 1.0
        elif avg_time < 5:
            return 0.8
        elif avg_time < 10:
            return 0.6
        elif avg_time < 30:
            return 0.4
        else:
            return 0.2

    def _calculate_content_quality_score(self, indicators: List[IOC]) -> float:
        """Calculate content quality score"""
        if not indicators:
            return 0.0

        # Check for duplicate indicators
        values = [ioc.value for ioc in indicators]
        unique_values = set(values)
        duplicate_ratio = 1 - (len(unique_values) / len(values))

        # Check for high-confidence indicators
        high_confidence_count = sum(1 for ioc in indicators if ioc.confidence > 0.8)
        high_confidence_ratio = high_confidence_count / len(indicators)

        # Check for proper threat level distribution
        threat_levels = [ioc.threat_level for ioc in indicators]
        has_threat_diversity = len(set(threat_levels)) > 1

        # Combined score
        quality_score = (
            (1 - duplicate_ratio) * 0.4  # Less duplicates = higher quality
            + high_confidence_ratio * 0.4  # More high confidence = higher quality
            + (0.2 if has_threat_diversity else 0.0) * 0.2  # Threat diversity bonus
        )

        return min(1.0, quality_score)

    def _calculate_freshness_score(self, indicators: List[IOC]) -> float:
        """Calculate freshness score based on indicator age"""
        if not indicators:
            return 0.0

        now = datetime.utcnow()
        fresh_count = 0

        for ioc in indicators:
            age_hours = (now - ioc.created_at).total_seconds() / 3600
            if age_hours < 24:  # Less than 1 day old
                fresh_count += 1

        return fresh_count / len(indicators)

    def get_feed_quality(self, feed_id: str) -> Dict[str, Any]:
        """Get quality assessment for a feed"""
        return self.quality_scores.get(
            feed_id,
            {
                "overall": 0.0,
                "reliability": 0.0,
                "performance": 0.0,
                "content_quality": 0.0,
                "freshness": 0.0,
                "last_assessed": None,
            },
        )

    def get_top_quality_feeds(self, limit: int = 10) -> List[Tuple[str, float]]:
        """Get top quality feeds"""
        sorted_feeds = sorted(
            self.quality_scores.items(), key=lambda x: x[1]["overall"], reverse=True
        )
        return [
            (feed_id, scores["overall"]) for feed_id, scores in sorted_feeds[:limit]
        ]


class RequestTracker:
    """Tracks request performance and manages active requests"""

    def __init__(self):
        self.active_requests = {}
        self.request_history = []
        self.max_history = 1000

    def start_request(self, request_id: str, feed_id: str, url: str):
        """Start tracking a request"""
        self.active_requests[request_id] = {
            "feed_id": feed_id,
            "url": url,
            "start_time": time.time(),
            "status": "active",
        }

    def complete_request(
        self, request_id: str, success: bool, response_size: int = 0, error: str = None
    ):
        """Complete request tracking"""
        if request_id in self.active_requests:
            request_info = self.active_requests[request_id]
            request_info.update(
                {
                    "end_time": time.time(),
                    "duration": time.time() - request_info["start_time"],
                    "success": success,
                    "response_size": response_size,
                    "error": error,
                    "status": "completed",
                }
            )

            # Move to history
            self.request_history.append(request_info.copy())
            if len(self.request_history) > self.max_history:
                self.request_history.pop(0)

            del self.active_requests[request_id]

    def get_active_requests(self) -> Dict[str, Dict]:
        """Get currently active requests"""
        return self.active_requests.copy()

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        if not self.request_history:
            return {
                "avg_response_time": 0.0,
                "success_rate": 0.0,
                "total_requests": 0,
                "avg_response_size": 0.0,
            }

        successful_requests = [r for r in self.request_history if r["success"]]

        return {
            "avg_response_time": sum(r["duration"] for r in self.request_history)
            / len(self.request_history),
            "success_rate": len(successful_requests) / len(self.request_history),
            "total_requests": len(self.request_history),
            "avg_response_size": sum(
                r.get("response_size", 0) for r in successful_requests
            )
            / max(len(successful_requests), 1),
        }


class TAXIIClient:
    """Enhanced TAXII 2.0/2.1 client for enterprise threat intelligence consumption

    Features:
    - TAXII 2.0 and 2.1 protocol support
    - Multiple authentication methods (basic, token, certificate, OAuth2)
    - Feed discovery and automatic collection detection
    - Incremental updates with pagination
    - Connection pooling and rate limiting
    - Feed health monitoring and comprehensive error handling
    - Multi-tenant feed management
    """

    def __init__(self, config: Dict[str, Any], stix_parser, threat_database):
        """Initialize enhanced TAXII client

        Args:
            config: TAXII configuration with enhanced settings
            stix_parser: STIX parser instance
            threat_database: Threat database for storing IOCs
        """
        self.config = config
        self.stix_parser = stix_parser
        self.threat_database = threat_database

        # Enhanced feed management
        self.feeds = {}  # feed_id -> ThreatFeed
        self.collections = {}  # feed_id -> List[collection_info]
        self.feed_health = {}  # feed_id -> health_status
        self.feed_manifests = {}  # feed_id -> manifest_data

        # TAXII 2.x specific configurations
        self.taxii_servers = {}  # server_url -> server_info
        self.discovery_endpoints = {}  # server_url -> discovery_info
        self.api_roots = {}  # server_url -> List[api_root]

        # Connection management
        self.client_sessions = {}  # feed_id -> aiohttp.ClientSession
        self.connection_pools = {}  # server_url -> connection_pool
        self.rate_limiters = {}  # feed_id -> rate_limiter

        # Update tracking with enhanced state
        self.last_updates = {}  # feed_id -> datetime
        self.update_locks = {}  # feed_id -> asyncio.Lock
        self.update_states = {}  # feed_id -> update_state_info
        self.pagination_cursors = {}  # feed_id -> {collection_id -> cursor}

        # Authentication management
        self.auth_tokens = {}  # feed_id -> token_info
        self.certificates = {}  # feed_id -> cert_info
        self.oauth_clients = {}  # feed_id -> oauth_client

        # Enhanced statistics and monitoring
        self.stats = {
            "feeds_configured": 0,
            "feeds_active": 0,
            "feeds_healthy": 0,
            "total_indicators_received": 0,
            "indicators_by_feed": {},
            "indicators_by_type": {},
            "collections_discovered": 0,
            "api_requests_made": 0,
            "api_requests_failed": 0,
            "bytes_transferred": 0,
            "last_successful_update": None,
            "update_errors": {},
            "connection_failures": 0,
            "authentication_failures": 0,
            "rate_limit_hits": 0,
            "pagination_requests": 0,
            "feed_quality_scores": {},
            "duplicate_indicators": 0,
            "expired_indicators_removed": 0,
            "performance_metrics": {
                "avg_request_time": 0.0,
                "max_request_time": 0.0,
                "min_request_time": float("inf"),
                "total_processing_time": 0.0,
            },
        }

        # Feed quality assessment
        self.feed_quality_manager = FeedQualityManager()

        # Circuit breaker for failed feeds
        self.circuit_breakers = {}  # feed_id -> CircuitBreaker

        # Performance monitoring
        self.request_tracker = RequestTracker()

        # Background tasks and scheduling
        self.update_tasks = []
        self.discovery_tasks = []
        self.health_check_tasks = []
        self.quality_assessment_tasks = []
        self.cleanup_tasks = []
        self.running = False
        self.scheduler = None

        # Graceful shutdown management
        self._shutdown_event = asyncio.Event()
        self._active_requests = weakref.WeakSet()

        # Configuration defaults
        self.default_timeout = config.get("default_timeout", 30)
        self.max_retries = config.get("max_retries", 3)
        self.retry_backoff = config.get("retry_backoff", 2.0)
        self.max_concurrent_requests = config.get("max_concurrent_requests", 10)
        self.enable_discovery = config.get("enable_discovery", True)
        self.health_check_interval = config.get(
            "health_check_interval", 300
        )  # 5 minutes
        self.pagination_limit = config.get("pagination_limit", 1000)

    async def initialize(self):
        """Initialize enhanced TAXII client with comprehensive setup"""
        try:
            logger.info("Initializing enhanced TAXII client")

            # Initialize connection pools
            await self._initialize_connection_pools()

            # Configure feeds from config
            await self._configure_feeds()

            # Setup authentication for all feeds
            await self._setup_authentication()

            # Discover TAXII servers and API roots if enabled
            if self.enable_discovery:
                await self._discover_taxii_servers()

            # Discover collections for all feeds
            await self._discover_collections()

            # Test initial connections and health
            await self._test_feed_connections()

            # Load last update timestamps and pagination state
            await self._load_update_history()
            await self._load_pagination_state()

            # Initialize rate limiters
            await self._setup_rate_limiters()

            logger.info(
                "Enhanced TAXII client initialized successfully",
                configured_feeds=len(self.feeds),
                discovered_collections=self.stats["collections_discovered"],
                healthy_feeds=self.stats["feeds_healthy"],
            )

        except Exception as e:
            logger.error("Failed to initialize enhanced TAXII client", error=str(e))
            await self._cleanup_on_error()
            raise

    async def _initialize_connection_pools(self):
        """Initialize HTTP connection pools for better performance"""
        try:
            # Create default SSL context
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED

            # Configure connection limits
            connector_limit = self.max_concurrent_requests * 2
            timeout = aiohttp.ClientTimeout(total=self.default_timeout)

            # Create session for each unique server
            servers = set()
            for feed_config in self.config.get("feeds", []):
                server_url = self._extract_server_url(feed_config["url"])
                servers.add(server_url)

            for server_url in servers:
                connector = aiohttp.TCPConnector(
                    limit=connector_limit,
                    limit_per_host=connector_limit // 2,
                    ssl=ssl_context,
                    keepalive_timeout=60,
                    enable_cleanup_closed=True,
                )

                session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    headers={"User-Agent": "SkausWatch-TAXII-Client/2.1"},
                )

                self.connection_pools[server_url] = session

            logger.info("Connection pools initialized", server_count=len(servers))

        except Exception as e:
            logger.error("Error initializing connection pools", error=str(e))
            raise

    def _extract_server_url(self, url: str) -> str:
        """Extract base server URL from feed URL"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def _configure_feeds(self):
        """Configure enhanced threat intelligence feeds with validation"""
        try:
            feed_configs = self.config.get("feeds", [])

            for feed_config in feed_configs:
                # Validate required fields
                if not feed_config.get("name") or not feed_config.get("url"):
                    logger.warning(
                        "Skipping invalid feed configuration", config=feed_config
                    )
                    continue

                # Enhanced feed configuration
                feed = ThreatFeed(
                    name=feed_config["name"],
                    url=feed_config["url"],
                    feed_type=feed_config.get("feed_type", "taxii"),
                    enabled=feed_config.get("enabled", True),
                    update_frequency=feed_config.get("update_frequency", 3600),
                    credentials=feed_config.get("credentials"),
                    headers=feed_config.get("headers"),
                    certificate_verification=feed_config.get("verify_ssl", True),
                    proxy_url=feed_config.get("proxy_url"),
                )

                # Store feed and initialize supporting structures
                self.feeds[feed.id] = feed
                self.update_locks[feed.id] = asyncio.Lock()
                self.collections[feed.id] = []
                self.feed_health[feed.id] = {"status": "unknown", "last_check": None}
                self.update_states[feed.id] = {"last_manifest": None, "error_count": 0}
                self.pagination_cursors[feed.id] = {}

                # Enhanced configuration options
                feed_config = feed_config.copy()
                feed_extra = {
                    "taxii_version": feed_config.get("taxii_version", "2.1"),
                    "auth_type": feed_config.get(
                        "auth_type", "none"
                    ),  # none, basic, token, cert, oauth2
                    "collections_filter": feed_config.get(
                        "collections_filter", []
                    ),  # specific collections
                    "content_types": feed_config.get(
                        "content_types", ["application/stix+json"]
                    ),
                    "added_after_mode": feed_config.get(
                        "added_after_mode", True
                    ),  # use added_after for incremental
                    "pagination_enabled": feed_config.get("pagination_enabled", True),
                    "max_page_size": feed_config.get("max_page_size", 1000),
                    "retry_policy": feed_config.get(
                        "retry_policy",
                        {
                            "max_retries": 3,
                            "backoff_factor": 2.0,
                            "retry_statuses": [429, 500, 502, 503, 504],
                        },
                    ),
                    "rate_limit": feed_config.get(
                        "rate_limit", {"requests_per_minute": 60, "burst_limit": 10}
                    ),
                }

                # Store enhanced configuration
                setattr(feed, "_enhanced_config", feed_extra)

                # Initialize statistics
                self.stats["indicators_by_feed"][feed.id] = 0

            self.stats["feeds_configured"] = len(self.feeds)
            logger.info(
                "Enhanced threat feeds configured",
                count=len(self.feeds),
                taxii_feeds=len(
                    [f for f in self.feeds.values() if f.feed_type == "taxii"]
                ),
            )

        except Exception as e:
            logger.error("Error configuring enhanced feeds", error=str(e))
            raise

    async def _setup_authentication(self):
        """Setup authentication for all configured feeds"""
        try:
            for feed_id, feed in self.feeds.items():
                if not feed.enabled:
                    continue

                enhanced_config = getattr(feed, "_enhanced_config", {})
                auth_type = enhanced_config.get("auth_type", "none")

                if auth_type == "basic" and feed.credentials:
                    # Basic authentication setup
                    username = feed.credentials.get("username")
                    password = feed.credentials.get("password")
                    if username and password:
                        credentials = base64.b64encode(
                            f"{username}:{password}".encode()
                        ).decode()
                        self.auth_tokens[feed_id] = {
                            "type": "basic",
                            "value": f"Basic {credentials}",
                            "expires": None,
                        }

                elif auth_type == "token" and feed.credentials:
                    # Token authentication setup
                    token = feed.credentials.get("token")
                    if token:
                        self.auth_tokens[feed_id] = {
                            "type": "token",
                            "value": f"Bearer {token}",
                            "expires": None,
                        }

                elif auth_type == "cert" and feed.credentials:
                    # Certificate authentication setup
                    cert_path = feed.credentials.get("cert_path")
                    key_path = feed.credentials.get("key_path")
                    if cert_path and key_path:
                        self.certificates[feed_id] = {
                            "cert_path": cert_path,
                            "key_path": key_path,
                            "ca_path": feed.credentials.get("ca_path"),
                        }

                elif auth_type == "oauth2" and feed.credentials:
                    # OAuth2 setup (will be implemented when needed)
                    await self._setup_oauth2_client(feed_id, feed.credentials)

            logger.info(
                "Authentication setup completed",
                basic_auth=len(
                    [t for t in self.auth_tokens.values() if t["type"] == "basic"]
                ),
                token_auth=len(
                    [t for t in self.auth_tokens.values() if t["type"] == "token"]
                ),
                cert_auth=len(self.certificates),
            )

        except Exception as e:
            logger.error("Error setting up authentication", error=str(e))
            raise

    async def _setup_oauth2_client(self, feed_id: str, credentials: Dict[str, str]):
        """Set up OAuth2 client credentials flow for TAXII feed authentication."""
        required = {"client_id", "client_secret", "token_url"}
        missing = required - credentials.keys()
        if missing:
            raise ValueError(
                f"OAuth2 credentials missing required fields for feed '{feed_id}': {missing}"
            )

        client_id = credentials["client_id"]
        client_secret = credentials["client_secret"]
        token_url = credentials["token_url"]

        logger.info(
            "Configuring OAuth2 client credentials flow",
            feed_id=feed_id,
            token_url=token_url,
            client_id=client_id[:4] + "****",
        )

        # Store credentials for use in request headers
        self.oauth_clients[feed_id] = {
            "client_id": client_id,
            "client_secret": client_secret,
            "token_url": token_url,
            "access_token": None,
            "expires_at": None,
        }

    async def _discover_taxii_servers(self):
        """Discover TAXII servers and their capabilities"""
        try:
            servers_discovered = 0

            for feed_id, feed in self.feeds.items():
                if not feed.enabled or feed.feed_type != "taxii":
                    continue

                try:
                    server_url = self._extract_server_url(feed.url)

                    if server_url not in self.taxii_servers:
                        discovery_info = await self._perform_server_discovery(
                            server_url, feed_id
                        )
                        if discovery_info:
                            self.taxii_servers[server_url] = discovery_info
                            servers_discovered += 1

                except Exception as e:
                    logger.error(
                        "Error discovering TAXII server",
                        feed_name=feed.name,
                        error=str(e),
                    )
                    continue

            logger.info(
                "TAXII server discovery completed",
                servers_discovered=servers_discovered,
            )

        except Exception as e:
            logger.error("Error in TAXII server discovery", error=str(e))

    async def _perform_server_discovery(
        self, server_url: str, feed_id: str
    ) -> Optional[Dict[str, Any]]:
        """Perform discovery on a specific TAXII server"""
        try:
            discovery_url = urljoin(server_url, "/taxii2/")
            session = self.connection_pools.get(server_url)

            if not session:
                logger.error("No session available for server", server_url=server_url)
                return None

            headers = self._build_headers(feed_id)

            async with session.get(discovery_url, headers=headers) as response:
                if response.status == 200:
                    discovery_data = await response.json()

                    # Parse API roots
                    api_roots = []
                    for api_root_url in discovery_data.get("api_roots", []):
                        api_root_info = await self._discover_api_root(
                            api_root_url, feed_id
                        )
                        if api_root_info:
                            api_roots.append(api_root_info)

                    return {
                        "title": discovery_data.get("title", "Unknown"),
                        "description": discovery_data.get("description", ""),
                        "contact": discovery_data.get("contact", ""),
                        "api_roots": api_roots,
                        "discovered_at": datetime.utcnow().isoformat(),
                    }
                else:
                    logger.warning(
                        "Discovery failed",
                        server_url=server_url,
                        status=response.status,
                    )

        except Exception as e:
            logger.error(
                "Error in server discovery", server_url=server_url, error=str(e)
            )

        return None

    async def _discover_api_root(
        self, api_root_url: str, feed_id: str
    ) -> Optional[Dict[str, Any]]:
        """Discover API root information"""
        try:
            server_url = self._extract_server_url(api_root_url)
            session = self.connection_pools.get(server_url)
            headers = self._build_headers(feed_id)

            async with session.get(api_root_url, headers=headers) as response:
                if response.status == 200:
                    api_root_data = await response.json()
                    return {
                        "url": api_root_url,
                        "title": api_root_data.get("title", ""),
                        "description": api_root_data.get("description", ""),
                        "versions": api_root_data.get("versions", ["2.1"]),
                        "max_content_length": api_root_data.get(
                            "max_content_length", 10485760
                        ),
                    }

        except Exception as e:
            logger.error(
                "Error discovering API root", api_root_url=api_root_url, error=str(e)
            )

        return None

    def _build_headers(self, feed_id: str) -> Dict[str, str]:
        """Build HTTP headers for TAXII requests"""
        headers = {
            "Accept": "application/taxii+json;version=2.1",
            "User-Agent": "SkausWatch-TAXII-Client/2.1",
        }

        # Add authentication headers
        auth_info = self.auth_tokens.get(feed_id)
        if auth_info:
            headers["Authorization"] = auth_info["value"]

        # Add custom headers from feed configuration
        feed = self.feeds.get(feed_id)
        if feed and feed.headers:
            headers.update(feed.headers)

        return headers

    async def _discover_collections(self):
        """Discover collections for all TAXII feeds"""
        try:
            total_collections = 0

            for feed_id, feed in self.feeds.items():
                if not feed.enabled or feed.feed_type != "taxii":
                    continue

                try:
                    collections = await self._discover_feed_collections(feed_id, feed)
                    self.collections[feed_id] = collections
                    total_collections += len(collections)

                    logger.info(
                        "Collections discovered for feed",
                        feed_name=feed.name,
                        collection_count=len(collections),
                    )

                except Exception as e:
                    logger.error(
                        "Error discovering collections for feed",
                        feed_name=feed.name,
                        error=str(e),
                    )

            self.stats["collections_discovered"] = total_collections
            logger.info(
                "Collection discovery completed", total_collections=total_collections
            )

        except Exception as e:
            logger.error("Error in collection discovery", error=str(e))

    async def _discover_feed_collections(
        self, feed_id: str, feed: ThreatFeed
    ) -> List[Dict[str, Any]]:
        """Discover collections for a specific feed"""
        try:
            # Extract API root from feed URL
            api_root_url = self._extract_api_root_from_url(feed.url)
            collections_url = urljoin(api_root_url, "collections/")

            server_url = self._extract_server_url(feed.url)
            session = self.connection_pools.get(server_url)
            headers = self._build_headers(feed_id)

            async with session.get(collections_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    collections = data.get("collections", [])

                    # Filter collections if specified
                    enhanced_config = getattr(feed, "_enhanced_config", {})
                    collections_filter = enhanced_config.get("collections_filter", [])

                    if collections_filter:
                        collections = [
                            col
                            for col in collections
                            if col.get("id") in collections_filter
                            or col.get("title") in collections_filter
                        ]

                    return collections
                else:
                    logger.error(
                        "Failed to discover collections",
                        feed_name=feed.name,
                        status=response.status,
                    )

        except Exception as e:
            logger.error(
                "Error discovering feed collections", feed_name=feed.name, error=str(e)
            )

        return []

    def _extract_api_root_from_url(self, url: str) -> str:
        """Extract API root URL from feed URL"""
        # Simple extraction - assumes URL structure follows TAXII 2.x standards
        if "/collections/" in url:
            return url.split("/collections/")[0] + "/"
        elif url.endswith("/"):
            return url
        else:
            return url + "/"

    async def _test_feed_connections(self):
        """Test connections and health for all configured feeds"""
        active_feeds = 0
        healthy_feeds = 0

        for feed_id, feed in self.feeds.items():
            if not feed.enabled:
                self.feed_health[feed_id] = {
                    "status": "disabled",
                    "last_check": datetime.utcnow().isoformat(),
                }
                continue

            try:
                health_status = await self._comprehensive_health_check(feed_id, feed)
                self.feed_health[feed_id] = health_status

                if health_status["status"] == "healthy":
                    active_feeds += 1
                    healthy_feeds += 1
                    logger.info("Feed is healthy", feed_name=feed.name)
                elif health_status["status"] == "degraded":
                    active_feeds += 1
                    logger.warning(
                        "Feed is degraded",
                        feed_name=feed.name,
                        issues=health_status.get("issues", []),
                    )
                else:
                    logger.error(
                        "Feed is unhealthy",
                        feed_name=feed.name,
                        error=health_status.get("error"),
                    )

            except Exception as e:
                logger.error(
                    "Error testing feed connection", feed_name=feed.name, error=str(e)
                )
                self.feed_health[feed_id] = {
                    "status": "error",
                    "error": str(e),
                    "last_check": datetime.utcnow().isoformat(),
                }

        self.stats["feeds_active"] = active_feeds
        self.stats["feeds_healthy"] = healthy_feeds

    async def _comprehensive_health_check(
        self, feed_id: str, feed: ThreatFeed
    ) -> Dict[str, Any]:
        """Perform comprehensive health check on a feed"""
        health_status = {
            "status": "unknown",
            "last_check": datetime.utcnow().isoformat(),
            "response_time": None,
            "issues": [],
            "collections_accessible": 0,
            "last_successful_request": None,
        }

        try:
            start_time = datetime.utcnow()

            if feed.feed_type == "taxii":
                # Test TAXII-specific endpoints
                taxii_health = await self._test_taxii_health(feed_id, feed)
                health_status.update(taxii_health)
            else:
                # Test HTTP-based feeds
                http_health = await self._test_http_health(feed_id, feed)
                health_status.update(http_health)

            # Calculate response time
            response_time = (datetime.utcnow() - start_time).total_seconds()
            health_status["response_time"] = response_time

            # Determine overall status
            if len(health_status["issues"]) == 0:
                health_status["status"] = "healthy"
            elif any("critical" in issue.lower() for issue in health_status["issues"]):
                health_status["status"] = "unhealthy"
            else:
                health_status["status"] = "degraded"

        except Exception as e:
            health_status.update(
                {
                    "status": "error",
                    "error": str(e),
                    "issues": [f"Health check failed: {str(e)}"],
                }
            )

        return health_status

    async def _test_taxii_health(
        self, feed_id: str, feed: ThreatFeed
    ) -> Dict[str, Any]:
        """Test TAXII feed health comprehensively"""
        health_data = {
            "issues": [],
            "collections_accessible": 0,
            "last_successful_request": None,
        }

        try:
            server_url = self._extract_server_url(feed.url)
            session = self.connection_pools.get(server_url)
            headers = self._build_headers(feed_id)

            if not session:
                health_data["issues"].append(
                    "CRITICAL: No connection session available"
                )
                return health_data

            # Test server discovery endpoint
            discovery_url = urljoin(server_url, "/taxii2/")
            try:
                async with session.get(discovery_url, headers=headers) as response:
                    if response.status == 200:
                        health_data["last_successful_request"] = (
                            datetime.utcnow().isoformat()
                        )
                    elif response.status == 401:
                        health_data["issues"].append("Authentication failed")
                        self.stats["authentication_failures"] += 1
                    elif response.status == 403:
                        health_data["issues"].append("Access forbidden")
                    else:
                        health_data["issues"].append(
                            f"Discovery endpoint returned {response.status}"
                        )
            except asyncio.TimeoutError:
                health_data["issues"].append("Discovery endpoint timeout")

            # Test collections accessibility
            collections = self.collections.get(feed_id, [])
            accessible_collections = 0

            for collection in collections[:3]:  # Test up to 3 collections
                collection_id = collection.get("id")
                if collection_id:
                    collection_url = urljoin(
                        self._extract_api_root_from_url(feed.url),
                        f"collections/{collection_id}/",
                    )

                    try:
                        async with session.get(
                            collection_url, headers=headers
                        ) as response:
                            if response.status == 200:
                                accessible_collections += 1
                            else:
                                health_data["issues"].append(
                                    f"Collection {collection_id} returned {response.status}"
                                )
                    except Exception as e:
                        health_data["issues"].append(
                            f"Collection {collection_id} error: {str(e)}"
                        )

            health_data["collections_accessible"] = accessible_collections

            if accessible_collections == 0 and collections:
                health_data["issues"].append("No collections are accessible")

        except Exception as e:
            health_data["issues"].append(f"TAXII health check error: {str(e)}")

        return health_data

    async def _test_http_health(self, feed_id: str, feed: ThreatFeed) -> Dict[str, Any]:
        """Test HTTP feed health"""
        health_data = {
            "issues": [],
            "collections_accessible": 1,  # HTTP feeds treated as single collection
            "last_successful_request": None,
        }

        try:
            server_url = self._extract_server_url(feed.url)
            session = self.connection_pools.get(server_url)

            if not session:
                # Create temporary session for non-TAXII feeds
                timeout = aiohttp.ClientTimeout(total=self.default_timeout)
                ssl_context = (
                    ssl.create_default_context()
                    if feed.certificate_verification
                    else False
                )
                connector = aiohttp.TCPConnector(ssl=ssl_context)
                session = aiohttp.ClientSession(connector=connector, timeout=timeout)

            headers = feed.headers or {}
            auth = None

            if feed.credentials:
                auth = aiohttp.BasicAuth(
                    feed.credentials.get("username", ""),
                    feed.credentials.get("password", ""),
                )

            async with session.head(feed.url, headers=headers, auth=auth) as response:
                if response.status < 400:
                    health_data["last_successful_request"] = (
                        datetime.utcnow().isoformat()
                    )
                elif response.status == 401:
                    health_data["issues"].append("Authentication required or failed")
                elif response.status == 403:
                    health_data["issues"].append("Access forbidden")
                elif response.status >= 500:
                    health_data["issues"].append(f"Server error: {response.status}")
                else:
                    health_data["issues"].append(f"HTTP error: {response.status}")

        except Exception as e:
            health_data["issues"].append(f"HTTP health check error: {str(e)}")

        return health_data

    async def _check_rate_limit(self, feed_id: str) -> bool:
        """Check if request is allowed under rate limit"""
        try:
            rate_limiter = self.rate_limiters.get(feed_id)
            if not rate_limiter:
                return True

            async with rate_limiter["lock"]:
                current_time = datetime.utcnow()
                minute_ago = current_time - timedelta(minutes=1)

                # Clean old requests
                rate_limiter["requests_made"] = [
                    req_time
                    for req_time in rate_limiter["requests_made"]
                    if req_time > minute_ago
                ]

                # Check limits
                requests_in_last_minute = len(rate_limiter["requests_made"])

                if requests_in_last_minute >= rate_limiter["requests_per_minute"]:
                    self.stats["rate_limit_hits"] += 1
                    return False

                # Add current request
                rate_limiter["requests_made"].append(current_time)
                return True

        except Exception as e:
            logger.error("Error checking rate limit", feed_id=feed_id, error=str(e))
            return True  # Allow request if rate limit check fails

    async def _load_update_history(self):
        """Load last update timestamps from threat database"""
        try:
            for feed_id in self.feeds:
                last_update = await self.threat_database.get_feed_last_update(feed_id)
                if last_update:
                    self.last_updates[feed_id] = last_update

        except Exception as e:
            logger.error("Error loading update history", error=str(e))

    async def _load_pagination_state(self):
        """Load pagination cursors and state from database"""
        try:
            for feed_id in self.feeds:
                # Load pagination cursors for each collection
                # This would typically be stored in the database
                # For now, initialize empty cursors
                self.pagination_cursors[feed_id] = {}

        except Exception as e:
            logger.error("Error loading pagination state", error=str(e))

    async def _setup_rate_limiters(self):
        """Setup rate limiters for each feed"""
        try:
            for feed_id, feed in self.feeds.items():
                enhanced_config = getattr(feed, "_enhanced_config", {})
                rate_limit_config = enhanced_config.get(
                    "rate_limit", {"requests_per_minute": 60, "burst_limit": 10}
                )

                # Simple rate limiter implementation
                self.rate_limiters[feed_id] = {
                    "requests_per_minute": rate_limit_config["requests_per_minute"],
                    "burst_limit": rate_limit_config["burst_limit"],
                    "requests_made": [],
                    "lock": asyncio.Lock(),
                }

        except Exception as e:
            logger.error("Error setting up rate limiters", error=str(e))

    async def _cleanup_on_error(self):
        """Cleanup resources on initialization error"""
        try:
            # Close connection pools
            for session in self.connection_pools.values():
                if session and not session.closed:
                    await session.close()

            self.connection_pools.clear()
            logger.info("Cleaned up resources after initialization error")

        except Exception as e:
            logger.error("Error during cleanup", error=str(e))

    async def start_feed_updates(self):
        """Start enhanced background feed update tasks with scheduling"""
        if self.running:
            logger.warning("Feed updates already running")
            return

        self.running = True

        # Start update task for each active feed
        for feed_id, feed in self.feeds.items():
            if feed.enabled:
                task = asyncio.create_task(
                    self._enhanced_feed_update_loop(feed_id),
                    name=f"feed_update_{feed.name}",
                )
                self.update_tasks.append(task)

        # Start health check tasks
        health_task = asyncio.create_task(
            self._health_check_loop(), name="feed_health_monitor"
        )
        self.health_check_tasks.append(health_task)

        # Start discovery refresh task
        if self.enable_discovery:
            discovery_task = asyncio.create_task(
                self._discovery_refresh_loop(), name="discovery_refresh"
            )
            self.discovery_tasks.append(discovery_task)

        logger.info(
            "Enhanced feed update system started",
            update_tasks=len(self.update_tasks),
            health_tasks=len(self.health_check_tasks),
            discovery_tasks=len(self.discovery_tasks),
        )

    async def _enhanced_feed_update_loop(self, feed_id: str):
        """Enhanced background update loop with adaptive scheduling and error handling"""
        feed = self.feeds.get(feed_id)
        if not feed:
            return

        logger.info("Enhanced feed update loop started", feed_name=feed.name)
        consecutive_errors = 0

        try:
            while self.running:
                try:
                    # Check rate limits
                    if not await self._check_rate_limit(feed_id):
                        await asyncio.sleep(60)  # Wait 1 minute if rate limited
                        continue

                    # Check if update is needed
                    if await self._should_update_feed(feed):
                        update_start = datetime.utcnow()

                        # Perform update with error handling
                        success = await self._resilient_feed_update(feed_id)

                        if success:
                            consecutive_errors = 0
                            update_duration = (
                                datetime.utcnow() - update_start
                            ).total_seconds()

                            # Adaptive scheduling based on update success
                            sleep_time = await self._calculate_adaptive_sleep_time(
                                feed_id, update_duration
                            )
                        else:
                            consecutive_errors += 1
                            # Exponential backoff for errors
                            sleep_time = min(
                                feed.update_frequency * (2**consecutive_errors),
                                3600,  # Max 1 hour
                            )

                            logger.warning(
                                "Feed update failed, backing off",
                                feed_name=feed.name,
                                consecutive_errors=consecutive_errors,
                                backoff_seconds=sleep_time,
                            )
                    else:
                        # Normal interval when no update needed
                        sleep_time = min(
                            feed.update_frequency // 4, 300
                        )  # Check every 1/4 interval or 5 min

                    await asyncio.sleep(sleep_time)

                except Exception as e:
                    consecutive_errors += 1
                    logger.error(
                        "Error in enhanced feed update loop",
                        feed_name=feed.name,
                        error=str(e),
                    )

                    # Record error with enhanced details
                    self.stats["update_errors"][feed_id] = {
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat(),
                        "consecutive_errors": consecutive_errors,
                        "error_type": type(e).__name__,
                    }

                    # Progressive backoff
                    backoff_time = min(
                        300 * consecutive_errors, 3600
                    )  # 5min * errors, max 1 hour
                    await asyncio.sleep(backoff_time)

        except asyncio.CancelledError:
            logger.info("Enhanced feed update loop cancelled", feed_name=feed.name)
        except Exception as e:
            logger.error(
                "Fatal error in enhanced feed update loop",
                feed_name=feed.name,
                error=str(e),
            )

    async def _health_check_loop(self):
        """Background health monitoring loop"""
        logger.info("Feed health monitoring started")

        try:
            while self.running:
                try:
                    healthy_feeds = 0

                    for feed_id, feed in self.feeds.items():
                        if not feed.enabled:
                            continue

                        # Perform health check
                        health_status = await self._comprehensive_health_check(
                            feed_id, feed
                        )
                        self.feed_health[feed_id] = health_status

                        if health_status["status"] == "healthy":
                            healthy_feeds += 1

                    self.stats["feeds_healthy"] = healthy_feeds

                    await asyncio.sleep(self.health_check_interval)

                except Exception as e:
                    logger.error("Error in health check loop", error=str(e))
                    await asyncio.sleep(60)  # Wait 1 minute on error

        except asyncio.CancelledError:
            logger.info("Health check loop cancelled")
        except Exception as e:
            logger.error("Fatal error in health check loop", error=str(e))

    async def _discovery_refresh_loop(self):
        """Background discovery refresh loop"""
        logger.info("Discovery refresh loop started")

        try:
            while self.running:
                try:
                    # Refresh server discovery every 6 hours
                    await self._discover_taxii_servers()

                    # Refresh collection discovery every 2 hours
                    await self._discover_collections()

                    await asyncio.sleep(7200)  # 2 hours

                except Exception as e:
                    logger.error("Error in discovery refresh loop", error=str(e))
                    await asyncio.sleep(1800)  # Wait 30 minutes on error

        except asyncio.CancelledError:
            logger.info("Discovery refresh loop cancelled")
        except Exception as e:
            logger.error("Fatal error in discovery refresh loop", error=str(e))

    async def _calculate_adaptive_sleep_time(
        self, feed_id: str, update_duration: float
    ) -> int:
        """Calculate adaptive sleep time based on feed performance"""
        feed = self.feeds[feed_id]
        base_interval = feed.update_frequency

        # Adjust based on update duration
        if update_duration < 5:  # Fast updates
            multiplier = 0.8
        elif update_duration > 30:  # Slow updates
            multiplier = 1.2
        else:
            multiplier = 1.0

        # Adjust based on feed health
        health_status = self.feed_health.get(feed_id, {}).get("status", "unknown")
        if health_status == "healthy":
            multiplier *= 0.9
        elif health_status == "degraded":
            multiplier *= 1.1
        elif health_status == "unhealthy":
            multiplier *= 2.0

        return max(int(base_interval * multiplier), 60)  # Minimum 1 minute

    async def _resilient_feed_update(self, feed_id: str) -> bool:
        """Perform resilient feed update with retries and fallback"""
        feed = self.feeds.get(feed_id)
        if not feed:
            return False

        enhanced_config = getattr(feed, "_enhanced_config", {})
        retry_policy = enhanced_config.get(
            "retry_policy",
            {
                "max_retries": 3,
                "backoff_factor": 2.0,
                "retry_statuses": [429, 500, 502, 503, 504],
            },
        )

        last_error = None

        for attempt in range(retry_policy["max_retries"] + 1):
            try:
                if attempt > 0:
                    # Wait with exponential backoff
                    backoff_time = retry_policy["backoff_factor"] ** (attempt - 1)
                    await asyncio.sleep(min(backoff_time, 60))

                    logger.info(
                        "Retrying feed update",
                        feed_name=feed.name,
                        attempt=attempt + 1,
                        max_attempts=retry_policy["max_retries"] + 1,
                    )

                success = await self.update_feed(feed_id)
                if success:
                    return True

            except Exception as e:
                last_error = e
                logger.warning(
                    "Feed update attempt failed",
                    feed_name=feed.name,
                    attempt=attempt + 1,
                    error=str(e),
                )

                # Check if this is a retryable error
                if (
                    hasattr(e, "status")
                    and e.status not in retry_policy["retry_statuses"]
                ):
                    logger.info(
                        "Non-retryable error, stopping attempts",
                        feed_name=feed.name,
                        status=e.status,
                    )
                    break

        # All attempts failed
        logger.error(
            "All feed update attempts failed",
            feed_name=feed.name,
            final_error=str(last_error) if last_error else "Unknown",
        )

        return False

    async def _should_update_feed(self, feed: ThreatFeed) -> bool:
        """Check if feed should be updated"""
        try:
            last_update = self.last_updates.get(feed.id)

            if not last_update:
                return True  # Never updated

            next_update = last_update + timedelta(seconds=feed.update_frequency)
            return datetime.utcnow() >= next_update

        except Exception as e:
            logger.error("Error checking feed update status", error=str(e))
            return False

    async def update_feed(self, feed_id: str) -> bool:
        """Enhanced feed update with comprehensive error handling and statistics

        Args:
            feed_id: ID of feed to update

        Returns:
            True if update was successful
        """
        feed = self.feeds.get(feed_id)
        if not feed:
            logger.error("Feed not found", feed_id=feed_id)
            return False

        if not feed.enabled:
            logger.debug("Feed disabled, skipping update", feed_name=feed.name)
            return False

        async with self.update_locks[feed_id]:
            try:
                logger.info("Starting enhanced threat feed update", feed_name=feed.name)

                start_time = datetime.utcnow()
                update_metrics = {
                    "indicators_received": 0,
                    "indicators_processed": 0,
                    "indicators_stored": 0,
                    "api_requests_made": 0,
                    "bytes_transferred": 0,
                    "collections_updated": 0,
                    "pagination_requests": 0,
                }

                # Perform feed-type specific update
                if feed.feed_type == "taxii":
                    success, metrics = await self._update_taxii_feed_enhanced(
                        feed_id, feed
                    )
                elif feed.feed_type in ["json", "xml", "csv"]:
                    success, metrics = await self._update_http_feed_enhanced(
                        feed_id, feed
                    )
                else:
                    logger.error(
                        "Unsupported feed type",
                        feed_name=feed.name,
                        feed_type=feed.feed_type,
                    )
                    return False

                if not success:
                    return False

                update_metrics.update(metrics)

                # Update comprehensive statistics
                self.last_updates[feed_id] = start_time
                self.stats["indicators_by_feed"][feed_id] += update_metrics[
                    "indicators_stored"
                ]
                self.stats["total_indicators_received"] += update_metrics[
                    "indicators_received"
                ]
                self.stats["api_requests_made"] += update_metrics["api_requests_made"]
                self.stats["bytes_transferred"] += update_metrics["bytes_transferred"]
                self.stats["pagination_requests"] += update_metrics[
                    "pagination_requests"
                ]
                self.stats["last_successful_update"] = start_time.isoformat()

                # Update feed health to healthy
                if feed_id in self.feed_health:
                    self.feed_health[feed_id]["status"] = "healthy"
                    self.feed_health[feed_id][
                        "last_successful_request"
                    ] = start_time.isoformat()

                # Clear any previous errors
                self.stats["update_errors"].pop(feed_id, None)
                if feed_id in self.update_states:
                    self.update_states[feed_id]["error_count"] = 0

                # Save update timestamp and state
                await self.threat_database.set_feed_last_update(feed_id, start_time)
                await self._save_pagination_state(feed_id)

                update_time = (datetime.utcnow() - start_time).total_seconds()

                logger.info(
                    "Enhanced feed update completed successfully",
                    feed_name=feed.name,
                    **update_metrics,
                    update_time=update_time,
                )

                return True

            except Exception as e:
                logger.error(
                    "Error in enhanced feed update", feed_name=feed.name, error=str(e)
                )

                # Enhanced error recording
                error_info = {
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "timestamp": datetime.utcnow().isoformat(),
                    "feed_type": feed.feed_type,
                    "feed_url": feed.url,
                }

                self.stats["update_errors"][feed_id] = error_info
                self.stats["api_requests_failed"] += 1

                # Update error count in state
                if feed_id in self.update_states:
                    self.update_states[feed_id]["error_count"] += 1

                # Update feed health to unhealthy
                if feed_id in self.feed_health:
                    self.feed_health[feed_id]["status"] = "unhealthy"
                    self.feed_health[feed_id]["last_error"] = error_info

                return False

    async def _save_pagination_state(self, feed_id: str):
        """Save pagination cursors to database"""
        try:
            # This would save to database in a real implementation
            # For now, just log the action
            cursors = self.pagination_cursors.get(feed_id, {})
            if cursors:
                logger.debug(
                    "Saving pagination state",
                    feed_id=feed_id,
                    cursor_count=len(cursors),
                )
        except Exception as e:
            logger.error("Error saving pagination state", feed_id=feed_id, error=str(e))

    async def _update_taxii_feed_enhanced(
        self, feed_id: str, feed: ThreatFeed
    ) -> Tuple[bool, Dict[str, int]]:
        """Enhanced TAXII feed update with TAXII 2.x support, pagination, and incremental updates"""
        try:
            metrics = {
                "indicators_received": 0,
                "indicators_processed": 0,
                "indicators_stored": 0,
                "api_requests_made": 0,
                "bytes_transferred": 0,
                "collections_updated": 0,
                "pagination_requests": 0,
            }

            enhanced_config = getattr(feed, "_enhanced_config", {})
            taxii_version = enhanced_config.get("taxii_version", "2.1")

            if taxii_version.startswith("2."):
                # Use TAXII 2.x API
                success, taxii_metrics = await self._update_taxii_2x_feed(feed_id, feed)
                metrics.update(taxii_metrics)
            else:
                # Fallback to TAXII 1.x (legacy)
                success, taxii_metrics = await self._update_taxii_1x_feed(feed_id, feed)
                metrics.update(taxii_metrics)

            return success, metrics

        except Exception as e:
            logger.error("Error in enhanced TAXII feed update", error=str(e))
            return False, {}

    async def _update_taxii_2x_feed(
        self, feed_id: str, feed: ThreatFeed
    ) -> Tuple[bool, Dict[str, int]]:
        """Update TAXII 2.x feed with modern API support"""
        metrics = {
            "indicators_received": 0,
            "indicators_processed": 0,
            "indicators_stored": 0,
            "api_requests_made": 0,
            "bytes_transferred": 0,
            "collections_updated": 0,
            "pagination_requests": 0,
        }

        try:
            server_url = self._extract_server_url(feed.url)
            session = self.connection_pools.get(server_url)
            headers = self._build_headers(feed_id)

            if not session:
                logger.error(
                    "No session available for TAXII 2.x update", feed_name=feed.name
                )
                return False, metrics

            # Get collections for this feed
            collections = self.collections.get(feed_id, [])
            if not collections:
                logger.warning("No collections found for feed", feed_name=feed.name)
                return True, metrics  # Not an error, just no collections

            enhanced_config = getattr(feed, "_enhanced_config", {})
            api_root_url = self._extract_api_root_from_url(feed.url)

            # Process each collection
            for collection in collections:
                collection_id = collection.get("id")
                if not collection_id:
                    continue

                try:
                    collection_metrics = await self._update_taxii_collection(
                        session, api_root_url, collection_id, feed_id, headers
                    )

                    # Aggregate metrics
                    for key in metrics:
                        metrics[key] += collection_metrics.get(key, 0)

                    metrics["collections_updated"] += 1

                except Exception as e:
                    logger.error(
                        "Error updating TAXII collection",
                        collection_id=collection_id,
                        feed_name=feed.name,
                        error=str(e),
                    )
                    continue

            return True, metrics

        except Exception as e:
            logger.error("Error in TAXII 2.x feed update", error=str(e))
            return False, metrics

    async def _update_taxii_collection(
        self,
        session: aiohttp.ClientSession,
        api_root_url: str,
        collection_id: str,
        feed_id: str,
        headers: Dict[str, str],
    ) -> Dict[str, int]:
        """Update a specific TAXII collection with pagination support"""
        metrics = {
            "indicators_received": 0,
            "indicators_processed": 0,
            "indicators_stored": 0,
            "api_requests_made": 0,
            "bytes_transferred": 0,
            "pagination_requests": 0,
        }

        try:
            feed = self.feeds[feed_id]
            enhanced_config = getattr(feed, "_enhanced_config", {})

            # Build objects URL
            objects_url = urljoin(api_root_url, f"collections/{collection_id}/objects/")

            # Prepare query parameters
            params = {}

            # Add incremental update parameter
            if enhanced_config.get("added_after_mode", True):
                last_update = self.last_updates.get(feed_id)
                if last_update:
                    params["added_after"] = last_update.strftime(
                        "%Y-%m-%dT%H:%M:%S.%fZ"
                    )

            # Add content type filters
            content_types = enhanced_config.get(
                "content_types", ["application/stix+json"]
            )
            if content_types:
                params["match[type]"] = ",".join(
                    [
                        "indicator",
                        "malware",
                        "attack-pattern",
                        "threat-actor",
                        "intrusion-set",
                        "campaign",
                        "course-of-action",
                        "vulnerability",
                    ]
                )

            # Pagination support
            pagination_enabled = enhanced_config.get("pagination_enabled", True)
            max_page_size = enhanced_config.get("max_page_size", 1000)

            if pagination_enabled:
                params["limit"] = min(max_page_size, self.pagination_limit)

            # Get pagination cursor if available
            collection_cursors = self.pagination_cursors.get(feed_id, {})
            cursor = collection_cursors.get(collection_id)
            if cursor:
                params["next"] = cursor

            # Fetch objects with pagination
            has_more_pages = True
            page_count = 0

            while has_more_pages and page_count < 100:  # Safety limit
                try:
                    metrics["api_requests_made"] += 1

                    async with session.get(
                        objects_url, headers=headers, params=params
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            content_length = response.headers.get("Content-Length", "0")
                            metrics["bytes_transferred"] += int(content_length)

                            # Process objects
                            objects = data.get("objects", [])

                            for obj in objects:
                                try:
                                    # Parse STIX object
                                    stix_indicators = (
                                        await self.stix_parser._parse_stix_object(obj)
                                    )
                                    metrics["indicators_processed"] += 1

                                    if stix_indicators:
                                        # Store in database
                                        success = (
                                            await self.threat_database.store_indicator(
                                                stix_indicators
                                            )
                                        )
                                        if success:
                                            metrics["indicators_stored"] += 1

                                            # Update type statistics
                                            indicator_type = stix_indicators.type
                                            self.stats["indicators_by_type"][
                                                indicator_type
                                            ] = (
                                                self.stats["indicators_by_type"].get(
                                                    indicator_type, 0
                                                )
                                                + 1
                                            )

                                except Exception as e:
                                    logger.error(
                                        "Error processing STIX object",
                                        collection_id=collection_id,
                                        error=str(e),
                                    )
                                    continue

                            metrics["indicators_received"] += len(objects)

                            # Check for more pages
                            if pagination_enabled:
                                more = data.get("more", False)
                                next_cursor = data.get("next")

                                if more and next_cursor:
                                    # Save cursor and continue
                                    collection_cursors[collection_id] = next_cursor
                                    params["next"] = next_cursor
                                    params.pop(
                                        "added_after", None
                                    )  # Remove for subsequent pages
                                    page_count += 1
                                    metrics["pagination_requests"] += 1

                                    # Small delay between paginated requests
                                    await asyncio.sleep(0.1)
                                else:
                                    has_more_pages = False
                                    # Clear cursor when done
                                    collection_cursors.pop(collection_id, None)
                            else:
                                has_more_pages = False

                        elif response.status == 401:
                            logger.error(
                                "Authentication failed for collection",
                                collection_id=collection_id,
                            )
                            self.stats["authentication_failures"] += 1
                            has_more_pages = False
                        elif response.status == 429:
                            logger.warning(
                                "Rate limited for collection",
                                collection_id=collection_id,
                            )
                            self.stats["rate_limit_hits"] += 1
                            # Wait and retry
                            await asyncio.sleep(60)
                            continue
                        else:
                            logger.error(
                                "HTTP error for collection",
                                collection_id=collection_id,
                                status=response.status,
                            )
                            has_more_pages = False

                except asyncio.TimeoutError:
                    logger.error(
                        "Timeout updating collection", collection_id=collection_id
                    )
                    has_more_pages = False
                except Exception as e:
                    logger.error(
                        "Error in pagination request",
                        collection_id=collection_id,
                        error=str(e),
                    )
                    has_more_pages = False

            # Update pagination cursors
            self.pagination_cursors[feed_id] = collection_cursors

            logger.debug(
                "Collection update completed",
                collection_id=collection_id,
                pages_processed=page_count,
                indicators_received=metrics["indicators_received"],
                indicators_stored=metrics["indicators_stored"],
            )

            return metrics

        except Exception as e:
            logger.error(
                "Error updating TAXII collection",
                collection_id=collection_id,
                error=str(e),
            )
            return metrics

    async def _update_taxii_1x_feed(
        self, feed_id: str, feed: ThreatFeed
    ) -> Tuple[bool, Dict[str, int]]:
        """Legacy TAXII 1.x feed update using cabby client"""
        metrics = {
            "indicators_received": 0,
            "indicators_processed": 0,
            "indicators_stored": 0,
            "api_requests_made": 1,
            "bytes_transferred": 0,
            "collections_updated": 0,
            "pagination_requests": 0,
        }

        try:
            # Create legacy TAXII 1.x client
            client = create_client(
                feed.url,
                username=feed.credentials.get("username") if feed.credentials else None,
                password=feed.credentials.get("password") if feed.credentials else None,
                verify_ssl=feed.certificate_verification,
                proxy=feed.proxy_url,
            )

            # Discover services
            services = client.discover_services()
            collection_service = None

            for service in services:
                if service.type == "COLLECTION_MANAGEMENT":
                    collection_service = service
                    break

            if not collection_service:
                logger.error(
                    "No collection management service found", feed_name=feed.name
                )
                return False, metrics

            # Get collections
            collections = client.get_collections(service_id=collection_service.id)

            for collection in collections:
                try:
                    # Determine time range for incremental updates
                    begin_time = self.last_updates.get(feed_id)
                    if begin_time:
                        begin_time = begin_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

                    # Poll collection for new content
                    content_blocks = client.poll(
                        collection_name=collection.name,
                        begin_date=begin_time,
                        content_binding=["application/xml"],
                    )

                    metrics["api_requests_made"] += 1
                    metrics["collections_updated"] += 1

                    # Process content blocks
                    for content_block in content_blocks:
                        try:
                            # Parse STIX content
                            stix_indicators = await self.stix_parser.parse_content(
                                content_block.content
                            )

                            metrics["bytes_transferred"] += len(content_block.content)
                            metrics["indicators_processed"] += len(stix_indicators)

                            # Store indicators in threat database
                            for indicator in stix_indicators:
                                success = await self.threat_database.store_indicator(
                                    indicator
                                )
                                if success:
                                    metrics["indicators_stored"] += 1

                            metrics["indicators_received"] += len(stix_indicators)

                        except Exception as e:
                            logger.error(
                                "Error processing content block",
                                collection=collection.name,
                                error=str(e),
                            )
                            continue

                except Exception as e:
                    logger.error(
                        "Error polling collection",
                        collection=collection.name,
                        error=str(e),
                    )
                    continue

            return True, metrics

        except Exception as e:
            logger.error("Error in TAXII 1.x feed update", error=str(e))
            return False, metrics

    async def _update_http_feed_enhanced(
        self, feed_id: str, feed: ThreatFeed
    ) -> Tuple[bool, Dict[str, int]]:
        """Enhanced HTTP-based threat feed update with better error handling"""
        metrics = {
            "indicators_received": 0,
            "indicators_processed": 0,
            "indicators_stored": 0,
            "api_requests_made": 1,
            "bytes_transferred": 0,
            "collections_updated": 1,
            "pagination_requests": 0,
        }

        try:
            server_url = self._extract_server_url(feed.url)
            session = self.connection_pools.get(server_url)

            # Use connection pool if available, otherwise create temporary session
            if not session:
                timeout = aiohttp.ClientTimeout(total=300)  # 5 minutes
                ssl_context = (
                    ssl.create_default_context()
                    if feed.certificate_verification
                    else False
                )
                connector = aiohttp.TCPConnector(ssl=ssl_context)
                session = aiohttp.ClientSession(
                    connector=connector, timeout=timeout, headers=feed.headers or {}
                )
                temporary_session = True
            else:
                temporary_session = False

            try:
                # Add authentication if configured
                auth = None
                headers = feed.headers or {}

                # Enhanced authentication support
                if feed.credentials:
                    auth_type = getattr(feed, "_enhanced_config", {}).get(
                        "auth_type", "basic"
                    )

                    if auth_type == "basic":
                        auth = aiohttp.BasicAuth(
                            feed.credentials.get("username", ""),
                            feed.credentials.get("password", ""),
                        )
                    elif auth_type == "token":
                        token = feed.credentials.get("token")
                        if token:
                            headers["Authorization"] = f"Bearer {token}"

                # Check rate limits
                if not await self._check_rate_limit(feed_id):
                    logger.warning(
                        "Rate limit exceeded for HTTP feed", feed_name=feed.name
                    )
                    return False, metrics

                async with session.get(
                    feed.url, headers=headers, auth=auth
                ) as response:
                    if response.status >= 400:
                        if response.status == 401:
                            self.stats["authentication_failures"] += 1
                        elif response.status == 429:
                            self.stats["rate_limit_hits"] += 1

                        raise Exception(f"HTTP {response.status}: {response.reason}")

                    content = await response.text()
                    content_length = response.headers.get(
                        "Content-Length", str(len(content))
                    )
                    metrics["bytes_transferred"] = int(content_length)

                    # Enhanced content parsing with metrics
                    processing_metrics = await self._process_http_content_enhanced(
                        content, feed_id, feed
                    )

                    # Update metrics
                    metrics["indicators_received"] = processing_metrics[
                        "indicators_received"
                    ]
                    metrics["indicators_processed"] = processing_metrics[
                        "indicators_processed"
                    ]
                    metrics["indicators_stored"] = processing_metrics[
                        "indicators_stored"
                    ]

                    return True, metrics

            finally:
                if temporary_session and session:
                    await session.close()

        except Exception as e:
            logger.error("Error in enhanced HTTP feed update", error=str(e))
            return False, metrics

    async def _process_http_content_enhanced(
        self, content: str, feed_id: str, feed: ThreatFeed
    ) -> Dict[str, int]:
        """Enhanced HTTP content processing with detailed metrics"""
        metrics = {
            "indicators_received": 0,
            "indicators_processed": 0,
            "indicators_stored": 0,
        }

        try:
            if feed.feed_type == "json":
                json_metrics = await self._process_json_feed_enhanced(
                    content, feed_id, feed
                )
                metrics.update(json_metrics)
            elif feed.feed_type == "xml":
                xml_metrics = await self._process_xml_feed_enhanced(
                    content, feed_id, feed
                )
                metrics.update(xml_metrics)
            elif feed.feed_type == "csv":
                csv_metrics = await self._process_csv_feed_enhanced(
                    content, feed_id, feed
                )
                metrics.update(csv_metrics)

            return metrics

        except Exception as e:
            logger.error("Error processing HTTP content", error=str(e))
            return metrics

    async def _process_json_feed_enhanced(
        self, content: str, feed_id: str, feed: ThreatFeed
    ) -> Dict[str, int]:
        """Enhanced JSON threat feed content processing"""
        metrics = {
            "indicators_received": 0,
            "indicators_processed": 0,
            "indicators_stored": 0,
        }

        try:
            data = json.loads(content)

            # Handle different JSON formats
            if isinstance(data, dict):
                # Check for STIX bundle
                if data.get("type") == "bundle":
                    stix_indicators = await self.stix_parser.parse_stix_bundle(data)
                    metrics["indicators_received"] = len(stix_indicators)

                    for indicator in stix_indicators:
                        try:
                            metrics["indicators_processed"] += 1
                            success = await self.threat_database.store_indicator(
                                indicator
                            )
                            if success:
                                metrics["indicators_stored"] += 1
                                # Update type statistics
                                self.stats["indicators_by_type"][indicator.type] = (
                                    self.stats["indicators_by_type"].get(
                                        indicator.type, 0
                                    )
                                    + 1
                                )
                        except Exception as e:
                            logger.error("Error storing STIX indicator", error=str(e))

                # Check for indicators array
                elif "indicators" in data:
                    indicators_data = data["indicators"]
                    metrics["indicators_received"] = len(indicators_data)

                    for item in indicators_data:
                        try:
                            metrics["indicators_processed"] += 1
                            indicator = await self._convert_to_ioc(item, feed)
                            if indicator:
                                success = await self.threat_database.store_indicator(
                                    indicator
                                )
                                if success:
                                    metrics["indicators_stored"] += 1
                        except Exception as e:
                            logger.error(
                                "Error processing indicator item", error=str(e)
                            )

            elif isinstance(data, list):
                # Array of indicators
                metrics["indicators_received"] = len(data)

                for item in data:
                    try:
                        metrics["indicators_processed"] += 1
                        indicator = await self._convert_to_ioc(item, feed)
                        if indicator:
                            success = await self.threat_database.store_indicator(
                                indicator
                            )
                            if success:
                                metrics["indicators_stored"] += 1
                    except Exception as e:
                        logger.error("Error processing list indicator", error=str(e))

            return metrics

        except json.JSONDecodeError as e:
            logger.error(
                "Invalid JSON in feed content", feed_name=feed.name, error=str(e)
            )
            return metrics
        except Exception as e:
            logger.error("Error processing enhanced JSON feed", error=str(e))
            return metrics

    async def _process_xml_feed_enhanced(
        self, content: str, feed_id: str, feed: ThreatFeed
    ) -> Dict[str, int]:
        """Enhanced XML threat feed content processing"""
        metrics = {
            "indicators_received": 0,
            "indicators_processed": 0,
            "indicators_stored": 0,
        }

        try:
            # Parse as STIX XML
            stix_indicators = await self.stix_parser.parse_content(content)
            metrics["indicators_received"] = len(stix_indicators)

            for indicator in stix_indicators:
                try:
                    metrics["indicators_processed"] += 1
                    success = await self.threat_database.store_indicator(indicator)
                    if success:
                        metrics["indicators_stored"] += 1
                        # Update type statistics
                        self.stats["indicators_by_type"][indicator.type] = (
                            self.stats["indicators_by_type"].get(indicator.type, 0) + 1
                        )
                except Exception as e:
                    logger.error("Error storing XML indicator", error=str(e))

            return metrics

        except Exception as e:
            logger.error("Error processing enhanced XML feed", error=str(e))
            return metrics

    async def _process_csv_feed_enhanced(
        self, content: str, feed_id: str, feed: ThreatFeed
    ) -> Dict[str, int]:
        """Enhanced CSV threat feed content processing"""
        metrics = {
            "indicators_received": 0,
            "indicators_processed": 0,
            "indicators_stored": 0,
        }

        try:
            import csv
            from io import StringIO

            reader = csv.DictReader(StringIO(content))
            rows = list(reader)
            metrics["indicators_received"] = len(rows)

            for row in rows:
                try:
                    metrics["indicators_processed"] += 1
                    indicator = await self._convert_csv_to_ioc(row, feed)
                    if indicator:
                        success = await self.threat_database.store_indicator(indicator)
                        if success:
                            metrics["indicators_stored"] += 1
                except Exception as e:
                    logger.error("Error processing CSV row", error=str(e))

            return metrics

        except Exception as e:
            logger.error("Error processing enhanced CSV feed", error=str(e))
            return metrics

    async def _convert_to_ioc(
        self, data: Dict[str, Any], feed: ThreatFeed
    ) -> Optional[IOC]:
        """Convert generic data to IOC format"""
        try:
            # Extract common fields
            indicator_type = data.get("type", "unknown")
            value = data.get("value") or data.get("indicator")
            description = data.get("description", "")

            # Map threat level
            threat_level = ThreatLevel.UNKNOWN
            threat_level_str = str(data.get("threat_level", "")).lower()
            if threat_level_str in ["critical", "high"]:
                threat_level = ThreatLevel.HIGH
            elif threat_level_str in ["medium", "moderate"]:
                threat_level = ThreatLevel.MEDIUM
            elif threat_level_str in ["low"]:
                threat_level = ThreatLevel.LOW

            if not value:
                return None

            return IOC(
                type=indicator_type,
                value=value,
                description=description,
                threat_level=threat_level,
                confidence=float(data.get("confidence", 0.5)),
                source=feed.name,
                tags=data.get("tags", []),
                malware_families=data.get("malware_families", []),
                kill_chain_phases=data.get("kill_chain_phases", []),
            )

        except Exception as e:
            logger.error("Error converting to IOC", error=str(e))
            return None

    async def _convert_csv_to_ioc(
        self, row: Dict[str, str], feed: ThreatFeed
    ) -> Optional[IOC]:
        """Convert CSV row to IOC format"""
        try:
            # Common CSV field mappings
            field_mappings = {
                "type": ["type", "indicator_type", "ioc_type"],
                "value": ["value", "indicator", "ioc", "observable"],
                "description": ["description", "desc", "comment"],
                "threat_level": ["threat_level", "severity", "criticality"],
                "confidence": ["confidence", "score", "rating"],
            }

            ioc_data = {}

            # Map CSV fields to IOC fields
            for ioc_field, csv_fields in field_mappings.items():
                for csv_field in csv_fields:
                    if csv_field in row and row[csv_field]:
                        ioc_data[ioc_field] = row[csv_field]
                        break

            return await self._convert_to_ioc(ioc_data, feed)

        except Exception as e:
            logger.error("Error converting CSV to IOC", error=str(e))
            return None

    def get_feed_status(self) -> Dict[str, Any]:
        """Get comprehensive status of all configured feeds"""
        feed_statuses = {}

        for feed_id, feed in self.feeds.items():
            enhanced_config = getattr(feed, "_enhanced_config", {})
            health_info = self.feed_health.get(feed_id, {})
            update_state = self.update_states.get(feed_id, {})
            collections = self.collections.get(feed_id, [])
            cursors = self.pagination_cursors.get(feed_id, {})

            feed_statuses[feed_id] = {
                "name": feed.name,
                "url": feed.url,
                "enabled": feed.enabled,
                "feed_type": feed.feed_type,
                "taxii_version": enhanced_config.get("taxii_version", "unknown"),
                "auth_type": enhanced_config.get("auth_type", "none"),
                "collections_count": len(collections),
                "collections": [
                    {
                        "id": col.get("id"),
                        "title": col.get("title", ""),
                        "description": col.get("description", ""),
                        "can_read": col.get("can_read", True),
                        "has_cursor": col.get("id") in cursors,
                    }
                    for col in collections
                ],
                "health": {
                    "status": health_info.get("status", "unknown"),
                    "last_check": health_info.get("last_check"),
                    "response_time": health_info.get("response_time"),
                    "issues": health_info.get("issues", []),
                    "collections_accessible": health_info.get(
                        "collections_accessible", 0
                    ),
                    "last_successful_request": health_info.get(
                        "last_successful_request"
                    ),
                },
                "updates": {
                    "last_update": self.last_updates.get(feed_id),
                    "last_successful_update": feed.last_success,
                    "last_error": self.stats["update_errors"].get(feed_id),
                    "error_count": update_state.get("error_count", 0),
                    "update_frequency": feed.update_frequency,
                },
                "statistics": {
                    "indicators_received": self.stats["indicators_by_feed"].get(
                        feed_id, 0
                    ),
                    "pagination_cursors": len(cursors),
                },
                "configuration": {
                    "pagination_enabled": enhanced_config.get(
                        "pagination_enabled", True
                    ),
                    "max_page_size": enhanced_config.get("max_page_size", 1000),
                    "added_after_mode": enhanced_config.get("added_after_mode", True),
                    "collections_filter": enhanced_config.get("collections_filter", []),
                    "content_types": enhanced_config.get("content_types", []),
                    "rate_limit": enhanced_config.get("rate_limit", {}),
                },
            }

        return {
            "feeds": feed_statuses,
            "statistics": {
                **self.stats,
                "connection_pools": len(self.connection_pools),
                "taxii_servers_discovered": len(self.taxii_servers),
                "cache_hit_ratio": (
                    self.stats.get("cache_hits", 0)
                    / max(
                        self.stats.get("cache_hits", 0)
                        + self.stats.get("cache_misses", 0),
                        1,
                    )
                ),
            },
            "system": {
                "running": self.running,
                "update_tasks": len(self.update_tasks),
                "health_check_tasks": len(self.health_check_tasks),
                "discovery_tasks": len(self.discovery_tasks),
                "discovery_enabled": self.enable_discovery,
                "health_check_interval": self.health_check_interval,
            },
            "servers": self.taxii_servers,
        }

    async def add_feed(self, feed_config: Dict[str, Any]) -> str:
        """Add new threat intelligence feed with enhanced configuration

        Args:
            feed_config: Enhanced feed configuration

        Returns:
            Feed ID
        """
        try:
            # Validate required fields
            if not feed_config.get("name") or not feed_config.get("url"):
                raise ValueError("Feed name and URL are required")

            feed = ThreatFeed(
                name=feed_config["name"],
                url=feed_config["url"],
                feed_type=feed_config.get("feed_type", "taxii"),
                enabled=feed_config.get("enabled", True),
                update_frequency=feed_config.get("update_frequency", 3600),
                credentials=feed_config.get("credentials"),
                headers=feed_config.get("headers"),
                certificate_verification=feed_config.get("verify_ssl", True),
                proxy_url=feed_config.get("proxy_url"),
            )

            # Enhanced configuration
            feed_extra = {
                "taxii_version": feed_config.get("taxii_version", "2.1"),
                "auth_type": feed_config.get("auth_type", "none"),
                "collections_filter": feed_config.get("collections_filter", []),
                "content_types": feed_config.get(
                    "content_types", ["application/stix+json"]
                ),
                "added_after_mode": feed_config.get("added_after_mode", True),
                "pagination_enabled": feed_config.get("pagination_enabled", True),
                "max_page_size": feed_config.get("max_page_size", 1000),
                "retry_policy": feed_config.get(
                    "retry_policy",
                    {
                        "max_retries": 3,
                        "backoff_factor": 2.0,
                        "retry_statuses": [429, 500, 502, 503, 504],
                    },
                ),
                "rate_limit": feed_config.get(
                    "rate_limit", {"requests_per_minute": 60, "burst_limit": 10}
                ),
            }
            setattr(feed, "_enhanced_config", feed_extra)

            # Initialize supporting structures
            self.feeds[feed.id] = feed
            self.update_locks[feed.id] = asyncio.Lock()
            self.collections[feed.id] = []
            self.feed_health[feed.id] = {"status": "unknown", "last_check": None}
            self.update_states[feed.id] = {"last_manifest": None, "error_count": 0}
            self.pagination_cursors[feed.id] = {}
            self.stats["indicators_by_feed"][feed.id] = 0
            self.stats["feeds_configured"] = len(self.feeds)

            # Setup authentication for new feed
            await self._setup_feed_authentication(feed.id)

            # Setup rate limiter
            rate_limit_config = feed_extra["rate_limit"]
            self.rate_limiters[feed.id] = {
                "requests_per_minute": rate_limit_config["requests_per_minute"],
                "burst_limit": rate_limit_config["burst_limit"],
                "requests_made": [],
                "lock": asyncio.Lock(),
            }

            # Discover collections if TAXII and discovery enabled
            if feed.feed_type == "taxii" and self.enable_discovery:
                try:
                    collections = await self._discover_feed_collections(feed.id, feed)
                    self.collections[feed.id] = collections
                    self.stats["collections_discovered"] += len(collections)
                except Exception as e:
                    logger.error(
                        "Error discovering collections for new feed",
                        feed_name=feed.name,
                        error=str(e),
                    )

            # Test connection and health
            if feed.enabled:
                try:
                    health_status = await self._comprehensive_health_check(
                        feed.id, feed
                    )
                    self.feed_health[feed.id] = health_status

                    if health_status["status"] not in ["healthy", "degraded"]:
                        logger.warning(
                            "New feed health check failed",
                            feed_name=feed.name,
                            status=health_status["status"],
                        )
                except Exception as e:
                    logger.error(
                        "Error testing new feed connection",
                        feed_name=feed.name,
                        error=str(e),
                    )

            # Start update task if system is running
            if self.running and feed.enabled:
                task = asyncio.create_task(
                    self._enhanced_feed_update_loop(feed.id),
                    name=f"feed_update_{feed.name}",
                )
                self.update_tasks.append(task)

            logger.info(
                "Enhanced threat feed added",
                feed_name=feed.name,
                feed_id=feed.id,
                collections_discovered=len(self.collections[feed.id]),
                health_status=self.feed_health[feed.id].get("status", "unknown"),
            )

            return feed.id

        except Exception as e:
            logger.error("Error adding enhanced threat feed", error=str(e))
            raise

    async def _setup_feed_authentication(self, feed_id: str):
        """Setup authentication for a specific feed"""
        try:
            feed = self.feeds[feed_id]
            enhanced_config = getattr(feed, "_enhanced_config", {})
            auth_type = enhanced_config.get("auth_type", "none")

            if auth_type == "basic" and feed.credentials:
                username = feed.credentials.get("username")
                password = feed.credentials.get("password")
                if username and password:
                    credentials = base64.b64encode(
                        f"{username}:{password}".encode()
                    ).decode()
                    self.auth_tokens[feed_id] = {
                        "type": "basic",
                        "value": f"Basic {credentials}",
                        "expires": None,
                    }
            elif auth_type == "token" and feed.credentials:
                token = feed.credentials.get("token")
                if token:
                    self.auth_tokens[feed_id] = {
                        "type": "token",
                        "value": f"Bearer {token}",
                        "expires": None,
                    }
            elif auth_type == "cert" and feed.credentials:
                cert_path = feed.credentials.get("cert_path")
                key_path = feed.credentials.get("key_path")
                if cert_path and key_path:
                    self.certificates[feed_id] = {
                        "cert_path": cert_path,
                        "key_path": key_path,
                        "ca_path": feed.credentials.get("ca_path"),
                    }
        except Exception as e:
            logger.error(
                "Error setting up feed authentication", feed_id=feed_id, error=str(e)
            )

    async def remove_feed(self, feed_id: str) -> bool:
        """Remove threat intelligence feed with comprehensive cleanup

        Args:
            feed_id: ID of feed to remove

        Returns:
            True if feed was removed successfully
        """
        try:
            if feed_id not in self.feeds:
                logger.warning("Feed not found for removal", feed_id=feed_id)
                return False

            feed = self.feeds[feed_id]
            logger.info("Removing threat feed", feed_name=feed.name, feed_id=feed_id)

            # Cancel update task
            for task in self.update_tasks:
                if task.get_name() == f"feed_update_{feed.name}":
                    task.cancel()
                    self.update_tasks.remove(task)
                    break

            # Remove from all collections
            del self.feeds[feed_id]
            del self.update_locks[feed_id]
            self.collections.pop(feed_id, None)
            self.feed_health.pop(feed_id, None)
            self.update_states.pop(feed_id, None)
            self.pagination_cursors.pop(feed_id, None)
            self.auth_tokens.pop(feed_id, None)
            self.certificates.pop(feed_id, None)
            self.oauth_clients.pop(feed_id, None)
            self.rate_limiters.pop(feed_id, None)

            # Remove from statistics
            self.last_updates.pop(feed_id, None)
            self.stats["indicators_by_feed"].pop(feed_id, None)
            self.stats["update_errors"].pop(feed_id, None)

            self.stats["feeds_configured"] = len(self.feeds)

            # Update health statistics
            healthy_feeds = sum(
                1
                for health in self.feed_health.values()
                if health.get("status") == "healthy"
            )
            self.stats["feeds_healthy"] = healthy_feeds

            logger.info(
                "Threat feed removed successfully", feed_name=feed.name, feed_id=feed_id
            )
            return True

        except Exception as e:
            logger.error("Error removing threat feed", feed_id=feed_id, error=str(e))
            return False

    async def stop(self):
        """Stop enhanced TAXII client and comprehensive cleanup"""
        logger.info("Stopping enhanced TAXII client")
        self.running = False

        # Cancel all task types
        all_tasks = self.update_tasks + self.health_check_tasks + self.discovery_tasks

        for task in all_tasks:
            if not task.done():
                task.cancel()

        # Wait for tasks to complete with timeout
        if all_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*all_tasks, return_exceptions=True), timeout=30.0
                )
            except asyncio.TimeoutError:
                logger.warning("Some tasks did not complete within timeout")

        # Clear task lists
        self.update_tasks.clear()
        self.health_check_tasks.clear()
        self.discovery_tasks.clear()

        # Close connection pools
        for session in self.connection_pools.values():
            if session and not session.closed:
                try:
                    await session.close()
                except Exception as e:
                    logger.error("Error closing session", error=str(e))

        self.connection_pools.clear()

        # Clear OAuth clients if any
        self.oauth_clients.clear()

        # Generate final statistics report
        final_stats = self._generate_final_stats_report()

        logger.info("Enhanced TAXII client stopped", **final_stats)

    def _generate_final_stats_report(self) -> Dict[str, Any]:
        """Generate comprehensive final statistics report"""
        performance_metrics = self.request_tracker.get_performance_metrics()

        return {
            "total_indicators_received": self.stats["total_indicators_received"],
            "total_api_requests": self.stats["api_requests_made"],
            "bytes_transferred": self.stats["bytes_transferred"],
            "feeds_configured": self.stats["feeds_configured"],
            "feeds_healthy": self.stats["feeds_healthy"],
            "collections_discovered": self.stats["collections_discovered"],
            "duplicate_indicators_filtered": self.stats["duplicate_indicators"],
            "expired_indicators_cleaned": self.stats["expired_indicators_removed"],
            "avg_response_time": performance_metrics.get("avg_response_time", 0.0),
            "success_rate": performance_metrics.get("success_rate", 0.0),
            "top_quality_feeds": self.feed_quality_manager.get_top_quality_feeds(5),
        }

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(
            (ClientError, ClientTimeout, asyncio.TimeoutError)
        ),
    )
    async def _resilient_http_request(
        self, session: aiohttp.ClientSession, method: str, url: str, **kwargs
    ) -> aiohttp.ClientResponse:
        """Make resilient HTTP request with retry logic"""
        request_id = str(uuid.uuid4())
        feed_id = kwargs.pop("_feed_id", "unknown")

        # Track request
        self.request_tracker.start_request(request_id, feed_id, url)

        try:
            # Add to active requests for graceful shutdown
            self._active_requests.add(request_id)

            async with session.request(method, url, **kwargs) as response:
                response_size = int(response.headers.get("Content-Length", 0))
                self.request_tracker.complete_request(
                    request_id,
                    success=response.status < 400,
                    response_size=response_size,
                )
                return response

        except Exception as e:
            self.request_tracker.complete_request(
                request_id, success=False, error=str(e)
            )
            raise
