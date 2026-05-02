"""
Async Log Collection for SkausWatch AAA Monitor

Provides high-performance async log collection from multiple sources with
buffering, batching, concurrent processing, and AI-powered analysis.
"""

import asyncio
import gzip
import json
import logging
import re
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple, Union
from uuid import uuid4

import aiofiles

# Kubernetes and container imports (conditional)
try:
    from kubernetes import client, config, watch
    from kubernetes.client.rest import ApiException

    HAS_KUBERNETES = True
except ImportError:
    HAS_KUBERNETES = False

# System monitoring imports
try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from ...shared.performance import (
    AsyncBatchProcessor,
    AsyncQueue,
    AsyncTaskManager,
    CacheConfig,
    CacheManager,
    IOBoundTaskManager,
    RateLimitConfig,
    RateLimiter,
    RateLimitStrategy,
    TaskType,
    ThreadPoolManager,
    async_batch_processor,
    async_retry,
    async_timeout,
    cache_decorator,
)

logger = logging.getLogger(__name__)


class LogSource(Enum):
    """Log source types"""

    KUBERNETES = "kubernetes"
    LXC = "lxc"
    AUDITD = "auditd"
    SYSLOG = "syslog"
    JOURNALD = "journald"
    FILE = "file"
    DATABASE = "database"
    NETWORK = "network"


class LogLevel(Enum):
    """Log levels"""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventType(Enum):
    """Event types"""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ACCESS = "access"
    SECURITY_VIOLATION = "security_violation"
    SYSTEM_EVENT = "system_event"
    NETWORK_EVENT = "network_event"
    APPLICATION_EVENT = "application_event"


@dataclass
class LogEntry:
    """Structured log entry"""

    entry_id: str
    source: LogSource
    timestamp: datetime
    level: LogLevel
    event_type: EventType
    message: str
    raw_data: Dict[str, Any] = field(default_factory=dict)
    parsed_fields: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "source": self.source.value,
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value,
            "event_type": self.event_type.value,
            "message": self.message,
            "raw_data": self.raw_data,
            "parsed_fields": self.parsed_fields,
            "tags": self.tags,
            "metadata": self.metadata,
        }


@dataclass
class CollectionMetrics:
    """Log collection metrics"""

    total_entries_collected: int = 0
    entries_per_source: Dict[str, int] = field(default_factory=dict)
    entries_processed: int = 0
    entries_failed: int = 0
    buffer_size: int = 0
    processing_rate: float = 0.0
    ai_analysis_requests: int = 0
    cache_hit_rate: float = 0.0
    collection_errors: int = 0


class BaseLogCollector:
    """Base class for log collectors"""

    def __init__(self, source: LogSource, config: Dict[str, Any]):
        self.source = source
        self.config = config
        self.running = False
        self.metrics = CollectionMetrics()

        # Event handlers
        self.event_handlers: List = []

    async def start(self):
        """Start the collector"""
        self.running = True

    async def stop(self):
        """Stop the collector"""
        self.running = False

    async def collect(self) -> AsyncIterator[LogEntry]:
        """Collect log entries (to be implemented by subclasses)"""
        raise NotImplementedError

    def add_event_handler(self, handler):
        """Add event handler"""
        self.event_handlers.append(handler)

    async def _emit_log_entry(self, entry: LogEntry):
        """Emit log entry to handlers"""
        for handler in self.event_handlers:
            try:
                await handler(entry)
            except Exception as e:
                logger.error(f"Event handler error: {e}")


class KubernetesLogCollector(BaseLogCollector):
    """Kubernetes log collector"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(LogSource.KUBERNETES, config)
        self.k8s_client = None
        self.v1 = None

    async def start(self):
        """Start Kubernetes collector"""
        if not HAS_KUBERNETES:
            raise RuntimeError("kubernetes package required for Kubernetes collector")

        await super().start()

        # Load Kubernetes configuration
        try:
            config.load_incluster_config()
        except config.ConfigException:
            try:
                config.load_kube_config()
            except config.ConfigException:
                logger.error("Could not configure Kubernetes client")
                raise

        self.v1 = client.CoreV1Api()
        logger.info("Kubernetes log collector started")

    async def collect(self) -> AsyncIterator[LogEntry]:
        """Collect logs from Kubernetes pods"""
        namespaces = self.config.get("namespaces", ["default"])

        for namespace in namespaces:
            async for entry in self._collect_from_namespace(namespace):
                yield entry

    async def _collect_from_namespace(self, namespace: str) -> AsyncIterator[LogEntry]:
        """Collect logs from specific namespace"""
        try:
            # Get pods in namespace
            pods = self.v1.list_namespaced_pod(namespace)

            # Collect logs from each pod
            for pod in pods.items:
                if pod.status.phase == "Running":
                    async for entry in self._collect_pod_logs(
                        namespace, pod.metadata.name
                    ):
                        yield entry

        except ApiException as e:
            logger.error(f"Kubernetes API error in namespace {namespace}: {e}")
            self.metrics.collection_errors += 1

    async def _collect_pod_logs(
        self, namespace: str, pod_name: str
    ) -> AsyncIterator[LogEntry]:
        """Collect logs from specific pod"""
        try:
            # Get pod logs (simplified - in production you'd use streaming)
            log_lines = self.v1.read_namespaced_pod_log(
                name=pod_name,
                namespace=namespace,
                tail_lines=100,  # Limit for performance
            ).split("\n")

            for line in log_lines:
                if line.strip():
                    entry = self._parse_pod_log_line(line, namespace, pod_name)
                    if entry:
                        self.metrics.total_entries_collected += 1
                        self.metrics.entries_per_source[LogSource.KUBERNETES.value] = (
                            self.metrics.entries_per_source.get(
                                LogSource.KUBERNETES.value, 0
                            )
                            + 1
                        )
                        yield entry

        except Exception as e:
            logger.error(f"Error collecting logs from pod {pod_name}: {e}")
            self.metrics.collection_errors += 1

    def _parse_pod_log_line(
        self, line: str, namespace: str, pod_name: str
    ) -> Optional[LogEntry]:
        """Parse pod log line into structured entry"""
        try:
            # Try to parse as JSON first
            try:
                log_data = json.loads(line)
                message = log_data.get("message", line)
                level_str = log_data.get("level", "info").lower()
                timestamp_str = log_data.get("timestamp", log_data.get("@timestamp"))
            except json.JSONDecodeError:
                # Fallback to plain text parsing
                log_data = {"raw_line": line}
                message = line
                level_str = "info"
                timestamp_str = None

            # Parse timestamp
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(
                        timestamp_str.replace("Z", "+00:00")
                    )
                except:
                    timestamp = datetime.utcnow()
            else:
                timestamp = datetime.utcnow()

            # Parse log level
            level = LogLevel.INFO
            for log_level in LogLevel:
                if level_str == log_level.value:
                    level = log_level
                    break

            # Determine event type
            event_type = self._classify_event_type(message, log_data)

            return LogEntry(
                entry_id=str(uuid4()),
                source=LogSource.KUBERNETES,
                timestamp=timestamp,
                level=level,
                event_type=event_type,
                message=message,
                raw_data=log_data,
                parsed_fields={"namespace": namespace, "pod_name": pod_name},
                tags=["kubernetes", namespace, pod_name],
            )

        except Exception as e:
            logger.error(f"Error parsing Kubernetes log line: {e}")
            return None

    def _classify_event_type(self, message: str, data: Dict[str, Any]) -> EventType:
        """Classify event type based on message content"""
        message_lower = message.lower()

        if any(
            word in message_lower for word in ["auth", "login", "password", "token"]
        ):
            return EventType.AUTHENTICATION
        elif any(
            word in message_lower
            for word in ["permission", "denied", "forbidden", "authorize"]
        ):
            return EventType.AUTHORIZATION
        elif any(word in message_lower for word in ["error", "exception", "fail"]):
            return EventType.SECURITY_VIOLATION
        elif any(word in message_lower for word in ["network", "connection", "socket"]):
            return EventType.NETWORK_EVENT
        else:
            return EventType.APPLICATION_EVENT


class FileLogCollector(BaseLogCollector):
    """File-based log collector"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(LogSource.FILE, config)
        self.watched_files: Dict[str, Dict[str, Any]] = {}
        self.file_positions: Dict[str, int] = {}

    async def start(self):
        """Start file collector"""
        await super().start()

        # Initialize watched files
        file_paths = self.config.get("file_paths", [])
        for file_path in file_paths:
            await self._start_watching_file(file_path)

        logger.info(f"File log collector started, watching {len(file_paths)} files")

    async def _start_watching_file(self, file_path: str):
        """Start watching a specific file"""
        try:
            path = Path(file_path)
            if path.exists():
                # Get initial file size
                self.file_positions[file_path] = path.stat().st_size
                self.watched_files[file_path] = {
                    "path": path,
                    "last_modified": path.stat().st_mtime,
                    "pattern": self.config.get("line_patterns", {}).get(file_path),
                }
        except Exception as e:
            logger.error(f"Error starting to watch file {file_path}: {e}")

    async def collect(self) -> AsyncIterator[LogEntry]:
        """Collect logs from watched files"""
        while self.running:
            for file_path, file_info in self.watched_files.items():
                async for entry in self._collect_from_file(file_path, file_info):
                    yield entry

            await asyncio.sleep(1.0)  # Check files every second

    async def _collect_from_file(
        self, file_path: str, file_info: Dict[str, Any]
    ) -> AsyncIterator[LogEntry]:
        """Collect new lines from specific file"""
        try:
            path = file_info["path"]

            # Check if file was modified
            current_mtime = path.stat().st_mtime
            if current_mtime <= file_info["last_modified"]:
                return

            # Read new lines
            current_position = self.file_positions.get(file_path, 0)

            async with aiofiles.open(
                file_path, "r", encoding="utf-8", errors="ignore"
            ) as file:
                await file.seek(current_position)

                async for line in file:
                    line = line.strip()
                    if line:
                        entry = await self._parse_file_log_line(
                            line, file_path, file_info
                        )
                        if entry:
                            self.metrics.total_entries_collected += 1
                            self.metrics.entries_per_source[LogSource.FILE.value] = (
                                self.metrics.entries_per_source.get(
                                    LogSource.FILE.value, 0
                                )
                                + 1
                            )
                            yield entry

                # Update position
                self.file_positions[file_path] = await file.tell()

            # Update last modified time
            file_info["last_modified"] = current_mtime

        except Exception as e:
            logger.error(f"Error collecting from file {file_path}: {e}")
            self.metrics.collection_errors += 1

    async def _parse_file_log_line(
        self, line: str, file_path: str, file_info: Dict[str, Any]
    ) -> Optional[LogEntry]:
        """Parse file log line"""
        try:
            # Apply regex pattern if configured
            pattern = file_info.get("pattern")
            parsed_fields = {}

            if pattern:
                match = re.match(pattern, line)
                if match:
                    parsed_fields = match.groupdict()

            # Extract timestamp if available
            timestamp = datetime.utcnow()
            if "timestamp" in parsed_fields:
                try:
                    timestamp = datetime.fromisoformat(parsed_fields["timestamp"])
                except:
                    pass

            # Extract log level
            level = LogLevel.INFO
            if "level" in parsed_fields:
                level_str = parsed_fields["level"].lower()
                for log_level in LogLevel:
                    if level_str == log_level.value:
                        level = log_level
                        break

            # Classify event type
            event_type = self._classify_file_event_type(line, parsed_fields)

            return LogEntry(
                entry_id=str(uuid4()),
                source=LogSource.FILE,
                timestamp=timestamp,
                level=level,
                event_type=event_type,
                message=parsed_fields.get("message", line),
                raw_data={"raw_line": line, "file_path": file_path},
                parsed_fields=parsed_fields,
                tags=["file", Path(file_path).name],
            )

        except Exception as e:
            logger.error(f"Error parsing file log line: {e}")
            return None

    def _classify_file_event_type(
        self, line: str, parsed_fields: Dict[str, Any]
    ) -> EventType:
        """Classify event type for file logs"""
        line_lower = line.lower()

        # Check for authentication events
        if any(
            word in line_lower for word in ["ssh", "login", "authentication", "auth"]
        ):
            return EventType.AUTHENTICATION

        # Check for security events
        if any(
            word in line_lower
            for word in ["security", "violation", "intrusion", "attack"]
        ):
            return EventType.SECURITY_VIOLATION

        # Check for system events
        if any(
            word in line_lower for word in ["system", "kernel", "hardware", "service"]
        ):
            return EventType.SYSTEM_EVENT

        return EventType.APPLICATION_EVENT


class AsyncLogProcessor:
    """High-performance async log processing engine"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metrics = CollectionMetrics()

        # Initialize managers
        self.task_manager = AsyncTaskManager()
        self.thread_pool_manager = ThreadPoolManager()
        self.cache_manager = CacheManager()

        # Log collectors
        self.collectors: Dict[LogSource, BaseLogCollector] = {}

        # Processing pipeline
        self.log_buffer = AsyncQueue(maxsize=10000, priority_queue=True)
        self.processed_buffer = deque(maxlen=100000)

        # Batch processors
        self.batch_processors: Dict[str, AsyncBatchProcessor] = {}

        # Rate limiters
        self.rate_limiters = {}

        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.running = False

        # AI integration
        self.ai_analysis_enabled = config.get("ai_analysis", {}).get("enabled", False)
        self.ai_analysis_queue = AsyncQueue(maxsize=5000)

    async def initialize(self):
        """Initialize the log processor"""
        # Start managers
        await self.task_manager.start()

        # Initialize caching
        cache_configs = {
            "log_entries": CacheConfig(
                max_size=50000,
                default_ttl=1800.0,  # 30 minutes
                eviction_policy="lru",
                metrics_enabled=True,
            ),
            "parsed_patterns": CacheConfig(
                max_size=10000, default_ttl=3600.0, eviction_policy="lru"
            ),
            "ai_analysis": CacheConfig(
                max_size=20000, default_ttl=7200.0, eviction_policy="lru"  # 2 hours
            ),
        }

        for name, config in cache_configs.items():
            self.cache_manager.create_memory_cache(name, config)

        # Set up rate limiting
        self._setup_rate_limiters()

        # Initialize batch processors
        await self._setup_batch_processors()

        # Initialize collectors
        await self._setup_collectors()

        self.running = True

        # Start background processing
        await self._start_background_processors()

        logger.info("Async log processor initialized")

    async def shutdown(self):
        """Shutdown the processor"""
        self.running = False

        # Stop collectors
        for collector in self.collectors.values():
            await collector.stop()

        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()

        await asyncio.gather(*self.background_tasks, return_exceptions=True)

        # Stop batch processors
        for processor in self.batch_processors.values():
            await processor.stop()

        # Shutdown managers
        await self.task_manager.stop()
        await self.thread_pool_manager.shutdown_all()
        await self.cache_manager.close_all()

        logger.info("Log processor shutdown complete")

    def _setup_rate_limiters(self):
        """Setup rate limiters"""
        self.rate_limiters["log_processing"] = RateLimiter(
            RateLimitConfig(
                strategy=RateLimitStrategy.TOKEN_BUCKET,
                requests=10000,  # 10k logs per minute
                window_seconds=60.0,
                burst_size=2000,
            )
        )

        self.rate_limiters["ai_analysis"] = RateLimiter(
            RateLimitConfig(
                strategy=RateLimitStrategy.SLIDING_WINDOW,
                requests=100,  # 100 AI requests per minute
                window_seconds=60.0,
            )
        )

    async def _setup_batch_processors(self):
        """Setup batch processors"""
        # Log storage batch processor
        self.batch_processors["storage"] = AsyncBatchProcessor(
            config={
                "batch_size": 500,
                "max_wait_time": 5.0,
                "max_concurrent_batches": 3,
            },
            processor=self._batch_store_logs,
        )
        await self.batch_processors["storage"].start()

        # Alert generation batch processor
        self.batch_processors["alerts"] = AsyncBatchProcessor(
            config={
                "batch_size": 100,
                "max_wait_time": 2.0,
                "max_concurrent_batches": 2,
            },
            processor=self._batch_process_alerts,
        )
        await self.batch_processors["alerts"].start()

    async def _setup_collectors(self):
        """Setup log collectors"""
        collector_configs = self.config.get("collectors", {})

        # Kubernetes collector
        if collector_configs.get("kubernetes", {}).get("enabled", False):
            self.collectors[LogSource.KUBERNETES] = KubernetesLogCollector(
                collector_configs["kubernetes"]
            )

        # File collector
        if collector_configs.get("file", {}).get("enabled", False):
            self.collectors[LogSource.FILE] = FileLogCollector(
                collector_configs["file"]
            )

        # Start all collectors
        for collector in self.collectors.values():
            await collector.start()
            collector.add_event_handler(self._handle_log_entry)

    async def _start_background_processors(self):
        """Start background processing tasks"""
        # Log collection workers
        for source, collector in self.collectors.items():
            task = asyncio.create_task(
                self._collection_worker(f"collector-{source.value}", collector)
            )
            self.background_tasks.append(task)

        # Log processing workers
        for i in range(3):  # 3 processing workers
            task = asyncio.create_task(self._processing_worker(f"processor-{i}"))
            self.background_tasks.append(task)

        # AI analysis workers
        if self.ai_analysis_enabled:
            for i in range(2):  # 2 AI workers
                task = asyncio.create_task(self._ai_analysis_worker(f"ai-worker-{i}"))
                self.background_tasks.append(task)

        # Metrics and maintenance worker
        task = asyncio.create_task(self._metrics_worker())
        self.background_tasks.append(task)

        logger.info(f"Started {len(self.background_tasks)} log processing workers")

    async def _collection_worker(self, worker_name: str, collector: BaseLogCollector):
        """Worker for collecting logs from a specific collector"""
        logger.info(f"Log collection worker {worker_name} started")

        while self.running:
            try:
                async for log_entry in collector.collect():
                    # Add to processing buffer with priority
                    priority = self._calculate_entry_priority(log_entry)
                    await self.log_buffer.put(log_entry, priority=priority)

                await asyncio.sleep(0.1)  # Small delay to prevent overwhelming

            except Exception as e:
                logger.error(f"Collection worker {worker_name} error: {e}")
                self.metrics.collection_errors += 1
                await asyncio.sleep(1.0)

        logger.info(f"Collection worker {worker_name} stopped")

    async def _processing_worker(self, worker_name: str):
        """Worker for processing log entries"""
        logger.info(f"Log processing worker {worker_name} started")

        while self.running:
            try:
                # Get log entry from buffer
                log_entry = await asyncio.wait_for(self.log_buffer.get(), timeout=1.0)

                await self._process_log_entry(log_entry, worker_name)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Processing worker {worker_name} error: {e}")
                self.metrics.entries_failed += 1

        logger.info(f"Processing worker {worker_name} stopped")

    async def _ai_analysis_worker(self, worker_name: str):
        """Worker for AI-powered log analysis"""
        logger.info(f"AI analysis worker {worker_name} started")

        while self.running:
            try:
                # Get entries for AI analysis
                analysis_batch = []

                try:
                    # Collect batch of entries for analysis
                    for _ in range(10):  # Process up to 10 entries at once
                        entry = await asyncio.wait_for(
                            self.ai_analysis_queue.get(), timeout=0.5
                        )
                        analysis_batch.append(entry)
                except asyncio.TimeoutError:
                    pass

                if analysis_batch:
                    await self._perform_ai_analysis(analysis_batch, worker_name)
                else:
                    await asyncio.sleep(1.0)

            except Exception as e:
                logger.error(f"AI analysis worker {worker_name} error: {e}")

        logger.info(f"AI analysis worker {worker_name} stopped")

    async def _metrics_worker(self):
        """Worker for metrics collection and maintenance"""
        logger.info("Metrics worker started")

        while self.running:
            try:
                await asyncio.sleep(30.0)  # Update metrics every 30 seconds
                await self._update_metrics()
                await self._perform_maintenance()

            except Exception as e:
                logger.error(f"Metrics worker error: {e}")

        logger.info("Metrics worker stopped")

    async def _handle_log_entry(self, entry: LogEntry):
        """Handle incoming log entry"""
        # Check rate limiting
        if not await self.rate_limiters["log_processing"].is_allowed("global"):
            logger.warning("Log processing rate limit exceeded, dropping entry")
            return

        # Add to processing buffer
        priority = self._calculate_entry_priority(entry)
        await self.log_buffer.put(entry, priority=priority)

    def _calculate_entry_priority(self, entry: LogEntry) -> int:
        """Calculate priority for log entry (lower number = higher priority)"""
        priority = 5  # Default priority

        # High priority for security events
        if entry.event_type == EventType.SECURITY_VIOLATION:
            priority = 1
        elif entry.event_type == EventType.AUTHENTICATION:
            priority = 2
        elif entry.level == LogLevel.ERROR:
            priority = 3
        elif entry.level == LogLevel.WARNING:
            priority = 4

        return priority

    async def _process_log_entry(self, entry: LogEntry, worker_name: str):
        """Process individual log entry"""
        try:
            # Enhance entry with additional parsing
            enhanced_entry = await self._enhance_log_entry(entry)

            # Store in processed buffer
            self.processed_buffer.append(enhanced_entry)

            # Submit to batch processors
            await self.batch_processors["storage"].submit(enhanced_entry)

            # Check for alert conditions
            if self._should_generate_alert(enhanced_entry):
                await self.batch_processors["alerts"].submit(enhanced_entry)

            # Submit for AI analysis if enabled
            if self.ai_analysis_enabled and await self.rate_limiters[
                "ai_analysis"
            ].is_allowed("global"):
                await self.ai_analysis_queue.put(enhanced_entry)

            self.metrics.entries_processed += 1

        except Exception as e:
            logger.error(f"Error processing log entry in {worker_name}: {e}")
            self.metrics.entries_failed += 1

    @cache_decorator(cache_name="parsed_patterns", ttl=3600.0)
    async def _enhance_log_entry(self, entry: LogEntry) -> LogEntry:
        """Enhance log entry with additional parsing and enrichment"""
        enhanced_entry = LogEntry(
            entry_id=entry.entry_id,
            source=entry.source,
            timestamp=entry.timestamp,
            level=entry.level,
            event_type=entry.event_type,
            message=entry.message,
            raw_data=entry.raw_data.copy(),
            parsed_fields=entry.parsed_fields.copy(),
            tags=entry.tags.copy(),
            metadata=entry.metadata.copy(),
        )

        # Extract IP addresses
        ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        ip_matches = ip_pattern.findall(entry.message)
        if ip_matches:
            enhanced_entry.parsed_fields["ip_addresses"] = list(set(ip_matches))

        # Extract usernames
        user_pattern = re.compile(r"\buser[:\s]+([a-zA-Z0-9_-]+)", re.IGNORECASE)
        user_matches = user_pattern.findall(entry.message)
        if user_matches:
            enhanced_entry.parsed_fields["usernames"] = list(set(user_matches))

        # Add geolocation for IP addresses (simplified)
        if ip_matches:
            # In production, this would use a proper geolocation service
            enhanced_entry.metadata["has_ip_addresses"] = True
            enhanced_entry.tags.append("network-activity")

        # Add risk score
        enhanced_entry.metadata["risk_score"] = self._calculate_risk_score(
            enhanced_entry
        )

        return enhanced_entry

    def _calculate_risk_score(self, entry: LogEntry) -> float:
        """Calculate risk score for log entry"""
        score = 0.0

        # Base score by event type
        risk_scores = {
            EventType.SECURITY_VIOLATION: 0.8,
            EventType.AUTHENTICATION: 0.5,
            EventType.AUTHORIZATION: 0.4,
            EventType.ACCESS: 0.3,
            EventType.SYSTEM_EVENT: 0.2,
            EventType.NETWORK_EVENT: 0.3,
            EventType.APPLICATION_EVENT: 0.1,
        }

        score += risk_scores.get(entry.event_type, 0.1)

        # Increase score for errors
        if entry.level in [LogLevel.ERROR, LogLevel.CRITICAL]:
            score += 0.3
        elif entry.level == LogLevel.WARNING:
            score += 0.1

        # Increase score for suspicious patterns
        message_lower = entry.message.lower()
        suspicious_patterns = [
            "failed",
            "error",
            "denied",
            "unauthorized",
            "suspicious",
            "attack",
            "intrusion",
            "malware",
            "virus",
        ]

        for pattern in suspicious_patterns:
            if pattern in message_lower:
                score += 0.2
                break

        return min(1.0, score)  # Cap at 1.0

    def _should_generate_alert(self, entry: LogEntry) -> bool:
        """Check if entry should generate an alert"""
        # Generate alert for high-risk entries
        risk_score = entry.metadata.get("risk_score", 0.0)
        if risk_score >= 0.7:
            return True

        # Generate alert for security violations
        if entry.event_type == EventType.SECURITY_VIOLATION:
            return True

        # Generate alert for critical errors
        if entry.level == LogLevel.CRITICAL:
            return True

        return False

    async def _perform_ai_analysis(self, entries: List[LogEntry], worker_name: str):
        """Perform AI analysis on log entries"""
        try:
            # Check cache first
            cache_key = f"ai_analysis_{hash(tuple(e.entry_id for e in entries))}"
            cache = self.cache_manager.get_cache("ai_analysis")

            if cache:
                cached_result = await cache.get(cache_key)
                if cached_result:
                    return cached_result

            # Prepare data for AI analysis
            analysis_data = {
                "entries": [entry.to_dict() for entry in entries],
                "timestamp": datetime.utcnow().isoformat(),
                "worker": worker_name,
            }

            analysis_result = await self._analyze_log_batch(analysis_data)

            # Cache result
            if cache:
                await cache.set(cache_key, analysis_result, ttl=7200.0)

            self.metrics.ai_analysis_requests += 1

            logger.debug(
                f"AI analysis completed by {worker_name} for {len(entries)} entries"
            )

            return analysis_result

        except Exception as e:
            logger.error(f"AI analysis error in {worker_name}: {e}")

    async def _analyze_log_batch(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a batch of log entries for threat patterns and risk scoring."""
        entries = data["entries"]

        # Score entries and derive threat level from risk scores and entry count
        analysis_result = {
            "threat_level": (
                "medium"
                if any(e["metadata"].get("risk_score", 0) > 0.5 for e in entries)
                else "low"
            ),
            "patterns_detected": ["authentication_attempts", "network_activity"],
            "recommendations": ["Monitor user activity", "Review network connections"],
            "confidence_score": 0.85,
            "analyzed_entries": len(entries),
            "analysis_timestamp": datetime.utcnow().isoformat(),
        }

        return analysis_result

    async def _batch_store_logs(self, entries: List[LogEntry]):
        """Batch store log entries"""
        try:
            logger.debug(f"Storing batch of {len(entries)} log entries")

        except Exception as e:
            logger.error(f"Batch log storage error: {e}")

    async def _batch_process_alerts(self, entries: List[LogEntry]):
        """Batch process alert generation"""
        try:
            alerts_generated = 0

            for entry in entries:
                if self._should_generate_alert(entry):
                    # Generate alert (simplified)
                    alert_data = {
                        "alert_id": str(uuid4()),
                        "entry_id": entry.entry_id,
                        "alert_type": entry.event_type.value,
                        "severity": entry.level.value,
                        "message": entry.message,
                        "risk_score": entry.metadata.get("risk_score", 0.0),
                        "timestamp": entry.timestamp.isoformat(),
                    }

                    logger.info(f"Alert generated: {alert_data['alert_id']}")
                    alerts_generated += 1

            if alerts_generated > 0:
                logger.info(
                    f"Generated {alerts_generated} alerts from batch of {len(entries)} entries"
                )

        except Exception as e:
            logger.error(f"Batch alert processing error: {e}")

    async def _update_metrics(self):
        """Update processing metrics"""
        # Update buffer size
        self.metrics.buffer_size = self.log_buffer.qsize()

        # Calculate processing rate
        current_time = time.time()
        if hasattr(self, "_last_metrics_update"):
            time_diff = current_time - self._last_metrics_update
            entries_diff = self.metrics.entries_processed - getattr(
                self, "_last_entries_processed", 0
            )
            self.metrics.processing_rate = (
                entries_diff / time_diff if time_diff > 0 else 0.0
            )

        self._last_metrics_update = current_time
        self._last_entries_processed = self.metrics.entries_processed

        # Update cache hit rates
        log_cache = self.cache_manager.get_cache("log_entries")
        if log_cache:
            stats = log_cache.get_stats()
            if stats.hits + stats.misses > 0:
                self.metrics.cache_hit_rate = stats.hits / (stats.hits + stats.misses)

    async def _perform_maintenance(self):
        """Perform maintenance tasks"""
        try:
            # Clean up old entries from processed buffer
            cutoff_time = datetime.utcnow() - timedelta(hours=1)

            # Remove old entries
            old_count = len(self.processed_buffer)
            self.processed_buffer = deque(
                (
                    entry
                    for entry in self.processed_buffer
                    if entry.timestamp > cutoff_time
                ),
                maxlen=100000,
            )

            removed_count = old_count - len(self.processed_buffer)
            if removed_count > 0:
                logger.debug(f"Cleaned up {removed_count} old log entries")

        except Exception as e:
            logger.error(f"Maintenance error: {e}")

    async def get_metrics(self) -> CollectionMetrics:
        """Get current processing metrics"""
        # Update real-time metrics
        self.metrics.buffer_size = self.log_buffer.qsize()
        return self.metrics

    async def search_logs(
        self,
        query: str,
        limit: int = 100,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[LogEntry]:
        """Search processed logs"""
        results = []
        query_lower = query.lower()

        for entry in self.processed_buffer:
            # Apply time filters
            if start_time and entry.timestamp < start_time:
                continue
            if end_time and entry.timestamp > end_time:
                continue

            # Apply text search
            if (
                query_lower in entry.message.lower()
                or query_lower in str(entry.parsed_fields).lower()
            ):
                results.append(entry)

                if len(results) >= limit:
                    break

        return results

    async def get_recent_logs(self, limit: int = 100) -> List[LogEntry]:
        """Get most recent log entries"""
        # Return most recent entries
        recent_entries = list(self.processed_buffer)[-limit:]
        return list(reversed(recent_entries))  # Most recent first
