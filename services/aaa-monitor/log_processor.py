"""
SkausWatch AAA Monitor Service - Log Processor

Core log processing pipeline that handles event parsing, normalization,
enrichment, and routing to analysis engines and storage.
"""

import asyncio
import hashlib
import json
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, AsyncGenerator, Dict, List, Optional, Set

import structlog
from elasticsearch import AsyncElasticsearch
from motor.motor_asyncio import AsyncIOMotorClient

from .ai_integration.ai_provider import AIAnalysisType
from .ai_integration.analysis_engine import AIAnalysisEngine
from .models import (
    BaseEvent,
    EventSearchRequest,
    EventSearchResponse,
    EventType,
    LogSource,
    Severity,
    ThreatLevel,
)

logger = structlog.get_logger(__name__)


class LogProcessor:
    """Core log processing pipeline for AAA monitoring"""

    def __init__(
        self,
        config: Dict[str, Any],
        event_classifier,
        buffer_manager,
        indicator_matcher,
        ai_analysis_engine: Optional[AIAnalysisEngine] = None,
    ):
        """Initialize log processor

        Args:
            config: Log processing configuration
            event_classifier: Event classification service
            buffer_manager: Event buffering service
            indicator_matcher: Threat intelligence matcher
            ai_analysis_engine: AI analysis engine for intelligent log analysis
        """
        self.config = config
        self.event_classifier = event_classifier
        self.buffer_manager = buffer_manager
        self.indicator_matcher = indicator_matcher
        self.ai_analysis_engine = ai_analysis_engine

        # Processing statistics
        self.stats = {
            "total_events": 0,
            "events_by_source": defaultdict(int),
            "events_by_type": defaultdict(int),
            "events_by_severity": defaultdict(int),
            "processing_errors": 0,
            "ai_analyses_triggered": 0,
            "ai_analyses_completed": 0,
            "last_reset": datetime.utcnow(),
        }

        # AI analysis configuration
        self.ai_enabled = config.get("ai_analysis_enabled", True)
        self.ai_threshold = config.get("ai_analysis_threshold", 10)
        self.ai_trigger_conditions = config.get(
            "ai_trigger_conditions",
            {
                "severity_levels": [Severity.CRITICAL, Severity.HIGH],
                "event_types": [
                    EventType.SECURITY_VIOLATION,
                    EventType.PRIVILEGE_ESCALATION,
                ],
                "threat_matches": True,
                "batch_size": 5,
            },
        )

        # AI analysis tracking
        self.ai_event_buffer = defaultdict(list)
        self.ai_last_analysis = defaultdict(lambda: datetime.utcnow())
        self.ai_analysis_jobs = {}

        # Event storage backends
        self.elasticsearch = None
        self.mongodb = None

        # Event streaming
        self.event_streams = {}
        self.stream_filters = {}

        # Deduplication
        self.dedup_cache = {}
        self.dedup_window = timedelta(minutes=config.get("dedup_window_minutes", 5))

        # Processing queues
        self.processing_queue = asyncio.Queue(
            maxsize=config.get("queue_max_size", 10000)
        )
        self.high_priority_queue = asyncio.Queue(
            maxsize=config.get("hp_queue_max_size", 1000)
        )

        # Rate limiting
        self.rate_limits = defaultdict(lambda: deque())
        self.rate_limit_window = timedelta(seconds=config.get("rate_limit_window", 60))

        # Processing workers
        self.workers = []
        self.running = False

    async def initialize(self):
        """Initialize log processor and storage backends"""
        try:
            # Initialize Elasticsearch if configured
            if self.config.get("elasticsearch", {}).get("enabled", False):
                await self._initialize_elasticsearch()

            # Initialize MongoDB if configured
            if self.config.get("mongodb", {}).get("enabled", False):
                await self._initialize_mongodb()

            # Start processing workers
            await self._start_workers()

            logger.info("Log processor initialized successfully")

        except Exception as e:
            logger.error("Failed to initialize log processor", error=str(e))
            raise

    async def _initialize_elasticsearch(self):
        """Initialize Elasticsearch connection"""
        try:
            es_config = self.config["elasticsearch"]

            self.elasticsearch = AsyncElasticsearch(
                hosts=es_config.get("hosts", ["localhost:9200"]),
                http_auth=es_config.get("auth"),
                use_ssl=es_config.get("use_ssl", False),
                verify_certs=es_config.get("verify_certs", True),
                ca_certs=es_config.get("ca_certs"),
                timeout=es_config.get("timeout", 30),
            )

            # Test connection
            await self.elasticsearch.ping()

            # Create index templates
            await self._create_elasticsearch_templates()

            logger.info("Elasticsearch connection established")

        except Exception as e:
            logger.error("Failed to initialize Elasticsearch", error=str(e))
            self.elasticsearch = None
            raise

    async def _create_elasticsearch_templates(self):
        """Create Elasticsearch index templates"""
        try:
            template = {
                "index_patterns": ["aaa-events-*"],
                "template": {
                    "settings": {
                        "number_of_shards": self.config["elasticsearch"].get(
                            "shards", 1
                        ),
                        "number_of_replicas": self.config["elasticsearch"].get(
                            "replicas", 0
                        ),
                        "index.refresh_interval": "1s",
                    },
                    "mappings": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "timestamp": {"type": "date"},
                            "source": {"type": "keyword"},
                            "event_type": {"type": "keyword"},
                            "severity": {"type": "keyword"},
                            "message": {"type": "text", "analyzer": "standard"},
                            "raw_data": {"type": "object", "enabled": False},
                            "processed_data": {"type": "object"},
                            "tags": {"type": "keyword"},
                            "threat_matches": {"type": "nested"},
                            "ai_analysis": {"type": "object"},
                            "geo_location": {"type": "geo_point"},
                        }
                    },
                },
            }

            await self.elasticsearch.indices.put_index_template(
                name="aaa-events-template", body=template
            )

            logger.info("Elasticsearch index template created")

        except Exception as e:
            logger.error("Failed to create Elasticsearch templates", error=str(e))

    async def _initialize_mongodb(self):
        """Initialize MongoDB connection"""
        try:
            mongo_config = self.config["mongodb"]

            self.mongodb = AsyncIOMotorClient(
                mongo_config.get("uri", "mongodb://localhost:27017"),
                serverSelectionTimeoutMS=mongo_config.get("timeout", 5000),
            )

            # Test connection
            await self.mongodb.admin.command("ping")

            # Get database and collections
            self.db = self.mongodb[mongo_config.get("database", "aaa_monitor")]
            self.events_collection = self.db.events
            self.stats_collection = self.db.statistics

            # Create indexes
            await self._create_mongodb_indexes()

            logger.info("MongoDB connection established")

        except Exception as e:
            logger.error("Failed to initialize MongoDB", error=str(e))
            self.mongodb = None
            raise

    async def _create_mongodb_indexes(self):
        """Create MongoDB indexes"""
        try:
            # Create indexes for efficient querying
            await self.events_collection.create_index(
                [("timestamp", -1), ("source", 1), ("event_type", 1)]
            )

            await self.events_collection.create_index(
                [("severity", 1), ("timestamp", -1)]
            )

            await self.events_collection.create_index([("tags", 1), ("timestamp", -1)])

            await self.events_collection.create_index("id", unique=True)

            logger.info("MongoDB indexes created")

        except Exception as e:
            logger.error("Failed to create MongoDB indexes", error=str(e))

    async def _start_workers(self):
        """Start processing worker tasks"""
        num_workers = self.config.get("worker_count", 4)

        for i in range(num_workers):
            worker = asyncio.create_task(self._processing_worker(f"worker-{i}"))
            self.workers.append(worker)

        # High priority worker
        hp_worker = asyncio.create_task(self._high_priority_worker())
        self.workers.append(hp_worker)

        self.running = True
        logger.info("Processing workers started", count=num_workers + 1)

    async def process_event(self, event: BaseEvent) -> bool:
        """Process a single event through the pipeline

        Args:
            event: Event to process

        Returns:
            True if event was processed successfully
        """
        try:
            # Update statistics
            self.stats["total_events"] += 1
            self.stats["events_by_source"][event.source] += 1
            self.stats["events_by_type"][event.event_type] += 1
            self.stats["events_by_severity"][event.severity] += 1

            # Rate limiting check
            if await self._is_rate_limited(event):
                logger.warning(
                    "Event rate limited",
                    source=event.source,
                    event_type=event.event_type,
                )
                return False

            # Deduplication check
            if await self._is_duplicate(event):
                logger.debug("Duplicate event filtered", event_id=event.id)
                return False

            # Queue event for processing
            if event.severity in [Severity.CRITICAL, Severity.HIGH]:
                await self.high_priority_queue.put(event)
            else:
                await self.processing_queue.put(event)

            return True

        except Exception as e:
            logger.error("Error processing event", error=str(e), event_id=event.id)
            self.stats["processing_errors"] += 1
            return False

    async def _is_rate_limited(self, event: BaseEvent) -> bool:
        """Check if event should be rate limited"""
        try:
            rate_limit_key = f"{event.source}:{event.event_type}"
            current_time = datetime.utcnow()

            # Clean old entries
            cutoff_time = current_time - self.rate_limit_window
            rate_queue = self.rate_limits[rate_limit_key]

            while rate_queue and rate_queue[0] < cutoff_time:
                rate_queue.popleft()

            # Check rate limit
            max_events = self.config.get("rate_limit_events", 1000)
            if len(rate_queue) >= max_events:
                return True

            # Add current event
            rate_queue.append(current_time)
            return False

        except Exception as e:
            logger.error("Error checking rate limit", error=str(e))
            return False

    async def _is_duplicate(self, event: BaseEvent) -> bool:
        """Check if event is a duplicate within the dedup window"""
        try:
            # Create hash of event content
            content_hash = hashlib.sha256(
                f"{event.source}:{event.event_type}:{event.message}".encode()
            ).hexdigest()

            current_time = datetime.utcnow()

            # Check if we've seen this event recently
            if content_hash in self.dedup_cache:
                last_seen = self.dedup_cache[content_hash]
                if current_time - last_seen < self.dedup_window:
                    return True

            # Update cache
            self.dedup_cache[content_hash] = current_time

            # Clean old entries periodically
            if len(self.dedup_cache) > 10000:  # Arbitrary limit
                cutoff_time = current_time - self.dedup_window
                keys_to_remove = [
                    k for k, v in self.dedup_cache.items() if v < cutoff_time
                ]
                for key in keys_to_remove:
                    del self.dedup_cache[key]

            return False

        except Exception as e:
            logger.error("Error checking for duplicate", error=str(e))
            return False

    async def _processing_worker(self, worker_id: str):
        """Main event processing worker"""
        logger.info("Processing worker started", worker_id=worker_id)

        try:
            while self.running:
                try:
                    # Get event from queue with timeout
                    event = await asyncio.wait_for(
                        self.processing_queue.get(), timeout=1.0
                    )

                    await self._process_event_pipeline(event)

                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error(
                        "Error in processing worker", worker_id=worker_id, error=str(e)
                    )
                    await asyncio.sleep(1)

        except asyncio.CancelledError:
            logger.info("Processing worker cancelled", worker_id=worker_id)
        except Exception as e:
            logger.error(
                "Fatal error in processing worker", worker_id=worker_id, error=str(e)
            )

    async def _high_priority_worker(self):
        """High priority event processing worker"""
        logger.info("High priority worker started")

        try:
            while self.running:
                try:
                    # Get high priority event
                    event = await asyncio.wait_for(
                        self.high_priority_queue.get(), timeout=1.0
                    )

                    await self._process_event_pipeline(event, high_priority=True)

                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error("Error in high priority worker", error=str(e))
                    await asyncio.sleep(1)

        except asyncio.CancelledError:
            logger.info("High priority worker cancelled")
        except Exception as e:
            logger.error("Fatal error in high priority worker", error=str(e))

    async def _process_event_pipeline(
        self, event: BaseEvent, high_priority: bool = False
    ):
        """Process event through the complete pipeline"""
        try:
            start_time = time.time()

            # Step 1: Event enrichment
            await self._enrich_event(event)

            # Step 2: Threat intelligence matching
            await self._match_threat_intelligence(event)

            # Step 3: Event classification and normalization
            await self._classify_and_normalize(event)

            # Step 4: Geo-location enrichment
            await self._add_geolocation(event)

            # Step 5: Store event
            await self._store_event(event)

            # Step 6: Forward to analysis engines
            await self._forward_to_analysis(event, high_priority)

            # Step 7: Stream to subscribers
            await self._stream_event(event)

            # Step 8: Buffer for batch processing
            await self.buffer_manager.add_event(event)

            processing_time = time.time() - start_time

            logger.debug(
                "Event processed successfully",
                event_id=event.id,
                processing_time=processing_time,
                high_priority=high_priority,
            )

        except Exception as e:
            logger.error("Error in event pipeline", event_id=event.id, error=str(e))
            self.stats["processing_errors"] += 1

    async def _enrich_event(self, event: BaseEvent):
        """Enrich event with additional context"""
        try:
            enrichment_data = {}

            # Add processing metadata
            enrichment_data["processed_at"] = datetime.utcnow().isoformat()
            enrichment_data["processor_version"] = self.config.get("version", "1.0.0")

            # Extract IP addresses for geo-location
            ip_addresses = self._extract_ip_addresses(event)
            if ip_addresses:
                enrichment_data["ip_addresses"] = ip_addresses

            # Add hostname resolution
            hostnames = await self._resolve_hostnames(ip_addresses)
            if hostnames:
                enrichment_data["hostnames"] = hostnames

            # Add user enrichment
            if hasattr(event, "username") and event.username:
                user_info = await self._enrich_user_info(event.username)
                if user_info:
                    enrichment_data["user_info"] = user_info

            # Update event processed data
            if enrichment_data:
                event.processed_data.update(enrichment_data)

        except Exception as e:
            logger.error("Error enriching event", error=str(e))

    def _extract_ip_addresses(self, event: BaseEvent) -> List[str]:
        """Extract IP addresses from event data"""
        ip_addresses = []

        try:
            # Check direct IP fields
            if hasattr(event, "source_ip") and event.source_ip:
                ip_addresses.append(event.source_ip)
            if hasattr(event, "destination_ip") and event.destination_ip:
                ip_addresses.append(event.destination_ip)

            # Extract IPs from message using regex
            import re

            ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            message_ips = re.findall(ip_pattern, event.message)
            ip_addresses.extend(message_ips)

            # Extract from raw data
            if event.raw_data:
                raw_str = json.dumps(event.raw_data)
                raw_ips = re.findall(ip_pattern, raw_str)
                ip_addresses.extend(raw_ips)

            # Remove duplicates and invalid IPs
            unique_ips = []
            for ip in set(ip_addresses):
                try:
                    parts = ip.split(".")
                    if all(0 <= int(part) <= 255 for part in parts):
                        unique_ips.append(ip)
                except:
                    continue

            return unique_ips

        except Exception as e:
            logger.error("Error extracting IP addresses", error=str(e))
            return []

    async def _resolve_hostnames(self, ip_addresses: List[str]) -> Dict[str, str]:
        """Resolve hostnames for IP addresses"""
        hostnames = {}

        try:
            import socket

            for ip in ip_addresses:
                try:
                    # Reverse DNS lookup with timeout
                    hostname = await asyncio.wait_for(
                        asyncio.to_thread(socket.gethostbyaddr, ip), timeout=2.0
                    )
                    hostnames[ip] = hostname[0]
                except:
                    continue

            return hostnames

        except Exception as e:
            logger.error("Error resolving hostnames", error=str(e))
            return {}

    async def _enrich_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Enrich user information"""
        try:
            # This could integrate with LDAP, Active Directory, or user database
            # For now, return basic info
            user_info = {
                "username": username,
                "enriched_at": datetime.utcnow().isoformat(),
            }

            # Check if username indicates system account
            system_users = ["root", "admin", "administrator", "system", "daemon"]
            if username.lower() in system_users:
                user_info["account_type"] = "system"
            else:
                user_info["account_type"] = "user"

            return user_info

        except Exception as e:
            logger.error("Error enriching user info", username=username, error=str(e))
            return None

    async def _match_threat_intelligence(self, event: BaseEvent):
        """Match event against threat intelligence indicators"""
        try:
            if self.indicator_matcher:
                matches = await self.indicator_matcher.match_event(event)

                if matches:
                    event.processed_data["threat_matches"] = [
                        {
                            "ioc_id": match.ioc_id,
                            "matched_value": match.matched_value,
                            "field_name": match.field_name,
                            "confidence": match.confidence,
                            "threat_level": match.threat_level,
                        }
                        for match in matches
                    ]

                    # Add threat intelligence tags
                    threat_tags = [f"threat:{match.threat_level}" for match in matches]
                    event.tags.extend(threat_tags)

                    logger.info(
                        "Threat intelligence matches found",
                        event_id=event.id,
                        match_count=len(matches),
                    )

        except Exception as e:
            logger.error("Error matching threat intelligence", error=str(e))

    async def _classify_and_normalize(self, event: BaseEvent):
        """Classify and normalize event using ML classifier"""
        try:
            if self.event_classifier:
                classification = await self.event_classifier.classify_event(event)

                if classification:
                    event.processed_data["classification"] = classification

                    # Update event type if classifier provides better classification
                    if classification.get("predicted_type"):
                        event.event_type = classification["predicted_type"]

                    # Update severity if classifier provides better assessment
                    if classification.get("predicted_severity"):
                        event.severity = classification["predicted_severity"]

        except Exception as e:
            logger.error("Error classifying event", error=str(e))

    async def _add_geolocation(self, event: BaseEvent):
        """Add geolocation information for IP addresses"""
        try:
            ip_addresses = event.processed_data.get("ip_addresses", [])

            if ip_addresses and self.config.get("geolocation", {}).get(
                "enabled", False
            ):
                # This would integrate with GeoIP databases
                geo_info = {}

                for ip in ip_addresses:
                    # Placeholder for GeoIP lookup
                    # Would use MaxMind GeoIP2 or similar service
                    geo_info[ip] = {
                        "country": "Unknown",
                        "city": "Unknown",
                        "latitude": 0.0,
                        "longitude": 0.0,
                    }

                if geo_info:
                    event.processed_data["geo_locations"] = geo_info

        except Exception as e:
            logger.error("Error adding geolocation", error=str(e))

    async def _store_event(self, event: BaseEvent):
        """Store event in configured backends"""
        try:
            storage_tasks = []

            # Store in Elasticsearch
            if self.elasticsearch:
                storage_tasks.append(self._store_in_elasticsearch(event))

            # Store in MongoDB
            if self.mongodb:
                storage_tasks.append(self._store_in_mongodb(event))

            # Execute storage operations concurrently
            if storage_tasks:
                await asyncio.gather(*storage_tasks, return_exceptions=True)

        except Exception as e:
            logger.error("Error storing event", event_id=event.id, error=str(e))

    async def _store_in_elasticsearch(self, event: BaseEvent):
        """Store event in Elasticsearch"""
        try:
            # Create index name with date rotation
            index_name = f"aaa-events-{datetime.utcnow().strftime('%Y-%m')}"

            # Convert event to dict
            event_dict = event.dict()
            event_dict["@timestamp"] = event.timestamp.isoformat()

            # Store event
            await self.elasticsearch.index(
                index=index_name, id=event.id, body=event_dict
            )

        except Exception as e:
            logger.error(
                "Error storing event in Elasticsearch", event_id=event.id, error=str(e)
            )

    async def _store_in_mongodb(self, event: BaseEvent):
        """Store event in MongoDB"""
        try:
            # Convert event to dict
            event_dict = event.dict()
            event_dict["_id"] = event.id

            # Store event
            await self.events_collection.insert_one(event_dict)

        except Exception as e:
            logger.error(
                "Error storing event in MongoDB", event_id=event.id, error=str(e)
            )

    async def _forward_to_analysis(self, event: BaseEvent, high_priority: bool = False):
        """Forward event to analysis engines including AI analysis"""
        try:
            # Forward to AI analysis if enabled and conditions are met
            if self.ai_enabled and self.ai_analysis_engine:
                await self._handle_ai_analysis(event, high_priority)

            # Forward to other analysis engines (placeholder for future expansion)
            # This could include:
            # - Correlation analysis
            # - Behavioral analysis
            # - Pattern recognition
            # - Custom analysis engines

        except Exception as e:
            logger.error("Error forwarding to analysis", error=str(e))

    async def _handle_ai_analysis(self, event: BaseEvent, high_priority: bool = False):
        """Handle AI analysis for events"""
        try:
            # Check if event should trigger AI analysis
            if not await self._should_trigger_ai_analysis(event, high_priority):
                return

            # Determine analysis type based on event characteristics
            analysis_type = await self._determine_analysis_type(event)

            # Get analysis context
            context = await self._build_ai_context(event)

            if high_priority or event.severity in [Severity.CRITICAL, Severity.HIGH]:
                # Real-time analysis for high priority events
                job_id = await self.ai_analysis_engine.analyze_real_time(
                    events=[event],
                    analysis_type=analysis_type,
                    priority=5 if event.severity == Severity.CRITICAL else 4,
                    context=context,
                )

                self.ai_analysis_jobs[job_id] = {
                    "event_id": event.id,
                    "analysis_type": analysis_type.value,
                    "created_at": datetime.utcnow(),
                    "mode": "real_time",
                }

                self.stats["ai_analyses_triggered"] += 1

                logger.info(
                    "Real-time AI analysis triggered",
                    event_id=event.id,
                    job_id=job_id,
                    analysis_type=analysis_type.value,
                )

                # Start background task to process results
                asyncio.create_task(self._process_ai_result(job_id, event))

            else:
                # Add to batch for batch analysis
                analysis_key = f"{analysis_type.value}:{event.source.value}"
                self.ai_event_buffer[analysis_key].append(event)

                # Check if batch should be processed
                if len(
                    self.ai_event_buffer[analysis_key]
                ) >= self.ai_trigger_conditions.get("batch_size", 5):
                    await self._process_ai_batch(analysis_key, analysis_type)

        except Exception as e:
            logger.error("Error handling AI analysis", event_id=event.id, error=str(e))

    async def _should_trigger_ai_analysis(
        self, event: BaseEvent, high_priority: bool = False
    ) -> bool:
        """Determine if event should trigger AI analysis"""
        try:
            # Always analyze high priority events
            if high_priority:
                return True

            # Check severity level triggers
            if event.severity in self.ai_trigger_conditions.get("severity_levels", []):
                return True

            # Check event type triggers
            if event.event_type in self.ai_trigger_conditions.get("event_types", []):
                return True

            # Check if event has threat intelligence matches
            if self.ai_trigger_conditions.get(
                "threat_matches", False
            ) and event.processed_data.get("threat_matches"):
                return True

            # Check for security-related tags
            security_tags = ["security", "threat", "malicious", "suspicious", "attack"]
            if any(
                tag.lower() in " ".join(event.tags).lower() for tag in security_tags
            ):
                return True

            # Check for anomalous patterns (placeholder - could be enhanced)
            if await self._is_anomalous_event(event):
                return True

            return False

        except Exception as e:
            logger.error("Error checking AI analysis triggers", error=str(e))
            return False

    async def _is_anomalous_event(self, event: BaseEvent) -> bool:
        """Check if event shows anomalous characteristics"""
        try:
            # Simple anomaly detection based on frequency
            event_signature = f"{event.source.value}:{event.event_type.value}"
            current_time = datetime.utcnow()

            # Check if we've seen too many similar events recently
            recent_events = [
                e
                for e in self.ai_event_buffer.get(event_signature, [])
                if (current_time - e.timestamp).total_seconds() < 300  # 5 minutes
            ]

            # If we have more than normal frequency, consider it anomalous
            if len(recent_events) > 10:
                return True

            # Check for unusual time patterns (e.g., activity outside business hours)
            hour = current_time.hour
            if hour < 6 or hour > 22:  # Outside typical business hours
                if event.event_type in [
                    EventType.AUTHENTICATION,
                    EventType.FILE_ACCESS,
                ]:
                    return True

            return False

        except Exception as e:
            logger.error("Error checking for anomalous event", error=str(e))
            return False

    async def _determine_analysis_type(self, event: BaseEvent) -> AIAnalysisType:
        """Determine appropriate AI analysis type for event"""
        try:
            # Security events
            if event.event_type in [
                EventType.SECURITY_VIOLATION,
                EventType.PRIVILEGE_ESCALATION,
            ] or event.processed_data.get("threat_matches"):
                return AIAnalysisType.SECURITY_EVENT

            # Authentication events
            if event.event_type == EventType.AUTHENTICATION:
                # Check if failed authentication or unusual pattern
                if hasattr(event, "success") and not event.success:
                    return AIAnalysisType.SECURITY_EVENT
                return AIAnalysisType.ANOMALY_DETECTION

            # Network events
            if event.event_type == EventType.NETWORK:
                return AIAnalysisType.THREAT_CLASSIFICATION

            # File access events
            if event.event_type == EventType.FILE_ACCESS:
                return AIAnalysisType.ANOMALY_DETECTION

            # Default to pattern analysis for other events
            return AIAnalysisType.PATTERN_ANALYSIS

        except Exception as e:
            logger.error("Error determining analysis type", error=str(e))
            return AIAnalysisType.SECURITY_EVENT

    async def _build_ai_context(self, event: BaseEvent) -> Dict[str, Any]:
        """Build context information for AI analysis"""
        try:
            context = {
                "event_source": event.source.value,
                "event_type": event.event_type.value,
                "severity": event.severity.value,
                "timestamp": event.timestamp.isoformat(),
                "has_threat_matches": bool(event.processed_data.get("threat_matches")),
                "processing_metadata": {
                    "processor_version": self.config.get("version", "1.0.0"),
                    "processed_at": datetime.utcnow().isoformat(),
                },
            }

            # Add geo-location context if available
            if event.processed_data.get("geo_locations"):
                context["geo_context"] = event.processed_data["geo_locations"]

            # Add user context for authentication events
            if hasattr(event, "username") and event.username:
                context["user_context"] = {
                    "username": event.username,
                    "user_info": event.processed_data.get("user_info", {}),
                }

            # Add network context if available
            if event.processed_data.get("ip_addresses"):
                context["network_context"] = {
                    "ip_addresses": event.processed_data["ip_addresses"],
                    "hostnames": event.processed_data.get("hostnames", {}),
                }

            # Add threat intelligence context
            if event.processed_data.get("threat_matches"):
                context["threat_intel_context"] = {
                    "match_count": len(event.processed_data["threat_matches"]),
                    "threat_levels": list(
                        set(
                            match["threat_level"]
                            for match in event.processed_data["threat_matches"]
                        )
                    ),
                }

            # Add system context for container events
            if event.source in [LogSource.KUBERNETES, LogSource.LXC_LXD]:
                context["container_context"] = {
                    "source": event.source.value,
                    "metadata": {
                        k: v
                        for k, v in event.processed_data.items()
                        if k
                        in [
                            "namespace",
                            "container_name",
                            "resource_name",
                            "cluster_name",
                        ]
                    },
                }

            return context

        except Exception as e:
            logger.error("Error building AI context", error=str(e))
            return {}

    async def _process_ai_batch(self, analysis_key: str, analysis_type: AIAnalysisType):
        """Process batch of events for AI analysis"""
        try:
            events = self.ai_event_buffer[analysis_key].copy()
            self.ai_event_buffer[analysis_key].clear()

            if not events:
                return

            # Build batch context
            context = {
                "batch_size": len(events),
                "analysis_key": analysis_key,
                "time_span": {
                    "start": min(e.timestamp for e in events).isoformat(),
                    "end": max(e.timestamp for e in events).isoformat(),
                },
                "event_sources": list(set(e.source.value for e in events)),
                "event_types": list(set(e.event_type.value for e in events)),
                "severity_levels": list(set(e.severity.value for e in events)),
            }

            # Submit for batch analysis
            job_id = await self.ai_analysis_engine.analyze_batch(
                events=events, analysis_type=analysis_type, context=context
            )

            if job_id:
                self.ai_analysis_jobs[job_id] = {
                    "event_count": len(events),
                    "analysis_type": analysis_type.value,
                    "analysis_key": analysis_key,
                    "created_at": datetime.utcnow(),
                    "mode": "batch",
                }

                self.stats["ai_analyses_triggered"] += 1

                logger.info(
                    "Batch AI analysis triggered",
                    job_id=job_id,
                    event_count=len(events),
                    analysis_type=analysis_type.value,
                )

        except Exception as e:
            logger.error(
                "Error processing AI batch", analysis_key=analysis_key, error=str(e)
            )

    async def _process_ai_result(
        self, job_id: str, original_event: Optional[BaseEvent] = None
    ):
        """Process AI analysis result"""
        try:
            # Wait a short time for analysis to complete
            await asyncio.sleep(1)

            result = await self.ai_analysis_engine.get_analysis_result(job_id)
            if not result:
                # Check again after a longer wait
                await asyncio.sleep(5)
                result = await self.ai_analysis_engine.get_analysis_result(job_id)

            if result:
                await self._handle_ai_analysis_result(result, original_event)
                self.stats["ai_analyses_completed"] += 1

                # Clean up job tracking
                if job_id in self.ai_analysis_jobs:
                    del self.ai_analysis_jobs[job_id]

            else:
                logger.warning("AI analysis result not available", job_id=job_id)

        except Exception as e:
            logger.error("Error processing AI result", job_id=job_id, error=str(e))

    async def _handle_ai_analysis_result(
        self, result, original_event: Optional[BaseEvent] = None
    ):
        """Handle AI analysis results and take appropriate actions"""
        try:
            logger.info(
                "Processing AI analysis result",
                job_id=result.job_id,
                confidence=result.confidence_score,
                threat_level=result.threat_level.value,
            )

            # Update event with AI analysis results if we have the original event
            if original_event:
                original_event.processed_data["ai_analysis"] = {
                    "job_id": result.job_id,
                    "analysis_type": result.analysis_type.value,
                    "confidence_score": result.confidence_score,
                    "threat_level": result.threat_level.value,
                    "recommendations": result.recommendations,
                    "iocs": result.iocs,
                    "timestamp": result.timestamp.isoformat(),
                    "providers_used": result.metadata.get("providers_used", []),
                }

                # Update event in storage
                await self._update_event_storage(original_event)

            # Generate alerts for high-confidence, high-threat results
            if result.confidence_score >= 0.8 and result.threat_level in [
                ThreatLevel.HIGH,
                ThreatLevel.CRITICAL,
            ]:
                await self._generate_ai_alert(result, original_event)

            # Store AI analysis results
            await self._store_ai_analysis_result(result)

        except Exception as e:
            logger.error("Error handling AI analysis result", error=str(e))

    async def _update_event_storage(self, event: BaseEvent):
        """Update event in storage backends with AI analysis results"""
        try:
            update_tasks = []

            if self.elasticsearch:
                update_tasks.append(self._update_elasticsearch_event(event))

            if self.mongodb:
                update_tasks.append(self._update_mongodb_event(event))

            if update_tasks:
                await asyncio.gather(*update_tasks, return_exceptions=True)

        except Exception as e:
            logger.error(
                "Error updating event storage", event_id=event.id, error=str(e)
            )

    async def _update_elasticsearch_event(self, event: BaseEvent):
        """Update event in Elasticsearch with AI analysis results"""
        try:
            index_name = f"aaa-events-{event.timestamp.strftime('%Y-%m')}"

            await self.elasticsearch.update(
                index=index_name,
                id=event.id,
                body={
                    "doc": {
                        "processed_data": event.processed_data,
                        "ai_analysis_updated": datetime.utcnow().isoformat(),
                    }
                },
            )

        except Exception as e:
            logger.error(
                "Error updating Elasticsearch event", event_id=event.id, error=str(e)
            )

    async def _update_mongodb_event(self, event: BaseEvent):
        """Update event in MongoDB with AI analysis results"""
        try:
            await self.events_collection.update_one(
                {"id": event.id},
                {
                    "$set": {
                        "processed_data": event.processed_data,
                        "ai_analysis_updated": datetime.utcnow(),
                    }
                },
            )

        except Exception as e:
            logger.error(
                "Error updating MongoDB event", event_id=event.id, error=str(e)
            )

    async def _generate_ai_alert(
        self, result, original_event: Optional[BaseEvent] = None
    ):
        """Generate alert based on AI analysis results"""
        try:
            alert_data = {
                "alert_id": f"ai-{result.job_id}",
                "type": "ai_analysis",
                "severity": (
                    "high" if result.threat_level == ThreatLevel.HIGH else "critical"
                ),
                "title": f"AI Detection: {result.analysis_type.value.replace('_', ' ').title()}",
                "description": f"AI analysis detected {result.threat_level.value} threat with {result.confidence_score:.1%} confidence",
                "confidence_score": result.confidence_score,
                "threat_level": result.threat_level.value,
                "recommendations": result.recommendations,
                "iocs": result.iocs,
                "timestamp": result.timestamp.isoformat(),
                "analysis_job_id": result.job_id,
                "events_analyzed": result.events_analyzed,
            }

            if original_event:
                alert_data["original_event"] = {
                    "id": original_event.id,
                    "source": original_event.source.value,
                    "event_type": original_event.event_type.value,
                    "message": original_event.message,
                }

            # Send alert through configured channels
            # This would integrate with alerting systems like:
            # - Slack
            # - Email
            # - PagerDuty
            # - Webhooks

            logger.warning(
                "AI analysis alert generated",
                alert_id=alert_data["alert_id"],
                threat_level=result.threat_level.value,
                confidence=result.confidence_score,
            )

        except Exception as e:
            logger.error("Error generating AI alert", error=str(e))

    async def _store_ai_analysis_result(self, result):
        """Store AI analysis results for historical analysis"""
        try:
            # Store in dedicated AI analysis index/collection
            result_data = {
                "job_id": result.job_id,
                "analysis_type": result.analysis_type.value,
                "events_analyzed": result.events_analyzed,
                "confidence_score": result.confidence_score,
                "threat_level": result.threat_level.value,
                "recommendations": result.recommendations,
                "iocs": result.iocs,
                "processing_time": result.processing_time,
                "timestamp": result.timestamp.isoformat(),
                "metadata": result.metadata,
                "providers_used": result.metadata.get("providers_used", []),
            }

            # Store in Elasticsearch
            if self.elasticsearch:
                await self.elasticsearch.index(
                    index=f"aaa-ai-analysis-{datetime.utcnow().strftime('%Y-%m')}",
                    id=result.job_id,
                    body=result_data,
                )

            # Store in MongoDB
            if self.mongodb:
                ai_collection = self.db.ai_analysis_results
                result_data["_id"] = result.job_id
                await ai_collection.insert_one(result_data)

        except Exception as e:
            logger.error(
                "Error storing AI analysis result", job_id=result.job_id, error=str(e)
            )

    async def _stream_event(self, event: BaseEvent):
        """Stream event to real-time subscribers"""
        try:
            # Send event to all active streams that match filters
            for stream_id, stream_queue in self.event_streams.items():
                try:
                    filters = self.stream_filters.get(stream_id, {})

                    if self._event_matches_filters(event, filters):
                        await stream_queue.put(event)

                except Exception as e:
                    logger.error(
                        "Error streaming to subscriber",
                        stream_id=stream_id,
                        error=str(e),
                    )

        except Exception as e:
            logger.error("Error streaming event", error=str(e))

    def _event_matches_filters(self, event: BaseEvent, filters: Dict[str, Any]) -> bool:
        """Check if event matches stream filters"""
        try:
            # Check source filter
            if "sources" in filters:
                if event.source not in filters["sources"]:
                    return False

            # Check event type filter
            if "event_types" in filters:
                if event.event_type not in filters["event_types"]:
                    return False

            # Check severity filter
            if "severities" in filters:
                if event.severity not in filters["severities"]:
                    return False

            return True

        except Exception as e:
            logger.error("Error checking event filters", error=str(e))
            return False

    async def search_events(self, request: EventSearchRequest) -> EventSearchResponse:
        """Search events based on criteria"""
        try:
            # Use Elasticsearch if available, otherwise MongoDB
            if self.elasticsearch:
                return await self._search_elasticsearch(request)
            elif self.mongodb:
                return await self._search_mongodb(request)
            else:
                raise Exception("No search backend available")

        except Exception as e:
            logger.error("Error searching events", error=str(e))
            raise

    async def _search_elasticsearch(
        self, request: EventSearchRequest
    ) -> EventSearchResponse:
        """Search events using Elasticsearch"""
        try:
            # Build query
            query = {"bool": {"must": []}}

            # Add filters
            if request.sources:
                query["bool"]["must"].append({"terms": {"source": request.sources}})

            if request.event_types:
                query["bool"]["must"].append(
                    {"terms": {"event_type": request.event_types}}
                )

            if request.severities:
                query["bool"]["must"].append(
                    {"terms": {"severity": request.severities}}
                )

            # Time range filter
            if request.start_time or request.end_time:
                time_filter = {"range": {"timestamp": {}}}
                if request.start_time:
                    time_filter["range"]["timestamp"][
                        "gte"
                    ] = request.start_time.isoformat()
                if request.end_time:
                    time_filter["range"]["timestamp"][
                        "lte"
                    ] = request.end_time.isoformat()
                query["bool"]["must"].append(time_filter)

            # Text search
            if request.query:
                query["bool"]["must"].append(
                    {
                        "multi_match": {
                            "query": request.query,
                            "fields": ["message", "processed_data.*"],
                        }
                    }
                )

            # Execute search
            start_time = time.time()

            result = await self.elasticsearch.search(
                index="aaa-events-*",
                body={
                    "query": query,
                    "from": request.offset,
                    "size": request.limit,
                    "sort": [{request.sort_by: {"order": request.sort_order}}],
                },
            )

            query_time = time.time() - start_time

            # Convert results
            events = []
            for hit in result["hits"]["hits"]:
                event_data = hit["_source"]
                # Convert back to BaseEvent (simplified)
                events.append(BaseEvent(**event_data))

            return EventSearchResponse(
                events=events,
                total_count=result["hits"]["total"]["value"],
                limit=request.limit,
                offset=request.offset,
                query_time=query_time,
            )

        except Exception as e:
            logger.error("Error searching Elasticsearch", error=str(e))
            raise

    async def _search_mongodb(self, request: EventSearchRequest) -> EventSearchResponse:
        """Search events using MongoDB"""
        try:
            # Build MongoDB query
            query = {}

            # Add filters
            if request.sources:
                query["source"] = {"$in": request.sources}

            if request.event_types:
                query["event_type"] = {"$in": request.event_types}

            if request.severities:
                query["severity"] = {"$in": request.severities}

            # Time range filter
            if request.start_time or request.end_time:
                time_filter = {}
                if request.start_time:
                    time_filter["$gte"] = request.start_time
                if request.end_time:
                    time_filter["$lte"] = request.end_time
                query["timestamp"] = time_filter

            # Text search
            if request.query:
                query["$text"] = {"$search": request.query}

            # Execute search
            start_time = time.time()

            # Get total count
            total_count = await self.events_collection.count_documents(query)

            # Get results
            sort_direction = -1 if request.sort_order == "desc" else 1
            cursor = (
                self.events_collection.find(query)
                .sort(request.sort_by, sort_direction)
                .skip(request.offset)
                .limit(request.limit)
            )

            events = []
            async for doc in cursor:
                # Remove MongoDB _id field
                doc.pop("_id", None)
                events.append(BaseEvent(**doc))

            query_time = time.time() - start_time

            return EventSearchResponse(
                events=events,
                total_count=total_count,
                limit=request.limit,
                offset=request.offset,
                query_time=query_time,
            )

        except Exception as e:
            logger.error("Error searching MongoDB", error=str(e))
            raise

    async def get_event_by_id(self, event_id: str) -> Optional[BaseEvent]:
        """Get event by ID"""
        try:
            if self.elasticsearch:
                result = await self.elasticsearch.get(index="aaa-events-*", id=event_id)
                return BaseEvent(**result["_source"])
            elif self.mongodb:
                doc = await self.events_collection.find_one({"id": event_id})
                if doc:
                    doc.pop("_id", None)
                    return BaseEvent(**doc)

            return None

        except Exception as e:
            logger.error("Error getting event by ID", event_id=event_id, error=str(e))
            return None

    async def stream_events(
        self,
        sources: Optional[List[LogSource]] = None,
        event_types: Optional[List[EventType]] = None,
        severities: Optional[List[Severity]] = None,
    ) -> AsyncGenerator[BaseEvent, None]:
        """Stream real-time events"""
        try:
            # Create stream ID and queue
            stream_id = f"stream-{int(time.time())}"
            stream_queue = asyncio.Queue(maxsize=1000)

            # Set up filters
            filters = {}
            if sources:
                filters["sources"] = sources
            if event_types:
                filters["event_types"] = event_types
            if severities:
                filters["severities"] = severities

            # Register stream
            self.event_streams[stream_id] = stream_queue
            self.stream_filters[stream_id] = filters

            try:
                while True:
                    # Get event from stream queue
                    event = await asyncio.wait_for(stream_queue.get(), timeout=30.0)
                    yield event

            except asyncio.TimeoutError:
                # Stream timeout, cleanup and exit
                pass
            finally:
                # Cleanup stream
                self.event_streams.pop(stream_id, None)
                self.stream_filters.pop(stream_id, None)

        except Exception as e:
            logger.error("Error in event stream", error=str(e))

    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics"""
        current_time = datetime.utcnow()
        uptime = (current_time - self.stats["last_reset"]).total_seconds()

        return {
            **self.stats,
            "uptime_seconds": uptime,
            "events_per_second": (
                self.stats["total_events"] / uptime if uptime > 0 else 0
            ),
            "queue_sizes": {
                "processing": self.processing_queue.qsize(),
                "high_priority": self.high_priority_queue.qsize(),
            },
        }

    async def normalize_api_data(self, event: BaseEvent) -> BaseEvent:
        """Normalize API-specific data formats for consistent processing"""
        try:
            # Handle Kubernetes API data normalization
            if event.source == LogSource.KUBERNETES:
                event = await self._normalize_kubernetes_data(event)

            # Handle LXD API data normalization
            elif event.source == LogSource.LXC_LXD:
                event = await self._normalize_lxd_data(event)

            # Handle database query results
            elif "database_row" in event.raw_data:
                event = await self._normalize_database_data(event)

            # Handle syslog message normalization
            elif "syslog_message" in event.raw_data:
                event = await self._normalize_syslog_data(event)

            # Handle journald entry normalization
            elif "journald_entry" in event.raw_data:
                event = await self._normalize_journald_data(event)

            return event

        except Exception as e:
            logger.error("Error normalizing API data", error=str(e), event_id=event.id)
            return event

    async def _normalize_kubernetes_data(self, event: BaseEvent) -> BaseEvent:
        """Normalize Kubernetes API data"""
        try:
            # Extract structured data from Kubernetes API responses
            if "k8s_object" in event.raw_data:
                k8s_obj = event.raw_data["k8s_object"]

                # Extract common Kubernetes metadata
                event.processed_data.update(
                    {
                        "namespace": k8s_obj.get("metadata", {}).get("namespace"),
                        "resource_name": k8s_obj.get("metadata", {}).get("name"),
                        "resource_kind": k8s_obj.get("kind"),
                        "api_version": k8s_obj.get("apiVersion"),
                        "cluster_name": event.raw_data.get("cluster_name"),
                    }
                )

            # Handle pod logs with structured format
            if "pod_logs" in event.raw_data:
                logs = event.raw_data["pod_logs"]
                if isinstance(logs, str):
                    # Try to parse as JSON if it looks like structured logs
                    try:
                        import json

                        log_data = json.loads(logs)
                        event.processed_data["structured_log"] = log_data
                    except json.JSONDecodeError:
                        # Keep as plain text
                        event.processed_data["log_text"] = logs

            return event

        except Exception as e:
            logger.error("Error normalizing Kubernetes data", error=str(e))
            return event

    async def _normalize_lxd_data(self, event: BaseEvent) -> BaseEvent:
        """Normalize LXD API data"""
        try:
            # Extract structured data from LXD API responses
            if "lxd_event" in event.raw_data:
                lxd_event = event.raw_data["lxd_event"]

                # Extract LXD metadata
                metadata = lxd_event.get("metadata", {})
                event.processed_data.update(
                    {
                        "lxd_operation": lxd_event.get("type"),
                        "container_name": metadata.get("name"),
                        "container_description": metadata.get("description"),
                        "operation_status": metadata.get("status"),
                        "operation_class": metadata.get("class"),
                        "endpoint_url": event.raw_data.get("endpoint"),
                    }
                )

            # Handle container state information
            if "container_state" in event.raw_data:
                state = event.raw_data["container_state"]
                event.processed_data.update(
                    {
                        "container_status": state.get("status"),
                        "container_status_code": state.get("status_code"),
                        "memory_usage": state.get("memory", {}).get("usage"),
                        "cpu_usage": state.get("cpu", {}).get("usage"),
                    }
                )

            return event

        except Exception as e:
            logger.error("Error normalizing LXD data", error=str(e))
            return event

    async def _normalize_database_data(self, event: BaseEvent) -> BaseEvent:
        """Normalize database query result data"""
        try:
            db_row = event.raw_data.get("database_row", {})

            # Extract common database fields into processed_data
            event.processed_data.update(
                {
                    "query_id": event.raw_data.get("query_id"),
                    "connection_id": event.raw_data.get("connection_id"),
                    "table_name": db_row.get("table_name"),
                    "record_id": db_row.get("id") or db_row.get("record_id"),
                }
            )

            # Handle time-based fields
            for time_field in ["created_at", "updated_at", "logged_at", "event_time"]:
                if time_field in db_row:
                    try:
                        if isinstance(db_row[time_field], str):
                            from datetime import datetime

                            parsed_time = datetime.fromisoformat(
                                db_row[time_field].replace("Z", "+00:00")
                            )
                            event.processed_data[f"{time_field}_parsed"] = parsed_time
                    except Exception:
                        pass

            return event

        except Exception as e:
            logger.error("Error normalizing database data", error=str(e))
            return event

    async def _normalize_syslog_data(self, event: BaseEvent) -> BaseEvent:
        """Normalize syslog message data"""
        try:
            # Extract syslog-specific fields
            event.processed_data.update(
                {
                    "syslog_facility": event.raw_data.get("syslog_facility"),
                    "syslog_severity": event.raw_data.get("syslog_severity"),
                    "syslog_hostname": event.raw_data.get("syslog_hostname"),
                    "syslog_tag": event.raw_data.get("syslog_tag"),
                    "syslog_protocol": event.raw_data.get("syslog_protocol"),
                    "syslog_source": event.raw_data.get("syslog_source"),
                }
            )

            # Parse structured data from syslog messages
            message = event.message

            # Try to extract key-value pairs from message
            import re

            kv_pattern = r"(\w+)=([^\s]+)"
            matches = re.findall(kv_pattern, message)
            if matches:
                event.processed_data["extracted_fields"] = dict(matches)

            return event

        except Exception as e:
            logger.error("Error normalizing syslog data", error=str(e))
            return event

    async def _normalize_journald_data(self, event: BaseEvent) -> BaseEvent:
        """Normalize journald entry data"""
        try:
            journald_entry = event.raw_data.get("journald_entry", {})

            # Extract systemd/journald specific fields
            event.processed_data.update(
                {
                    "systemd_unit": journald_entry.get("_SYSTEMD_UNIT"),
                    "systemd_user_unit": journald_entry.get("_SYSTEMD_USER_UNIT"),
                    "systemd_slice": journald_entry.get("_SYSTEMD_SLICE"),
                    "hostname": journald_entry.get("_HOSTNAME"),
                    "machine_id": journald_entry.get("_MACHINE_ID"),
                    "boot_id": journald_entry.get("_BOOT_ID"),
                    "process_name": journald_entry.get("_COMM"),
                    "process_id": journald_entry.get("_PID"),
                    "user_id": journald_entry.get("_UID"),
                    "group_id": journald_entry.get("_GID"),
                    "priority": journald_entry.get("PRIORITY"),
                    "transport": journald_entry.get("_TRANSPORT"),
                }
            )

            # Handle journald timestamps (microseconds since epoch)
            realtime_timestamp = journald_entry.get("__REALTIME_TIMESTAMP")
            if realtime_timestamp:
                try:
                    from datetime import datetime

                    parsed_time = datetime.fromtimestamp(
                        int(realtime_timestamp) / 1000000
                    )
                    event.processed_data["journald_realtime"] = parsed_time
                except Exception:
                    pass

            return event

        except Exception as e:
            logger.error("Error normalizing journald data", error=str(e))
            return event

    async def handle_pagination(
        self, source: str, cursor: Optional[str] = None, limit: int = 1000
    ) -> Dict[str, Any]:
        """Handle paginated API responses"""
        try:
            pagination_info = {
                "source": source,
                "limit": limit,
                "cursor": cursor,
                "has_more": False,
                "next_cursor": None,
                "total_count": None,
            }

            # Store pagination state for incremental collection
            if not hasattr(self, "pagination_state"):
                self.pagination_state = {}

            self.pagination_state[source] = pagination_info

            return pagination_info

        except Exception as e:
            logger.error("Error handling pagination", error=str(e), source=source)
            return {}

    async def implement_backfill(
        self, source: str, start_time: datetime, end_time: Optional[datetime] = None
    ) -> int:
        """Implement backfill capabilities for missed logs"""
        try:
            if end_time is None:
                end_time = datetime.utcnow()

            logger.info(
                "Starting backfill operation",
                source=source,
                start_time=start_time,
                end_time=end_time,
            )

            # Track backfill progress
            backfill_count = 0

            # This would be implemented by specific collectors
            # For now, we'll return a placeholder count

            logger.info(
                "Backfill operation completed",
                source=source,
                events_backfilled=backfill_count,
            )

            return backfill_count

        except Exception as e:
            logger.error("Error in backfill operation", error=str(e), source=source)
            return 0

    async def get_processing_stats(self) -> Dict[str, Any]:
        """Get enhanced processing statistics"""
        try:
            current_time = datetime.utcnow()
            uptime = current_time - self.stats["last_reset"]

            stats = {
                "uptime_seconds": uptime.total_seconds(),
                "total_events": self.stats["total_events"],
                "events_per_second": self.stats["total_events"]
                / max(uptime.total_seconds(), 1),
                "processing_errors": self.stats["processing_errors"],
                "error_rate": self.stats["processing_errors"]
                / max(self.stats["total_events"], 1),
                "events_by_source": dict(self.stats["events_by_source"]),
                "events_by_type": dict(self.stats["events_by_type"]),
                "events_by_severity": dict(self.stats["events_by_severity"]),
                "queue_sizes": {
                    "processing": self.processing_queue.qsize(),
                    "high_priority": self.high_priority_queue.qsize(),
                },
                "worker_count": len(self.workers),
                "storage_backends": {
                    "elasticsearch": bool(self.elasticsearch),
                    "mongodb": bool(self.mongodb),
                },
                "deduplication_cache_size": len(self.dedup_cache),
                "ai_analysis": {
                    "enabled": self.ai_enabled,
                    "engine_available": bool(self.ai_analysis_engine),
                    "analyses_triggered": self.stats["ai_analyses_triggered"],
                    "analyses_completed": self.stats["ai_analyses_completed"],
                    "active_jobs": len(self.ai_analysis_jobs),
                    "completion_rate": (
                        self.stats["ai_analyses_completed"]
                        / max(self.stats["ai_analyses_triggered"], 1)
                    ),
                    "buffer_sizes": {
                        key: len(events) for key, events in self.ai_event_buffer.items()
                    },
                },
            }

            # Add AI engine statistics if available
            if self.ai_analysis_engine:
                ai_engine_stats = await self.ai_analysis_engine.get_statistics()
                stats["ai_analysis"]["engine_stats"] = ai_engine_stats

            return stats

        except Exception as e:
            logger.error("Error getting processing stats", error=str(e))
            return {}

    async def stop(self):
        """Stop log processor"""
        self.running = False

        # Cancel all workers
        for worker in self.workers:
            worker.cancel()

        # Wait for workers to complete
        if self.workers:
            await asyncio.gather(*self.workers, return_exceptions=True)

        # Close connections
        if self.elasticsearch:
            await self.elasticsearch.close()

        if self.mongodb:
            self.mongodb.close()

        logger.info("Log processor stopped")
