"""
SkausWatch AAA Monitor Service - Kubernetes Collector

Completely clientless Kubernetes log collector that monitors pod logs, audit logs,
event streams, authentication events, and RBAC violations using direct API calls.
No agents or log forwarding required.
"""

import asyncio
import base64
import json
import logging
import os
import re
import ssl
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional
from urllib.parse import urlencode, urljoin

import aiohttp
import structlog
import yaml

from ..models import (
    AuthenticationEvent,
    AuthorizationEvent,
    BaseEvent,
    ContainerEvent,
    EventType,
    LogSource,
    Severity,
)

logger = structlog.get_logger(__name__)


class KubernetesCollector:
    """Kubernetes log collector for AAA monitoring"""

    def __init__(self, config, log_processor, analysis_engine):
        """Initialize Kubernetes collector

        Args:
            config: Kubernetes collector configuration (dataclass)
            log_processor: Log processor instance
            analysis_engine: Analysis engine instance
        """
        self.config = config
        self.log_processor = log_processor
        self.analysis_engine = analysis_engine

        # API session management
        self.api_sessions = {}
        self.api_connectors = {}

        # Collection state
        self.running = False
        self.collection_tasks = []

        # Log streaming state
        self.log_positions = {}  # Track log positions per pod
        self.watch_resources = {}  # Track resource versions for watch APIs

        # Event patterns for analysis
        self.auth_patterns = {
            "failed_login": re.compile(
                r"authentication failed|login failed|invalid credentials", re.IGNORECASE
            ),
            "successful_login": re.compile(
                r"authentication successful|login successful|authenticated",
                re.IGNORECASE,
            ),
            "permission_denied": re.compile(
                r"permission denied|access denied|forbidden|unauthorized", re.IGNORECASE
            ),
            "token_expired": re.compile(
                r"token expired|token invalid|expired token", re.IGNORECASE
            ),
            "service_account": re.compile(
                r"service account|serviceaccount", re.IGNORECASE
            ),
            "rbac_violation": re.compile(
                r"rbac.*denied|role.*denied|rolebinding.*denied", re.IGNORECASE
            ),
        }

        self.container_patterns = {
            "started": re.compile(r"container.*started|pod.*started", re.IGNORECASE),
            "stopped": re.compile(r"container.*stopped|pod.*stopped", re.IGNORECASE),
            "failed": re.compile(r"container.*failed|pod.*failed", re.IGNORECASE),
            "killed": re.compile(r"container.*killed|pod.*killed", re.IGNORECASE),
            "oom_killed": re.compile(r"oom.*killed|out of memory", re.IGNORECASE),
            "image_pull_failed": re.compile(
                r"image.*pull.*failed|failed.*pull.*image", re.IGNORECASE
            ),
        }

        # Audit log patterns
        self.audit_patterns = {
            "create": re.compile(r'"verb":\s*"create"'),
            "delete": re.compile(r'"verb":\s*"delete"'),
            "update": re.compile(r'"verb":\s*"update"'),
            "get": re.compile(r'"verb":\s*"get"'),
            "list": re.compile(r'"verb":\s*"list"'),
            "watch": re.compile(r'"verb":\s*"watch"'),
            "patch": re.compile(r'"verb":\s*"patch"'),
            "escalate": re.compile(r'"verb":\s*"escalate"'),
            "impersonate": re.compile(r'"verb":\s*"impersonate"'),
        }

    async def initialize(self):
        """Initialize Kubernetes API connections"""
        try:
            # Initialize HTTP sessions for each API server
            for i, api_config in enumerate(self.config.api_servers):
                session_id = f"k8s-{i}"

                # Create SSL context
                ssl_context = None

                # Check for Kubernetes in-cluster CA certificate (most common)
                k8s_ca_file = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
                if Path(k8s_ca_file).exists():
                    ssl_context = ssl.create_default_context(cafile=k8s_ca_file)
                elif not api_config.verify_ssl:
                    # Skip SSL verification in development (alpha)
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                elif api_config.ca_file:
                    ssl_context = ssl.create_default_context()
                    ssl_context.load_verify_locations(api_config.ca_file)
                else:
                    ssl_context = ssl.create_default_context()

                if api_config.cert_file and api_config.key_file:
                    ssl_context.load_cert_chain(
                        api_config.cert_file, api_config.key_file
                    )

                # Create connector with connection pooling
                connector = aiohttp.TCPConnector(
                    ssl=ssl_context,
                    limit=self.config.max_connections,
                    limit_per_host=self.config.connection_pool_size,
                    ttl_dns_cache=300,
                    use_dns_cache=True,
                    keepalive_timeout=30,
                    enable_cleanup_closed=True,
                )
                self.api_connectors[session_id] = connector

                # Create HTTP session
                timeout = aiohttp.ClientTimeout(total=api_config.timeout)
                session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    headers=await self._build_auth_headers(api_config),
                )
                self.api_sessions[session_id] = {
                    "session": session,
                    "config": api_config,
                    "base_url": api_config.server.rstrip("/"),
                }

                # Test connection
                await self._test_api_connection(session_id)

            logger.info(
                "Kubernetes collector initialized successfully",
                api_servers=len(self.api_sessions),
            )

        except Exception as e:
            logger.error("Failed to initialize Kubernetes collector", error=str(e))
            raise

    async def _build_auth_headers(self, api_config) -> Dict[str, str]:
        """Build authentication headers for API requests"""
        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        # Token authentication (preferred)
        if api_config.token:
            headers["Authorization"] = f"Bearer {api_config.token}"
        elif api_config.token_file:
            try:
                with open(api_config.token_file, "r") as f:
                    token = f.read().strip()
                headers["Authorization"] = f"Bearer {token}"
            except Exception as e:
                logger.error(
                    "Failed to read token file",
                    file=api_config.token_file,
                    error=str(e),
                )
                raise

        return headers

    async def _test_api_connection(self, session_id: str):
        """Test Kubernetes API connection"""
        try:
            session_info = self.api_sessions[session_id]
            session = session_info["session"]
            base_url = session_info["base_url"]

            # Test basic API access
            version_url = urljoin(base_url, "/version")
            async with session.get(version_url) as response:
                if response.status == 200:
                    version_data = await response.json()
                    logger.info(
                        "Kubernetes API connection successful",
                        server=base_url,
                        version=version_data.get("gitVersion"),
                    )
                else:
                    raise Exception(f"API version check failed: {response.status}")

            # Test namespace access
            ns_url = urljoin(base_url, "/api/v1/namespaces")
            async with session.get(ns_url) as response:
                if response.status == 200:
                    ns_data = await response.json()
                    ns_count = len(ns_data.get("items", []))
                    logger.info(
                        "Kubernetes namespace access verified",
                        server=base_url,
                        namespace_count=ns_count,
                    )
                else:
                    logger.warning(
                        "Limited namespace access",
                        server=base_url,
                        status=response.status,
                    )

        except Exception as e:
            logger.error(
                "Kubernetes API connection test failed",
                session_id=session_id,
                error=str(e),
            )
            raise

    async def start_collection(self):
        """Start log collection from Kubernetes"""
        if self.running:
            logger.warning("Kubernetes collector already running")
            return

        self.running = True
        logger.info("Starting Kubernetes log collection")

        try:
            # Start different collection streams
            if getattr(self.config, "collect_pod_logs", True):
                task = asyncio.create_task(self._collect_pod_logs())
                self.collection_tasks.append(task)

            if getattr(self.config, "collect_events", True):
                task = asyncio.create_task(self._collect_events())
                self.collection_tasks.append(task)

            if getattr(self.config, "collect_audit_logs", True):
                task = asyncio.create_task(self._collect_audit_logs())
                self.collection_tasks.append(task)

            if getattr(self.config, "monitor_rbac", True):
                task = asyncio.create_task(self._monitor_rbac_violations())
                self.collection_tasks.append(task)

            # Wait for all tasks
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)

        except Exception as e:
            logger.error("Error in Kubernetes log collection", error=str(e))
        finally:
            self.running = False

    async def stop(self):
        """Stop log collection"""
        self.running = False

        # Cancel all collection tasks
        for task in self.collection_tasks:
            if not task.done():
                task.cancel()

        # Wait for tasks to complete
        if self.collection_tasks:
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)

        self.collection_tasks.clear()

        # Close all HTTP sessions
        for session_info in self.api_sessions.values():
            await session_info["session"].close()

        # Close all connectors
        for connector in self.api_connectors.values():
            await connector.close()

        self.api_sessions.clear()
        self.api_connectors.clear()

        logger.info("Kubernetes collector stopped")

    async def _collect_pod_logs(self):
        """Collect logs from pods using direct API calls"""
        logger.info("Starting pod log collection")

        try:
            while self.running:
                # Process each API server
                for session_id in self.api_sessions.keys():
                    if not self.running:
                        break

                    try:
                        await self._collect_logs_from_server(session_id)
                    except Exception as e:
                        logger.error(
                            "Error collecting from API server",
                            session_id=session_id,
                            error=str(e),
                        )

                # Wait before next collection cycle
                await asyncio.sleep(self.config.log_poll_interval)

        except asyncio.CancelledError:
            logger.info("Pod log collection cancelled")
        except Exception as e:
            logger.error("Fatal error in pod log collection", error=str(e))

    async def _collect_logs_from_server(self, session_id: str):
        """Collect logs from a specific API server"""
        session_info = self.api_sessions[session_id]
        session = session_info["session"]
        base_url = session_info["base_url"]

        try:
            # Get namespaces to monitor
            namespaces = self.config.namespaces
            if not namespaces or "all" in namespaces:
                namespaces = await self._get_all_namespaces(session, base_url)

            # Process each namespace
            for namespace in namespaces:
                if not self.running:
                    break
                await self._process_namespace_logs_api(session, base_url, namespace)

        except Exception as e:
            logger.error(
                "Error collecting logs from server", session_id=session_id, error=str(e)
            )

    async def _get_all_namespaces(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> List[str]:
        """Get all available namespaces"""
        try:
            ns_url = urljoin(base_url, "/api/v1/namespaces")
            async with session.get(ns_url) as response:
                if response.status == 200:
                    ns_data = await response.json()
                    return [
                        item["metadata"]["name"] for item in ns_data.get("items", [])
                    ]
                else:
                    logger.warning(
                        "Failed to get namespaces, using default",
                        status=response.status,
                    )
                    return ["default"]
        except Exception as e:
            logger.error("Error getting namespaces", error=str(e))
            return ["default"]

    async def _process_namespace_logs_api(
        self, session: aiohttp.ClientSession, base_url: str, namespace: str
    ):
        """Process logs for a specific namespace using API calls"""
        try:
            # Get pods in namespace
            pods_url = urljoin(base_url, f"/api/v1/namespaces/{namespace}/pods")
            async with session.get(pods_url) as response:
                if response.status != 200:
                    logger.warning(
                        "Failed to get pods",
                        namespace=namespace,
                        status=response.status,
                    )
                    return

                pods_data = await response.json()

                # Process each pod
                for pod_item in pods_data.get("items", []):
                    if not self.running:
                        break

                    await self._process_pod_logs_api(
                        session, base_url, pod_item, namespace
                    )

        except Exception as e:
            logger.error(
                "Error processing namespace logs", namespace=namespace, error=str(e)
            )

    async def _process_pod_logs_api(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        pod_item: Dict,
        namespace: str,
    ):
        """Process logs for a specific pod using API calls"""
        try:
            pod_name = pod_item["metadata"]["name"]
            pod_uid = pod_item["metadata"]["uid"]

            # Get containers from pod spec
            containers = pod_item.get("spec", {}).get("containers", [])

            # Process each container
            for container in containers:
                container_name = container["name"]

                try:
                    await self._collect_container_logs_api(
                        session, base_url, namespace, pod_name, container_name, pod_uid
                    )

                except Exception as e:
                    logger.error(
                        "Error processing pod container logs",
                        pod=pod_name,
                        container=container_name,
                        namespace=namespace,
                        error=str(e),
                    )

        except Exception as e:
            logger.error(
                "Error processing pod logs",
                pod=pod_item.get("metadata", {}).get("name"),
                error=str(e),
            )

    async def _collect_container_logs_api(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        namespace: str,
        pod_name: str,
        container_name: str,
        pod_uid: str,
    ):
        """Collect logs for a container using Kubernetes logs API"""
        try:
            # Build log position key
            position_key = f"{namespace}/{pod_name}/{container_name}"

            # Build logs URL with parameters
            logs_url = urljoin(
                base_url, f"/api/v1/namespaces/{namespace}/pods/{pod_name}/log"
            )

            params = {
                "container": container_name,
                "timestamps": "true",
                "sinceSeconds": self.config.log_since_seconds,
                "tailLines": self.config.log_lines_per_request,
            }

            # Add position tracking if available
            if position_key in self.log_positions:
                params["sinceTime"] = self.log_positions[position_key].isoformat() + "Z"

            # Make API request
            async with session.get(logs_url, params=params) as response:
                if response.status == 200:
                    logs_text = await response.text()

                    if logs_text.strip():
                        # Update position
                        self.log_positions[position_key] = datetime.utcnow()

                        # Parse and process logs
                        await self._parse_pod_logs(
                            logs_text, pod_name, container_name, namespace
                        )

                elif response.status == 404:
                    # Pod/container not found - might be terminated
                    logger.debug(
                        "Pod/container logs not found (terminated?)",
                        pod=pod_name,
                        container=container_name,
                    )
                else:
                    logger.warning(
                        "Failed to get container logs",
                        pod=pod_name,
                        container=container_name,
                        status=response.status,
                    )

        except Exception as e:
            logger.error(
                "Error collecting container logs via API",
                pod=pod_name,
                container=container_name,
                error=str(e),
            )

    async def _parse_pod_logs(
        self, logs: str, pod_name: str, container_name: str, namespace: str
    ):
        """Parse pod logs and create events"""
        try:
            log_lines = logs.strip().split("\n")

            for line in log_lines:
                if not line.strip():
                    continue

                # Try to extract timestamp
                timestamp = datetime.utcnow()
                try:
                    # Common log timestamp patterns
                    timestamp_patterns = [
                        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)",  # ISO format
                        r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})",  # YYYY/MM/DD format
                        r"(\w{3} \d{2} \d{2}:\d{2}:\d{2})",  # syslog format
                    ]

                    for pattern in timestamp_patterns:
                        match = re.search(pattern, line)
                        if match:
                            timestamp_str = match.group(1)
                            # Parse timestamp based on format
                            try:
                                timestamp = datetime.fromisoformat(
                                    timestamp_str.rstrip("Z")
                                )
                            except:
                                # Fallback parsing
                                pass
                            break
                except Exception:
                    # Use current time if parsing fails
                    pass

                # Classify log line
                event_type, severity = await self._classify_log_line(line)

                # Create appropriate event based on classification
                if event_type == EventType.AUTHENTICATION:
                    event = await self._create_auth_event(
                        line, pod_name, container_name, namespace, timestamp
                    )
                elif event_type == EventType.AUTHORIZATION:
                    event = await self._create_authz_event(
                        line, pod_name, container_name, namespace, timestamp
                    )
                elif event_type == EventType.CONTAINER_EVENT:
                    event = await self._create_container_event(
                        line, pod_name, container_name, namespace, timestamp
                    )
                else:
                    # Generic event
                    event = BaseEvent(
                        source=LogSource.KUBERNETES,
                        event_type=event_type,
                        severity=severity,
                        message=line,
                        timestamp=timestamp,
                        raw_data={
                            "pod_name": pod_name,
                            "container_name": container_name,
                            "namespace": namespace,
                            "log_line": line,
                        },
                        tags=["kubernetes", "pod-logs", namespace, pod_name],
                    )

                # Send event for processing
                await self.log_processor.process_event(event)

        except Exception as e:
            logger.error("Error parsing pod logs", error=str(e))

    async def _classify_log_line(self, line: str) -> tuple[EventType, Severity]:
        """Classify log line to determine event type and severity"""
        line_lower = line.lower()

        # Check authentication patterns
        for pattern_name, pattern in self.auth_patterns.items():
            if pattern.search(line):
                if "failed" in pattern_name or "denied" in pattern_name:
                    return EventType.AUTHENTICATION, Severity.HIGH
                else:
                    return EventType.AUTHENTICATION, Severity.INFO

        # Check authorization patterns
        if "permission denied" in line_lower or "access denied" in line_lower:
            return EventType.AUTHORIZATION, Severity.HIGH
        elif "rbac" in line_lower:
            return EventType.AUTHORIZATION, Severity.MEDIUM

        # Check container patterns
        for pattern_name, pattern in self.container_patterns.items():
            if pattern.search(line):
                if pattern_name in ["failed", "killed", "oom_killed"]:
                    return EventType.CONTAINER_EVENT, Severity.HIGH
                else:
                    return EventType.CONTAINER_EVENT, Severity.INFO

        # Check for error/warning levels
        if any(word in line_lower for word in ["error", "fatal", "critical"]):
            return EventType.SYSTEM_CALL, Severity.HIGH
        elif any(word in line_lower for word in ["warning", "warn"]):
            return EventType.SYSTEM_CALL, Severity.MEDIUM
        elif any(word in line_lower for word in ["info", "debug"]):
            return EventType.SYSTEM_CALL, Severity.INFO

        # Default
        return EventType.ACCOUNTING, Severity.LOW

    async def _create_auth_event(
        self,
        line: str,
        pod_name: str,
        container_name: str,
        namespace: str,
        timestamp: datetime,
    ) -> AuthenticationEvent:
        """Create authentication event from log line"""
        # Extract authentication details
        username = None
        source_ip = None
        success = True
        method = None

        # Extract username
        username_patterns = [
            r"user[:\s]+([^\s,]+)",
            r"username[:\s]+([^\s,]+)",
            r"subject[:\s]+([^\s,]+)",
        ]

        for pattern in username_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                username = match.group(1)
                break

        # Extract IP address
        ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            source_ip = ip_match.group(1)

        # Determine success
        if any(
            word in line.lower() for word in ["failed", "error", "denied", "invalid"]
        ):
            success = False

        # Determine method
        if "token" in line.lower():
            method = "token"
        elif "certificate" in line.lower() or "cert" in line.lower():
            method = "certificate"
        elif "password" in line.lower():
            method = "password"

        return AuthenticationEvent(
            source=LogSource.KUBERNETES,
            event_type=EventType.AUTHENTICATION,
            severity=Severity.HIGH if not success else Severity.INFO,
            message=line,
            timestamp=timestamp,
            username=username,
            source_ip=source_ip,
            success=success,
            method=method,
            raw_data={
                "pod_name": pod_name,
                "container_name": container_name,
                "namespace": namespace,
                "log_line": line,
            },
            tags=["kubernetes", "authentication", namespace, pod_name],
        )

    async def _create_authz_event(
        self,
        line: str,
        pod_name: str,
        container_name: str,
        namespace: str,
        timestamp: datetime,
    ) -> AuthorizationEvent:
        """Create authorization event from log line"""
        username = None
        resource = None
        action = None
        result = "denied"

        # Extract details from line
        if "permission denied" in line.lower() or "access denied" in line.lower():
            result = "denied"
        elif "allowed" in line.lower() or "granted" in line.lower():
            result = "allowed"

        # Extract resource information
        resource_patterns = [
            r"resource[:\s]+([^\s,]+)",
            r"api[:\s]+([^\s,]+)",
            r"endpoint[:\s]+([^\s,]+)",
        ]

        for pattern in resource_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                resource = match.group(1)
                break

        return AuthorizationEvent(
            source=LogSource.KUBERNETES,
            event_type=EventType.AUTHORIZATION,
            severity=Severity.HIGH if result == "denied" else Severity.INFO,
            message=line,
            timestamp=timestamp,
            username=username,
            resource=resource,
            action=action,
            result=result,
            namespace=namespace,
            raw_data={
                "pod_name": pod_name,
                "container_name": container_name,
                "namespace": namespace,
                "log_line": line,
            },
            tags=["kubernetes", "authorization", namespace, pod_name],
        )

    async def _create_container_event(
        self,
        line: str,
        pod_name: str,
        container_name: str,
        namespace: str,
        timestamp: datetime,
    ) -> ContainerEvent:
        """Create container event from log line"""
        action = None
        exit_code = None

        # Determine action from patterns
        for pattern_name, pattern in self.container_patterns.items():
            if pattern.search(line):
                action = pattern_name
                break

        # Extract exit code if present
        exit_code_pattern = r"exit.*code[:\s]+(\d+)"
        exit_match = re.search(exit_code_pattern, line, re.IGNORECASE)
        if exit_match:
            exit_code = int(exit_match.group(1))

        return ContainerEvent(
            source=LogSource.KUBERNETES,
            event_type=EventType.CONTAINER_EVENT,
            severity=(
                Severity.HIGH
                if action in ["failed", "killed", "oom_killed"]
                else Severity.INFO
            ),
            message=line,
            timestamp=timestamp,
            container_name=container_name,
            pod_name=pod_name,
            namespace=namespace,
            action=action,
            exit_code=exit_code,
            raw_data={
                "pod_name": pod_name,
                "container_name": container_name,
                "namespace": namespace,
                "log_line": line,
            },
            tags=["kubernetes", "container", namespace, pod_name],
        )

    async def _collect_events(self):
        """Collect Kubernetes events using watch API"""
        logger.info("Starting Kubernetes events collection")

        try:
            while self.running:
                # Process each API server
                for session_id in self.api_sessions.keys():
                    if not self.running:
                        break

                    try:
                        await self._watch_events_from_server(session_id)
                    except Exception as e:
                        logger.error(
                            "Error watching events from API server",
                            session_id=session_id,
                            error=str(e),
                        )
                        await asyncio.sleep(30)

        except asyncio.CancelledError:
            logger.info("Kubernetes events collection cancelled")
        except Exception as e:
            logger.error("Fatal error in events collection", error=str(e))

    async def _watch_events_from_server(self, session_id: str):
        """Watch events from a specific API server using streaming"""
        session_info = self.api_sessions[session_id]
        session = session_info["session"]
        base_url = session_info["base_url"]

        try:
            # Build events watch URL
            events_url = urljoin(base_url, "/api/v1/events")

            params = {
                "watch": "true",
                "timeoutSeconds": self.config.event_watch_timeout,
            }

            # Add resource version for resume capability
            watch_key = f"{session_id}-events"
            if watch_key in self.watch_resources:
                params["resourceVersion"] = self.watch_resources[watch_key]

            # Stream events
            async with session.get(events_url, params=params) as response:
                if response.status != 200:
                    logger.error("Failed to watch events", status=response.status)
                    return

                async for line in response.content:
                    if not self.running:
                        break

                    try:
                        line_str = line.decode("utf-8").strip()
                        if line_str:
                            event_data = json.loads(line_str)

                            # Update resource version for resume
                            if (
                                "object" in event_data
                                and "metadata" in event_data["object"]
                            ):
                                resource_version = event_data["object"]["metadata"].get(
                                    "resourceVersion"
                                )
                                if resource_version:
                                    self.watch_resources[watch_key] = resource_version

                            await self._process_k8s_event(event_data)
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.error("Error processing event line", error=str(e))

        except Exception as e:
            logger.error("Error watching events", session_id=session_id, error=str(e))

    async def _process_k8s_event(self, event):
        """Process a Kubernetes event"""
        try:
            event_type = event["type"]  # ADDED, MODIFIED, DELETED
            k8s_event = event["object"]

            if event_type in ["ADDED", "MODIFIED"]:
                # Create event from Kubernetes event
                severity = await self._determine_event_severity(k8s_event)

                aaa_event = BaseEvent(
                    source=LogSource.KUBERNETES,
                    event_type=EventType.SYSTEM_CALL,
                    severity=severity,
                    message=k8s_event.message or "Kubernetes event",
                    timestamp=k8s_event.first_timestamp or datetime.utcnow(),
                    raw_data={
                        "kubernetes_event": {
                            "type": k8s_event.type,
                            "reason": k8s_event.reason,
                            "message": k8s_event.message,
                            "count": k8s_event.count,
                            "namespace": k8s_event.namespace,
                            "name": k8s_event.metadata.name,
                            "involved_object": (
                                {
                                    "kind": k8s_event.involved_object.kind,
                                    "name": k8s_event.involved_object.name,
                                    "namespace": k8s_event.involved_object.namespace,
                                }
                                if k8s_event.involved_object
                                else None
                            ),
                        }
                    },
                    tags=[
                        "kubernetes",
                        "events",
                        k8s_event.namespace or "default",
                        k8s_event.reason,
                    ],
                )

                await self.log_processor.process_event(aaa_event)

        except Exception as e:
            logger.error("Error processing Kubernetes event", error=str(e))

    async def _determine_event_severity(self, k8s_event) -> Severity:
        """Determine severity based on Kubernetes event type and reason"""
        reason = k8s_event.reason.lower() if k8s_event.reason else ""
        event_type = k8s_event.type.lower() if k8s_event.type else ""

        # Critical events
        if any(word in reason for word in ["failed", "error", "killed", "oomkilled"]):
            return Severity.CRITICAL

        # High severity events
        if any(word in reason for word in ["unhealthy", "backoff", "pulling"]):
            return Severity.HIGH

        # Medium severity events
        if any(word in reason for word in ["warning", "nodenotready"]):
            return Severity.MEDIUM

        # Low severity events
        if any(word in reason for word in ["scheduled", "started", "created"]):
            return Severity.LOW

        return Severity.INFO

    async def _collect_audit_logs(self):
        """Collect Kubernetes audit logs via API server audit endpoint"""
        logger.info("Starting Kubernetes audit logs collection")

        try:
            while self.running:
                # Process each API server
                for session_id in self.api_sessions.keys():
                    if not self.running:
                        break

                    try:
                        await self._collect_audit_from_server(session_id)
                    except Exception as e:
                        logger.error(
                            "Error collecting audit logs from API server",
                            session_id=session_id,
                            error=str(e),
                        )

                # Wait before next collection cycle
                await asyncio.sleep(self.config.audit_log_poll_interval)

        except asyncio.CancelledError:
            logger.info("Kubernetes audit logs collection cancelled")
        except Exception as e:
            logger.error("Fatal error in audit logs collection", error=str(e))

    async def _collect_audit_from_server(self, session_id: str):
        """Collect audit logs from API server metrics or logs endpoint"""
        session_info = self.api_sessions[session_id]
        session = session_info["session"]
        base_url = session_info["base_url"]

        try:
            # Try to get audit events via the audit API if available
            audit_urls = [
                "/api/v1/events?fieldSelector=type=Warning,type=Normal",
                "/apis/audit.k8s.io/v1/events",
                "/logs/audit.log",  # Some clusters expose audit logs here
            ]

            for audit_url in audit_urls:
                try:
                    full_url = urljoin(base_url, audit_url)

                    params = {}
                    if "since" in audit_url or "events" in audit_url:
                        # For events API, get recent events
                        since_time = datetime.utcnow() - timedelta(
                            seconds=self.config.audit_log_poll_interval * 2
                        )
                        params["timeoutSeconds"] = 30

                    async with session.get(full_url, params=params) as response:
                        if response.status == 200:
                            if "application/json" in response.headers.get(
                                "content-type", ""
                            ):
                                audit_data = await response.json()
                                await self._process_audit_events(audit_data, session_id)
                            else:
                                audit_text = await response.text()
                                await self._process_audit_text(audit_text, session_id)
                            break  # Success, don't try other URLs
                        elif response.status == 404:
                            continue  # Try next URL
                        else:
                            logger.debug(
                                "Audit endpoint returned error",
                                url=audit_url,
                                status=response.status,
                            )

                except Exception as e:
                    logger.debug(
                        "Error accessing audit endpoint", url=audit_url, error=str(e)
                    )
                    continue

        except Exception as e:
            logger.error(
                "Error collecting audit logs", session_id=session_id, error=str(e)
            )

    async def _process_audit_events(self, audit_data: Dict, session_id: str):
        """Process audit events from JSON API response"""
        try:
            items = audit_data.get("items", [])
            if isinstance(audit_data, list):
                items = audit_data

            for item in items:
                if not self.running:
                    break

                # Convert API event to audit-like format
                audit_line = json.dumps(
                    {
                        "kind": item.get("kind", "Event"),
                        "verb": item.get("verb", "get"),
                        "user": item.get("user", {}),
                        "timestamp": item.get("eventTime")
                        or item.get("firstTimestamp"),
                        "resource": item.get("involvedObject", {}),
                        "reason": item.get("reason"),
                        "message": item.get("message"),
                        "metadata": item.get("metadata", {}),
                    }
                )

                await self._process_audit_line(audit_line)

        except Exception as e:
            logger.error(
                "Error processing audit events", session_id=session_id, error=str(e)
            )

    async def _process_audit_text(self, audit_text: str, session_id: str):
        """Process audit logs from text format"""
        try:
            lines = audit_text.strip().split("\n")

            for line in lines:
                if not line.strip():
                    continue

                await self._process_audit_line(line.strip())

        except Exception as e:
            logger.error(
                "Error processing audit text", session_id=session_id, error=str(e)
            )

    async def _process_audit_line(self, line: str):
        """Process audit log line"""
        try:
            if not line.strip():
                return

            # Parse JSON audit log entry
            try:
                audit_data = json.loads(line)
            except json.JSONDecodeError:
                # Skip non-JSON lines
                return

            # Extract audit information
            verb = audit_data.get("verb", "")
            user = audit_data.get("user", {})
            username = user.get("username", "")
            resource = audit_data.get("resource", {})

            # Create authorization event for audit log
            event = AuthorizationEvent(
                source=LogSource.KUBERNETES,
                event_type=EventType.AUTHORIZATION,
                severity=await self._determine_audit_severity(verb, audit_data),
                message=f"Kubernetes API {verb} operation by {username}",
                timestamp=datetime.utcnow(),
                username=username,
                resource=resource.get("resource", ""),
                action=verb,
                result="allowed",  # Audit logs typically contain successful operations
                namespace=audit_data.get("namespace"),
                raw_data={"audit_log": audit_data},
                tags=[
                    "kubernetes",
                    "audit",
                    verb,
                    audit_data.get("namespace", "default"),
                ],
            )

            await self.log_processor.process_event(event)

        except Exception as e:
            logger.error("Error processing audit line", error=str(e))

    async def _determine_audit_severity(self, verb: str, audit_data: Dict) -> Severity:
        """Determine severity of audit event"""
        # High-risk operations
        if verb in ["delete", "create", "escalate", "impersonate"]:
            return Severity.HIGH

        # Medium-risk operations
        if verb in ["update", "patch"]:
            return Severity.MEDIUM

        # Low-risk operations
        return Severity.LOW

    async def _monitor_rbac_violations(self):
        """Monitor RBAC violations"""
        logger.info("Starting RBAC violations monitoring")

        try:
            while self.running:
                try:
                    # Check for RBAC-related events
                    # This could monitor specific patterns in logs or events
                    await asyncio.sleep(getattr(self.config, "rbac_check_interval", 60))

                    # TODO: Implement specific RBAC violation detection
                    # This would analyze recent events/logs for RBAC patterns

                except Exception as e:
                    logger.error("Error in RBAC monitoring", error=str(e))
                    await asyncio.sleep(60)

        except asyncio.CancelledError:
            logger.info("RBAC violations monitoring cancelled")
        except Exception as e:
            logger.error("Fatal error in RBAC monitoring", error=str(e))
