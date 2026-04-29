"""
SkausWatch AAA Monitor Service - LXC/LXD Collector

Completely clientless LXC/LXD container log collector using REST API.
Monitors container logs, lifecycle events, resource usage, and security events
through direct API calls. No agents or log forwarding required.
"""

import asyncio
import base64
import json
import logging
import re
import ssl
import subprocess
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional
from urllib.parse import urlencode, urljoin

import aiohttp
import structlog
import websockets

from ..models import (
    AuthenticationEvent,
    AuthorizationEvent,
    BaseEvent,
    ContainerEvent,
    EventType,
    FileAccessEvent,
    LogSource,
    NetworkEvent,
    ProcessEvent,
    Severity,
)

logger = structlog.get_logger(__name__)


class LXCCollector:
    """LXC/LXD container log collector for AAA monitoring"""

    def __init__(self, config, log_processor, analysis_engine):
        """Initialize LXC collector

        Args:
            config: LXC collector configuration (dataclass)
            log_processor: Log processor instance
            analysis_engine: Analysis engine instance
        """
        self.config = config
        self.log_processor = log_processor
        self.analysis_engine = analysis_engine

        # Collection state
        self.running = False
        self.collection_tasks = []

        # LXD API sessions and connections
        self.lxd_sessions = {}
        self.lxd_connectors = {}
        self.websocket_connections = {}

        # Container tracking
        self.monitored_containers = {}
        self.container_log_positions = {}
        self.container_metadata = {}

        # Event patterns for analysis
        self.auth_patterns = {
            "ssh_success": re.compile(r"sshd.*Accepted.*from", re.IGNORECASE),
            "ssh_failure": re.compile(r"sshd.*Failed.*from", re.IGNORECASE),
            "sudo_success": re.compile(r"sudo.*COMMAND", re.IGNORECASE),
            "sudo_failure": re.compile(r"sudo.*authentication failure", re.IGNORECASE),
            "login_success": re.compile(r"login.*opened for user", re.IGNORECASE),
            "login_failure": re.compile(
                r"login.*authentication failure", re.IGNORECASE
            ),
            "pam_success": re.compile(r"pam.*session opened", re.IGNORECASE),
            "pam_failure": re.compile(r"pam.*authentication failure", re.IGNORECASE),
        }

        self.container_patterns = {
            "started": re.compile(
                r"Started container|Container.*started", re.IGNORECASE
            ),
            "stopped": re.compile(
                r"Stopped container|Container.*stopped", re.IGNORECASE
            ),
            "created": re.compile(
                r"Created container|Container.*created", re.IGNORECASE
            ),
            "deleted": re.compile(
                r"Deleted container|Container.*deleted", re.IGNORECASE
            ),
            "failed": re.compile(r"Failed.*container|Container.*failed", re.IGNORECASE),
            "oom": re.compile(r"out of memory|oom.*killed", re.IGNORECASE),
            "network_error": re.compile(
                r"network.*error|network.*failed", re.IGNORECASE
            ),
        }

        self.security_patterns = {
            "privilege_escalation": re.compile(
                r"setuid|setgid|su -|sudo", re.IGNORECASE
            ),
            "file_access_denied": re.compile(
                r"permission denied|access denied", re.IGNORECASE
            ),
            "network_violation": re.compile(
                r"connection.*refused|port.*blocked", re.IGNORECASE
            ),
            "resource_limit": re.compile(
                r"resource.*limit|quota.*exceeded", re.IGNORECASE
            ),
            "capability_violation": re.compile(
                r"capability.*denied|cap_.*denied", re.IGNORECASE
            ),
        }

    async def initialize(self):
        """Initialize LXC/LXD collector with REST API connections"""
        try:
            # Initialize HTTP sessions for each LXD endpoint
            for i, endpoint_config in enumerate(self.config.lxd_endpoints):
                session_id = f"lxd-{i}"

                # Create SSL context
                ssl_context = ssl.create_default_context()
                if not endpoint_config.verify_ssl:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                elif endpoint_config.server_cert_file:
                    ssl_context.load_verify_locations(endpoint_config.server_cert_file)

                if endpoint_config.cert_file and endpoint_config.key_file:
                    ssl_context.load_cert_chain(
                        endpoint_config.cert_file, endpoint_config.key_file
                    )

                # Create connector with connection pooling
                connector = aiohttp.TCPConnector(
                    ssl=ssl_context,
                    limit=self.config.max_connections,
                    limit_per_host=5,
                    ttl_dns_cache=300,
                    use_dns_cache=True,
                    keepalive_timeout=30,
                    enable_cleanup_closed=True,
                )
                self.lxd_connectors[session_id] = connector

                # Create HTTP session
                timeout = aiohttp.ClientTimeout(total=endpoint_config.timeout)
                session = aiohttp.ClientSession(connector=connector, timeout=timeout)
                self.lxd_sessions[session_id] = {
                    "session": session,
                    "config": endpoint_config,
                    "base_url": endpoint_config.url.rstrip("/"),
                    "containers": set(),
                }

                # Test connection
                await self._test_lxd_connection(session_id)

            # Get initial container list
            await self._update_container_list()

            logger.info(
                "LXC/LXD collector initialized successfully",
                endpoints=len(self.lxd_sessions),
                monitored_containers=len(self.monitored_containers),
            )

        except Exception as e:
            logger.error("Failed to initialize LXC collector", error=str(e))
            raise

    async def _test_lxd_connection(self, session_id: str):
        """Test LXD REST API connection"""
        try:
            session_info = self.lxd_sessions[session_id]
            session = session_info["session"]
            base_url = session_info["base_url"]

            # Test basic API access
            api_url = urljoin(base_url, "/1.0")
            async with session.get(api_url) as response:
                if response.status == 200:
                    api_data = await response.json()
                    server_info = api_data.get("metadata", {})
                    logger.info(
                        "LXD API connection successful",
                        server=base_url,
                        version=server_info.get("server_version"),
                        api_version=server_info.get("api_version"),
                    )
                else:
                    raise Exception(f"API test failed: {response.status}")

        except Exception as e:
            logger.error(
                "LXD API connection test failed", session_id=session_id, error=str(e)
            )
            raise

    async def _update_container_list(self):
        """Update list of monitored containers from all endpoints"""
        try:
            # Process each LXD endpoint
            for session_id in self.lxd_sessions.keys():
                await self._update_containers_from_endpoint(session_id)

        except Exception as e:
            logger.error("Error updating container list", error=str(e))

    async def _update_containers_from_endpoint(self, session_id: str):
        """Update container list from a specific LXD endpoint"""
        try:
            session_info = self.lxd_sessions[session_id]
            session = session_info["session"]
            base_url = session_info["base_url"]

            # Get containers from API
            containers_url = urljoin(base_url, "/1.0/containers")
            async with session.get(containers_url) as response:
                if response.status != 200:
                    logger.warning(
                        "Failed to get containers",
                        session_id=session_id,
                        status=response.status,
                    )
                    return

                containers_data = await response.json()
                container_names = []

                # Extract container names from URLs
                for container_url in containers_data.get("metadata", []):
                    container_name = container_url.split("/")[-1]
                    container_names.append(container_name)

                    # Get detailed container info
                    await self._get_container_details(session_id, container_name)

                # Update session container list
                old_containers = session_info["containers"]
                new_containers = set(container_names)

                added = new_containers - old_containers
                removed = old_containers - new_containers

                session_info["containers"] = new_containers

                # Update global monitored containers
                for container in added:
                    container_key = f"{session_id}:{container}"
                    self.monitored_containers[container_key] = {
                        "session_id": session_id,
                        "name": container,
                        "endpoint": base_url,
                    }

                for container in removed:
                    container_key = f"{session_id}:{container}"
                    if container_key in self.monitored_containers:
                        del self.monitored_containers[container_key]
                    # Clean up log positions
                    self.container_log_positions.pop(container_key, None)

                if added:
                    logger.info(
                        "New containers detected",
                        session_id=session_id,
                        containers=list(added),
                    )
                if removed:
                    logger.info(
                        "Containers removed",
                        session_id=session_id,
                        containers=list(removed),
                    )

        except Exception as e:
            logger.error(
                "Error updating containers from endpoint",
                session_id=session_id,
                error=str(e),
            )

    async def _get_container_details(self, session_id: str, container_name: str):
        """Get detailed information about a container"""
        try:
            session_info = self.lxd_sessions[session_id]
            session = session_info["session"]
            base_url = session_info["base_url"]

            # Get container details
            container_url = urljoin(base_url, f"/1.0/containers/{container_name}")
            async with session.get(container_url) as response:
                if response.status == 200:
                    container_data = await response.json()
                    metadata = container_data.get("metadata", {})

                    container_key = f"{session_id}:{container_name}"
                    self.container_metadata[container_key] = {
                        "status": metadata.get("status"),
                        "status_code": metadata.get("status_code"),
                        "architecture": metadata.get("architecture"),
                        "config": metadata.get("config", {}),
                        "created_at": metadata.get("created_at"),
                        "last_used_at": metadata.get("last_used_at"),
                    }

        except Exception as e:
            logger.debug(
                "Error getting container details",
                session_id=session_id,
                container=container_name,
                error=str(e),
            )

    async def start_collection(self):
        """Start log collection from LXC/LXD containers"""
        if self.running:
            logger.warning("LXC collector already running")
            return

        self.running = True
        logger.info("Starting LXC/LXD log collection")

        try:
            # Start container discovery task
            task = asyncio.create_task(self._container_discovery_loop())
            self.collection_tasks.append(task)

            # Start log collection for each container type
            if self.config.collect_container_logs:
                task = asyncio.create_task(self._collect_container_logs_api())
                self.collection_tasks.append(task)

            if self.config.monitor_events:
                task = asyncio.create_task(self._monitor_container_events_api())
                self.collection_tasks.append(task)

            if self.config.monitor_resource_usage:
                task = asyncio.create_task(self._monitor_resource_usage_api())
                self.collection_tasks.append(task)

            # Start WebSocket event monitoring
            for session_id in self.lxd_sessions.keys():
                task = asyncio.create_task(self._monitor_websocket_events(session_id))
                self.collection_tasks.append(task)

            # Wait for all tasks
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)

        except Exception as e:
            logger.error("Error in LXC log collection", error=str(e))
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

        # Close WebSocket connections
        for ws_conn in self.websocket_connections.values():
            try:
                await ws_conn.close()
            except Exception:
                pass
        self.websocket_connections.clear()

        # Close all HTTP sessions
        for session_info in self.lxd_sessions.values():
            await session_info["session"].close()

        # Close all connectors
        for connector in self.lxd_connectors.values():
            await connector.close()

        self.lxd_sessions.clear()
        self.lxd_connectors.clear()

        logger.info("LXC collector stopped")

    async def _container_discovery_loop(self):
        """Periodically discover new containers"""
        logger.info("Starting container discovery loop")

        try:
            while self.running:
                try:
                    await self._update_container_list()
                    await asyncio.sleep(getattr(self.config, "discovery_interval", 60))

                except Exception as e:
                    logger.error("Error in container discovery", error=str(e))
                    await asyncio.sleep(60)

        except asyncio.CancelledError:
            logger.info("Container discovery cancelled")
        except Exception as e:
            logger.error("Fatal error in container discovery", error=str(e))

    async def _collect_container_logs_api(self):
        """Collect logs from individual containers using LXD API"""
        logger.info("Starting container logs collection via API")

        try:
            while self.running:
                try:
                    for (
                        container_key,
                        container_info,
                    ) in self.monitored_containers.copy().items():
                        if not self.running:
                            break

                        await self._process_container_logs_api(
                            container_info["session_id"], container_info["name"]
                        )

                    await asyncio.sleep(self.config.log_poll_interval)

                except Exception as e:
                    logger.error("Error in container logs collection", error=str(e))
                    await asyncio.sleep(30)

        except asyncio.CancelledError:
            logger.info("Container logs collection cancelled")
        except Exception as e:
            logger.error("Fatal error in container logs collection", error=str(e))

    async def _process_container_logs_api(self, session_id: str, container_name: str):
        """Process logs for a specific container using LXD API"""
        try:
            session_info = self.lxd_sessions[session_id]
            session = session_info["session"]
            base_url = session_info["base_url"]

            # Get container logs via API
            logs_url = urljoin(base_url, f"/1.0/containers/{container_name}/logs")

            # First, get available log files
            async with session.get(logs_url) as response:
                if response.status != 200:
                    logger.debug(
                        "Container logs not available",
                        container=container_name,
                        status=response.status,
                    )
                    return

                logs_data = await response.json()
                log_files = logs_data.get("metadata", [])

                # Process each log file
                for log_file in log_files:
                    await self._fetch_container_log_file(
                        session_id, container_name, log_file
                    )

        except Exception as e:
            logger.error(
                "Error processing container logs via API",
                container=container_name,
                error=str(e),
            )

    async def _fetch_container_log_file(
        self, session_id: str, container_name: str, log_file: str
    ):
        """Fetch a specific log file from container"""
        try:
            session_info = self.lxd_sessions[session_id]
            session = session_info["session"]
            base_url = session_info["base_url"]

            # Get log file content
            log_content_url = urljoin(
                base_url, f"/1.0/containers/{container_name}/logs/{log_file}"
            )

            position_key = f"{session_id}:{container_name}:{log_file}"

            async with session.get(log_content_url) as response:
                if response.status == 200:
                    log_content = await response.text()

                    # Only process new content based on position tracking
                    if position_key in self.container_log_positions:
                        # Skip already processed content
                        last_position = self.container_log_positions[position_key]
                        if len(log_content) <= last_position:
                            return
                        log_content = log_content[last_position:]

                    # Update position
                    self.container_log_positions[position_key] = len(log_content)

                    if log_content.strip():
                        await self._parse_container_logs(
                            log_content, container_name, "api-" + log_file
                        )

        except Exception as e:
            logger.debug(
                "Error fetching container log file",
                container=container_name,
                log_file=log_file,
                error=str(e),
            )

    async def _parse_container_logs(
        self, logs_content: str, container_name: str, source_type: str
    ):
        """Parse container logs and create events"""
        try:
            lines = logs_content.strip().split("\n")

            for line in lines:
                if not line.strip():
                    continue

                # Extract timestamp
                timestamp = datetime.utcnow()
                try:
                    # Try to parse common log timestamp formats
                    if source_type == "journalctl":
                        # JSON format from journalctl
                        try:
                            log_entry = json.loads(line)
                            timestamp_str = log_entry.get("__REALTIME_TIMESTAMP")
                            if timestamp_str:
                                timestamp = datetime.fromtimestamp(
                                    int(timestamp_str) / 1000000
                                )
                            line = log_entry.get("MESSAGE", line)
                        except json.JSONDecodeError:
                            pass
                    else:
                        # Standard syslog format
                        # Extract timestamp from beginning of line
                        timestamp_patterns = [
                            r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",  # Dec 31 23:59:59
                            r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",  # 2023-12-31T23:59:59
                        ]

                        for pattern in timestamp_patterns:
                            match = re.match(pattern, line)
                            if match:
                                # Parse timestamp based on format
                                try:
                                    timestamp_str = match.group(1)
                                    if "T" in timestamp_str:
                                        timestamp = datetime.fromisoformat(
                                            timestamp_str
                                        )
                                    else:
                                        # Add current year for syslog format
                                        current_year = datetime.now().year
                                        timestamp = datetime.strptime(
                                            f"{current_year} {timestamp_str}",
                                            "%Y %b %d %H:%M:%S",
                                        )
                                except:
                                    pass
                                break
                except Exception:
                    pass

                # Classify and create events
                events = await self._classify_and_create_events(
                    line, container_name, timestamp
                )

                # Process each event
                for event in events:
                    await self.log_processor.process_event(event)

        except Exception as e:
            logger.error(
                "Error parsing container logs", container=container_name, error=str(e)
            )

    async def _classify_and_create_events(
        self, line: str, container_name: str, timestamp: datetime
    ) -> List[BaseEvent]:
        """Classify log line and create appropriate events"""
        events = []

        try:
            line_lower = line.lower()

            # Check authentication patterns
            for pattern_name, pattern in self.auth_patterns.items():
                if pattern.search(line):
                    event = await self._create_auth_event(
                        line, container_name, timestamp, pattern_name
                    )
                    events.append(event)
                    break

            # Check container patterns
            for pattern_name, pattern in self.container_patterns.items():
                if pattern.search(line):
                    event = await self._create_container_event(
                        line, container_name, timestamp, pattern_name
                    )
                    events.append(event)
                    break

            # Check security patterns
            for pattern_name, pattern in self.security_patterns.items():
                if pattern.search(line):
                    event = await self._create_security_event(
                        line, container_name, timestamp, pattern_name
                    )
                    events.append(event)
                    break

            # If no specific pattern matched, create generic event for significant entries
            if not events and any(
                word in line_lower for word in ["error", "warning", "failed", "denied"]
            ):
                event = BaseEvent(
                    source=LogSource.LXC_LXD,
                    event_type=EventType.SYSTEM_CALL,
                    severity=(
                        Severity.MEDIUM if "warning" in line_lower else Severity.HIGH
                    ),
                    message=line,
                    timestamp=timestamp,
                    raw_data={"container_name": container_name, "log_line": line},
                    tags=["lxc", "container", container_name],
                )
                events.append(event)

        except Exception as e:
            logger.error("Error classifying log line", error=str(e))

        return events

    async def _create_auth_event(
        self, line: str, container_name: str, timestamp: datetime, pattern_name: str
    ) -> AuthenticationEvent:
        """Create authentication event from log line"""
        # Extract authentication details
        username = None
        source_ip = None
        success = "success" in pattern_name
        method = None

        # Extract username
        username_patterns = [
            r"user\s+(\w+)",
            r"for\s+(\w+)",
            r"USER=(\w+)",
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

        # Determine method
        if "ssh" in line.lower():
            method = "ssh"
        elif "sudo" in line.lower():
            method = "sudo"
        elif "pam" in line.lower():
            method = "pam"
        elif "login" in line.lower():
            method = "login"

        return AuthenticationEvent(
            source=LogSource.LXC_LXD,
            event_type=EventType.AUTHENTICATION,
            severity=Severity.HIGH if not success else Severity.INFO,
            message=line,
            timestamp=timestamp,
            username=username,
            source_ip=source_ip,
            success=success,
            method=method,
            raw_data={
                "container_name": container_name,
                "log_line": line,
                "pattern_matched": pattern_name,
            },
            tags=["lxc", "authentication", container_name, method or "unknown"],
        )

    async def _create_container_event(
        self, line: str, container_name: str, timestamp: datetime, pattern_name: str
    ) -> ContainerEvent:
        """Create container event from log line"""
        action = pattern_name
        exit_code = None

        # Extract exit code if present
        exit_code_pattern = r"exit.*code[:\s]+(\d+)"
        exit_match = re.search(exit_code_pattern, line, re.IGNORECASE)
        if exit_match:
            exit_code = int(exit_match.group(1))

        severity = Severity.HIGH if pattern_name in ["failed", "oom"] else Severity.INFO

        return ContainerEvent(
            source=LogSource.LXC_LXD,
            event_type=EventType.CONTAINER_EVENT,
            severity=severity,
            message=line,
            timestamp=timestamp,
            container_name=container_name,
            action=action,
            exit_code=exit_code,
            raw_data={
                "container_name": container_name,
                "log_line": line,
                "pattern_matched": pattern_name,
            },
            tags=["lxc", "container", container_name, action],
        )

    async def _create_security_event(
        self, line: str, container_name: str, timestamp: datetime, pattern_name: str
    ) -> BaseEvent:
        """Create security event from log line"""
        if pattern_name == "privilege_escalation":
            event_type = EventType.PRIVILEGE_ESCALATION
            severity = Severity.HIGH
        elif pattern_name == "file_access_denied":
            event_type = EventType.FILE_ACCESS
            severity = Severity.MEDIUM
        elif pattern_name == "network_violation":
            event_type = EventType.NETWORK
            severity = Severity.MEDIUM
        else:
            event_type = EventType.SECURITY_VIOLATION
            severity = Severity.HIGH

        return BaseEvent(
            source=LogSource.LXC_LXD,
            event_type=event_type,
            severity=severity,
            message=line,
            timestamp=timestamp,
            raw_data={
                "container_name": container_name,
                "log_line": line,
                "security_pattern": pattern_name,
            },
            tags=["lxc", "security", container_name, pattern_name],
        )

    async def _collect_system_logs(self):
        """Collect system-level logs related to LXC/LXD"""
        logger.info("Starting system logs collection for LXC/LXD")

        try:
            while self.running:
                try:
                    # Monitor LXD daemon logs
                    await self._monitor_lxd_logs()

                    # Monitor systemd logs for LXC/LXD services
                    await self._monitor_systemd_logs()

                    await asyncio.sleep(getattr(self.config, "system_log_interval", 60))

                except Exception as e:
                    logger.error("Error in system logs collection", error=str(e))
                    await asyncio.sleep(60)

        except asyncio.CancelledError:
            logger.info("System logs collection cancelled")
        except Exception as e:
            logger.error("Fatal error in system logs collection", error=str(e))

    async def _monitor_lxd_logs(self):
        """Monitor LXD daemon logs"""
        try:
            lxd_log_paths = [
                "/var/snap/lxd/common/lxd/logs/lxd.log",
                "/var/log/lxd/lxd.log",
                "/var/lib/lxd/logs/lxd.log",
            ]

            for log_path in lxd_log_paths:
                if Path(log_path).exists():
                    await self._read_log_file(log_path, "lxd-daemon")
                    break

        except Exception as e:
            logger.error("Error monitoring LXD logs", error=str(e))

    async def _monitor_systemd_logs(self):
        """Monitor systemd logs for LXC/LXD services"""
        try:
            # Get recent systemd logs for LXD services
            services = ["lxd", "lxd.service", "lxd-containers"]

            for service in services:
                try:
                    result = await asyncio.create_subprocess_exec(
                        "journalctl",
                        "-u",
                        service,
                        "--since",
                        "5 minutes ago",
                        "--output",
                        "json",
                        "--no-pager",
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    stdout, stderr = await result.communicate()

                    if result.returncode == 0:
                        await self._parse_container_logs(
                            stdout.decode(), service, "journalctl"
                        )

                except Exception as e:
                    logger.debug(
                        "Error getting systemd logs for service",
                        service=service,
                        error=str(e),
                    )

        except Exception as e:
            logger.error("Error monitoring systemd logs", error=str(e))

    async def _monitor_container_events_api(self):
        """Monitor container lifecycle events via API polling"""
        logger.info("Starting container events monitoring via API")

        try:
            while self.running:
                try:
                    for session_id in self.lxd_sessions.keys():
                        if not self.running:
                            break
                        await self._poll_container_events(session_id)

                    await asyncio.sleep(self.config.event_monitor_interval)

                except Exception as e:
                    logger.error("Error in container events monitoring", error=str(e))
                    await asyncio.sleep(30)

        except asyncio.CancelledError:
            logger.info("Container events monitoring cancelled")
        except Exception as e:
            logger.error("Fatal error in container events monitoring", error=str(e))

    async def _poll_container_events(self, session_id: str):
        """Poll for container state changes"""
        try:
            session_info = self.lxd_sessions[session_id]
            session = session_info["session"]
            base_url = session_info["base_url"]

            # Get current container states and compare with cached states
            containers_url = urljoin(base_url, "/1.0/containers?recursion=1")
            async with session.get(containers_url) as response:
                if response.status != 200:
                    return

                containers_data = await response.json()
                current_containers = containers_data.get("metadata", [])

                for container in current_containers:
                    container_name = container.get("name")
                    if not container_name:
                        continue

                    container_key = f"{session_id}:{container_name}"
                    current_status = container.get("status")
                    current_status_code = container.get("status_code")

                    # Check for state changes
                    if container_key in self.container_metadata:
                        old_metadata = self.container_metadata[container_key]
                        old_status = old_metadata.get("status")

                        if old_status != current_status:
                            # Container state changed
                            await self._create_state_change_event(
                                session_id, container_name, old_status, current_status
                            )

                    # Update metadata
                    self.container_metadata[container_key] = {
                        "status": current_status,
                        "status_code": current_status_code,
                        "architecture": container.get("architecture"),
                        "config": container.get("config", {}),
                        "created_at": container.get("created_at"),
                        "last_used_at": container.get("last_used_at"),
                    }

        except Exception as e:
            logger.error(
                "Error polling container events", session_id=session_id, error=str(e)
            )

    async def _monitor_lxd_events(self):
        """Monitor LXD events using API"""
        try:
            # Use lxc monitor command for real-time events
            process = await asyncio.create_subprocess_exec(
                "lxc",
                "monitor",
                "--type",
                "lifecycle",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Read events for a limited time
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=getattr(self.config, "event_timeout", 30)
                )

                if stdout:
                    await self._process_lxd_events(stdout.decode())

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()

        except Exception as e:
            logger.error("Error monitoring LXD events", error=str(e))

    async def _monitor_websocket_events(self, session_id: str):
        """Monitor LXD events via WebSocket connection"""
        logger.info("Starting WebSocket events monitoring", session_id=session_id)

        try:
            session_info = self.lxd_sessions[session_id]
            config = session_info["config"]
            base_url = session_info["base_url"]

            # Convert HTTP URL to WebSocket URL
            ws_url = base_url.replace("https://", "wss://").replace("http://", "ws://")
            ws_url = urljoin(ws_url, "/1.0/events")

            # WebSocket headers for authentication
            headers = {}
            if config.cert_file and config.key_file:
                # For client certificate auth, we need to handle this differently
                # with websockets library
                pass

            while self.running:
                try:
                    # Create SSL context if needed
                    ssl_context = None
                    if ws_url.startswith("wss://"):
                        ssl_context = ssl.create_default_context()
                        if not config.verify_ssl:
                            ssl_context.check_hostname = False
                            ssl_context.verify_mode = ssl.CERT_NONE
                        elif config.server_cert_file:
                            ssl_context.load_verify_locations(config.server_cert_file)
                        if config.cert_file and config.key_file:
                            ssl_context.load_cert_chain(
                                config.cert_file, config.key_file
                            )

                    # Connect to WebSocket
                    async with websockets.connect(
                        ws_url,
                        ssl=ssl_context,
                        extra_headers=headers,
                        ping_interval=self.config.websocket_ping_interval,
                        ping_timeout=10,
                        close_timeout=10,
                    ) as websocket:
                        self.websocket_connections[session_id] = websocket

                        logger.info(
                            "WebSocket connected for events", session_id=session_id
                        )

                        async for message in websocket:
                            if not self.running:
                                break

                            try:
                                event_data = json.loads(message)
                                await self._process_websocket_event(
                                    event_data, session_id
                                )
                            except json.JSONDecodeError:
                                logger.debug(
                                    "Invalid JSON in WebSocket message",
                                    session_id=session_id,
                                )
                                continue

                except websockets.exceptions.ConnectionClosed:
                    logger.info(
                        "WebSocket connection closed, reconnecting...",
                        session_id=session_id,
                    )
                    await asyncio.sleep(5)
                except Exception as e:
                    logger.error(
                        "WebSocket error, retrying...",
                        session_id=session_id,
                        error=str(e),
                    )
                    await asyncio.sleep(10)

        except asyncio.CancelledError:
            logger.info("WebSocket events monitoring cancelled", session_id=session_id)
        except Exception as e:
            logger.error(
                "Fatal error in WebSocket events monitoring",
                session_id=session_id,
                error=str(e),
            )
        finally:
            if session_id in self.websocket_connections:
                del self.websocket_connections[session_id]

    async def _process_websocket_event(self, event_data: Dict, session_id: str):
        """Process event received via WebSocket"""
        try:
            metadata = event_data.get("metadata", {})
            event_type = event_data.get("type", "")

            # Process different types of events
            if event_type in ["operation", "lifecycle"]:
                await self._create_lxd_lifecycle_event(event_data, session_id)
            elif event_type == "logging":
                # Handle log events
                await self._process_log_event(event_data, session_id)

        except Exception as e:
            logger.error(
                "Error processing WebSocket event", session_id=session_id, error=str(e)
            )

    async def _create_state_change_event(
        self, session_id: str, container_name: str, old_status: str, new_status: str
    ):
        """Create event for container state change"""
        try:
            action_map = {
                "Running": "started",
                "Stopped": "stopped",
                "Frozen": "frozen",
                "Error": "failed",
            }

            action = action_map.get(new_status, new_status.lower())
            severity = Severity.HIGH if new_status == "Error" else Severity.INFO

            event = ContainerEvent(
                source=LogSource.LXC_LXD,
                event_type=EventType.CONTAINER_EVENT,
                severity=severity,
                message=f"Container {action}: {container_name} ({old_status} -> {new_status})",
                timestamp=datetime.utcnow(),
                container_name=container_name,
                action=action,
                raw_data={
                    "session_id": session_id,
                    "old_status": old_status,
                    "new_status": new_status,
                    "endpoint": self.lxd_sessions[session_id]["base_url"],
                },
                tags=["lxc", "lifecycle", container_name, action],
            )

            await self.log_processor.process_event(event)

        except Exception as e:
            logger.error("Error creating state change event", error=str(e))

    async def _create_lxd_lifecycle_event(self, event_data: Dict, session_id: str):
        """Create event from LXD lifecycle event"""
        try:
            event_type_map = {
                "container-started": "started",
                "container-stopped": "stopped",
                "container-created": "created",
                "container-deleted": "deleted",
                "operation": "operation",
                "lifecycle": "lifecycle",
            }

            metadata = event_data.get("metadata", {})
            container_name = metadata.get(
                "name", metadata.get("description", "unknown")
            )
            action = event_type_map.get(event_data.get("type"), "unknown")

            # Extract more details from the event
            operation_type = metadata.get("class", "")
            status = metadata.get("status", "")

            event = ContainerEvent(
                source=LogSource.LXC_LXD,
                event_type=EventType.CONTAINER_EVENT,
                severity=Severity.HIGH if "error" in status.lower() else Severity.INFO,
                message=f"Container {action}: {container_name} ({operation_type})",
                timestamp=datetime.utcnow(),
                container_name=container_name,
                action=action,
                raw_data={
                    "lxd_event": event_data,
                    "session_id": session_id,
                    "endpoint": self.lxd_sessions[session_id]["base_url"],
                },
                tags=["lxc", "lifecycle", container_name, action],
            )

            await self.log_processor.process_event(event)

        except Exception as e:
            logger.error("Error creating LXD lifecycle event", error=str(e))

    async def _process_log_event(self, event_data: Dict, session_id: str):
        """Process log event from WebSocket"""
        try:
            metadata = event_data.get("metadata", {})
            log_data = metadata.get("message", "")
            level = metadata.get("level", "info")
            context = metadata.get("context", {})

            container_name = context.get("container", "system")

            # Create log event
            severity_map = {
                "error": Severity.HIGH,
                "warn": Severity.MEDIUM,
                "info": Severity.INFO,
                "debug": Severity.LOW,
            }

            event = BaseEvent(
                source=LogSource.LXC_LXD,
                event_type=EventType.SYSTEM_CALL,
                severity=severity_map.get(level.lower(), Severity.INFO),
                message=log_data,
                timestamp=datetime.utcnow(),
                raw_data={
                    "lxd_log": event_data,
                    "session_id": session_id,
                    "endpoint": self.lxd_sessions[session_id]["base_url"],
                    "level": level,
                    "context": context,
                },
                tags=["lxc", "logs", container_name, level],
            )

            await self.log_processor.process_event(event)

        except Exception as e:
            logger.error("Error processing log event", error=str(e))

    async def _detect_events_from_logs(self):
        """Detect container events from log analysis (fallback method)"""
        # This would analyze recent logs to detect lifecycle events
        # Implementation would be similar to log parsing but focused on events
        pass

    async def _monitor_resource_usage_api(self):
        """Monitor container resource usage via API"""
        logger.info("Starting container resource usage monitoring via API")

        try:
            while self.running:
                try:
                    for (
                        container_key,
                        container_info,
                    ) in self.monitored_containers.copy().items():
                        if not self.running:
                            break

                        await self._collect_container_metrics_api(
                            container_info["session_id"], container_info["name"]
                        )

                    await asyncio.sleep(self.config.metrics_interval)

                except Exception as e:
                    logger.error("Error in resource usage monitoring", error=str(e))
                    await asyncio.sleep(60)

        except asyncio.CancelledError:
            logger.info("Resource usage monitoring cancelled")
        except Exception as e:
            logger.error("Fatal error in resource usage monitoring", error=str(e))

    async def _collect_container_metrics_api(
        self, session_id: str, container_name: str
    ):
        """Collect metrics for a specific container using API"""
        try:
            session_info = self.lxd_sessions[session_id]
            session = session_info["session"]
            base_url = session_info["base_url"]

            # Get container state (includes resource usage)
            state_url = urljoin(base_url, f"/1.0/containers/{container_name}/state")

            async with session.get(state_url) as response:
                if response.status == 200:
                    state_data = await response.json()
                    metadata = state_data.get("metadata", {})

                    await self._process_container_metrics_api(
                        metadata, session_id, container_name
                    )

        except Exception as e:
            logger.error(
                "Error collecting container metrics via API",
                container=container_name,
                error=str(e),
            )

    async def _process_container_metrics_api(
        self, metrics_data: Dict, session_id: str, container_name: str
    ):
        """Process container metrics and generate events for anomalies"""
        try:
            # Extract resource usage
            memory = metrics_data.get("memory", {})
            cpu = metrics_data.get("cpu", {})
            network = metrics_data.get("network", {})

            # Check for resource limit violations
            memory_usage = memory.get("usage", 0)
            memory_usage_peak = memory.get("usage_peak", 0)

            # Generate events for high resource usage
            if memory_usage > 0:
                # You could set thresholds and create events here
                # For now, we'll log metrics
                logger.debug(
                    "Container resource usage",
                    container=container_name,
                    memory_usage=memory_usage,
                    memory_peak=memory_usage_peak,
                    cpu_usage=cpu.get("usage", 0),
                )

        except Exception as e:
            logger.error(
                "Error processing container metrics",
                container=container_name,
                error=str(e),
            )

    async def _process_container_metrics(
        self, metrics_output: str, container_name: str
    ):
        """Process container metrics and generate events for anomalies"""
        try:
            # Parse metrics output and check for resource limit violations
            lines = metrics_output.strip().split("\n")

            for line in lines:
                line = line.strip()

                # Look for resource usage patterns that might indicate issues
                if "memory usage" in line.lower() or "cpu usage" in line.lower():
                    # Extract usage percentages and check thresholds
                    # This would create events for high resource usage
                    pass

        except Exception as e:
            logger.error(
                "Error processing container metrics",
                container=container_name,
                error=str(e),
            )
