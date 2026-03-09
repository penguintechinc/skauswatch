"""
SkausWatch AAA Monitor Service - Journald Collector

Journald collector using systemd journal APIs for remote log collection.
Completely clientless operation via HTTP APIs.
"""

import asyncio
import json
import logging
import re
import ssl
import traceback
from datetime import datetime, timedelta
from typing import Any, AsyncGenerator, Dict, List, Optional
from urllib.parse import urlencode, urljoin

import aiohttp
import structlog

from ..models import (
    AuthenticationEvent,
    AuthorizationEvent,
    BaseEvent,
    EventType,
    FileAccessEvent,
    LogSource,
    NetworkEvent,
    ProcessEvent,
    Severity,
    SystemCallEvent,
)

logger = structlog.get_logger(__name__)


class JournaldCollector:
    """Journald collector using systemd journal remote APIs"""

    def __init__(self, config: Dict[str, Any], log_processor, analysis_engine):
        """Initialize Journald collector

        Args:
            config: Journald collector configuration
            log_processor: Log processor instance
            analysis_engine: Analysis engine instance
        """
        self.config = config
        self.log_processor = log_processor
        self.analysis_engine = analysis_engine

        # Collection state
        self.running = False
        self.collection_tasks = []

        # HTTP sessions for API access
        self.http_sessions = {}
        self.http_connectors = {}

        # Cursor tracking for each endpoint
        self.cursors = {}

        # Service unit patterns for filtering
        self.auth_services = {
            "sshd.service",
            "systemd-logind.service",
            "sudo",
            "pam",
            "login",
            "gdm.service",
            "lightdm.service",
        }

        self.security_services = {
            "auditd.service",
            "apparmor.service",
            "firewalld.service",
            "iptables.service",
            "fail2ban.service",
        }

        # Message classification patterns
        self.auth_patterns = {
            "ssh_success": re.compile(
                r"Accepted.*for\s+(\w+)\s+from\s+([\d.]+)", re.IGNORECASE
            ),
            "ssh_failure": re.compile(
                r"Failed.*for\s+(\w+)\s+from\s+([\d.]+)", re.IGNORECASE
            ),
            "sudo_command": re.compile(r"(\w+)\s*:.*COMMAND=(.+)", re.IGNORECASE),
            "login_success": re.compile(
                r"session opened for user\s+(\w+)", re.IGNORECASE
            ),
            "login_failure": re.compile(
                r"authentication failure.*user=(\w+)", re.IGNORECASE
            ),
        }

    async def initialize(self):
        """Initialize journald collector"""
        try:
            # Initialize HTTP sessions for each endpoint
            for endpoint in self.config.endpoints:
                session_id = f"journald-{endpoint.host}:{endpoint.port}"
                await self._initialize_session(session_id, endpoint)

            logger.info(
                "Journald collector initialized successfully",
                endpoints=len(self.config.endpoints),
            )

        except Exception as e:
            logger.error("Failed to initialize journald collector", error=str(e))
            raise

    async def _initialize_session(self, session_id: str, endpoint):
        """Initialize HTTP session for journald endpoint"""
        try:
            # Create SSL context if needed
            ssl_context = None
            if endpoint.ssl:
                ssl_context = ssl.create_default_context()
                if endpoint.cert_file and endpoint.key_file:
                    ssl_context.load_cert_chain(endpoint.cert_file, endpoint.key_file)

            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=10,
                ttl_dns_cache=300,
                use_dns_cache=True,
                keepalive_timeout=30,
                enable_cleanup_closed=True,
            )

            base_url = f"{'https' if endpoint.ssl else 'http'}://{endpoint.host}:{endpoint.port}"

            timeout = aiohttp.ClientTimeout(total=30)
            session = aiohttp.ClientSession(connector=connector, timeout=timeout)

            self.http_sessions[session_id] = {
                "session": session,
                "base_url": base_url,
                "config": endpoint,
            }
            self.http_connectors[session_id] = connector

            # Test connection
            await self._test_connection(session_id)

            logger.info("Journald API session initialized", session_id=session_id)

        except Exception as e:
            logger.error(
                "Failed to initialize journald session",
                session_id=session_id,
                error=str(e),
            )

    async def _test_connection(self, session_id: str):
        """Test journald API connection"""
        try:
            session_info = self.http_sessions[session_id]
            session = session_info["session"]
            base_url = session_info["base_url"]

            # Test basic API access
            status_url = urljoin(base_url, "/entries?n=1")
            async with session.get(status_url) as response:
                if response.status == 200:
                    logger.info(
                        "Journald API connection successful", session_id=session_id
                    )
                else:
                    logger.warning(
                        "Journald API connection test failed",
                        session_id=session_id,
                        status=response.status,
                    )

        except Exception as e:
            logger.error(
                "Journald API connection test failed",
                session_id=session_id,
                error=str(e),
            )

    async def start_collection(self):
        """Start journald log collection"""
        if self.running:
            logger.warning("Journald collector already running")
            return

        self.running = True
        logger.info("Starting journald log collection")

        try:
            # Start collection from each endpoint
            for session_id in self.http_sessions.keys():
                task = asyncio.create_task(self._collect_from_endpoint(session_id))
                self.collection_tasks.append(task)

            # Wait for all tasks
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)

        except Exception as e:
            logger.error("Error in journald log collection", error=str(e))
        finally:
            self.running = False

    async def stop(self):
        """Stop journald log collection"""
        self.running = False

        # Cancel all collection tasks
        for task in self.collection_tasks:
            if not task.done():
                task.cancel()

        # Wait for tasks to complete
        if self.collection_tasks:
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)

        self.collection_tasks.clear()

        # Close HTTP sessions
        for session_info in self.http_sessions.values():
            await session_info["session"].close()

        # Close connectors
        for connector in self.http_connectors.values():
            await connector.close()

        self.http_sessions.clear()
        self.http_connectors.clear()

        logger.info("Journald collector stopped")

    async def _collect_from_endpoint(self, session_id: str):
        """Collect logs from a specific journald endpoint"""
        logger.info("Starting journald collection from endpoint", session_id=session_id)

        try:
            session_info = self.http_sessions[session_id]
            session = session_info["session"]
            base_url = session_info["base_url"]

            while self.running:
                try:
                    # Build query parameters
                    params = {
                        "follow": "false",
                        "output": "json",
                        "since": self._get_since_time(),
                        "n": "1000",  # Limit entries per request
                    }

                    # Add cursor if available for incremental collection
                    cursor = self.cursors.get(session_id)
                    if cursor:
                        params["after-cursor"] = cursor

                    # Add unit filters if configured
                    if self.config.units:
                        for unit in self.config.units:
                            params[f"UNIT={unit}"] = ""

                    # Make API request
                    entries_url = urljoin(base_url, "/entries")
                    async with session.get(entries_url, params=params) as response:
                        if response.status == 200:
                            await self._process_journal_entries(response, session_id)
                        else:
                            logger.warning(
                                "Journald API query failed",
                                session_id=session_id,
                                status=response.status,
                            )

                    await asyncio.sleep(self.config.poll_interval)

                except Exception as e:
                    logger.error(
                        "Error collecting from journald endpoint",
                        session_id=session_id,
                        error=str(e),
                    )
                    await asyncio.sleep(30)

        except asyncio.CancelledError:
            logger.info("Journald collection cancelled", session_id=session_id)
        except Exception as e:
            logger.error(
                "Fatal error in journald collection",
                session_id=session_id,
                error=str(e),
            )

    def _get_since_time(self) -> str:
        """Get since time for journal query"""
        # Get logs from last poll interval + buffer
        since_time = datetime.utcnow() - timedelta(
            seconds=self.config.poll_interval + 60
        )
        return since_time.strftime("%Y-%m-%d %H:%M:%S")

    async def _process_journal_entries(self, response, session_id: str):
        """Process journal entries from API response"""
        try:
            # Read response line by line (journal entries are JSON lines)
            async for line in response.content:
                if not self.running:
                    break

                try:
                    line_str = line.decode("utf-8").strip()
                    if not line_str:
                        continue

                    entry = json.loads(line_str)
                    await self._process_journal_entry(entry, session_id)

                    # Update cursor for incremental collection
                    cursor = entry.get("__CURSOR")
                    if cursor:
                        self.cursors[session_id] = cursor

                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    logger.debug(
                        "Error processing journal entry",
                        session_id=session_id,
                        error=str(e),
                    )

        except Exception as e:
            logger.error(
                "Error processing journal entries", session_id=session_id, error=str(e)
            )

    async def _process_journal_entry(self, entry: Dict, session_id: str):
        """Process individual journal entry"""
        try:
            # Extract key fields
            message = entry.get("MESSAGE", "")
            unit = entry.get("_SYSTEMD_UNIT", "")
            hostname = entry.get("_HOSTNAME", "unknown")
            timestamp_str = entry.get("__REALTIME_TIMESTAMP")
            priority = entry.get("PRIORITY", "6")
            comm = entry.get("_COMM", "")
            pid = entry.get("_PID", "")
            uid = entry.get("_UID", "")

            # Parse timestamp (microseconds since epoch)
            try:
                timestamp = datetime.fromtimestamp(int(timestamp_str) / 1000000)
            except (ValueError, TypeError):
                timestamp = datetime.utcnow()

            # Skip empty messages
            if not message.strip():
                return

            # Map priority to severity
            severity_map = {
                "0": Severity.CRITICAL,  # emergency
                "1": Severity.CRITICAL,  # alert
                "2": Severity.CRITICAL,  # critical
                "3": Severity.HIGH,  # error
                "4": Severity.MEDIUM,  # warning
                "5": Severity.INFO,  # notice
                "6": Severity.INFO,  # info
                "7": Severity.LOW,  # debug
            }
            severity = severity_map.get(priority, Severity.INFO)

            # Classify and create events
            events = await self._classify_journal_entry(
                message, unit, hostname, timestamp, severity, entry
            )

            # Process events
            for event in events:
                event.raw_data.update(
                    {
                        "journald_entry": entry,
                        "session_id": session_id,
                        "hostname": hostname,
                        "unit": unit,
                        "comm": comm,
                        "pid": pid,
                        "uid": uid,
                    }
                )
                await self.log_processor.process_event(event)

        except Exception as e:
            logger.error(
                "Error processing journal entry", session_id=session_id, error=str(e)
            )

    async def _classify_journal_entry(
        self,
        message: str,
        unit: str,
        hostname: str,
        timestamp: datetime,
        severity: Severity,
        entry: Dict,
    ) -> List[BaseEvent]:
        """Classify journal entry and create appropriate events"""
        events = []

        try:
            message_lower = message.lower()

            # Authentication and authorization events
            if unit in self.auth_services or any(
                service in unit.lower()
                for service in ["auth", "login", "ssh", "pam", "sudo"]
            ):
                auth_event = await self._create_auth_event_from_journal(
                    message, unit, hostname, timestamp, severity, entry
                )
                if auth_event:
                    events.append(auth_event)

            # Security service events
            elif unit in self.security_services or any(
                service in unit.lower() for service in ["audit", "firewall", "security"]
            ):
                security_event = BaseEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.SECURITY_VIOLATION,
                    severity=severity,
                    message=message,
                    timestamp=timestamp,
                    raw_data={"unit": unit, "hostname": hostname},
                    tags=["journald", "security", hostname, unit],
                )
                events.append(security_event)

            # Kernel events
            elif unit == "kernel" or entry.get("_TRANSPORT") == "kernel":
                kernel_event = BaseEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.SYSTEM_CALL,
                    severity=severity,
                    message=message,
                    timestamp=timestamp,
                    raw_data={"unit": unit, "hostname": hostname},
                    tags=["journald", "kernel", hostname],
                )
                events.append(kernel_event)

            # Network-related events
            elif any(
                keyword in message_lower
                for keyword in [
                    "network",
                    "connection",
                    "firewall",
                    "iptables",
                    "netfilter",
                ]
            ):
                network_event = BaseEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.NETWORK,
                    severity=severity,
                    message=message,
                    timestamp=timestamp,
                    raw_data={"unit": unit, "hostname": hostname},
                    tags=["journald", "network", hostname, unit],
                )
                events.append(network_event)

            # Process events (for significant process events)
            elif any(
                keyword in message_lower
                for keyword in ["started", "stopped", "failed", "crashed", "killed"]
            ):
                process_event = BaseEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.PROCESS,
                    severity=severity,
                    message=message,
                    timestamp=timestamp,
                    raw_data={"unit": unit, "hostname": hostname},
                    tags=["journald", "process", hostname, unit],
                )
                events.append(process_event)

            # Generic system events for errors and warnings
            elif severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                system_event = BaseEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.ACCOUNTING,
                    severity=severity,
                    message=message,
                    timestamp=timestamp,
                    raw_data={"unit": unit, "hostname": hostname},
                    tags=["journald", "system", hostname, unit],
                )
                events.append(system_event)

        except Exception as e:
            logger.error("Error classifying journal entry", error=str(e))

        return events

    async def _create_auth_event_from_journal(
        self,
        message: str,
        unit: str,
        hostname: str,
        timestamp: datetime,
        severity: Severity,
        entry: Dict,
    ) -> Optional[AuthenticationEvent]:
        """Create authentication event from journal entry"""
        try:
            username = None
            source_ip = None
            success = True
            method = "system"

            # Check authentication patterns
            for pattern_name, pattern in self.auth_patterns.items():
                match = pattern.search(message)
                if match:
                    if pattern_name.startswith("ssh"):
                        method = "ssh"
                        if len(match.groups()) >= 2:
                            username = match.group(1)
                            source_ip = match.group(2)
                        success = "success" in pattern_name

                    elif pattern_name.startswith("sudo"):
                        method = "sudo"
                        if len(match.groups()) >= 1:
                            username = match.group(1)
                        # Sudo commands are generally successful
                        success = True

                    elif pattern_name.startswith("login"):
                        method = "login"
                        if len(match.groups()) >= 1:
                            username = match.group(1)
                        success = "success" in pattern_name

                    break

            # Extract additional details if not found by patterns
            if not username:
                # Try to extract from common fields
                username = entry.get("USER", entry.get("_SYSTEMD_USER", ""))
                if not username:
                    # Extract from message
                    user_patterns = [r"user\s+(\w+)", r"for\s+(\w+)", r"USER=(\w+)"]
                    for pattern in user_patterns:
                        match = re.search(pattern, message, re.IGNORECASE)
                        if match:
                            username = match.group(1)
                            break

            if not source_ip:
                # Try to extract IP address
                ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
                ip_match = re.search(ip_pattern, message)
                if ip_match:
                    source_ip = ip_match.group(1)

            # Determine success if not already set
            if any(
                word in message.lower()
                for word in ["failed", "failure", "invalid", "denied"]
            ):
                success = False

            # Adjust severity based on success
            if not success:
                severity = Severity.HIGH

            # Only create event if we have meaningful authentication information
            if username or source_ip or not success:
                return AuthenticationEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.AUTHENTICATION,
                    severity=severity,
                    message=message,
                    timestamp=timestamp,
                    username=username,
                    source_ip=source_ip,
                    success=success,
                    method=method,
                    raw_data={
                        "unit": unit,
                        "hostname": hostname,
                        "journal_entry": entry,
                    },
                    tags=["journald", "authentication", hostname, method],
                )

            return None

        except Exception as e:
            logger.error("Error creating auth event from journal", error=str(e))
            return None
