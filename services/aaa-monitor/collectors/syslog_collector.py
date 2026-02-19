"""
SkausWatch AAA Monitor Service - Syslog Collector

Syslog collector that receives RFC3164 and RFC5424 syslog messages
directly from network sources. Completely clientless operation.
"""

import asyncio
import json
import logging
import re
import socket
import traceback
from datetime import datetime, timedelta
from typing import Any, AsyncGenerator, Dict, List, Optional
from urllib.parse import urlparse

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


class SyslogCollector:
    """RFC3164/RFC5424 syslog message collector"""

    def __init__(self, config: Dict[str, Any], log_processor, analysis_engine):
        """Initialize Syslog collector

        Args:
            config: Syslog collector configuration
            log_processor: Log processor instance
            analysis_engine: Analysis engine instance
        """
        self.config = config
        self.log_processor = log_processor
        self.analysis_engine = analysis_engine

        # Collection state
        self.running = False
        self.collection_tasks = []

        # Server sockets
        self.tcp_server = None
        self.udp_transport = None
        self.udp_protocol = None

        # Client connections to remote syslog servers
        self.client_connections = {}

        # Message parsing patterns
        self.rfc3164_pattern = re.compile(
            r"^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$"
        )

        self.rfc5424_pattern = re.compile(
            r"^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$"
        )

        # Facility and severity mappings
        self.facilities = {
            0: "kernel",
            1: "user",
            2: "mail",
            3: "daemon",
            4: "auth",
            5: "syslog",
            6: "lpr",
            7: "news",
            8: "uucp",
            9: "cron",
            10: "authpriv",
            11: "ftp",
            16: "local0",
            17: "local1",
            18: "local2",
            19: "local3",
            20: "local4",
            21: "local5",
            22: "local6",
            23: "local7",
        }

        self.syslog_severities = {
            0: "emergency",
            1: "alert",
            2: "critical",
            3: "error",
            4: "warning",
            5: "notice",
            6: "info",
            7: "debug",
        }

    async def initialize(self):
        """Initialize syslog collector"""
        try:
            logger.info(
                "Initializing syslog collector",
                listen_port=self.config.listen_port,
                listen_address=self.config.listen_address,
                protocol=self.config.protocol,
            )

        except Exception as e:
            logger.error("Failed to initialize syslog collector", error=str(e))
            raise

    async def start_collection(self):
        """Start syslog collection"""
        if self.running:
            logger.warning("Syslog collector already running")
            return

        self.running = True
        logger.info("Starting syslog collection")

        try:
            # Start syslog servers
            if self.config.protocol in ["tcp", "both"]:
                task = asyncio.create_task(self._start_tcp_server())
                self.collection_tasks.append(task)

            if self.config.protocol in ["udp", "both"]:
                task = asyncio.create_task(self._start_udp_server())
                self.collection_tasks.append(task)

            # Start client connections to remote syslog servers
            for server_config in self.config.servers:
                task = asyncio.create_task(self._connect_to_server(server_config))
                self.collection_tasks.append(task)

            # Wait for all tasks
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)

        except Exception as e:
            logger.error("Error in syslog collection", error=str(e))
        finally:
            self.running = False

    async def stop(self):
        """Stop syslog collection"""
        self.running = False

        # Cancel all collection tasks
        for task in self.collection_tasks:
            if not task.done():
                task.cancel()

        # Wait for tasks to complete
        if self.collection_tasks:
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)

        self.collection_tasks.clear()

        # Close servers
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()

        if self.udp_transport:
            self.udp_transport.close()

        # Close client connections
        for conn_info in self.client_connections.values():
            if conn_info.get("writer"):
                conn_info["writer"].close()
                await conn_info["writer"].wait_closed()

        self.client_connections.clear()

        logger.info("Syslog collector stopped")

    async def _start_tcp_server(self):
        """Start TCP syslog server"""
        try:
            self.tcp_server = await asyncio.start_server(
                self._handle_tcp_client,
                self.config.listen_address,
                self.config.listen_port,
            )

            logger.info(
                "TCP syslog server started",
                address=self.config.listen_address,
                port=self.config.listen_port,
            )

            async with self.tcp_server:
                await self.tcp_server.serve_forever()

        except Exception as e:
            logger.error("Error in TCP syslog server", error=str(e))

    async def _handle_tcp_client(self, reader, writer):
        """Handle TCP client connection"""
        client_address = writer.get_extra_info("peername")
        logger.debug("TCP syslog client connected", client=client_address)

        try:
            while self.running:
                # Read syslog message (assuming newline-delimited)
                try:
                    data = await asyncio.wait_for(reader.readline(), timeout=60)
                    if not data:
                        break

                    message = data.decode("utf-8", errors="ignore").strip()
                    if message:
                        await self._process_syslog_message(
                            message, "tcp", client_address
                        )

                except asyncio.TimeoutError:
                    # Keep connection alive
                    continue
                except Exception as e:
                    logger.debug(
                        "Error reading from TCP client",
                        client=client_address,
                        error=str(e),
                    )
                    break

        except Exception as e:
            logger.error(
                "Error handling TCP client", client=client_address, error=str(e)
            )
        finally:
            writer.close()
            await writer.wait_closed()
            logger.debug("TCP syslog client disconnected", client=client_address)

    async def _start_udp_server(self):
        """Start UDP syslog server"""
        try:
            loop = asyncio.get_running_loop()

            # Create UDP endpoint
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: SyslogUDPProtocol(self),
                local_addr=(self.config.listen_address, self.config.listen_port),
            )

            self.udp_transport = transport
            self.udp_protocol = protocol

            logger.info(
                "UDP syslog server started",
                address=self.config.listen_address,
                port=self.config.listen_port,
            )

            # Keep server running
            while self.running:
                await asyncio.sleep(1)

        except Exception as e:
            logger.error("Error in UDP syslog server", error=str(e))

    async def _connect_to_server(self, server_config):
        """Connect to remote syslog server as client"""
        session_id = f"syslog-{server_config.host}:{server_config.port}"

        try:
            logger.info(
                "Connecting to syslog server",
                host=server_config.host,
                port=server_config.port,
                protocol=server_config.protocol,
            )

            while self.running:
                try:
                    if server_config.protocol.lower() == "tcp":
                        reader, writer = await asyncio.open_connection(
                            server_config.host, server_config.port
                        )

                        self.client_connections[session_id] = {
                            "reader": reader,
                            "writer": writer,
                            "config": server_config,
                        }

                        # Read messages from server
                        while self.running:
                            try:
                                data = await reader.readline()
                                if not data:
                                    break

                                message = data.decode("utf-8", errors="ignore").strip()
                                if message:
                                    await self._process_syslog_message(
                                        message,
                                        "tcp-client",
                                        (server_config.host, server_config.port),
                                    )

                            except Exception as e:
                                logger.debug(
                                    "Error reading from syslog server",
                                    session_id=session_id,
                                    error=str(e),
                                )
                                break

                        # Clean up connection
                        writer.close()
                        await writer.wait_closed()

                    else:
                        # UDP client connection would be different
                        logger.warning("UDP client connections not implemented yet")
                        break

                except Exception as e:
                    logger.error(
                        "Error connecting to syslog server",
                        session_id=session_id,
                        error=str(e),
                    )
                    await asyncio.sleep(30)  # Retry after delay

        except asyncio.CancelledError:
            logger.info("Syslog server connection cancelled", session_id=session_id)
        except Exception as e:
            logger.error(
                "Fatal error in syslog server connection",
                session_id=session_id,
                error=str(e),
            )

    async def _process_syslog_message(self, message: str, protocol: str, source: tuple):
        """Process received syslog message"""
        try:
            # Parse syslog message
            parsed = await self._parse_syslog_message(message)
            if not parsed:
                return

            # Extract components
            facility = parsed["facility"]
            severity = parsed["severity"]
            timestamp = parsed["timestamp"]
            hostname = parsed["hostname"]
            tag = parsed.get("tag", "")
            content = parsed["content"]

            # Classify message and create events
            events = await self._classify_syslog_message(
                content, timestamp, hostname, tag, facility, severity
            )

            # Add source information to events
            for event in events:
                event.raw_data.update(
                    {
                        "syslog_message": message,
                        "syslog_facility": facility,
                        "syslog_severity": severity,
                        "syslog_hostname": hostname,
                        "syslog_tag": tag,
                        "syslog_protocol": protocol,
                        "syslog_source": source,
                    }
                )
                await self.log_processor.process_event(event)

        except Exception as e:
            logger.error(
                "Error processing syslog message", message=message[:100], error=str(e)
            )

    async def _parse_syslog_message(self, message: str) -> Optional[Dict]:
        """Parse syslog message according to RFC3164 or RFC5424"""
        try:
            # Try RFC5424 format first
            match = self.rfc5424_pattern.match(message)
            if match:
                priority = int(match.group(1))
                version = match.group(2)
                timestamp_str = match.group(3)
                hostname = match.group(4)
                app_name = match.group(5)
                proc_id = match.group(6)
                msg_id = match.group(7)
                msg = match.group(8)

                facility = priority >> 3
                severity = priority & 7

                # Parse timestamp
                timestamp = self._parse_rfc5424_timestamp(timestamp_str)

                return {
                    "format": "rfc5424",
                    "facility": facility,
                    "severity": severity,
                    "timestamp": timestamp,
                    "hostname": hostname if hostname != "-" else "unknown",
                    "app_name": app_name if app_name != "-" else None,
                    "proc_id": proc_id if proc_id != "-" else None,
                    "msg_id": msg_id if msg_id != "-" else None,
                    "content": msg,
                    "tag": app_name if app_name != "-" else "syslog",
                }

            # Try RFC3164 format
            match = self.rfc3164_pattern.match(message)
            if match:
                priority = int(match.group(1))
                timestamp_str = match.group(2)
                hostname = match.group(3)
                msg = match.group(4)

                facility = priority >> 3
                severity = priority & 7

                # Parse timestamp
                timestamp = self._parse_rfc3164_timestamp(timestamp_str)

                # Extract tag from message
                tag = "syslog"
                if ":" in msg:
                    parts = msg.split(":", 1)
                    if len(parts) == 2 and " " not in parts[0]:
                        tag = parts[0]
                        msg = parts[1].lstrip()

                return {
                    "format": "rfc3164",
                    "facility": facility,
                    "severity": severity,
                    "timestamp": timestamp,
                    "hostname": hostname,
                    "content": msg,
                    "tag": tag,
                }

            # If no pattern matches, treat as raw message
            return {
                "format": "raw",
                "facility": 16,  # local0
                "severity": 6,  # info
                "timestamp": datetime.utcnow(),
                "hostname": "unknown",
                "content": message,
                "tag": "raw",
            }

        except Exception as e:
            logger.error("Error parsing syslog message", error=str(e))
            return None

    def _parse_rfc3164_timestamp(self, timestamp_str: str) -> datetime:
        """Parse RFC3164 timestamp format"""
        try:
            # RFC3164: "Dec 31 23:59:59"
            current_year = datetime.now().year
            timestamp = datetime.strptime(
                f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S"
            )
            return timestamp
        except Exception:
            return datetime.utcnow()

    def _parse_rfc5424_timestamp(self, timestamp_str: str) -> datetime:
        """Parse RFC5424 timestamp format"""
        try:
            # RFC5424: "2023-12-31T23:59:59.123456Z" or "-" for unknown
            if timestamp_str == "-":
                return datetime.utcnow()

            # Handle various ISO 8601 formats
            timestamp_str = timestamp_str.replace("T", " ").rstrip("Z")

            # Try with microseconds
            try:
                return datetime.fromisoformat(timestamp_str)
            except:
                # Try without microseconds
                if "." in timestamp_str:
                    timestamp_str = timestamp_str.split(".")[0]
                return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

        except Exception:
            return datetime.utcnow()

    async def _classify_syslog_message(
        self,
        content: str,
        timestamp: datetime,
        hostname: str,
        tag: str,
        facility: int,
        severity: int,
    ) -> List[BaseEvent]:
        """Classify syslog message and create appropriate events"""
        events = []

        try:
            content_lower = content.lower()

            # Map syslog severity to event severity
            severity_map = {
                0: Severity.CRITICAL,  # emergency
                1: Severity.CRITICAL,  # alert
                2: Severity.CRITICAL,  # critical
                3: Severity.HIGH,  # error
                4: Severity.MEDIUM,  # warning
                5: Severity.INFO,  # notice
                6: Severity.INFO,  # info
                7: Severity.LOW,  # debug
            }

            event_severity = severity_map.get(severity, Severity.INFO)

            # Authentication events
            if facility in [4, 10]:  # auth, authpriv
                if any(
                    keyword in content_lower
                    for keyword in [
                        "login",
                        "authentication",
                        "password",
                        "failed",
                        "accepted",
                    ]
                ):
                    event = await self._create_auth_event_from_syslog(
                        content, timestamp, hostname, tag, event_severity
                    )
                    if event:
                        events.append(event)

            # SSH events
            elif "ssh" in tag.lower() or "sshd" in content_lower:
                event = await self._create_ssh_event_from_syslog(
                    content, timestamp, hostname, tag, event_severity
                )
                if event:
                    events.append(event)

            # Sudo events
            elif "sudo" in content_lower:
                event = await self._create_sudo_event_from_syslog(
                    content, timestamp, hostname, tag, event_severity
                )
                if event:
                    events.append(event)

            # Kernel/system events
            elif facility == 0:  # kernel
                event = BaseEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.SYSTEM_CALL,
                    severity=event_severity,
                    message=content,
                    timestamp=timestamp,
                    raw_data={"hostname": hostname, "tag": tag, "facility": facility},
                    tags=["syslog", "kernel", hostname],
                )
                events.append(event)

            # Network events
            elif any(
                keyword in content_lower
                for keyword in ["connection", "network", "firewall", "iptables"]
            ):
                event = BaseEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.NETWORK,
                    severity=event_severity,
                    message=content,
                    timestamp=timestamp,
                    raw_data={"hostname": hostname, "tag": tag, "facility": facility},
                    tags=["syslog", "network", hostname],
                )
                events.append(event)

            # Generic system event for other interesting messages
            elif severity <= 4:  # emergency, alert, critical, error, warning
                event = BaseEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.ACCOUNTING,
                    severity=event_severity,
                    message=content,
                    timestamp=timestamp,
                    raw_data={"hostname": hostname, "tag": tag, "facility": facility},
                    tags=["syslog", self.facilities.get(facility, "unknown"), hostname],
                )
                events.append(event)

        except Exception as e:
            logger.error("Error classifying syslog message", error=str(e))

        return events

    async def _create_auth_event_from_syslog(
        self,
        content: str,
        timestamp: datetime,
        hostname: str,
        tag: str,
        severity: Severity,
    ) -> Optional[AuthenticationEvent]:
        """Create authentication event from syslog message"""
        try:
            username = None
            source_ip = None
            success = True
            method = "system"

            # Extract username
            username_patterns = [
                r"user\s+(\w+)",
                r"for\s+(\w+)",
                r"USER=(\w+)",
                r"login\s+(\w+)",
            ]

            for pattern in username_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    username = match.group(1)
                    break

            # Extract IP address
            ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            ip_match = re.search(ip_pattern, content)
            if ip_match:
                source_ip = ip_match.group(1)

            # Determine success
            if any(
                word in content.lower()
                for word in ["failed", "failure", "invalid", "denied"]
            ):
                success = False

            # Determine method
            if "password" in content.lower():
                method = "password"
            elif "key" in content.lower():
                method = "publickey"
            elif "certificate" in content.lower():
                method = "certificate"

            if username or source_ip:
                return AuthenticationEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.AUTHENTICATION,
                    severity=Severity.HIGH if not success else severity,
                    message=content,
                    timestamp=timestamp,
                    username=username,
                    source_ip=source_ip,
                    success=success,
                    method=method,
                    raw_data={
                        "hostname": hostname,
                        "tag": tag,
                        "syslog_content": content,
                    },
                    tags=["syslog", "authentication", hostname, method],
                )

            return None

        except Exception as e:
            logger.error("Error creating auth event from syslog", error=str(e))
            return None

    async def _create_ssh_event_from_syslog(
        self,
        content: str,
        timestamp: datetime,
        hostname: str,
        tag: str,
        severity: Severity,
    ) -> Optional[AuthenticationEvent]:
        """Create SSH event from syslog message"""
        try:
            username = None
            source_ip = None
            success = False
            method = "ssh"

            # SSH success patterns
            if "Accepted" in content:
                success = True
                # Extract username and IP
                accepted_pattern = r"Accepted \w+ for (\w+) from ([\d.]+)"
                match = re.search(accepted_pattern, content)
                if match:
                    username = match.group(1)
                    source_ip = match.group(2)

            # SSH failure patterns
            elif any(word in content for word in ["Failed", "Invalid", "Disconnected"]):
                success = False
                # Extract username and IP
                failed_patterns = [
                    r"Failed password for (\w+) from ([\d.]+)",
                    r"Invalid user (\w+) from ([\d.]+)",
                    r"Disconnected from (\w+) ([\d.]+)",
                ]

                for pattern in failed_patterns:
                    match = re.search(pattern, content)
                    if match:
                        if pattern.startswith("Disconnected"):
                            username = match.group(1)
                            source_ip = match.group(2)
                        else:
                            username = match.group(1)
                            source_ip = match.group(2)
                        break

            if username or source_ip:
                return AuthenticationEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.AUTHENTICATION,
                    severity=Severity.HIGH if not success else severity,
                    message=content,
                    timestamp=timestamp,
                    username=username,
                    source_ip=source_ip,
                    success=success,
                    method=method,
                    raw_data={"hostname": hostname, "tag": tag, "service": "sshd"},
                    tags=["syslog", "ssh", hostname],
                )

            return None

        except Exception as e:
            logger.error("Error creating SSH event from syslog", error=str(e))
            return None

    async def _create_sudo_event_from_syslog(
        self,
        content: str,
        timestamp: datetime,
        hostname: str,
        tag: str,
        severity: Severity,
    ) -> Optional[BaseEvent]:
        """Create sudo event from syslog message"""
        try:
            if "COMMAND" in content:
                # Successful sudo command
                command_pattern = r"(\w+)\s*:\s*TTY=([^\s]*)\s*;\s*PWD=([^\s]*)\s*;\s*USER=([^\s]*)\s*;\s*COMMAND=(.*)"
                match = re.search(command_pattern, content)

                if match:
                    username = match.group(1)
                    tty = match.group(2)
                    pwd = match.group(3)
                    target_user = match.group(4)
                    command = match.group(5)

                    return BaseEvent(
                        source=LogSource.SYSTEM,
                        event_type=EventType.PRIVILEGE_ESCALATION,
                        severity=severity,
                        message=content,
                        timestamp=timestamp,
                        raw_data={
                            "hostname": hostname,
                            "tag": tag,
                            "service": "sudo",
                            "username": username,
                            "target_user": target_user,
                            "command": command,
                            "tty": tty,
                            "pwd": pwd,
                        },
                        tags=["syslog", "sudo", hostname],
                    )

            return None

        except Exception as e:
            logger.error("Error creating sudo event from syslog", error=str(e))
            return None


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for syslog messages"""

    def __init__(self, collector: SyslogCollector):
        self.collector = collector

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            message = data.decode("utf-8", errors="ignore").strip()
            if message and self.collector.running:
                # Process message asynchronously
                asyncio.create_task(
                    self.collector._process_syslog_message(message, "udp", addr)
                )
        except Exception as e:
            logger.error("Error processing UDP syslog message", error=str(e))

    def error_received(self, exc):
        logger.error("UDP syslog protocol error", error=str(exc))
