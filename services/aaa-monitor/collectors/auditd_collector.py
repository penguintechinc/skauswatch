"""
SkausWatch AAA Monitor Service - Auditd Collector

Completely clientless auditd log collector for hypervisor monitoring.
Collects from centralized syslog servers, ELK stacks, SSH connections,
and journald APIs. No agents or log forwarding required.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, AsyncGenerator
import traceback
import ssl
from urllib.parse import urljoin, urlencode
import socket

import structlog
import aiohttp
import asyncssh

from ..models import (
    BaseEvent,
    AuthenticationEvent,
    AuthorizationEvent,
    SystemCallEvent,
    ProcessEvent,
    NetworkEvent,
    FileAccessEvent,
    EventType,
    LogSource,
    Severity,
)

logger = structlog.get_logger(__name__)


class AuditdCollector:
    """Completely clientless auditd log collector for hypervisor AAA monitoring"""

    def __init__(self, config: Dict[str, Any], log_processor, analysis_engine):
        """Initialize Auditd collector

        Args:
            config: Auditd collector configuration
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

        # SSH connections
        self.ssh_connections = {}

        # Syslog connections
        self.syslog_connections = {}

        # Log position tracking
        self.log_positions = {}

        # Event patterns for classification
        self.syscall_patterns = {
            "execve": re.compile(r'type=EXECVE.*comm="([^"]*)".*exe="([^"]*)"'),
            "openat": re.compile(r'type=OPENAT.*name="([^"]*)".*success=(\w+)'),
            "connect": re.compile(r"type=SOCKADDR.*saddr=([^\s]+)"),
            "bind": re.compile(r"type=BIND.*addr=([^\s]+)"),
            "chown": re.compile(r'type=CHOWN.*name="([^"]*)".*success=(\w+)'),
            "chmod": re.compile(r'type=CHMOD.*name="([^"]*)".*success=(\w+)'),
            "unlink": re.compile(r'type=UNLINK.*name="([^"]*)".*success=(\w+)'),
            "rename": re.compile(r'type=RENAME.*name="([^"]*)".*success=(\w+)'),
        }

        self.auth_patterns = {
            "user_login": re.compile(
                r'type=USER_LOGIN.*acct="([^"]*)".*addr=([^\s]+).*res=(\w+)'
            ),
            "user_logout": re.compile(
                r'type=USER_LOGOUT.*acct="([^"]*)".*addr=([^\s]+)'
            ),
            "user_start": re.compile(
                r'type=USER_START.*acct="([^"]*)".*addr=([^\s]+).*res=(\w+)'
            ),
            "user_end": re.compile(r'type=USER_END.*acct="([^"]*)".*addr=([^\s]+)'),
            "cred_acq": re.compile(
                r'type=CRED_ACQ.*acct="([^"]*)".*addr=([^\s]+).*res=(\w+)'
            ),
            "cred_disp": re.compile(r'type=CRED_DISP.*acct="([^"]*)".*addr=([^\s]+)'),
            "user_auth": re.compile(
                r'type=USER_AUTH.*acct="([^"]*)".*addr=([^\s]+).*res=(\w+)'
            ),
        }

        self.privilege_patterns = {
            "setuid": re.compile(r"type=SETUID.*old-auid=(\d+).*new-auid=(\d+)"),
            "setgid": re.compile(r"type=SETGID.*old-gid=(\d+).*new-gid=(\d+)"),
            "priv_escalation": re.compile(
                r"type=PRIV_ESCALATION.*old-ses=(\d+).*new-ses=(\d+)"
            ),
            "user_role_change": re.compile(
                r'type=USER_ROLE_CHANGE.*acct="([^"]*)".*old-role=([^\s]+).*new-role=([^\s]+)'
            ),
        }

        self.network_patterns = {
            "netfilter_cfg": re.compile(
                r"type=NETFILTER_CFG.*table=([^\s]+).*family=(\d+)"
            ),
            "iptables": re.compile(
                r"type=IPTABLES.*table=([^\s]+).*chain=([^\s]+).*rule=([^\s]+)"
            ),
            "sockaddr": re.compile(r"type=SOCKADDR.*saddr=([^\s]+)"),
        }

        # Critical system calls to monitor
        self.critical_syscalls = {
            "mount",
            "umount",
            "swapon",
            "swapoff",
            "init_module",
            "delete_module",
            "quotactl",
            "settimeofday",
            "stime",
            "adjtimex",
            "setdomainname",
            "sethostname",
            "personality",
            "uselib",
            "ustat",
            "statfs",
        }

        # Sensitive files to monitor
        self.sensitive_files = {
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/gshadow",
            "/etc/sudoers",
            "/etc/ssh/",
            "/root/.ssh/",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/fstab",
            "/etc/crontab",
        }

    async def initialize(self):
        """Initialize auditd collector with centralized sources"""
        try:
            # Initialize Elasticsearch connections if configured
            if self.config.elasticsearch_url:
                await self._initialize_elasticsearch_session()

            # Initialize Splunk connections if configured
            if self.config.splunk_url:
                await self._initialize_splunk_session()

            # Initialize journald API connections
            for endpoint in self.config.journald_endpoints:
                await self._initialize_journald_session(endpoint)

            # Initialize SSH connections
            for ssh_config in self.config.ssh_connections:
                await self._initialize_ssh_connection(ssh_config)

            # Initialize syslog server connections
            for syslog_config in self.config.syslog_servers:
                await self._initialize_syslog_connection(syslog_config)

            logger.info(
                "Auditd collector initialized successfully",
                elasticsearch=bool(self.config.elasticsearch_url),
                splunk=bool(self.config.splunk_url),
                journald_endpoints=len(self.config.journald_endpoints),
                ssh_connections=len(self.config.ssh_connections),
                syslog_servers=len(self.config.syslog_servers),
            )

        except Exception as e:
            logger.error("Failed to initialize auditd collector", error=str(e))
            raise

    async def _initialize_elasticsearch_session(self):
        """Initialize Elasticsearch HTTP session"""
        try:
            connector = aiohttp.TCPConnector(
                limit=self.config.max_connections_per_host, ttl_dns_cache=300
            )

            auth = None
            if (
                self.config.elasticsearch_username
                and self.config.elasticsearch_password
            ):
                auth = aiohttp.BasicAuth(
                    self.config.elasticsearch_username,
                    self.config.elasticsearch_password,
                )

            timeout = aiohttp.ClientTimeout(total=self.config.connection_timeout)
            session = aiohttp.ClientSession(
                connector=connector, auth=auth, timeout=timeout
            )

            self.http_sessions["elasticsearch"] = session
            self.http_connectors["elasticsearch"] = connector

            # Test connection
            async with session.get(self.config.elasticsearch_url) as response:
                if response.status == 200:
                    cluster_info = await response.json()
                    logger.info(
                        "Elasticsearch connection successful",
                        cluster_name=cluster_info.get("cluster_name"),
                        version=cluster_info.get("version", {}).get("number"),
                    )
                else:
                    logger.warning(
                        "Elasticsearch connection test failed", status=response.status
                    )

        except Exception as e:
            logger.error("Failed to initialize Elasticsearch session", error=str(e))

    async def _initialize_splunk_session(self):
        """Initialize Splunk HTTP session"""
        try:
            connector = aiohttp.TCPConnector(
                limit=self.config.max_connections_per_host, ttl_dns_cache=300
            )

            headers = {}
            if self.config.splunk_token:
                headers["Authorization"] = f"Bearer {self.config.splunk_token}"

            timeout = aiohttp.ClientTimeout(total=self.config.connection_timeout)
            session = aiohttp.ClientSession(
                connector=connector, headers=headers, timeout=timeout
            )

            self.http_sessions["splunk"] = session
            self.http_connectors["splunk"] = connector

            logger.info("Splunk session initialized", url=self.config.splunk_url)

        except Exception as e:
            logger.error("Failed to initialize Splunk session", error=str(e))

    async def _initialize_journald_session(self, endpoint):
        """Initialize journald API session"""
        try:
            session_id = f"journald-{endpoint.host}:{endpoint.port}"

            # Create SSL context if needed
            ssl_context = None
            if endpoint.ssl:
                ssl_context = ssl.create_default_context()
                if endpoint.cert_file and endpoint.key_file:
                    ssl_context.load_cert_chain(endpoint.cert_file, endpoint.key_file)

            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=self.config.max_connections_per_host,
                ttl_dns_cache=300,
            )

            base_url = f"{'https' if endpoint.ssl else 'http'}://{endpoint.host}:{endpoint.port}"

            timeout = aiohttp.ClientTimeout(total=self.config.connection_timeout)
            session = aiohttp.ClientSession(connector=connector, timeout=timeout)

            self.http_sessions[session_id] = {
                "session": session,
                "base_url": base_url,
                "config": endpoint,
            }
            self.http_connectors[session_id] = connector

            logger.info("Journald API session initialized", session_id=session_id)

        except Exception as e:
            logger.error(
                "Failed to initialize journald session",
                endpoint=f"{endpoint.host}:{endpoint.port}",
                error=str(e),
            )

    async def _initialize_ssh_connection(self, ssh_config):
        """Initialize SSH connection for direct log access"""
        try:
            session_id = f"ssh-{ssh_config.host}:{ssh_config.port}"

            # SSH connection options
            connect_kwargs = {
                "host": ssh_config.host,
                "port": ssh_config.port,
                "username": ssh_config.username,
                "known_hosts": None,  # Disable host key checking for automation
            }

            if ssh_config.key_file:
                connect_kwargs["client_keys"] = [ssh_config.key_file]
                if ssh_config.key_passphrase:
                    connect_kwargs["passphrase"] = ssh_config.key_passphrase
            elif ssh_config.password:
                connect_kwargs["password"] = ssh_config.password

            # Store connection config for lazy connection
            self.ssh_connections[session_id] = {
                "config": ssh_config,
                "connect_kwargs": connect_kwargs,
                "connection": None,
                "last_used": None,
            }

            logger.info("SSH connection configured", session_id=session_id)

        except Exception as e:
            logger.error(
                "Failed to configure SSH connection", host=ssh_config.host, error=str(e)
            )

    async def _initialize_syslog_connection(self, syslog_config):
        """Initialize syslog server connection"""
        try:
            session_id = f"syslog-{syslog_config.host}:{syslog_config.port}"

            self.syslog_connections[session_id] = {
                "config": syslog_config,
                "connection": None,
                "reader": None,
                "writer": None,
            }

            logger.info("Syslog connection configured", session_id=session_id)

        except Exception as e:
            logger.error(
                "Failed to configure syslog connection",
                host=syslog_config.host,
                error=str(e),
            )

    async def start_collection(self):
        """Start log collection from centralized sources"""
        if self.running:
            logger.warning("Auditd collector already running")
            return

        self.running = True
        logger.info("Starting auditd log collection")

        try:
            # Start Elasticsearch log collection
            if "elasticsearch" in self.http_sessions:
                task = asyncio.create_task(self._collect_from_elasticsearch())
                self.collection_tasks.append(task)

            # Start Splunk log collection
            if "splunk" in self.http_sessions:
                task = asyncio.create_task(self._collect_from_splunk())
                self.collection_tasks.append(task)

            # Start journald API collection
            for session_id in self.http_sessions.keys():
                if session_id.startswith("journald-"):
                    task = asyncio.create_task(self._collect_from_journald(session_id))
                    self.collection_tasks.append(task)

            # Start SSH log collection
            for session_id in self.ssh_connections.keys():
                task = asyncio.create_task(self._collect_from_ssh(session_id))
                self.collection_tasks.append(task)

            # Start syslog collection
            for session_id in self.syslog_connections.keys():
                task = asyncio.create_task(self._collect_from_syslog(session_id))
                self.collection_tasks.append(task)

            # Wait for all tasks
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)

        except Exception as e:
            logger.error("Error in auditd log collection", error=str(e))
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

        # Close SSH connections
        for ssh_info in self.ssh_connections.values():
            if ssh_info["connection"]:
                ssh_info["connection"].close()

        # Close syslog connections
        for syslog_info in self.syslog_connections.values():
            if syslog_info["writer"]:
                syslog_info["writer"].close()

        # Close HTTP sessions
        for session_info in self.http_sessions.values():
            if isinstance(session_info, dict):
                await session_info["session"].close()
            else:
                await session_info.close()

        # Close connectors
        for connector in self.http_connectors.values():
            await connector.close()

        self.http_sessions.clear()
        self.http_connectors.clear()
        self.ssh_connections.clear()
        self.syslog_connections.clear()

        logger.info("Auditd collector stopped")

    async def _collect_from_elasticsearch(self):
        """Collect audit logs from Elasticsearch"""
        logger.info("Starting Elasticsearch audit logs collection")

        try:
            session = self.http_sessions["elasticsearch"]

            while self.running:
                try:
                    # Query for recent audit logs
                    query = {
                        "query": {
                            "bool": {
                                "must": [
                                    {"range": {"@timestamp": {"gte": "now-5m"}}},
                                    {"exists": {"field": "auditd"}},
                                ]
                            }
                        },
                        "sort": [{"@timestamp": {"order": "desc"}}],
                        "size": 1000,
                    }

                    search_url = f"{self.config.elasticsearch_url}/{self.config.elasticsearch_index_pattern}/_search"

                    async with session.post(search_url, json=query) as response:
                        if response.status == 200:
                            results = await response.json()
                            hits = results.get("hits", {}).get("hits", [])

                            for hit in hits:
                                source = hit.get("_source", {})
                                await self._process_elasticsearch_log(source)

                        else:
                            logger.warning(
                                "Elasticsearch query failed", status=response.status
                            )

                    await asyncio.sleep(self.config.audit_poll_interval)

                except Exception as e:
                    logger.error("Error in Elasticsearch collection", error=str(e))
                    await asyncio.sleep(30)

        except asyncio.CancelledError:
            logger.info("Elasticsearch logs collection cancelled")
        except Exception as e:
            logger.error("Fatal error in Elasticsearch logs collection", error=str(e))

    async def _collect_from_splunk(self):
        """Collect audit logs from Splunk"""
        logger.info("Starting Splunk audit logs collection")

        try:
            session = self.http_sessions["splunk"]

            while self.running:
                try:
                    # Splunk search query for audit logs
                    search_query = f"search index={self.config.splunk_index} earliest=-5m | head 1000"

                    search_url = f"{self.config.splunk_url}/services/search/jobs/export"

                    data = {
                        "search": search_query,
                        "output_mode": "json",
                        "earliest_time": "-5m",
                        "latest_time": "now",
                    }

                    async with session.post(search_url, data=data) as response:
                        if response.status == 200:
                            async for line in response.content:
                                try:
                                    log_data = json.loads(line.decode())
                                    await self._process_splunk_log(log_data)
                                except json.JSONDecodeError:
                                    continue
                        else:
                            logger.warning(
                                "Splunk query failed", status=response.status
                            )

                    await asyncio.sleep(self.config.audit_poll_interval)

                except Exception as e:
                    logger.error("Error in Splunk collection", error=str(e))
                    await asyncio.sleep(30)

        except asyncio.CancelledError:
            logger.info("Splunk logs collection cancelled")
        except Exception as e:
            logger.error("Fatal error in Splunk logs collection", error=str(e))

    async def _collect_from_journald(self, session_id: str):
        """Collect logs from journald API"""
        logger.info("Starting journald API logs collection", session_id=session_id)

        try:
            session_info = self.http_sessions[session_id]
            session = session_info["session"]
            base_url = session_info["base_url"]

            while self.running:
                try:
                    # Query journald for recent entries
                    since_timestamp = int(
                        (datetime.utcnow() - timedelta(minutes=5)).timestamp()
                    )

                    params = {
                        "since": since_timestamp,
                        "follow": False,
                        "output": "json",
                        "lines": 1000,
                    }

                    entries_url = f"{base_url}/entries"

                    async with session.get(entries_url, params=params) as response:
                        if response.status == 200:
                            async for line in response.content:
                                try:
                                    entry = json.loads(line.decode())
                                    await self._process_journald_entry(
                                        entry, session_id
                                    )
                                except json.JSONDecodeError:
                                    continue
                        else:
                            logger.warning(
                                "Journald API query failed",
                                session_id=session_id,
                                status=response.status,
                            )

                    await asyncio.sleep(self.config.audit_poll_interval)

                except Exception as e:
                    logger.error(
                        "Error in journald collection",
                        session_id=session_id,
                        error=str(e),
                    )
                    await asyncio.sleep(30)

        except asyncio.CancelledError:
            logger.info("Journald logs collection cancelled", session_id=session_id)
        except Exception as e:
            logger.error(
                "Fatal error in journald logs collection",
                session_id=session_id,
                error=str(e),
            )

    async def _collect_from_ssh(self, session_id: str):
        """Collect logs via SSH from hypervisor hosts"""
        logger.info("Starting SSH logs collection", session_id=session_id)

        try:
            ssh_info = self.ssh_connections[session_id]

            while self.running:
                try:
                    # Establish SSH connection if needed
                    if not ssh_info["connection"] or ssh_info["connection"].is_closed():
                        ssh_info["connection"] = await asyncssh.connect(
                            **ssh_info["connect_kwargs"]
                        )
                        logger.info("SSH connection established", session_id=session_id)

                    conn = ssh_info["connection"]

                    # Read audit logs from hypervisor
                    audit_commands = [
                        "tail -n 100 /var/log/audit/audit.log",
                        "tail -n 100 /var/log/auth.log",
                        "journalctl -n 100 --no-pager -o json",
                    ]

                    for command in audit_commands:
                        try:
                            result = await conn.run(command)
                            if result.exit_status == 0:
                                output = result.stdout
                                await self._process_ssh_output(
                                    output, session_id, command
                                )
                        except Exception as e:
                            logger.debug(
                                "SSH command failed",
                                session_id=session_id,
                                command=command,
                                error=str(e),
                            )

                    ssh_info["last_used"] = datetime.utcnow()
                    await asyncio.sleep(self.config.ssh_poll_interval)

                except Exception as e:
                    logger.error(
                        "Error in SSH collection", session_id=session_id, error=str(e)
                    )
                    # Close broken connection
                    if ssh_info["connection"]:
                        ssh_info["connection"].close()
                        ssh_info["connection"] = None
                    await asyncio.sleep(60)

        except asyncio.CancelledError:
            logger.info("SSH logs collection cancelled", session_id=session_id)
        except Exception as e:
            logger.error(
                "Fatal error in SSH logs collection",
                session_id=session_id,
                error=str(e),
            )

    async def _collect_from_syslog(self, session_id: str):
        """Collect logs from syslog server"""
        logger.info("Starting syslog collection", session_id=session_id)

        try:
            syslog_info = self.syslog_connections[session_id]
            config = syslog_info["config"]

            while self.running:
                try:
                    # Connect to syslog server
                    if config.protocol.lower() == "tcp":
                        reader, writer = await asyncio.open_connection(
                            config.host, config.port
                        )
                        syslog_info["reader"] = reader
                        syslog_info["writer"] = writer

                        # Read syslog messages
                        while self.running:
                            try:
                                data = await reader.read(1024)
                                if not data:
                                    break

                                message = data.decode("utf-8", errors="ignore")
                                await self._process_syslog_message(message, session_id)

                            except asyncio.IncompleteReadError:
                                break

                    elif config.protocol.lower() == "udp":
                        # UDP syslog collection would need different approach
                        # For now, we'll skip UDP implementation
                        logger.info("UDP syslog collection not implemented yet")
                        break

                except Exception as e:
                    logger.error(
                        "Error in syslog collection",
                        session_id=session_id,
                        error=str(e),
                    )
                    await asyncio.sleep(30)

        except asyncio.CancelledError:
            logger.info("Syslog collection cancelled", session_id=session_id)
        except Exception as e:
            logger.error(
                "Fatal error in syslog collection", session_id=session_id, error=str(e)
            )

    # Processing methods for different sources
    async def _process_elasticsearch_log(self, source: Dict):
        """Process log entry from Elasticsearch"""
        try:
            # Extract audit data from Elasticsearch document
            auditd_data = source.get("auditd", {})
            message = source.get("message", "")
            timestamp_str = source.get("@timestamp", "")

            # Parse timestamp
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except:
                timestamp = datetime.utcnow()

            if message:
                events = await self._classify_audit_record(message, timestamp)
                for event in events:
                    event.raw_data["elasticsearch_source"] = source
                    await self.log_processor.process_event(event)

        except Exception as e:
            logger.error("Error processing Elasticsearch log", error=str(e))

    async def _process_splunk_log(self, log_data: Dict):
        """Process log entry from Splunk"""
        try:
            raw_message = log_data.get("_raw", "")
            timestamp_str = log_data.get("_time", "")

            # Parse timestamp
            try:
                timestamp = datetime.fromtimestamp(float(timestamp_str))
            except:
                timestamp = datetime.utcnow()

            if raw_message:
                events = await self._classify_audit_record(raw_message, timestamp)
                for event in events:
                    event.raw_data["splunk_source"] = log_data
                    await self.log_processor.process_event(event)

        except Exception as e:
            logger.error("Error processing Splunk log", error=str(e))

    async def _process_journald_entry(self, entry: Dict, session_id: str):
        """Process journald entry"""
        try:
            message = entry.get("MESSAGE", "")
            timestamp_str = entry.get("__REALTIME_TIMESTAMP", "")

            # Parse timestamp (microseconds since epoch)
            try:
                timestamp = datetime.fromtimestamp(int(timestamp_str) / 1000000)
            except:
                timestamp = datetime.utcnow()

            if message:
                events = await self._classify_audit_record(message, timestamp)
                for event in events:
                    event.raw_data["journald_entry"] = entry
                    event.raw_data["session_id"] = session_id
                    await self.log_processor.process_event(event)

        except Exception as e:
            logger.error(
                "Error processing journald entry", session_id=session_id, error=str(e)
            )

    async def _process_ssh_output(self, output: str, session_id: str, command: str):
        """Process output from SSH command"""
        try:
            lines = output.strip().split("\n")

            for line in lines:
                if not line.strip():
                    continue

                try:
                    # Handle JSON output from journalctl
                    if command.startswith("journalctl") and line.startswith("{"):
                        entry = json.loads(line)
                        await self._process_journald_entry(entry, session_id)
                    else:
                        # Handle regular log lines
                        await self._parse_audit_line(line)
                except json.JSONDecodeError:
                    # Not JSON, process as regular log line
                    await self._parse_audit_line(line)
                except Exception as e:
                    logger.debug(
                        "Error processing SSH line", session_id=session_id, error=str(e)
                    )

        except Exception as e:
            logger.error(
                "Error processing SSH output", session_id=session_id, error=str(e)
            )

    async def _process_syslog_message(self, message: str, session_id: str):
        """Process syslog message"""
        try:
            # Parse syslog format and extract audit messages
            lines = message.strip().split("\n")

            for line in lines:
                if not line.strip():
                    continue

                # Look for audit-related messages
                if any(
                    keyword in line.lower()
                    for keyword in ["audit", "auditd", "sudo", "su:", "ssh", "login"]
                ):
                    await self._parse_audit_line(line)

        except Exception as e:
            logger.error(
                "Error processing syslog message", session_id=session_id, error=str(e)
            )

    async def _parse_audit_line(self, line: str):
        """Parse individual audit log line and create events"""
        try:
            # Extract timestamp
            timestamp = await self._extract_timestamp(line)

            # Classify the audit record
            events = await self._classify_audit_record(line, timestamp)

            # Process each event
            for event in events:
                await self.log_processor.process_event(event)

        except Exception as e:
            logger.error("Error parsing audit line", error=str(e))

    async def _extract_timestamp(self, line: str) -> datetime:
        """Extract timestamp from audit log line"""
        try:
            # Audit log format: type=TYPE msg=audit(timestamp:sequence): ...
            timestamp_pattern = r"msg=audit\((\d+\.\d+):\d+\):"
            match = re.search(timestamp_pattern, line)

            if match:
                timestamp_str = match.group(1)
                timestamp = datetime.fromtimestamp(float(timestamp_str))
                return timestamp
            else:
                return datetime.utcnow()

        except Exception:
            return datetime.utcnow()

    async def _classify_audit_record(
        self, line: str, timestamp: datetime
    ) -> List[BaseEvent]:
        """Classify audit record and create appropriate events"""
        events = []

        try:
            # Check authentication patterns
            for pattern_name, pattern in self.auth_patterns.items():
                match = pattern.search(line)
                if match:
                    event = await self._create_auth_event(
                        line, timestamp, pattern_name, match
                    )
                    events.append(event)
                    break

            # Check privilege escalation patterns
            for pattern_name, pattern in self.privilege_patterns.items():
                match = pattern.search(line)
                if match:
                    event = await self._create_privilege_event(
                        line, timestamp, pattern_name, match
                    )
                    events.append(event)
                    break

            # Check system call patterns
            for pattern_name, pattern in self.syscall_patterns.items():
                match = pattern.search(line)
                if match:
                    event = await self._create_syscall_event(
                        line, timestamp, pattern_name, match
                    )
                    events.append(event)
                    break

            # Check network patterns
            for pattern_name, pattern in self.network_patterns.items():
                match = pattern.search(line)
                if match:
                    event = await self._create_network_event(
                        line, timestamp, pattern_name, match
                    )
                    events.append(event)
                    break

            # If no specific pattern matched, create generic audit event for certain types
            if not events and any(
                audit_type in line
                for audit_type in ["SYSCALL", "PATH", "CWD", "PROCTITLE"]
            ):
                event = await self._create_generic_audit_event(line, timestamp)
                if event:
                    events.append(event)

        except Exception as e:
            logger.error("Error classifying audit record", error=str(e))

        return events

    async def _create_auth_event(
        self, line: str, timestamp: datetime, pattern_name: str, match
    ) -> AuthenticationEvent:
        """Create authentication event from audit line"""
        username = None
        source_ip = None
        success = True
        method = "system"

        try:
            # Extract username from match groups
            if match.groups() and len(match.groups()) >= 1:
                username = match.group(1)

            # Extract IP address
            if len(match.groups()) >= 2:
                addr_info = match.group(2)
                # Parse address info
                ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", addr_info)
                if ip_match:
                    source_ip = ip_match.group(1)

            # Determine success
            if len(match.groups()) >= 3:
                result = match.group(3).lower()
                success = result in ["success", "yes", "successful"]

            # Determine authentication method
            if "login" in pattern_name:
                method = "login"
            elif "cred" in pattern_name:
                method = "credentials"
            elif "auth" in pattern_name:
                method = "authentication"

        except Exception as e:
            logger.error("Error extracting auth event details", error=str(e))

        severity = Severity.HIGH if not success else Severity.INFO

        return AuthenticationEvent(
            source=LogSource.AUDITD,
            event_type=EventType.AUTHENTICATION,
            severity=severity,
            message=line,
            timestamp=timestamp,
            username=username,
            source_ip=source_ip,
            success=success,
            method=method,
            raw_data={"audit_line": line, "pattern_matched": pattern_name},
            tags=["auditd", "authentication", pattern_name, method],
        )

    async def _create_privilege_event(
        self, line: str, timestamp: datetime, pattern_name: str, match
    ) -> BaseEvent:
        """Create privilege escalation event from audit line"""
        try:
            old_value = None
            new_value = None
            username = None

            # Extract privilege change details
            if pattern_name in ["setuid", "setgid"]:
                if len(match.groups()) >= 2:
                    old_value = match.group(1)
                    new_value = match.group(2)
            elif pattern_name == "user_role_change":
                if len(match.groups()) >= 3:
                    username = match.group(1)
                    old_value = match.group(2)
                    new_value = match.group(3)

            # Extract additional context from audit line
            pid_match = re.search(r"pid=(\d+)", line)
            pid = int(pid_match.group(1)) if pid_match else None

            comm_match = re.search(r'comm="([^"]*)"', line)
            command = comm_match.group(1) if comm_match else None

        except Exception as e:
            logger.error("Error extracting privilege event details", error=str(e))
            old_value = new_value = username = None
            pid = None
            command = None

        return BaseEvent(
            source=LogSource.AUDITD,
            event_type=EventType.PRIVILEGE_ESCALATION,
            severity=Severity.HIGH,
            message=line,
            timestamp=timestamp,
            raw_data={
                "audit_line": line,
                "pattern_matched": pattern_name,
                "old_value": old_value,
                "new_value": new_value,
                "username": username,
                "pid": pid,
                "command": command,
            },
            tags=["auditd", "privilege-escalation", pattern_name],
        )

    async def _create_syscall_event(
        self, line: str, timestamp: datetime, pattern_name: str, match
    ) -> SystemCallEvent:
        """Create system call event from audit line"""
        try:
            syscall_name = pattern_name
            arguments = []
            result = None
            pid = None
            user = None

            # Extract system call details
            if pattern_name == "execve":
                if len(match.groups()) >= 2:
                    command = match.group(1)
                    executable = match.group(2)
                    arguments = [command, executable]
            elif pattern_name in ["openat", "chown", "chmod", "unlink", "rename"]:
                if len(match.groups()) >= 2:
                    filename = match.group(1)
                    result = match.group(2)
                    arguments = [filename]

            # Extract PID
            pid_match = re.search(r"pid=(\d+)", line)
            if pid_match:
                pid = int(pid_match.group(1))

            # Extract user ID
            uid_match = re.search(r"uid=(\d+)", line)
            if uid_match:
                # Convert UID to username if possible
                user = uid_match.group(1)

            # Extract return code
            exit_match = re.search(r"exit=(-?\d+)", line)
            return_code = int(exit_match.group(1)) if exit_match else None

        except Exception as e:
            logger.error("Error extracting syscall event details", error=str(e))
            arguments = []
            result = None
            pid = None
            user = None
            return_code = None

        # Determine severity based on syscall type and result
        severity = Severity.INFO
        if syscall_name in self.critical_syscalls:
            severity = Severity.HIGH
        elif result == "fail" or (return_code and return_code < 0):
            severity = Severity.MEDIUM

        return SystemCallEvent(
            source=LogSource.AUDITD,
            event_type=EventType.SYSTEM_CALL,
            severity=severity,
            message=line,
            timestamp=timestamp,
            syscall=syscall_name,
            pid=pid,
            user=user,
            result=result,
            arguments=arguments,
            return_code=return_code,
            raw_data={"audit_line": line, "pattern_matched": pattern_name},
            tags=["auditd", "syscall", syscall_name],
        )

    async def _create_network_event(
        self, line: str, timestamp: datetime, pattern_name: str, match
    ) -> NetworkEvent:
        """Create network event from audit line"""
        try:
            protocol = None
            source_ip = None
            destination_ip = None
            source_port = None
            destination_port = None

            if pattern_name == "sockaddr":
                # Parse socket address information
                addr_info = match.group(1) if match.groups() else ""

                # Try to extract IP and port from hex-encoded address
                if addr_info.startswith("02"):  # AF_INET family
                    # Parse IPv4 socket address structure
                    try:
                        # Simple parsing for demonstration
                        # In practice, this would need proper hex decoding
                        pass
                    except:
                        pass

            # Extract additional network context
            pid_match = re.search(r"pid=(\d+)", line)
            pid = int(pid_match.group(1)) if pid_match else None

        except Exception as e:
            logger.error("Error extracting network event details", error=str(e))

        return NetworkEvent(
            source=LogSource.AUDITD,
            event_type=EventType.NETWORK,
            severity=Severity.INFO,
            message=line,
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            raw_data={"audit_line": line, "pattern_matched": pattern_name},
            tags=["auditd", "network", pattern_name],
        )

    async def _create_generic_audit_event(
        self, line: str, timestamp: datetime
    ) -> Optional[BaseEvent]:
        """Create generic audit event for unclassified records"""
        try:
            # Only create events for potentially interesting audit records
            if any(
                keyword in line.upper()
                for keyword in ["DENIED", "FAILED", "ERROR", "VIOLATION", "SUSPICIOUS"]
            ):

                return BaseEvent(
                    source=LogSource.AUDITD,
                    event_type=EventType.SYSTEM_CALL,
                    severity=Severity.MEDIUM,
                    message=line,
                    timestamp=timestamp,
                    raw_data={"audit_line": line},
                    tags=["auditd", "generic"],
                )

            return None

        except Exception as e:
            logger.error("Error creating generic audit event", error=str(e))
            return None
