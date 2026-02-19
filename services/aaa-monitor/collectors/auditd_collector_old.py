"""
SkausWatch AAA Monitor Service - Auditd Collector

Auditd log collector for hypervisor monitoring that captures system calls,
file access events, network connections, login events, and privilege escalations.
"""

import asyncio
import json
import logging
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, AsyncGenerator
import traceback

import structlog
import aiofiles

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
    """Auditd log collector for hypervisor AAA monitoring"""

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

        # Audit log paths
        self.audit_log_path = config.get("audit_log_path", "/var/log/audit/audit.log")
        self.auth_log_path = config.get("auth_log_path", "/var/log/auth.log")

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
        """Initialize auditd collector"""
        try:
            # Verify auditd installation and configuration
            await self._verify_auditd_installation()

            # Check audit log files
            await self._verify_audit_logs()

            # Initialize log positions
            await self._initialize_log_positions()

            logger.info("Auditd collector initialized successfully")

        except Exception as e:
            logger.error("Failed to initialize auditd collector", error=str(e))
            raise

    async def _verify_auditd_installation(self):
        """Verify auditd installation and service status"""
        try:
            # Check if auditd service is running
            result = await asyncio.create_subprocess_exec(
                "systemctl",
                "is-active",
                "auditd",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = await result.communicate()

            if result.returncode == 0:
                status = stdout.decode().strip()
                logger.info("Auditd service status", status=status)

                if status != "active":
                    logger.warning("Auditd service is not active", status=status)
            else:
                logger.warning("Cannot determine auditd service status")

            # Check audit rules
            await self._check_audit_rules()

        except FileNotFoundError:
            logger.warning("systemctl not found, cannot verify auditd service")
        except Exception as e:
            logger.error("Error verifying auditd installation", error=str(e))

    async def _check_audit_rules(self):
        """Check current audit rules configuration"""
        try:
            result = await asyncio.create_subprocess_exec(
                "auditctl", "-l", stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = await result.communicate()

            if result.returncode == 0:
                rules_output = stdout.decode()
                rules_count = (
                    len(rules_output.strip().split("\n")) if rules_output.strip() else 0
                )
                logger.info("Audit rules loaded", count=rules_count)

                # Log some key rules if they exist
                if "syscall" in rules_output:
                    logger.info("System call monitoring enabled")
                if "/etc/passwd" in rules_output:
                    logger.info("Sensitive file monitoring enabled")
            else:
                logger.warning("Cannot retrieve audit rules", error=stderr.decode())

        except FileNotFoundError:
            logger.warning("auditctl not found, cannot check audit rules")
        except Exception as e:
            logger.error("Error checking audit rules", error=str(e))

    async def _verify_audit_logs(self):
        """Verify audit log files exist and are readable"""
        log_files = [
            self.audit_log_path,
            self.auth_log_path,
        ]

        for log_file in log_files:
            try:
                log_path = Path(log_file)
                if log_path.exists():
                    # Check if file is readable
                    async with aiofiles.open(log_file, "r") as f:
                        # Try to read first line
                        await f.readline()
                    logger.info("Audit log file verified", path=log_file)
                else:
                    logger.warning("Audit log file not found", path=log_file)

            except PermissionError:
                logger.error("Permission denied accessing audit log", path=log_file)
                raise
            except Exception as e:
                logger.error("Error verifying audit log", path=log_file, error=str(e))

    async def _initialize_log_positions(self):
        """Initialize log file positions for tailing"""
        log_files = [self.audit_log_path, self.auth_log_path]

        for log_file in log_files:
            try:
                log_path = Path(log_file)
                if log_path.exists():
                    # Start from end of file for new installations
                    # or from saved position for resumed monitoring
                    file_size = log_path.stat().st_size
                    self.log_positions[log_file] = file_size
                    logger.info(
                        "Initialized log position", file=log_file, position=file_size
                    )

            except Exception as e:
                logger.error(
                    "Error initializing log position", file=log_file, error=str(e)
                )
                self.log_positions[log_file] = 0

    async def start_collection(self):
        """Start log collection from auditd"""
        if self.running:
            logger.warning("Auditd collector already running")
            return

        self.running = True
        logger.info("Starting auditd log collection")

        try:
            # Start audit log collection
            if self.config.get("collect_audit_logs", True):
                task = asyncio.create_task(self._collect_audit_logs())
                self.collection_tasks.append(task)

            # Start auth log collection
            if self.config.get("collect_auth_logs", True):
                task = asyncio.create_task(self._collect_auth_logs())
                self.collection_tasks.append(task)

            # Start real-time audit monitoring
            if self.config.get("monitor_realtime", True):
                task = asyncio.create_task(self._monitor_realtime_events())
                self.collection_tasks.append(task)

            # Start system call analysis
            if self.config.get("analyze_syscalls", True):
                task = asyncio.create_task(self._analyze_syscall_patterns())
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
        logger.info("Auditd collector stopped")

    async def _collect_audit_logs(self):
        """Collect and process audit.log entries"""
        logger.info("Starting audit logs collection")

        try:
            while self.running:
                try:
                    await self._process_audit_log_file(self.audit_log_path)
                    await asyncio.sleep(self.config.get("audit_poll_interval", 5))

                except Exception as e:
                    logger.error("Error in audit logs collection", error=str(e))
                    await asyncio.sleep(30)

        except asyncio.CancelledError:
            logger.info("Audit logs collection cancelled")
        except Exception as e:
            logger.error("Fatal error in audit logs collection", error=str(e))

    async def _process_audit_log_file(self, log_file: str):
        """Process audit log file for new entries"""
        try:
            current_position = self.log_positions.get(log_file, 0)

            async with aiofiles.open(log_file, "r") as f:
                await f.seek(current_position)

                lines = []
                async for line in f:
                    lines.append(line.strip())

                # Update position
                new_position = await f.tell()
                self.log_positions[log_file] = new_position

                # Process new lines
                if lines:
                    await self._process_audit_lines(lines)

        except Exception as e:
            logger.error("Error processing audit log file", file=log_file, error=str(e))

    async def _process_audit_lines(self, lines: List[str]):
        """Process audit log lines"""
        for line in lines:
            if not line.strip():
                continue

            try:
                await self._parse_audit_line(line)
            except Exception as e:
                logger.error("Error parsing audit line", line=line[:100], error=str(e))

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

    async def _collect_auth_logs(self):
        """Collect and process auth.log entries"""
        logger.info("Starting auth logs collection")

        try:
            while self.running:
                try:
                    await self._process_auth_log_file(self.auth_log_path)
                    await asyncio.sleep(self.config.get("auth_poll_interval", 10))

                except Exception as e:
                    logger.error("Error in auth logs collection", error=str(e))
                    await asyncio.sleep(30)

        except asyncio.CancelledError:
            logger.info("Auth logs collection cancelled")
        except Exception as e:
            logger.error("Fatal error in auth logs collection", error=str(e))

    async def _process_auth_log_file(self, log_file: str):
        """Process authentication log file for new entries"""
        try:
            if not Path(log_file).exists():
                return

            current_position = self.log_positions.get(log_file, 0)

            async with aiofiles.open(log_file, "r") as f:
                await f.seek(current_position)

                lines = []
                async for line in f:
                    lines.append(line.strip())

                # Update position
                new_position = await f.tell()
                self.log_positions[log_file] = new_position

                # Process new lines
                if lines:
                    await self._process_auth_lines(lines)

        except Exception as e:
            logger.error("Error processing auth log file", file=log_file, error=str(e))

    async def _process_auth_lines(self, lines: List[str]):
        """Process authentication log lines"""
        for line in lines:
            if not line.strip():
                continue

            try:
                await self._parse_auth_line(line)
            except Exception as e:
                logger.error("Error parsing auth line", line=line[:100], error=str(e))

    async def _parse_auth_line(self, line: str):
        """Parse authentication log line and create events"""
        try:
            # Extract timestamp from syslog format
            timestamp = await self._extract_syslog_timestamp(line)

            # Common auth log patterns
            auth_events = []

            # SSH authentication
            if "sshd" in line:
                event = await self._parse_ssh_auth(line, timestamp)
                if event:
                    auth_events.append(event)

            # Sudo events
            elif "sudo" in line:
                event = await self._parse_sudo_event(line, timestamp)
                if event:
                    auth_events.append(event)

            # System login events
            elif any(service in line for service in ["login", "systemd-logind"]):
                event = await self._parse_login_event(line, timestamp)
                if event:
                    auth_events.append(event)

            # Process events
            for event in auth_events:
                await self.log_processor.process_event(event)

        except Exception as e:
            logger.error("Error parsing auth line", error=str(e))

    async def _extract_syslog_timestamp(self, line: str) -> datetime:
        """Extract timestamp from syslog format"""
        try:
            # Syslog format: Dec 31 23:59:59 hostname service: message
            timestamp_pattern = r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
            match = re.match(timestamp_pattern, line)

            if match:
                timestamp_str = match.group(1)
                # Add current year
                current_year = datetime.now().year
                timestamp = datetime.strptime(
                    f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S"
                )
                return timestamp
            else:
                return datetime.utcnow()

        except Exception:
            return datetime.utcnow()

    async def _parse_ssh_auth(
        self, line: str, timestamp: datetime
    ) -> Optional[AuthenticationEvent]:
        """Parse SSH authentication events"""
        try:
            username = None
            source_ip = None
            success = False
            method = "ssh"

            # SSH success patterns
            if "Accepted" in line:
                success = True
                # Extract username and IP
                accepted_pattern = r"Accepted \w+ for (\w+) from ([\d.]+)"
                match = re.search(accepted_pattern, line)
                if match:
                    username = match.group(1)
                    source_ip = match.group(2)

            # SSH failure patterns
            elif "Failed" in line or "Invalid" in line:
                success = False
                # Extract username and IP
                failed_patterns = [
                    r"Failed password for (\w+) from ([\d.]+)",
                    r"Invalid user (\w+) from ([\d.]+)",
                    r"Failed password for invalid user (\w+) from ([\d.]+)",
                ]

                for pattern in failed_patterns:
                    match = re.search(pattern, line)
                    if match:
                        username = match.group(1)
                        source_ip = match.group(2)
                        break

            if username or source_ip:
                return AuthenticationEvent(
                    source=LogSource.AUDITD,
                    event_type=EventType.AUTHENTICATION,
                    severity=Severity.HIGH if not success else Severity.INFO,
                    message=line,
                    timestamp=timestamp,
                    username=username,
                    source_ip=source_ip,
                    success=success,
                    method=method,
                    raw_data={"auth_line": line, "service": "sshd"},
                    tags=["auditd", "ssh", "authentication"],
                )

            return None

        except Exception as e:
            logger.error("Error parsing SSH auth event", error=str(e))
            return None

    async def _parse_sudo_event(
        self, line: str, timestamp: datetime
    ) -> Optional[BaseEvent]:
        """Parse sudo events"""
        try:
            if "COMMAND" in line:
                # Successful sudo command
                command_pattern = r"(\w+)\s*:\s*TTY=([^\s]*)\s*;\s*PWD=([^\s]*)\s*;\s*USER=([^\s]*)\s*;\s*COMMAND=(.*)"
                match = re.search(command_pattern, line)

                if match:
                    username = match.group(1)
                    tty = match.group(2)
                    pwd = match.group(3)
                    target_user = match.group(4)
                    command = match.group(5)

                    return BaseEvent(
                        source=LogSource.AUDITD,
                        event_type=EventType.PRIVILEGE_ESCALATION,
                        severity=Severity.MEDIUM,
                        message=line,
                        timestamp=timestamp,
                        raw_data={
                            "auth_line": line,
                            "service": "sudo",
                            "username": username,
                            "target_user": target_user,
                            "command": command,
                            "tty": tty,
                            "pwd": pwd,
                        },
                        tags=["auditd", "sudo", "privilege-escalation"],
                    )

            return None

        except Exception as e:
            logger.error("Error parsing sudo event", error=str(e))
            return None

    async def _parse_login_event(
        self, line: str, timestamp: datetime
    ) -> Optional[AuthenticationEvent]:
        """Parse system login events"""
        try:
            username = None
            success = True
            method = "login"

            # Extract username
            user_patterns = [
                r"session opened for user (\w+)",
                r"session closed for user (\w+)",
                r"Successful login for (\w+)",
                r"Failed login for (\w+)",
            ]

            for pattern in user_patterns:
                match = re.search(pattern, line)
                if match:
                    username = match.group(1)
                    break

            # Determine success
            if "failed" in line.lower() or "error" in line.lower():
                success = False

            if username:
                return AuthenticationEvent(
                    source=LogSource.AUDITD,
                    event_type=EventType.AUTHENTICATION,
                    severity=Severity.HIGH if not success else Severity.INFO,
                    message=line,
                    timestamp=timestamp,
                    username=username,
                    success=success,
                    method=method,
                    raw_data={"auth_line": line, "service": "login"},
                    tags=["auditd", "login", "authentication"],
                )

            return None

        except Exception as e:
            logger.error("Error parsing login event", error=str(e))
            return None

    async def _monitor_realtime_events(self):
        """Monitor real-time audit events using ausearch"""
        logger.info("Starting real-time audit events monitoring")

        try:
            while self.running:
                try:
                    # Use ausearch for recent events
                    result = await asyncio.create_subprocess_exec(
                        "ausearch",
                        "-ts",
                        "recent",
                        "--format",
                        "text",
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    stdout, stderr = await result.communicate()

                    if result.returncode == 0:
                        events_output = stdout.decode()
                        if events_output.strip():
                            await self._process_ausearch_output(events_output)

                    await asyncio.sleep(self.config.get("realtime_interval", 30))

                except FileNotFoundError:
                    logger.info(
                        "ausearch not available, disabling real-time monitoring"
                    )
                    break
                except Exception as e:
                    logger.error("Error in real-time events monitoring", error=str(e))
                    await asyncio.sleep(60)

        except asyncio.CancelledError:
            logger.info("Real-time events monitoring cancelled")
        except Exception as e:
            logger.error("Fatal error in real-time events monitoring", error=str(e))

    async def _process_ausearch_output(self, output: str):
        """Process ausearch output"""
        try:
            # Parse ausearch output and create events
            lines = output.strip().split("\n")
            for line in lines:
                if line.strip():
                    await self._parse_audit_line(line)

        except Exception as e:
            logger.error("Error processing ausearch output", error=str(e))

    async def _analyze_syscall_patterns(self):
        """Analyze system call patterns for anomalies"""
        logger.info("Starting system call pattern analysis")

        try:
            while self.running:
                try:
                    # This would implement pattern analysis logic
                    # For now, just placeholder
                    await asyncio.sleep(
                        self.config.get("pattern_analysis_interval", 300)
                    )

                except Exception as e:
                    logger.error("Error in syscall pattern analysis", error=str(e))
                    await asyncio.sleep(300)

        except asyncio.CancelledError:
            logger.info("System call pattern analysis cancelled")
        except Exception as e:
            logger.error("Fatal error in syscall pattern analysis", error=str(e))
