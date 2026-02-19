"""
SkausWatch AAA Monitor Service - File Collector

File-based collector for monitoring log files on network-mounted filesystems.
Supports inotify for real-time monitoring and polling for remote mounts.
"""

import asyncio
import fnmatch
import json
import logging
import re
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

import aiofiles
import structlog
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

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


class FileCollector:
    """File-based log collector for network-mounted log files"""

    def __init__(self, config: Dict[str, Any], log_processor, analysis_engine):
        """Initialize File collector

        Args:
            config: File collector configuration
            log_processor: Log processor instance
            analysis_engine: Analysis engine instance
        """
        self.config = config
        self.log_processor = log_processor
        self.analysis_engine = analysis_engine

        # Collection state
        self.running = False
        self.collection_tasks = []

        # File monitoring
        self.observers = []
        self.monitored_files = {}
        self.file_positions = {}

        # Log file patterns
        self.log_patterns = self.config.file_patterns or ["*.log", "*.txt"]

    async def initialize(self):
        """Initialize file collector"""
        try:
            # Discover log files in mount points
            await self._discover_log_files()

            logger.info(
                "File collector initialized successfully",
                mount_points=len(self.config.mount_points),
                monitored_files=len(self.monitored_files),
                use_inotify=self.config.use_inotify,
            )

        except Exception as e:
            logger.error("Failed to initialize file collector", error=str(e))
            raise

    async def _discover_log_files(self):
        """Discover log files in configured mount points"""
        try:
            for mount_point in self.config.mount_points:
                mount_path = Path(mount_point)
                if not mount_path.exists():
                    logger.warning("Mount point does not exist", path=mount_point)
                    continue

                # Recursively find log files
                for pattern in self.log_patterns:
                    for log_file in mount_path.rglob(pattern):
                        if log_file.is_file():
                            file_key = str(log_file.absolute())
                            self.monitored_files[file_key] = {
                                "path": log_file,
                                "mount_point": mount_point,
                                "last_modified": log_file.stat().st_mtime,
                                "size": log_file.stat().st_size,
                            }

                            # Initialize file position
                            self.file_positions[file_key] = log_file.stat().st_size

            logger.info("Discovered log files", count=len(self.monitored_files))

        except Exception as e:
            logger.error("Error discovering log files", error=str(e))

    async def start_collection(self):
        """Start file log collection"""
        if self.running:
            logger.warning("File collector already running")
            return

        self.running = True
        logger.info("Starting file log collection")

        try:
            # Start inotify monitoring if enabled
            if self.config.use_inotify:
                task = asyncio.create_task(self._start_inotify_monitoring())
                self.collection_tasks.append(task)

            # Start polling for files (for network mounts or fallback)
            task = asyncio.create_task(self._start_file_polling())
            self.collection_tasks.append(task)

            # Periodic file discovery
            task = asyncio.create_task(self._periodic_file_discovery())
            self.collection_tasks.append(task)

            # Wait for all tasks
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)

        except Exception as e:
            logger.error("Error in file log collection", error=str(e))
        finally:
            self.running = False

    async def stop(self):
        """Stop file log collection"""
        self.running = False

        # Cancel all collection tasks
        for task in self.collection_tasks:
            if not task.done():
                task.cancel()

        # Wait for tasks to complete
        if self.collection_tasks:
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)

        self.collection_tasks.clear()

        # Stop file observers
        for observer in self.observers:
            observer.stop()
            observer.join()

        self.observers.clear()

        logger.info("File collector stopped")

    async def _start_inotify_monitoring(self):
        """Start inotify-based file monitoring"""
        logger.info("Starting inotify file monitoring")

        try:
            # Group files by mount point for efficient monitoring
            mount_files = {}
            for file_key, file_info in self.monitored_files.items():
                mount_point = file_info["mount_point"]
                if mount_point not in mount_files:
                    mount_files[mount_point] = []
                mount_files[mount_point].append(file_info)

            # Create observers for each mount point
            for mount_point, files in mount_files.items():
                try:
                    observer = Observer()
                    event_handler = LogFileEventHandler(self, files)
                    observer.schedule(event_handler, mount_point, recursive=True)
                    observer.start()
                    self.observers.append(observer)

                    logger.info(
                        "Started inotify observer",
                        mount_point=mount_point,
                        files=len(files),
                    )

                except Exception as e:
                    logger.error(
                        "Failed to start inotify observer",
                        mount_point=mount_point,
                        error=str(e),
                    )

            # Keep observers running
            while self.running:
                await asyncio.sleep(1)

        except Exception as e:
            logger.error("Error in inotify monitoring", error=str(e))

    async def _start_file_polling(self):
        """Start polling-based file monitoring"""
        logger.info("Starting file polling monitoring")

        try:
            while self.running:
                try:
                    for file_key, file_info in self.monitored_files.items():
                        if not self.running:
                            break

                        await self._check_file_changes(file_key, file_info)

                    await asyncio.sleep(self.config.poll_interval)

                except Exception as e:
                    logger.error("Error in file polling", error=str(e))
                    await asyncio.sleep(30)

        except asyncio.CancelledError:
            logger.info("File polling cancelled")
        except Exception as e:
            logger.error("Fatal error in file polling", error=str(e))

    async def _periodic_file_discovery(self):
        """Periodically rediscover files"""
        logger.info("Starting periodic file discovery")

        try:
            while self.running:
                try:
                    await self._discover_log_files()
                    await asyncio.sleep(300)  # Rediscover every 5 minutes

                except Exception as e:
                    logger.error("Error in periodic file discovery", error=str(e))
                    await asyncio.sleep(60)

        except asyncio.CancelledError:
            logger.info("Periodic file discovery cancelled")
        except Exception as e:
            logger.error("Fatal error in periodic file discovery", error=str(e))

    async def _check_file_changes(self, file_key: str, file_info: Dict):
        """Check if file has changed and process new content"""
        try:
            file_path = file_info["path"]

            # Check if file still exists
            if not file_path.exists():
                logger.debug("File no longer exists", path=file_path)
                return

            # Get current file stats
            current_stat = file_path.stat()
            current_size = current_stat.st_size
            current_modified = current_stat.st_mtime

            # Check if file has grown or been modified
            if (
                current_size > file_info["size"]
                or current_modified > file_info["last_modified"]
            ):

                await self._process_file_changes(file_key, file_info, current_size)

                # Update file info
                file_info["size"] = current_size
                file_info["last_modified"] = current_modified

        except Exception as e:
            logger.error("Error checking file changes", file=file_key, error=str(e))

    async def _process_file_changes(
        self, file_key: str, file_info: Dict, current_size: int
    ):
        """Process changes in a log file"""
        try:
            file_path = file_info["path"]
            current_position = self.file_positions.get(file_key, 0)

            # If file has shrunk (rotated), start from beginning
            if current_size < current_position:
                current_position = 0
                logger.info("File appears to have been rotated", path=file_path)

            # Read new content
            async with aiofiles.open(
                file_path, "r", encoding="utf-8", errors="ignore"
            ) as f:
                await f.seek(current_position)

                lines = []
                async for line in f:
                    lines.append(line.strip())

                # Update position
                new_position = await f.tell()
                self.file_positions[file_key] = new_position

                # Process new lines
                if lines:
                    await self._process_log_lines(lines, file_info)
                    logger.debug(
                        "Processed new log lines", file=file_path.name, lines=len(lines)
                    )

        except Exception as e:
            logger.error("Error processing file changes", file=file_key, error=str(e))

    async def _process_log_lines(self, lines: List[str], file_info: Dict):
        """Process log lines and create events"""
        try:
            file_path = file_info["path"]
            mount_point = file_info["mount_point"]

            for line in lines:
                if not line.strip():
                    continue

                # Extract timestamp from log line
                timestamp = await self._extract_timestamp_from_line(line)

                # Classify log line and create events
                events = await self._classify_log_line(
                    line, file_path, mount_point, timestamp
                )

                # Process events
                for event in events:
                    await self.log_processor.process_event(event)

        except Exception as e:
            logger.error("Error processing log lines", error=str(e))

    async def _extract_timestamp_from_line(self, line: str) -> datetime:
        """Extract timestamp from log line"""
        try:
            # Common log timestamp patterns
            timestamp_patterns = [
                # ISO format: 2023-12-31T23:59:59.123456Z
                (
                    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)",
                    lambda m: datetime.fromisoformat(m.group(1).rstrip("Z")),
                ),
                # Syslog format: Dec 31 23:59:59
                (
                    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
                    lambda m: datetime.strptime(
                        f"{datetime.now().year} {m.group(1)}", "%Y %b %d %H:%M:%S"
                    ),
                ),
                # Common format: 2023/12/31 23:59:59
                (
                    r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})",
                    lambda m: datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S"),
                ),
                # Apache/Nginx format: [31/Dec/2023:23:59:59 +0000]
                (
                    r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s+[+-]\d{4}\]",
                    lambda m: datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S"),
                ),
            ]

            for pattern, parser in timestamp_patterns:
                match = re.search(pattern, line)
                if match:
                    try:
                        return parser(match)
                    except Exception:
                        continue

            # Fallback to current time
            return datetime.utcnow()

        except Exception:
            return datetime.utcnow()

    async def _classify_log_line(
        self, line: str, file_path: Path, mount_point: str, timestamp: datetime
    ) -> List[BaseEvent]:
        """Classify log line and create appropriate events"""
        events = []

        try:
            line_lower = line.lower()
            file_name = file_path.name

            # Determine severity based on log level keywords
            severity = Severity.INFO
            if any(word in line_lower for word in ["critical", "fatal", "emergency"]):
                severity = Severity.CRITICAL
            elif any(word in line_lower for word in ["error", "err"]):
                severity = Severity.HIGH
            elif any(word in line_lower for word in ["warning", "warn"]):
                severity = Severity.MEDIUM
            elif any(word in line_lower for word in ["debug"]):
                severity = Severity.LOW

            # Authentication events
            if any(
                keyword in line_lower
                for keyword in ["login", "authentication", "password", "ssh", "sudo"]
            ):
                auth_event = await self._create_auth_event_from_line(
                    line, file_path, timestamp, severity
                )
                if auth_event:
                    events.append(auth_event)

            # Security events
            elif any(
                keyword in line_lower
                for keyword in ["denied", "blocked", "firewall", "intrusion", "attack"]
            ):
                security_event = BaseEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.SECURITY_VIOLATION,
                    severity=severity,
                    message=line,
                    timestamp=timestamp,
                    raw_data={
                        "file_path": str(file_path),
                        "mount_point": mount_point,
                        "file_name": file_name,
                    },
                    tags=["file", "security", file_name, mount_point],
                )
                events.append(security_event)

            # Network events
            elif any(
                keyword in line_lower
                for keyword in ["connection", "network", "tcp", "udp", "port"]
            ):
                network_event = BaseEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.NETWORK,
                    severity=severity,
                    message=line,
                    timestamp=timestamp,
                    raw_data={
                        "file_path": str(file_path),
                        "mount_point": mount_point,
                        "file_name": file_name,
                    },
                    tags=["file", "network", file_name, mount_point],
                )
                events.append(network_event)

            # Application/process events
            elif any(
                keyword in line_lower
                for keyword in [
                    "started",
                    "stopped",
                    "crashed",
                    "exception",
                    "stack trace",
                ]
            ):
                process_event = BaseEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.PROCESS,
                    severity=severity,
                    message=line,
                    timestamp=timestamp,
                    raw_data={
                        "file_path": str(file_path),
                        "mount_point": mount_point,
                        "file_name": file_name,
                    },
                    tags=["file", "process", file_name, mount_point],
                )
                events.append(process_event)

            # Generic events for errors and warnings
            elif severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                generic_event = BaseEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.ACCOUNTING,
                    severity=severity,
                    message=line,
                    timestamp=timestamp,
                    raw_data={
                        "file_path": str(file_path),
                        "mount_point": mount_point,
                        "file_name": file_name,
                    },
                    tags=["file", "generic", file_name, mount_point],
                )
                events.append(generic_event)

        except Exception as e:
            logger.error("Error classifying log line", error=str(e))

        return events

    async def _create_auth_event_from_line(
        self, line: str, file_path: Path, timestamp: datetime, severity: Severity
    ) -> Optional[AuthenticationEvent]:
        """Create authentication event from log line"""
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
                r"username[:\s]+(\w+)",
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
                word in line.lower()
                for word in ["failed", "failure", "invalid", "denied"]
            ):
                success = False
                severity = Severity.HIGH

            # Determine method
            if "ssh" in line.lower():
                method = "ssh"
            elif "sudo" in line.lower():
                method = "sudo"
            elif "password" in line.lower():
                method = "password"
            elif "key" in line.lower():
                method = "key"

            if username or source_ip:
                return AuthenticationEvent(
                    source=LogSource.SYSTEM,
                    event_type=EventType.AUTHENTICATION,
                    severity=severity,
                    message=line,
                    timestamp=timestamp,
                    username=username,
                    source_ip=source_ip,
                    success=success,
                    method=method,
                    raw_data={"file_path": str(file_path), "file_name": file_path.name},
                    tags=["file", "authentication", file_path.name, method],
                )

            return None

        except Exception as e:
            logger.error("Error creating auth event from line", error=str(e))
            return None


class LogFileEventHandler(FileSystemEventHandler):
    """File system event handler for log file changes"""

    def __init__(self, collector: FileCollector, monitored_files: List[Dict]):
        self.collector = collector
        self.monitored_files = {info["path"]: info for info in monitored_files}

    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            file_path = Path(event.src_path)
            if file_path in self.monitored_files:
                # Schedule processing of file changes
                if self.collector.running:
                    file_key = str(file_path.absolute())
                    file_info = self.monitored_files[file_path]

                    asyncio.create_task(
                        self.collector._check_file_changes(file_key, file_info)
                    )

    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            file_path = Path(event.src_path)

            # Check if new file matches patterns
            for pattern in self.collector.log_patterns:
                if fnmatch.fnmatch(file_path.name, pattern):
                    logger.info("New log file detected", path=file_path)
                    # Add to monitored files
                    file_key = str(file_path.absolute())
                    file_info = {
                        "path": file_path,
                        "mount_point": str(file_path.parent),
                        "last_modified": file_path.stat().st_mtime,
                        "size": file_path.stat().st_size,
                    }
                    self.collector.monitored_files[file_key] = file_info
                    self.collector.file_positions[file_key] = 0  # Start from beginning
                    break
