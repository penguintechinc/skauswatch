"""
SkausWatch AAA Monitor Service - Utilities

Common utility functions and helpers for the AAA monitor service.
"""

import asyncio
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import structlog


def setup_logging(logging_config) -> None:
    """Setup structured logging configuration

    Args:
        logging_config: Logging configuration object
    """
    # Configure structlog processors based on format
    if logging_config.structured:
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
        ]

        if logging_config.format.lower() == "json":
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer())
    else:
        # Standard logging format
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.ConsoleRenderer(),
        ]

    # Configure structlog
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, logging_config.level.upper()),
    )

    # Configure file logging if specified
    if logging_config.file_path:
        file_path = Path(logging_config.file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        from logging.handlers import RotatingFileHandler

        # Parse max file size
        max_bytes = _parse_size_string(logging_config.max_file_size)

        file_handler = RotatingFileHandler(
            filename=file_path,
            maxBytes=max_bytes,
            backupCount=logging_config.backup_count,
            encoding="utf-8",
        )

        file_handler.setLevel(getattr(logging, logging_config.level.upper()))

        if logging_config.structured and logging_config.format.lower() == "json":
            file_formatter = logging.Formatter("%(message)s")
        else:
            file_formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )

        file_handler.setFormatter(file_formatter)

        # Add handler to root logger
        logging.getLogger().addHandler(file_handler)


def _parse_size_string(size_str: str) -> int:
    """Parse size string like '100MB' to bytes

    Args:
        size_str: Size string (e.g., '100MB', '1GB')

    Returns:
        Size in bytes
    """
    size_str = size_str.upper().strip()

    # Extract number and unit
    import re

    match = re.match(r"^(\d+(?:\.\d+)?)\s*([KMGT]?B?)$", size_str)

    if not match:
        raise ValueError(f"Invalid size string: {size_str}")

    number = float(match.group(1))
    unit = match.group(2) or "B"

    # Convert to bytes
    multipliers = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}

    return int(number * multipliers.get(unit, 1))


def get_version() -> str:
    """Get service version

    Returns:
        Version string
    """
    try:
        # Try to read version from file
        version_file = Path(__file__).parent / "VERSION"
        if version_file.exists():
            return version_file.read_text().strip()

        # Try to get from environment
        version = os.environ.get("AAA_VERSION", "1.0.0")
        return version

    except Exception:
        return "1.0.0"


def get_service_info() -> Dict[str, Any]:
    """Get service information

    Returns:
        Dictionary containing service info
    """
    import platform
    import psutil

    try:
        return {
            "name": "SkausWatch AAA Monitor Service",
            "version": get_version(),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "hostname": platform.node(),
            "pid": os.getpid(),
            "memory_usage": psutil.Process().memory_info().rss / 1024 / 1024,  # MB
            "cpu_count": psutil.cpu_count(),
            "started_at": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {
            "name": "SkausWatch AAA Monitor Service",
            "version": get_version(),
            "error": str(e),
        }


async def wait_for_port(host: str, port: int, timeout: int = 30) -> bool:
    """Wait for a TCP port to become available

    Args:
        host: Host to check
        port: Port to check
        timeout: Timeout in seconds

    Returns:
        True if port becomes available within timeout
    """
    import socket

    logger = structlog.get_logger(__name__)

    start_time = asyncio.get_event_loop().time()

    while True:
        try:
            # Test connection
            with socket.create_connection((host, port), timeout=5):
                logger.debug("Port is available", host=host, port=port)
                return True

        except (socket.error, ConnectionRefusedError, OSError):
            # Port not available yet
            pass

        # Check timeout
        elapsed = asyncio.get_event_loop().time() - start_time
        if elapsed >= timeout:
            logger.warning(
                "Timeout waiting for port", host=host, port=port, timeout=timeout
            )
            return False

        # Wait before retry
        await asyncio.sleep(1)


async def check_disk_space(path: str, min_free_bytes: int) -> bool:
    """Check if sufficient disk space is available

    Args:
        path: Path to check
        min_free_bytes: Minimum free bytes required

    Returns:
        True if sufficient space is available
    """
    import shutil

    try:
        total, used, free = shutil.disk_usage(path)
        return free >= min_free_bytes
    except Exception:
        return False


def format_bytes(bytes_value: int) -> str:
    """Format bytes value as human readable string

    Args:
        bytes_value: Number of bytes

    Returns:
        Formatted string (e.g., '1.2 GB')
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def format_duration(seconds: float) -> str:
    """Format duration in seconds as human readable string

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string (e.g., '1h 23m 45s')
    """
    if seconds < 60:
        return f"{seconds:.1f}s"

    minutes = int(seconds // 60)
    seconds = seconds % 60

    if minutes < 60:
        return f"{minutes}m {seconds:.0f}s"

    hours = minutes // 60
    minutes = minutes % 60

    if hours < 24:
        return f"{hours}h {minutes}m"

    days = hours // 24
    hours = hours % 24

    return f"{days}d {hours}h"


async def safe_shutdown(tasks: list, timeout: int = 30) -> None:
    """Safely shutdown async tasks

    Args:
        tasks: List of asyncio tasks to shutdown
        timeout: Shutdown timeout in seconds
    """
    logger = structlog.get_logger(__name__)

    if not tasks:
        return

    # Cancel all tasks
    for task in tasks:
        if not task.done():
            task.cancel()

    # Wait for tasks to complete with timeout
    try:
        await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True), timeout=timeout
        )
        logger.info("Tasks shutdown completed", task_count=len(tasks))

    except asyncio.TimeoutError:
        logger.warning("Task shutdown timeout", timeout=timeout, task_count=len(tasks))

        # Force terminate remaining tasks
        for task in tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass


def validate_config(config) -> list:
    """Validate configuration and return list of issues

    Args:
        config: Configuration object to validate

    Returns:
        List of validation issues (empty if valid)
    """
    issues = []

    try:
        # Check required fields
        if not config.security.secret_key:
            issues.append("Security secret key is not set")

        # Check AI configuration if enabled
        if config.ai.enabled:
            if (
                config.ai.openai.enabled
                and not config.ai.openai.api_key
                and config.ai.anthropic.enabled
                and not config.ai.anthropic.api_key
                and not config.ai.ollama.enabled
            ):
                issues.append(
                    "AI is enabled but no API keys or local models configured"
                )

        # Check database configuration
        if not config.database.password and config.database.type in [
            "postgresql",
            "mysql",
        ]:
            issues.append("Database password is not set for external database")

        # Check port conflicts
        used_ports = set()
        if config.api.port in used_ports:
            issues.append(f"Port conflict detected: {config.api.port}")
        used_ports.add(config.api.port)

        # Check disk space for logs and data
        if config.logging.file_path:
            log_dir = Path(config.logging.file_path).parent
            if not check_disk_space(str(log_dir), 100 * 1024 * 1024):  # 100MB
                issues.append(f"Insufficient disk space for logs: {log_dir}")

        return issues

    except Exception as e:
        issues.append(f"Configuration validation error: {str(e)}")
        return issues


class AsyncTaskManager:
    """Manager for async background tasks"""

    def __init__(self):
        self.tasks = []
        self.running = False
        self.logger = structlog.get_logger(self.__class__.__name__)

    def add_task(self, coro, name: Optional[str] = None):
        """Add a coroutine as a background task"""
        task = asyncio.create_task(coro, name=name)
        self.tasks.append(task)
        self.logger.debug(
            "Task added", name=name or "unnamed", total_tasks=len(self.tasks)
        )
        return task

    async def start_all(self):
        """Start monitoring all tasks"""
        self.running = True
        self.logger.info("Task manager started", task_count=len(self.tasks))

    async def stop_all(self, timeout: int = 30):
        """Stop all tasks gracefully"""
        self.running = False
        await safe_shutdown(self.tasks, timeout)
        self.tasks.clear()
        self.logger.info("Task manager stopped")

    def get_task_status(self) -> Dict[str, Any]:
        """Get status of all tasks"""
        status = {
            "total_tasks": len(self.tasks),
            "running_tasks": 0,
            "completed_tasks": 0,
            "failed_tasks": 0,
            "cancelled_tasks": 0,
            "tasks": [],
        }

        for task in self.tasks:
            task_info = {
                "name": task.get_name(),
                "done": task.done(),
                "cancelled": task.cancelled(),
            }

            if task.done():
                if task.cancelled():
                    task_info["status"] = "cancelled"
                    status["cancelled_tasks"] += 1
                else:
                    try:
                        task.result()
                        task_info["status"] = "completed"
                        status["completed_tasks"] += 1
                    except Exception as e:
                        task_info["status"] = "failed"
                        task_info["error"] = str(e)
                        status["failed_tasks"] += 1
            else:
                task_info["status"] = "running"
                status["running_tasks"] += 1

            status["tasks"].append(task_info)

        return status
