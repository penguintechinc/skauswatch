"""
Structured logging configuration for worker-scanner service.

Supports JSON (production) and console (development) formats with
request tracing via context variables.
"""

import logging
import logging.config
import os
import sys
from typing import Any, Dict, Optional

import structlog
from structlog.processors import JSONRenderer
from structlog.dev import ConsoleRenderer

# Environment configuration (read directly, avoid circular imports)
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("LOG_FORMAT", "console").lower()


def _add_timestamp(
    logger: structlog.types.WrappedLogger,
    method_name: str,
    event_dict: Dict[str, Any],
) -> Dict[str, Any]:
    """Add ISO 8601 formatted timestamp to log events."""
    from datetime import datetime, timezone

    event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    return event_dict


def _add_log_level(
    logger: structlog.types.WrappedLogger,
    method_name: str,
    event_dict: Dict[str, Any],
) -> Dict[str, Any]:
    """Add log level to event dict."""
    event_dict["log_level"] = method_name.upper()
    return event_dict


def _add_logger_name(
    logger: structlog.types.WrappedLogger,
    method_name: str,
    event_dict: Dict[str, Any],
) -> Dict[str, Any]:
    """Add logger name to event dict."""
    event_dict["logger"] = event_dict.get("_logger_name", "worker-scanner")
    return event_dict


def _add_request_id(
    logger: structlog.types.WrappedLogger,
    method_name: str,
    event_dict: Dict[str, Any],
) -> Dict[str, Any]:
    """Add request_id from context if available."""
    request_id = structlog.contextvars.get_contextvars().get("request_id")
    if request_id:
        event_dict["request_id"] = request_id
    return event_dict


def _add_exception_info(
    logger: structlog.types.WrappedLogger,
    method_name: str,
    event_dict: Dict[str, Any],
) -> Dict[str, Any]:
    """Add exception information if present."""
    exc_info = event_dict.pop("exc_info", None)
    if exc_info:
        event_dict["exception"] = True
        if sys.exc_info()[0] is not None:
            import traceback

            event_dict["exception_details"] = "".join(
                traceback.format_exception(*sys.exc_info())
            )
    return event_dict


def _configure_stdlib_logging() -> None:
    """Configure stdlib logging to use structlog."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            _add_timestamp,
            _add_log_level,
            _add_logger_name,
            _add_request_id,
            _add_exception_info,
            _get_log_renderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVEL)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(LOG_LEVEL)

    # Set formatter based on format
    if LOG_FORMAT == "json":
        console_handler.setFormatter(
            logging.Formatter(
                fmt="%(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
        )
    else:
        console_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
        )

    root_logger.addHandler(console_handler)


def _get_log_renderer() -> Any:
    """Get the appropriate log renderer based on LOG_FORMAT."""
    if LOG_FORMAT == "json":
        return JSONRenderer(serializer=_json_serializer)
    else:
        return ConsoleRenderer(colors=True)


def _json_serializer(obj: Any) -> Any:
    """Custom JSON serializer for non-standard types."""
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if hasattr(obj, "__str__"):
        return str(obj)
    return repr(obj)


def _initialize_logging() -> None:
    """Initialize logging configuration."""
    _configure_stdlib_logging()


def get_logger(name: str) -> structlog.types.WrappedLogger:
    """
    Get a structured logger instance.

    Args:
        name: Logger name, typically __name__ from calling module

    Returns:
        A structlog logger instance with built-in context support

    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("scan_started", target="example.com", scanner="nuclei")
        >>> logger.error("scan_failed", error=str(e), job_id=123)
    """
    return structlog.get_logger(name)


def set_request_id(request_id: str) -> None:
    """
    Set the request ID in context for request tracing.

    This context variable will be automatically included in all logs
    within the current context.

    Args:
        request_id: Unique identifier for the request/job
    """
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(request_id=request_id)


def clear_context() -> None:
    """Clear all context variables."""
    structlog.contextvars.clear_contextvars()


# Initialize logging on module import
_initialize_logging()
