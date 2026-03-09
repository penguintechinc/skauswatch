from datetime import datetime, timezone
from typing import Any

from .schema import OCSF_CLASSES, OCSFEvent


def normalize(raw: dict[str, Any], source: str = "unknown") -> OCSFEvent:
    """Map an arbitrary log record to an OCSF event."""
    now = datetime.now(tz=timezone.utc)
    class_uid = _detect_class(raw, source)
    class_name = OCSF_CLASSES.get(class_uid, "unknown")

    time_val = raw.get("timestamp") or raw.get("time") or raw.get("@timestamp")
    if isinstance(time_val, str):
        try:
            event_time = datetime.fromisoformat(time_val.replace("Z", "+00:00"))
        except ValueError:
            event_time = now
    elif isinstance(time_val, (int, float)):
        event_time = datetime.fromtimestamp(time_val, tz=timezone.utc)
    else:
        event_time = now

    severity = _detect_severity(raw)
    status = _detect_status(raw)
    message = raw.get("message") or raw.get("msg") or str(raw)[:500]

    return OCSFEvent(
        class_uid=class_uid,
        class_name=class_name,
        time=event_time,
        severity_id=severity,
        status_id=status,
        message=message,
        metadata={
            "version": "1.3.0",
            "product": {"name": "SkausWatch", "vendor_name": "PenguinTech"},
        },
        raw_data=raw,
    )


def _detect_class(raw: dict[str, Any], source: str) -> int:
    if "login" in source or raw.get("event_type") == "auth":
        return 3002
    if "network" in source or "src_ip" in raw:
        return 4001
    if "file" in source or "file_path" in raw:
        return 4003
    if "api" in source or "endpoint" in raw:
        return 6003
    return 2001  # default: security_finding


def _detect_severity(raw: dict[str, Any]) -> int:
    level = str(raw.get("level") or raw.get("severity") or "").lower()
    mapping = {
        "debug": 1,
        "info": 1,
        "informational": 1,
        "low": 2,
        "warning": 2,
        "warn": 2,
        "medium": 3,
        "error": 4,
        "high": 4,
        "critical": 5,
        "fatal": 5,
    }
    return mapping.get(level, 0)


def _detect_status(raw: dict[str, Any]) -> int:
    status = str(raw.get("status") or raw.get("result") or "").lower()
    if "success" in status or "ok" in status:
        return 1
    if "fail" in status or "error" in status or "denied" in status:
        return 2
    return 99
