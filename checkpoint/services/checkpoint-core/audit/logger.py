"""
checkpoint-core — Audit logger.

Writes sanitised audit events to checkpoint_audit_log and optionally
forwards them to the Watcher / OpenSearch integration (fire-and-forget).

SECURITY: Never log raw passwords, tokens, private keys, or full JWTs.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

import aiohttp
from penguin_dal import DB

logger = logging.getLogger(__name__)

# Fields that must never appear in audit details JSON
_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "secret",
        "token",
        "private_key",
        "client_secret",
        "code_verifier",
        "assertion",
        "refresh_token",
        "access_token",
        "id_token",
        "jwt",
        "api_key",
        "credential",
    }
)


def _sanitise(details: dict[str, Any]) -> dict[str, Any]:
    """
    Remove sensitive keys from a dict before storing in audit log.

    Operates recursively on nested dicts.
    """
    sanitised: dict[str, Any] = {}
    for key, value in details.items():
        if key.lower() in _SENSITIVE_KEYS:
            sanitised[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitised[key] = _sanitise(value)
        else:
            sanitised[key] = value
    return sanitised


class AuditLogger:
    """
    Write checkpoint audit events to the database and optionally to Watcher.

    Usage::

        audit = AuditLogger(db, watcher_enabled=True, watcher_url="https://...")
        await audit.log(
            event_type="oauth2.token_issued",
            actor_uuid="...",
            actor_ip="10.0.0.1",
            client_id="my-app",
            scopes="openid profile",
            details={"grant_type": "authorization_code"},
        )
    """

    def __init__(
        self,
        db: DB,
        *,
        watcher_enabled: bool = False,
        watcher_url: str = "",
    ) -> None:
        self._db = db
        self._watcher_enabled = watcher_enabled
        self._watcher_url = watcher_url.rstrip("/")

    async def log(
        self,
        event_type: str,
        *,
        actor_uuid: str | None = None,
        actor_ip: str | None = None,
        target_uuid: str | None = None,
        target_type: str | None = None,
        client_id: str | None = None,
        scopes: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Persist an audit event.

        Parameters
        ----------
        event_type:  dot-separated event name, e.g. "oauth2.token_issued"
        actor_uuid:  UUID of the user or service that triggered the event
        actor_ip:    Source IP address
        target_uuid: UUID of the resource affected (if any)
        target_type: Type of the affected resource, e.g. "user", "client"
        client_id:   OAuth2 client_id involved (if any)
        scopes:      Space-separated scopes associated with the event
        details:     Free-form dict of additional context (will be sanitised)
        """
        sanitised_details = _sanitise(details or {})
        now = datetime.now(tz=timezone.utc).replace(tzinfo=None)

        try:
            self._db.checkpoint_audit_log.insert(
                event_type=event_type,
                actor_uuid=actor_uuid,
                actor_ip=actor_ip,
                target_uuid=target_uuid,
                target_type=target_type,
                client_id=client_id,
                scopes=scopes,
                details_json=json.dumps(sanitised_details),
                created_at=now,
            )
            self._db.commit()
        except Exception as exc:  # noqa: BLE001
            logger.error("audit_log.db_write_failed event=%s error=%r", event_type, exc)

        if self._watcher_enabled and self._watcher_url:
            asyncio.create_task(
                self._forward_to_watcher(event_type, now, sanitised_details, actor_uuid, actor_ip)
            )

    async def _forward_to_watcher(
        self,
        event_type: str,
        timestamp: datetime,
        details: dict[str, Any],
        actor_uuid: str | None,
        actor_ip: str | None,
    ) -> None:
        """
        Fire-and-forget: POST event to Watcher / OpenSearch ingest API.

        Failures are logged but never propagated — audit forwarding must not
        break the primary auth flow.
        """
        payload = {
            "service": "checkpoint-core",
            "event_type": event_type,
            "timestamp": timestamp.isoformat() + "Z",
            "actor_uuid": actor_uuid,
            "actor_ip": actor_ip,
            "details": details,
        }
        url = f"{self._watcher_url}/api/v1/events"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status >= 400:
                        logger.warning(
                            "audit_log.watcher_error event=%s status=%d",
                            event_type,
                            resp.status,
                        )
        except Exception as exc:  # noqa: BLE001
            logger.warning("audit_log.watcher_unreachable event=%s error=%r", event_type, exc)
