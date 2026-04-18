"""
Elder push integration for the Checkpoint sub-module.

Polls identity_users for recently-changed records and POSTs them to the
Elder REST API so that Elder's user list stays in sync with Checkpoint's
identity provider.

Configuration (environment variables):
  ELDER_PUSH_ENABLED      — "true" / "false" (default: "false")
  ELDER_API_URL           — Base URL of the Elder REST API (e.g. https://elder.localhost.local)
  ELDER_API_KEY           — Bearer token for Elder API authentication
  ELDER_PUSH_INTERVAL_SEC — Poll interval in seconds (default: 30)
  ELDER_PUSH_LOOKBACK_SEC — How far back to look for changes (default: 60)
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from datetime import datetime, timedelta
from typing import Optional

import aiohttp
import structlog
from pydal import DAL

logger = structlog.get_logger(__name__)


def _is_elder_push_enabled() -> bool:
    """Return True when ELDER_PUSH_ENABLED env var is 'true'."""
    return os.getenv("ELDER_PUSH_ENABLED", "false").strip().lower() == "true"


def _elder_api_url() -> str:
    """Return the configured Elder API base URL (no trailing slash)."""
    return os.getenv("ELDER_API_URL", "").rstrip("/")


def _elder_api_key() -> str:
    """Return the Elder API bearer token."""
    return os.getenv("ELDER_API_KEY", "")


def _poll_interval() -> int:
    """Return poll interval in seconds."""
    try:
        return max(1, int(os.getenv("ELDER_PUSH_INTERVAL_SEC", "30")))
    except ValueError:
        return 30


def _lookback_seconds() -> int:
    """Return lookback window in seconds."""
    try:
        return max(1, int(os.getenv("ELDER_PUSH_LOOKBACK_SEC", "60")))
    except ValueError:
        return 60


class ElderPushLoop:
    """
    Background asyncio task that pushes identity changes to Elder.

    Lifecycle:
        loop = ElderPushLoop(database_uri)
        task = asyncio.create_task(loop.run())
        # On shutdown:
        task.cancel()
    """

    def __init__(self, database_uri: str) -> None:
        """
        Initialise the push loop.

        Args:
            database_uri: PyDAL-format database connection URI.
        """
        self._database_uri: str = database_uri
        self._running: bool = False
        self._retry_backoff: float = 5.0  # seconds, capped at 300
        self._session: Optional[aiohttp.ClientSession] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """
        Main loop.  Runs until cancelled.

        If ELDER_PUSH_ENABLED is false the coroutine returns immediately
        so this task is safe to schedule unconditionally.
        """
        if not _is_elder_push_enabled():
            logger.info("ElderPushLoop disabled (ELDER_PUSH_ENABLED != true)")
            return

        if not _elder_api_url():
            logger.warning(
                "ElderPushLoop: ELDER_API_URL not configured; push disabled"
            )
            return

        self._running = True
        logger.info(
            "ElderPushLoop started",
            interval_sec=_poll_interval(),
            lookback_sec=_lookback_seconds(),
            elder_url=_elder_api_url(),
        )

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            self._session = session
            while self._running:
                try:
                    await self._poll_and_push()
                    self._retry_backoff = 5.0  # reset on success
                    await asyncio.sleep(_poll_interval())
                except asyncio.CancelledError:
                    logger.info("ElderPushLoop cancelled")
                    self._running = False
                    return
                except Exception as exc:
                    logger.error(
                        "ElderPushLoop iteration failed",
                        error=str(exc),
                        retry_in=self._retry_backoff,
                    )
                    await asyncio.sleep(self._retry_backoff)
                    # Exponential backoff capped at 5 minutes
                    self._retry_backoff = min(self._retry_backoff * 2, 300.0)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _poll_and_push(self) -> None:
        """
        Query recently-updated identity_users and push each to Elder.

        Each call creates its own DAL instance to keep the async coroutine
        isolated from other concurrent DB users.
        """
        lookback = timedelta(seconds=_lookback_seconds())
        since: datetime = datetime.utcnow() - lookback

        # Per-iteration DAL instance — do NOT share across coroutines
        db: Optional[DAL] = None
        try:
            db = DAL(
                self._database_uri,
                pool_size=1,
                migrate=False,
                fake_migrate=False,
                lazy_tables=True,
            )
            # Lightweight table definition — only columns we need
            db.define_table(
                "identity_users",
                migrate=False,
                redefine=True,
            )

            changed_users = (
                db(db.identity_users.updated_at >= since)
                .select(
                    db.identity_users.uuid,
                    db.identity_users.email,
                    db.identity_users.display_name,
                    db.identity_users.given_name,
                    db.identity_users.family_name,
                    db.identity_users.status,
                    db.identity_users.external_id,
                    db.identity_users.external_provider,
                    db.identity_users.updated_at,
                )
                .as_list()
            )
        finally:
            if db:
                db.close()

        if not changed_users:
            return

        logger.debug(
            "ElderPushLoop: pushing changed users",
            count=len(changed_users),
        )

        for user in changed_users:
            await self._push_user(user)

    async def _push_user(self, user: dict) -> None:
        """
        POST a single identity user record to Elder.

        Args:
            user: Row dict from identity_users (no password_hash — PII-safe
                  subset intended for Elder's user registry).
        """
        if self._session is None:
            return

        api_url = _elder_api_url()
        api_key = _elder_api_key()

        # Build the payload — no PII beyond what Elder already holds
        payload: dict = {
            "uuid": user["uuid"],
            "email": user["email"],
            "display_name": user.get("display_name") or "",
            "given_name": user.get("given_name") or "",
            "family_name": user.get("family_name") or "",
            "status": user.get("status", "active"),
            "external_id": user.get("external_id") or "",
            "external_provider": user.get("external_provider") or "",
            "updated_at": (
                user["updated_at"].isoformat()
                if isinstance(user.get("updated_at"), datetime)
                else str(user.get("updated_at", ""))
            ),
            "source": "checkpoint",
        }

        headers: dict = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "X-Source": "checkpoint-identity",
        }

        endpoint = f"{api_url}/api/v1/identity/users/upsert"

        try:
            async with self._session.post(
                endpoint,
                json=payload,
                headers=headers,
            ) as resp:
                if resp.status in (200, 201, 204):
                    logger.debug(
                        "ElderPushLoop: user pushed",
                        # Log only uuid — never log email directly
                        uuid=user["uuid"],
                        status=resp.status,
                    )
                elif resp.status == 404:
                    logger.warning(
                        "ElderPushLoop: Elder upsert endpoint not found",
                        endpoint=endpoint,
                    )
                elif resp.status == 401:
                    logger.error(
                        "ElderPushLoop: Elder API rejected credentials (401)"
                    )
                elif resp.status == 409:
                    # Conflict — Elder already has a more recent record; skip silently
                    logger.debug(
                        "ElderPushLoop: conflict ignored (409)",
                        uuid=user["uuid"],
                    )
                else:
                    body = await resp.text()
                    logger.warning(
                        "ElderPushLoop: unexpected response from Elder",
                        uuid=user["uuid"],
                        status=resp.status,
                        body=body[:200],
                    )
        except aiohttp.ClientConnectorError as exc:
            logger.warning(
                "ElderPushLoop: cannot connect to Elder API",
                error=str(exc),
            )
        except asyncio.TimeoutError:
            logger.warning(
                "ElderPushLoop: request to Elder API timed out",
                uuid=user.get("uuid"),
            )
