"""Sync worker — Redis Streams consumer for all 5 cloud providers."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any

import aioredis
from pydal import DAL, Field  # noqa: F401 — Field needed for table definitions

from config import SyncWorkerConfig
from crypto.envelope import EnvelopeEncryption
from providers import get_provider, SyncResult

logger = logging.getLogger(__name__)

PROVIDERS = ("aws", "azure", "gcp", "oracle", "kubernetes")


class SyncWorker:
    """Consumes Redis Streams for each cloud provider and executes sync operations."""

    def __init__(self, cfg: SyncWorkerConfig) -> None:
        self._cfg = cfg
        self._redis: aioredis.Redis | None = None
        self._envelope = EnvelopeEncryption(cfg.encryption)
        self._running = False
        self._tasks: list[asyncio.Task[None]] = []

    async def start(self) -> None:
        """Connect to Redis and ensure consumer groups exist for all providers."""
        self._redis = await aioredis.from_url(
            self._cfg.redis.url,
            decode_responses=False,
        )
        for provider in PROVIDERS:
            stream = self._cfg.redis.stream_name(provider)
            group = self._cfg.redis.consumer_group
            try:
                await self._redis.xgroup_create(
                    stream, group, id="0", mkstream=True
                )
                logger.info("sync-worker: created consumer group %s on %s", group, stream)
            except aioredis.ResponseError as exc:
                if "BUSYGROUP" in str(exc):
                    pass  # group already exists — normal on restart
                else:
                    raise
        logger.info("sync-worker: connected to Redis, consumer groups ready")

    async def stop(self) -> None:
        """Cancel all consumer tasks and close connections."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._redis:
            await self._redis.close()
        logger.info("sync-worker: stopped")

    async def run(self) -> None:
        """Spawn one consumer coroutine per provider and run until stopped."""
        self._running = True
        self._tasks = [
            asyncio.create_task(self._consume_provider(p), name=f"consumer-{p}")
            for p in PROVIDERS
        ]
        await asyncio.gather(*self._tasks, return_exceptions=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _consume_provider(self, provider: str) -> None:
        """Main loop for a single provider stream consumer."""
        stream = self._cfg.redis.stream_name(provider)
        group = self._cfg.redis.consumer_group
        consumer_id = f"worker-{os.getpid()}-{provider}"
        logger.info("sync-worker: starting consumer %s on stream %s", consumer_id, stream)

        while self._running:
            try:
                messages = await self._redis.xreadgroup(
                    groupname=group,
                    consumername=consumer_id,
                    streams={stream: ">"},
                    count=self._cfg.redis.batch_size,
                    block=self._cfg.redis.block_ms,
                )
                if not messages:
                    continue
                for _stream, entries in messages:
                    for msg_id, fields in entries:
                        await self._handle_message(
                            provider, stream, group, msg_id, fields
                        )
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception(
                    "sync-worker: error in consumer %s — retrying in 5s", consumer_id
                )
                await asyncio.sleep(5)

    async def _handle_message(
        self,
        provider: str,
        stream: str,
        group: str,
        msg_id: bytes,
        fields: dict[bytes, bytes],
    ) -> None:
        """Decode and dispatch one stream message, then ACK it."""
        try:
            # Decode bytes → dict
            decoded: dict[str, Any] = {
                k.decode(): v.decode() for k, v in fields.items()
            }
            action = decoded.get("action", "push")
            integration_id = decoded.get("integration_id", "")
            secret_id = decoded.get("secret_id", "")

            logger.debug(
                "sync-worker: [%s] action=%s integration=%s secret=%s",
                provider,
                action,
                integration_id,
                secret_id,
            )

            if action == "push":
                await self._do_push(provider, decoded)
            elif action == "delete":
                await self._do_delete(provider, decoded)
            else:
                logger.warning("sync-worker: unknown action %r — skipping", action)
        except Exception:
            logger.exception(
                "sync-worker: failed to handle message %s on %s", msg_id, stream
            )
        finally:
            # Always ACK so the message doesn't block the pending entries list
            await self._redis.xack(stream, group, msg_id)

    async def _load_integration(
        self, integration_id: str
    ) -> dict[str, Any] | None:
        """Load a cloud_integration row and decrypt its credentials."""
        db = self._open_db()
        try:
            row = db(
                (db.icebox_cloud_integrations.id == integration_id)
                & (db.icebox_cloud_integrations.enabled == True)  # noqa: E712
            ).select().first()
            if not row:
                return None

            # Decrypt credentials blob
            creds_blob: str = row.encrypted_credentials
            creds_json = json.loads(creds_blob)
            plaintext = self._envelope.decrypt(
                ciphertext=creds_json["ciphertext"],
                encrypted_dek=creds_json["dek"],
                dek_version=creds_json["version"],
            )
            credentials: dict[str, Any] = json.loads(plaintext)
            config: dict[str, Any] = json.loads(row.config or "{}")

            return {
                "credentials": credentials,
                "config": config,
                "sync_direction": row.sync_direction,
            }
        finally:
            db.close()

    async def _do_push(self, provider: str, msg: dict[str, Any]) -> None:
        """Push a secret to the cloud provider."""
        integration_id: str = msg.get("integration_id", "")
        secret_id: str = msg.get("secret_id", "")
        secret_name: str = msg.get("secret_name", "")
        secret_value_enc: str = msg.get("encrypted_value", "")
        secret_dek: str = msg.get("encrypted_dek", "")
        dek_version_str: str = msg.get("dek_version", "1")

        # Decrypt the secret value for transmission to cloud
        try:
            plaintext = self._envelope.decrypt(
                ciphertext=secret_value_enc,
                encrypted_dek=secret_dek,
                dek_version=int(dek_version_str),
            )
        except Exception:
            logger.exception(
                "sync-worker: failed to decrypt secret %s — skipping push", secret_id
            )
            return

        integration = await self._load_integration(integration_id)
        if not integration:
            logger.warning(
                "sync-worker: integration %s not found or disabled — skipping", integration_id
            )
            return

        cloud_provider = get_provider(
            provider,
            integration["credentials"],
            integration["config"],
        )
        try:
            result: SyncResult = await cloud_provider.push_secret(
                name=secret_name,
                value=plaintext,
                secret_id=secret_id,
            )
        finally:
            await cloud_provider.close()

        await self._update_sync_state(secret_id, integration_id, result)

    async def _do_delete(self, provider: str, msg: dict[str, Any]) -> None:
        """Delete a secret from the cloud provider."""
        integration_id: str = msg.get("integration_id", "")
        secret_id: str = msg.get("secret_id", "")
        external_ref: str = msg.get("external_ref", "")

        if not external_ref:
            logger.warning(
                "sync-worker: delete for secret %s has no external_ref — skipping",
                secret_id,
            )
            return

        integration = await self._load_integration(integration_id)
        if not integration:
            return

        cloud_provider = get_provider(
            provider,
            integration["credentials"],
            integration["config"],
        )
        try:
            deleted = await cloud_provider.delete_secret(external_ref)
        finally:
            await cloud_provider.close()

        logger.info(
            "sync-worker: delete %s (external=%s): deleted=%s",
            secret_id,
            external_ref,
            deleted,
        )
        if deleted:
            await self._remove_sync_state(secret_id, integration_id)

    async def _update_sync_state(
        self,
        secret_id: str,
        integration_id: str,
        result: SyncResult,
    ) -> None:
        """Upsert a cloud_sync_state row after a sync operation."""
        import datetime

        db = self._open_db()
        try:
            now = datetime.datetime.utcnow().isoformat()
            existing = db(
                (db.icebox_cloud_sync_state.secret_id == secret_id)
                & (db.icebox_cloud_sync_state.integration_id == integration_id)
            ).select().first()

            if existing:
                db(
                    (db.icebox_cloud_sync_state.secret_id == secret_id)
                    & (db.icebox_cloud_sync_state.integration_id == integration_id)
                ).update(
                    external_ref=result.external_ref,
                    last_synced_at=now,
                    sync_status="synced" if result.success else "error",
                )
            else:
                db.icebox_cloud_sync_state.insert(
                    secret_id=secret_id,
                    integration_id=integration_id,
                    external_ref=result.external_ref,
                    last_synced_at=now,
                    sync_status="synced" if result.success else "error",
                    conflict_resolution="icebox_wins",
                )
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("sync-worker: failed to update sync state for %s", secret_id)
        finally:
            db.close()

    async def _remove_sync_state(
        self, secret_id: str, integration_id: str
    ) -> None:
        """Delete the cloud_sync_state row after a successful deletion."""
        db = self._open_db()
        try:
            db(
                (db.icebox_cloud_sync_state.secret_id == secret_id)
                & (db.icebox_cloud_sync_state.integration_id == integration_id)
            ).delete()
            db.commit()
        except Exception:
            db.rollback()
            logger.exception(
                "sync-worker: failed to remove sync state for %s", secret_id
            )
        finally:
            db.close()

    def _open_db(self) -> DAL:
        """Open a fresh DAL instance for this task (async-safe: one per coroutine)."""
        db_cfg = self._cfg.database
        db_uri = (
            f"{db_cfg.db_type}://{db_cfg.user}:{db_cfg.password}"
            f"@{db_cfg.host}:{db_cfg.port}/{db_cfg.name}"
        )
        db = DAL(db_uri, pool_size=1, migrate=False, fake_migrate=False, lazy_tables=True)

        # Define only the tables this worker needs
        db.define_table(
            "icebox_cloud_integrations",
            Field("id", "string"),
            Field("provider", "string"),
            Field("enabled", "boolean"),
            Field("encrypted_credentials", "text"),
            Field("config", "text"),
            Field("sync_direction", "string"),
        )
        db.define_table(
            "icebox_cloud_sync_state",
            Field("secret_id", "string"),
            Field("integration_id", "string"),
            Field("external_ref", "string"),
            Field("last_synced_at", "string"),
            Field("sync_status", "string"),
            Field("conflict_resolution", "string"),
        )
        return db
