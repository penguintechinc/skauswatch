"""
Redis Streams manager for event pipelines.

Provides:
- EDR Event Pipeline: skauswatch:edr:events
- Alert Processing: skauswatch:alerts:pending
- AI Task Queue: skauswatch:ai:tasks
- Threat Intel Updates: skauswatch:threatintel:updates
- Approval Workflows: skauswatch:approvals:pending
- Audit Log Stream: skauswatch:audit:log
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional

import redis.asyncio as redis
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class StreamMessage(BaseModel):
    """Message from a Redis Stream."""

    id: str
    stream: str
    data: Dict[str, Any]


class RedisStreamManager:
    """
    Manager for Redis Streams with consumer groups.

    Supports namespacing via key prefix for shared Redis environments.
    """

    # Stream names
    STREAM_EDR_EVENTS = "edr:events"
    STREAM_ALERTS_PENDING = "alerts:pending"
    STREAM_AI_TASKS = "ai:tasks"
    STREAM_THREAT_UPDATES = "threatintel:updates"
    STREAM_APPROVALS = "approvals:pending"
    STREAM_AUDIT_LOG = "audit:log"

    def __init__(
        self,
        redis_url: str,
        prefix: str = "skauswatch",
        max_connections: int = 20,
    ):
        """
        Initialize Redis Stream Manager.

        Args:
            redis_url: Redis connection URL
            prefix: Key prefix for namespacing
            max_connections: Maximum connection pool size
        """
        self.redis_url = redis_url
        self.prefix = prefix
        self.max_connections = max_connections
        self._client: Optional[redis.Redis] = None
        self._running = False

    async def connect(self) -> None:
        """Establish Redis connection."""
        if self._client is None:
            self._client = redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=self.max_connections,
            )
            await self._client.ping()
            logger.info(f"Connected to Redis with prefix '{self.prefix}'")

    async def close(self) -> None:
        """Close Redis connection."""
        self._running = False
        if self._client:
            await self._client.close()
            self._client = None
            logger.info("Redis connection closed")

    def _key(self, stream: str) -> str:
        """Generate prefixed key for a stream."""
        return f"{self.prefix}:{stream}"

    async def create_consumer_group(
        self,
        stream: str,
        group: str,
        start_id: str = "0",
    ) -> bool:
        """
        Create a consumer group for a stream.

        Args:
            stream: Stream name (without prefix)
            group: Consumer group name
            start_id: Starting message ID ("0" for all, "$" for new only)

        Returns:
            True if created, False if already exists
        """
        try:
            await self._client.xgroup_create(
                self._key(stream),
                group,
                id=start_id,
                mkstream=True,
            )
            logger.info(f"Created consumer group '{group}' for stream '{stream}'")
            return True
        except redis.ResponseError as e:
            if "BUSYGROUP" in str(e):
                logger.debug(f"Consumer group '{group}' already exists for '{stream}'")
                return False
            raise

    async def publish_event(
        self,
        stream: str,
        data: Dict[str, Any],
        max_len: int = 10000,
    ) -> str:
        """
        Publish an event to a stream.

        Args:
            stream: Stream name (without prefix)
            data: Event data dictionary
            max_len: Maximum stream length (trimmed approximately)

        Returns:
            Message ID
        """
        # Flatten nested dicts to strings for Redis
        flat_data = {}
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                flat_data[key] = json.dumps(value)
            elif isinstance(value, datetime):
                flat_data[key] = value.isoformat()
            else:
                flat_data[key] = str(value) if value is not None else ""

        message_id = await self._client.xadd(
            self._key(stream),
            flat_data,
            maxlen=max_len,
            approximate=True,
        )
        logger.debug(f"Published message {message_id} to {stream}")
        return message_id

    async def consume_stream(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int = 10,
        block: int = 5000,
    ) -> AsyncGenerator[StreamMessage, None]:
        """
        Consume events from a stream with a consumer group.

        Args:
            stream: Stream name (without prefix)
            group: Consumer group name
            consumer: Consumer name (unique within group)
            count: Max messages to fetch per batch
            block: Blocking timeout in milliseconds

        Yields:
            StreamMessage objects
        """
        self._running = True
        stream_key = self._key(stream)

        while self._running:
            try:
                messages = await self._client.xreadgroup(
                    groupname=group,
                    consumername=consumer,
                    streams={stream_key: ">"},
                    count=count,
                    block=block,
                )

                if not messages:
                    continue

                for stream_name, stream_messages in messages:
                    for msg_id, msg_data in stream_messages:
                        # Parse JSON fields back to dicts
                        parsed_data = {}
                        for key, value in msg_data.items():
                            try:
                                parsed_data[key] = json.loads(value)
                            except (json.JSONDecodeError, TypeError):
                                parsed_data[key] = value

                        yield StreamMessage(
                            id=msg_id,
                            stream=stream,
                            data=parsed_data,
                        )

                        # Acknowledge message
                        await self._client.xack(stream_key, group, msg_id)

            except redis.ConnectionError as e:
                logger.error(f"Redis connection error: {e}")
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Error consuming stream {stream}: {e}")
                await asyncio.sleep(0.5)

    async def get_pending_messages(
        self,
        stream: str,
        group: str,
        consumer: Optional[str] = None,
        count: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Get pending (unacknowledged) messages.

        Args:
            stream: Stream name
            group: Consumer group name
            consumer: Optional consumer name filter
            count: Maximum messages to return

        Returns:
            List of pending message info
        """
        result = await self._client.xpending_range(
            self._key(stream),
            group,
            min="-",
            max="+",
            count=count,
            consumername=consumer,
        )
        return result

    async def claim_stale_messages(
        self,
        stream: str,
        group: str,
        consumer: str,
        min_idle_time: int = 60000,
        count: int = 10,
    ) -> List[StreamMessage]:
        """
        Claim stale messages from other consumers.

        Args:
            stream: Stream name
            group: Consumer group name
            consumer: Consumer to assign messages to
            min_idle_time: Minimum idle time in milliseconds
            count: Maximum messages to claim

        Returns:
            List of claimed messages
        """
        messages = await self._client.xautoclaim(
            self._key(stream),
            group,
            consumer,
            min_idle_time=min_idle_time,
            count=count,
        )

        result = []
        if messages and len(messages) > 1:
            for msg_id, msg_data in messages[1]:
                if msg_data:
                    result.append(
                        StreamMessage(
                            id=msg_id,
                            stream=stream,
                            data=msg_data,
                        )
                    )
        return result

    async def get_stream_info(self, stream: str) -> Dict[str, Any]:
        """Get information about a stream."""
        try:
            info = await self._client.xinfo_stream(self._key(stream))
            return info
        except redis.ResponseError:
            return {}

    async def get_stream_length(self, stream: str) -> int:
        """Get the number of messages in a stream."""
        return await self._client.xlen(self._key(stream))

    async def trim_stream(self, stream: str, max_len: int) -> int:
        """
        Trim a stream to a maximum length.

        Returns:
            Number of messages removed
        """
        return await self._client.xtrim(
            self._key(stream),
            maxlen=max_len,
            approximate=True,
        )


# ============================================
# Specialized Stream Publishers
# ============================================


class EDREventPublisher:
    """Publisher for EDR events."""

    def __init__(self, stream_manager: RedisStreamManager):
        self.manager = stream_manager

    async def publish_event(self, event: Dict[str, Any]) -> str:
        """Publish an EDR event."""
        event["timestamp"] = datetime.utcnow().isoformat()
        return await self.manager.publish_event(
            RedisStreamManager.STREAM_EDR_EVENTS,
            event,
        )


class AlertPublisher:
    """Publisher for alerts."""

    def __init__(self, stream_manager: RedisStreamManager):
        self.manager = stream_manager

    async def publish_alert(self, alert: Dict[str, Any]) -> str:
        """Publish an alert for processing."""
        alert["timestamp"] = datetime.utcnow().isoformat()
        return await self.manager.publish_event(
            RedisStreamManager.STREAM_ALERTS_PENDING,
            alert,
        )


class AITaskPublisher:
    """Publisher for AI analysis tasks."""

    def __init__(self, stream_manager: RedisStreamManager):
        self.manager = stream_manager

    async def publish_task(self, task: Dict[str, Any]) -> str:
        """Publish an AI analysis task."""
        task["submitted_at"] = datetime.utcnow().isoformat()
        return await self.manager.publish_event(
            RedisStreamManager.STREAM_AI_TASKS,
            task,
        )


class AuditLogPublisher:
    """Publisher for audit log events."""

    def __init__(self, stream_manager: RedisStreamManager):
        self.manager = stream_manager

    async def log_event(
        self,
        event_type: str,
        action: str,
        success: bool,
        user_id: Optional[int] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "info",
    ) -> str:
        """Log an audit event."""
        event = {
            "event_type": event_type,
            "action": action,
            "success": success,
            "user_id": user_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details or {},
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
        }
        return await self.manager.publish_event(
            RedisStreamManager.STREAM_AUDIT_LOG,
            event,
        )


# ============================================
# Stream Consumer Factory
# ============================================


async def create_stream_consumer(
    stream_manager: RedisStreamManager,
    stream: str,
    group: str,
    consumer: str,
    handler: Callable[[StreamMessage], Any],
) -> asyncio.Task:
    """
    Create a background task that consumes from a stream.

    Args:
        stream_manager: RedisStreamManager instance
        stream: Stream name
        group: Consumer group name
        consumer: Consumer name
        handler: Async function to handle each message

    Returns:
        Asyncio task
    """
    await stream_manager.create_consumer_group(stream, group)

    async def consume_loop():
        async for message in stream_manager.consume_stream(stream, group, consumer):
            try:
                await handler(message)
            except Exception as e:
                logger.error(f"Error handling message {message.id}: {e}")

    return asyncio.create_task(consume_loop())
