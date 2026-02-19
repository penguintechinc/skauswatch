"""Async Redis Streams consumer module."""

import logging
from typing import AsyncGenerator, Dict, Optional, Tuple

import redis.asyncio as redis

logger = logging.getLogger(__name__)


class StreamConsumer:
    """Async Redis Streams consumer with consumer groups support."""

    def __init__(self, redis_url: str, prefix: str, group: str, consumer_name: str):
        """Initialize Redis Streams consumer.

        Args:
            redis_url: Redis connection URL (e.g., redis://localhost:6379)
            prefix: Stream key prefix
            group: Consumer group name
            consumer_name: Consumer instance name
        """
        self.redis_url = redis_url
        self.prefix = prefix
        self.group = group
        self.consumer_name = consumer_name
        self.client: Optional[redis.Redis] = None

    async def connect(self) -> None:
        """Connect to Redis."""
        try:
            self.client = await redis.from_url(self.redis_url, decode_responses=True)
            await self.client.ping()
            logger.info(f"Connected to Redis: {self.group}/{self.consumer_name}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    async def consume(
        self, stream: str, count: int = 1, block: int = 5000
    ) -> AsyncGenerator[Tuple[str, Dict], None]:
        """Consume messages from Redis stream.

        Args:
            stream: Stream name (without prefix)
            count: Number of messages to read per call
            block: Block timeout in milliseconds

        Yields:
            Tuple of (message_id, message_data)
        """
        if not self.client:
            raise RuntimeError("Not connected to Redis. Call connect() first.")

        full_stream = f"{self.prefix}{stream}"

        try:
            # Ensure consumer group exists
            await self._ensure_group(full_stream)

            while True:
                try:
                    # Read pending messages first (for reliability)
                    messages = await self.client.xreadgroup(
                        {full_stream: ">"},
                        self.group,
                        self.consumer_name,
                        count=count,
                        block=block,
                    )

                    if messages:
                        stream_name, msg_list = messages[0]
                        for msg_id, msg_data in msg_list:
                            yield msg_id, msg_data

                except redis.ResponseError as e:
                    if "NOGROUP" in str(e):
                        # Group was deleted, recreate it
                        await self._ensure_group(full_stream)
                    else:
                        logger.error(f"Redis error: {e}")
                        await self._backoff()

                except Exception as e:
                    logger.error(f"Error consuming from stream: {e}")
                    await self._backoff()

        except Exception as e:
            logger.error(f"Fatal error in consume loop: {e}")
            raise

    async def ack(self, stream: str, message_id: str) -> None:
        """Acknowledge message in consumer group.

        Args:
            stream: Stream name (without prefix)
            message_id: Message ID to acknowledge
        """
        if not self.client:
            raise RuntimeError("Not connected to Redis. Call connect() first.")

        full_stream = f"{self.prefix}{stream}"

        try:
            await self.client.xack(full_stream, self.group, message_id)
            logger.debug(f"Acknowledged message: {message_id}")
        except Exception as e:
            logger.error(f"Error acknowledging message {message_id}: {e}")

    async def close(self) -> None:
        """Close Redis connection."""
        if self.client:
            await self.client.close()
            logger.info("Redis connection closed")

    async def _ensure_group(self, stream: str) -> None:
        """Create consumer group if it doesn't exist.

        Args:
            stream: Full stream name
        """
        try:
            await self.client.xgroup_create(stream, self.group, id="0", mkstream=True)
            logger.info(f"Created consumer group: {self.group}")
        except redis.ResponseError as e:
            if "BUSYGROUP" in str(e):
                logger.debug(f"Consumer group already exists: {self.group}")
            else:
                raise

    @staticmethod
    async def _backoff(duration: float = 1.0) -> None:
        """Backoff before retry.

        Args:
            duration: Backoff duration in seconds
        """
        import asyncio

        await asyncio.sleep(duration)
