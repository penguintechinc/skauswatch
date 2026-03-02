import asyncio
import json
from typing import Any

import redis.asyncio as aioredis
from penguin_utils import get_logger

from ocsf.normalizer import normalize
from writers.parquet_writer import ParquetWriter
from writers.opensearch_writer import OpenSearchWriter

logger = get_logger(__name__)

STREAM_KEY = "skauswatch:logs:ingest"
GROUP_NAME = "log-receiver"
CONSUMER_NAME = "log-receiver-0"
BATCH_SIZE = 500


class RedisStreamConsumer:
    def __init__(
        self,
        redis_url: str,
        parquet: ParquetWriter,
        opensearch: OpenSearchWriter,
    ) -> None:
        self._redis = aioredis.from_url(redis_url)
        self._parquet = parquet
        self._opensearch = opensearch

    async def start(self) -> None:
        try:
            await self._redis.xgroup_create(STREAM_KEY, GROUP_NAME, id="0", mkstream=True)
        except Exception:
            pass  # group already exists

        logger.info("redis_consumer_started", stream=STREAM_KEY)
        while True:
            try:
                messages = await self._redis.xreadgroup(
                    GROUP_NAME, CONSUMER_NAME,
                    {STREAM_KEY: ">"}, count=BATCH_SIZE, block=5000
                )
                if messages:
                    await self._process(messages)
            except Exception as exc:
                logger.error("redis_consumer_error", error=str(exc))
                await asyncio.sleep(5)

    async def _process(self, messages: list[Any]) -> None:
        events = []
        ids = []
        for _stream, msgs in messages:
            for msg_id, fields in msgs:
                try:
                    raw = json.loads(fields.get(b"data", b"{}").decode())
                    events.append(normalize(raw, source="redis-stream"))
                    ids.append(msg_id)
                except Exception as exc:
                    logger.warning("redis_msg_parse_error", error=str(exc))

        if events:
            await self._parquet.write_batch(events)
            await self._opensearch.write_batch(events)
            if ids:
                await self._redis.xack(STREAM_KEY, GROUP_NAME, *ids)
