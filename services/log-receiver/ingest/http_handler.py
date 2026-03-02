from typing import Any

from aiohttp import web
from penguin_utils import get_logger

from ocsf.normalizer import normalize
from writers.parquet_writer import ParquetWriter
from writers.opensearch_writer import OpenSearchWriter

logger = get_logger(__name__)


class HTTPIngestHandler:
    def __init__(self, parquet: ParquetWriter, opensearch: OpenSearchWriter) -> None:
        self._parquet = parquet
        self._opensearch = opensearch

    async def handle_ingest(self, request: web.Request) -> web.Response:
        """POST /ingest — accepts JSON array or single log object."""
        try:
            body = await request.json()
        except Exception:
            return web.Response(status=400, text="Invalid JSON")

        records: list[dict[str, Any]] = body if isinstance(body, list) else [body]
        if len(records) > 10_000:
            return web.Response(status=413, text="Batch too large (max 10,000)")

        source = request.headers.get("X-Log-Source", "http")
        events = [normalize(r, source) for r in records]

        await self._parquet.write_batch(events)
        await self._opensearch.write_batch(events)

        return web.json_response({"ingested": len(events)}, status=202)

    async def handle_health(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "service": "log-receiver"})
