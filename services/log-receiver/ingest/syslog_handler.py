import asyncio
import re
from typing import Any

from penguin_utils import get_logger

from ocsf.normalizer import normalize
from writers.parquet_writer import ParquetWriter
from writers.opensearch_writer import OpenSearchWriter

logger = get_logger(__name__)

# RFC 5424: <priority>version timestamp hostname app-name procid msgid structured-data msg
SYSLOG_RE = re.compile(
    r"<(\d+)>\d* (\S+) (\S+) (\S+) \S+ \S+ \S+ (.*)", re.DOTALL
)


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, parquet: ParquetWriter, opensearch: OpenSearchWriter) -> None:
        self._parquet = parquet
        self._opensearch = opensearch

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.ensure_future(self._process(data, addr))

    async def _process(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            text = data.decode("utf-8", errors="replace").strip()
            raw = self._parse(text, addr)
            event = normalize(raw, source="syslog")
            await self._parquet.write_batch([event])
            await self._opensearch.write_batch([event])
        except Exception as exc:
            logger.warning("syslog_parse_error", error=str(exc))

    def _parse(self, text: str, addr: tuple[str, int]) -> dict[str, Any]:
        m = SYSLOG_RE.match(text)
        if m:
            priority, ts, host, app, msg = m.groups()
            return {
                "timestamp": ts,
                "hostname": host,
                "app_name": app,
                "message": msg.strip(),
                "src_ip": addr[0],
                "priority": int(priority),
            }
        return {"message": text, "src_ip": addr[0]}
