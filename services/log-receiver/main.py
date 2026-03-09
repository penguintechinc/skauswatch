import asyncio
import signal

from aiohttp import web
from ingest.http_handler import HTTPIngestHandler
from ingest.redis_consumer import RedisStreamConsumer
from ingest.syslog_handler import SyslogProtocol
from penguin_utils import configure_logging, get_logger
from writers.opensearch_writer import OpenSearchWriter
from writers.parquet_writer import ParquetWriter

from config import LogReceiverConfig

configure_logging()
logger = get_logger(__name__)


async def main() -> None:
    cfg = LogReceiverConfig()

    parquet = ParquetWriter(
        endpoint_url=cfg.s3_endpoint_url,
        region=cfg.s3_region,
        access_key=cfg.s3_access_key,
        secret_key=cfg.s3_secret_key,
        bucket=cfg.s3_siem_bucket,
    )
    opensearch = OpenSearchWriter(
        url=cfg.opensearch_url, retention_days=cfg.log_retention_days
    )
    await opensearch.ensure_ism_policy()

    http_handler = HTTPIngestHandler(parquet, opensearch)

    app = web.Application()
    app.router.add_post("/ingest", http_handler.handle_ingest)
    app.router.add_get("/healthz", http_handler.handle_health)

    # Start Redis consumer as background task
    consumer = RedisStreamConsumer(cfg.redis_url, parquet, opensearch)
    asyncio.ensure_future(consumer.start())

    # Start syslog UDP
    loop = asyncio.get_event_loop()
    await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(parquet, opensearch),
        local_addr=("0.0.0.0", cfg.syslog_udp_port),
    )

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", cfg.http_port)
    await site.start()
    logger.info(
        "log_receiver_started", http_port=cfg.http_port, udp_port=cfg.syslog_udp_port
    )

    loop = asyncio.get_event_loop()
    stop = loop.create_future()
    loop.add_signal_handler(signal.SIGTERM, stop.set_result, None)
    loop.add_signal_handler(signal.SIGINT, stop.set_result, None)
    await stop
    await runner.cleanup()
    await opensearch.close()


if __name__ == "__main__":
    asyncio.run(main())
