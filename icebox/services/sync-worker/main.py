"""IceBox sync-worker entry point."""
from __future__ import annotations

import asyncio
import logging
import signal
import sys

from config import load_config
from worker import SyncWorker

# Structured JSON logging
try:
    from pythonjsonlogger import jsonlogger  # type: ignore[import]

    handler = logging.StreamHandler()
    handler.setFormatter(
        jsonlogger.JsonFormatter(
            "%(asctime)s %(name)s %(levelname)s %(message)s"
        )
    )
    logging.root.addHandler(handler)
except ImportError:
    logging.basicConfig(
        stream=sys.stdout,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

logger = logging.getLogger(__name__)


async def _run() -> None:
    """Load config, start worker, handle shutdown signals."""
    cfg = load_config()
    logging.root.setLevel(cfg.log_level.upper())

    worker = SyncWorker(cfg)
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _handle_signal(sig: signal.Signals) -> None:
        logger.info("sync-worker: received signal %s, shutting down", sig.name)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal, sig)

    await worker.start()
    logger.info("sync-worker: started, consuming 5 provider streams")

    run_task = asyncio.create_task(worker.run())
    try:
        # Wait until a stop signal is received
        await stop_event.wait()
    finally:
        await worker.stop()
        run_task.cancel()
        try:
            await run_task
        except asyncio.CancelledError:
            pass

    logger.info("sync-worker: shutdown complete")


def main() -> None:
    """Synchronous wrapper for asyncio.run."""
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
