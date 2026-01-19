"""
Entry point for S3 scan worker service.

This module handles command-line argument parsing, configuration loading,
signal handling, and orchestration of the worker lifecycle.
"""

import argparse
import asyncio
import logging
import signal
import sys
from typing import Optional

from config import load_worker_config
from worker import S3ScanWorker

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class WorkerManager:
    """Manages worker lifecycle and signal handling."""

    def __init__(self, worker: S3ScanWorker):
        """Initialize worker manager.

        Args:
            worker: S3ScanWorker instance to manage
        """
        self.worker = worker
        self.shutdown_event: Optional[asyncio.Event] = None

    async def run(self) -> None:
        """Run worker until shutdown signal received.

        Sets up signal handlers for graceful shutdown and runs the worker
        in the asyncio event loop.

        Returns:
            None
        """
        self.shutdown_event = asyncio.Event()

        # Register signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._handle_signal)

        try:
            # Start worker
            await self.worker.start()
        except asyncio.CancelledError:
            logger.info("Worker task cancelled")
        except Exception as e:
            logger.error(f"Worker error: {e}", exc_info=True)
        finally:
            # Stop worker
            await self.worker.stop()

    def _handle_signal(self) -> None:
        """Handle shutdown signals (SIGTERM, SIGINT).

        Stops the running worker gracefully.
        """
        logger.info("Received shutdown signal, stopping worker...")
        if self.shutdown_event:
            self.shutdown_event.set()


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Namespace with parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="S3 Scan Worker - Processes malware scans for S3 objects",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run worker with default configuration from environment
  python main.py

  # Run with custom logging level
  python main.py --log-level DEBUG

  # Run with specific worker name
  CONSUMER_NAME=worker-1 python main.py
        """,
    )

    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: INFO)",
    )

    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to .env configuration file (uses environment variables by default)",
    )

    return parser.parse_args()


async def main() -> int:
    """Main entry point for worker.

    Loads configuration, creates worker, sets up signal handlers,
    and runs until shutdown.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    args = parse_args()

    # Set logging level
    logging.getLogger().setLevel(args.log_level)
    logger.info(f"Starting S3 Scan Worker (log_level={args.log_level})")

    try:
        # Load configuration from environment
        logger.info("Loading worker configuration...")
        config = load_worker_config()

        logger.info(
            f"Configuration loaded: "
            f"consumer_name={config.consumer_name}, "
            f"redis_url={config.redis_url}, "
            f"db_type={config.db_type}"
        )

        # Validate critical configuration
        if not config.consumer_name:
            logger.error("CONSUMER_NAME environment variable is required")
            return 1

        # Create worker
        logger.info("Creating S3ScanWorker instance...")
        worker = S3ScanWorker(config)

        # Create worker manager
        manager = WorkerManager(worker)

        # Run worker
        logger.info("Running worker...")
        await manager.run()

        logger.info("Worker stopped cleanly")
        return 0

    except KeyboardInterrupt:
        logger.info("Worker interrupted by user")
        return 0

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1


def run() -> None:
    """Entry point for command-line execution.

    Wraps async main() function for synchronous execution.
    """
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Interrupted")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    run()
