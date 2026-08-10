#!/usr/bin/env python3
"""SkausWatch Performance Integration Examples

This file demonstrates how to integrate and use the comprehensive async/threading
performance optimizations across all SkausWatch services.

Usage examples for:
- Shared performance utilities
- Service-specific optimizations
- Cross-service communication
- Performance monitoring
"""

import asyncio
import logging
from datetime import datetime
from typing import Any

# Import service-specific optimizations
from services.manager.async_database import AsyncDatabaseManager
from services.monitor.async_log_collector import AsyncLogCollector
from services.pki.async_certificate_processor import AsyncCertificateProcessor
from services.sshca.async_ssh_processor import AsyncSSHProcessor

# Import shared performance utilities
from shared.performance import (
    CacheManager,
    ConnectionPoolManager,
    MessageQueue,
    PerformanceMonitor,
    RateLimiter,
    ThreadPoolManager,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class SkausWatchIntegrationExample:
    """Comprehensive integration example showing how all performance optimizations
    work together across SkausWatch services.
    """

    def __init__(self):
        # Initialize shared performance managers
        self.thread_manager = ThreadPoolManager()
        self.connection_manager = ConnectionPoolManager()
        self.cache_manager = CacheManager()
        self.rate_limiter = RateLimiter()
        self.message_queue = MessageQueue()
        self.performance_monitor = PerformanceMonitor()

        # Initialize service processors
        self.db_manager = None
        self.cert_processor = None
        self.ssh_processor = None
        self.log_collector = None

        self.running = False

    async def initialize(self):
        """Initialize all services with performance optimizations."""
        logger.info("Initializing SkausWatch services with performance optimizations...")

        # Start performance monitoring
        await self.performance_monitor.start()

        # Initialize message queue for inter-service communication
        await self.message_queue.start()

        # Initialize service-specific managers
        self.db_manager = AsyncDatabaseManager(
            connection_manager=self.connection_manager,
            cache_manager=self.cache_manager,
            thread_manager=self.thread_manager,
            monitoring=self.performance_monitor,
        )

        self.cert_processor = AsyncCertificateProcessor(
            thread_manager=self.thread_manager,
            cache_manager=self.cache_manager,
            rate_limiter=self.rate_limiter,
            message_queue=self.message_queue,
            monitoring=self.performance_monitor,
        )

        self.ssh_processor = AsyncSSHProcessor(
            thread_manager=self.thread_manager,
            cache_manager=self.cache_manager,
            message_queue=self.message_queue,
            monitoring=self.performance_monitor,
        )

        self.log_collector = AsyncLogCollector(
            thread_manager=self.thread_manager,
            cache_manager=self.cache_manager,
            message_queue=self.message_queue,
            monitoring=self.performance_monitor,
        )

        # Initialize all services
        await self.db_manager.initialize()
        await self.cert_processor.start()
        await self.ssh_processor.start()
        await self.log_collector.start()

        self.running = True
        logger.info("All services initialized successfully!")

    async def demonstrate_concurrent_operations(self):
        """Demonstrate concurrent operations across multiple services."""
        logger.info("Demonstrating concurrent operations across services...")

        # Create concurrent tasks for different services
        tasks = []

        # Database operations
        tasks.append(self._demo_database_operations())

        # Certificate processing
        tasks.append(self._demo_certificate_processing())

        # SSH operations
        tasks.append(self._demo_ssh_operations())

        # Log processing
        tasks.append(self._demo_log_processing())

        # Cross-service communication
        tasks.append(self._demo_inter_service_communication())

        # Performance monitoring
        tasks.append(self._demo_performance_monitoring())

        # Run all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Log results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Task {i} failed: {result}")
            else:
                logger.info(f"Task {i} completed successfully: {result}")

    async def _demo_database_operations(self) -> dict[str, Any]:
        """Demonstrate async database operations with caching and pooling."""
        logger.info("Running database operations demo...")

        # Bulk insert with batch processing
        users_data = [
            {"username": f"user_{i}", "email": f"user_{i}@example.com"} for i in range(100)
        ]

        insert_result = await self.db_manager.bulk_insert(
            table="users", data=users_data, batch_size=20
        )

        # Cached query (will hit cache on subsequent calls)
        user_stats = await self.db_manager.execute_cached_query(
            query="SELECT COUNT(*) as total_users FROM users", cache_key="user_stats", ttl=300.0
        )

        # Background task processing
        task_id = await self.db_manager.submit_background_task(
            "cleanup_old_sessions", {"older_than_days": 30}
        )

        return {
            "inserted_users": insert_result["rows_affected"],
            "user_stats": user_stats,
            "background_task_id": task_id,
        }

    async def _demo_certificate_processing(self) -> dict[str, Any]:
        """Demonstrate async certificate processing."""
        logger.info("Running certificate processing demo...")

        # Submit multiple certificate requests
        cert_requests = []
        for i in range(10):
            request_id = await self.cert_processor.submit_certificate_request(
                {
                    "common_name": f"service_{i}.example.com",
                    "organization": "SkausWatch",
                    "key_size": 2048,
                    "validity_days": 365,
                }
            )
            cert_requests.append(request_id)

        # Wait for some certificates to be processed
        await asyncio.sleep(2)

        # Check processing status
        processed_count = 0
        for request_id in cert_requests:
            status = await self.cert_processor.get_request_status(request_id)
            if status["status"] == "completed":
                processed_count += 1

        # Get processing statistics
        stats = await self.cert_processor.get_processing_stats()

        return {
            "submitted_requests": len(cert_requests),
            "processed_certificates": processed_count,
            "processing_stats": stats,
        }

    async def _demo_ssh_operations(self) -> dict[str, Any]:
        """Demonstrate async SSH certificate processing."""
        logger.info("Running SSH operations demo...")

        # Submit SSH certificate requests
        ssh_requests = []
        for i in range(5):
            request_id = await self.ssh_processor.submit_certificate_request(
                {
                    "public_key": f"ssh-rsa AAAA...{i} user_{i}@host",
                    "principals": [f"user_{i}", f"service_{i}"],
                    "validity": 3600,  # 1 hour
                    "certificate_type": "user",
                }
            )
            ssh_requests.append(request_id)

        # Generate SSH configurations
        config_result = await self.ssh_processor.generate_ssh_config(
            {
                "hosts": [f"host_{i}.example.com" for i in range(3)],
                "ca_public_key": "ssh-rsa AAAA... ca@skauswatch",
            }
        )

        # Update KRL (Key Revocation List)
        krl_result = await self.ssh_processor.update_krl(["ssh-rsa AAAA...revoked_key"])

        return {
            "ssh_requests": len(ssh_requests),
            "config_generated": config_result["success"],
            "krl_updated": krl_result["success"],
        }

    async def _demo_log_processing(self) -> dict[str, Any]:
        """Demonstrate async log collection and processing."""
        logger.info("Running log processing demo...")

        # Submit log entries for processing
        log_entries = []
        for i in range(50):
            log_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "level": "INFO" if i % 4 != 0 else "ERROR",
                "service": f"service_{i % 4}",
                "message": f"Sample log message {i}",
                "source": "demo",
            }
            await self.log_collector.submit_log_entry(log_entry)
            log_entries.append(log_entry)

        # Wait for processing
        await asyncio.sleep(1)

        # Get processing statistics
        stats = await self.log_collector.get_processing_stats()

        # Get recent alerts (if any)
        alerts = await self.log_collector.get_recent_alerts(limit=5)

        return {
            "submitted_logs": len(log_entries),
            "processing_stats": stats,
            "recent_alerts": len(alerts),
        }

    async def _demo_inter_service_communication(self) -> dict[str, Any]:
        """Demonstrate cross-service communication using message queues."""
        logger.info("Running inter-service communication demo...")

        # PKI service requesting database information
        db_request = await self.message_queue.request(
            destination="database",
            message_type="query",
            payload={
                "query": "SELECT COUNT(*) FROM certificates WHERE status = 'active'",
                "timeout": 10.0,
            },
        )

        # SSH CA requesting certificate validation from PKI
        pki_request = await self.message_queue.request(
            destination="pki",
            message_type="validate_certificate",
            payload={"certificate_serial": "ABC123", "validation_type": "full"},
        )

        # monitor requesting health status from all services
        health_checks = []
        for service in ["database", "pki", "sshca"]:
            response = await self.message_queue.request(
                destination=service, message_type="health_check", payload={}
            )
            health_checks.append(response)

        return {
            "db_query_result": db_request.get("result"),
            "certificate_validation": pki_request.get("status"),
            "health_checks": len(health_checks),
        }

    async def _demo_performance_monitoring(self) -> dict[str, Any]:
        """Demonstrate performance monitoring and metrics collection."""
        logger.info("Running performance monitoring demo...")

        # Get current system metrics
        system_metrics = await self.performance_monitor.get_system_metrics()

        # Get service-specific metrics
        service_metrics = {}
        for service in ["database", "pki", "sshca", "monitor"]:
            metrics = await self.performance_monitor.get_service_metrics(service)
            service_metrics[service] = metrics

        # Check for any performance alerts
        alerts = await self.performance_monitor.get_active_alerts()

        # Get performance profiles for recent operations
        profiles = await self.performance_monitor.get_recent_profiles(limit=10)

        return {
            "system_metrics": {
                "cpu_usage": system_metrics.get("cpu_usage_percent"),
                "memory_usage": system_metrics.get("memory_usage_percent"),
                "disk_usage": system_metrics.get("disk_usage_percent"),
            },
            "service_count": len(service_metrics),
            "active_alerts": len(alerts),
            "performance_profiles": len(profiles),
        }

    async def demonstrate_load_testing(self):
        """Demonstrate system behavior under load."""
        logger.info("Starting load testing demonstration...")

        # Create high-load scenarios
        load_tasks = []

        # High-volume database operations
        for i in range(10):
            load_tasks.append(self._high_volume_db_operations(f"load_test_{i}"))

        # Concurrent certificate processing
        for i in range(5):
            load_tasks.append(self._high_volume_cert_processing(f"cert_load_{i}"))

        # Intensive log processing
        for i in range(3):
            load_tasks.append(self._high_volume_log_processing(f"log_load_{i}"))

        # Monitor performance during load test
        monitoring_task = asyncio.create_task(self._monitor_load_test())

        # Run load test
        start_time = datetime.utcnow()
        load_results = await asyncio.gather(*load_tasks, return_exceptions=True)
        end_time = datetime.utcnow()

        # Stop monitoring
        monitoring_task.cancel()

        # Collect results
        successful_tasks = sum(1 for r in load_results if not isinstance(r, Exception))
        failed_tasks = len(load_results) - successful_tasks
        duration = (end_time - start_time).total_seconds()

        logger.info(
            f"Load test completed: {successful_tasks} successful, {failed_tasks} failed, {duration:.2f}s duration"
        )

        return {
            "total_tasks": len(load_tasks),
            "successful_tasks": successful_tasks,
            "failed_tasks": failed_tasks,
            "duration_seconds": duration,
            "throughput": len(load_tasks) / duration,
        }

    async def _high_volume_db_operations(self, prefix: str):
        """Generate high-volume database operations."""
        for i in range(100):
            await self.db_manager.execute_query(
                f"SELECT * FROM users WHERE username LIKE '{prefix}_%' LIMIT 10"
            )
            if i % 20 == 0:
                await asyncio.sleep(0.01)  # Brief pause to prevent overwhelming

    async def _high_volume_cert_processing(self, prefix: str):
        """Generate high-volume certificate processing requests."""
        for i in range(50):
            await self.cert_processor.submit_certificate_request(
                {
                    "common_name": f"{prefix}_{i}.load-test.com",
                    "organization": "LoadTest",
                    "key_size": 2048,
                    "validity_days": 30,
                }
            )
            if i % 10 == 0:
                await asyncio.sleep(0.02)

    async def _high_volume_log_processing(self, prefix: str):
        """Generate high-volume log processing."""
        for i in range(200):
            await self.log_collector.submit_log_entry(
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "level": "INFO",
                    "service": prefix,
                    "message": f"Load test log entry {i}",
                    "source": "load_test",
                }
            )
            if i % 50 == 0:
                await asyncio.sleep(0.005)

    async def _monitor_load_test(self):
        """Monitor system performance during load test."""
        try:
            while True:
                metrics = await self.performance_monitor.get_system_metrics()
                logger.info(
                    f"Load test metrics - CPU: {metrics.get('cpu_usage_percent', 0):.1f}%, "
                    f"Memory: {metrics.get('memory_usage_percent', 0):.1f}%, "
                    f"Active connections: {metrics.get('active_connections', 0)}"
                )
                await asyncio.sleep(2)
        except asyncio.CancelledError:
            pass

    async def cleanup(self):
        """Cleanup all services and resources."""
        logger.info("Cleaning up services...")

        self.running = False

        # Stop services
        if self.log_collector:
            await self.log_collector.stop()
        if self.ssh_processor:
            await self.ssh_processor.stop()
        if self.cert_processor:
            await self.cert_processor.stop()
        if self.db_manager:
            await self.db_manager.cleanup()

        # Stop shared services
        await self.message_queue.stop()
        await self.performance_monitor.stop()
        await self.thread_manager.shutdown()
        await self.connection_manager.close_all()

        logger.info("Cleanup completed!")


async def main():
    """Main demonstration function."""
    logger.info("Starting SkausWatch Performance Integration Demo")

    # Create integration example
    integration = SkausWatchIntegrationExample()

    try:
        # Initialize all services
        await integration.initialize()

        # Run demonstrations
        logger.info("=" * 50)
        logger.info("CONCURRENT OPERATIONS DEMONSTRATION")
        logger.info("=" * 50)
        await integration.demonstrate_concurrent_operations()

        await asyncio.sleep(2)  # Brief pause between demos

        logger.info("=" * 50)
        logger.info("LOAD TESTING DEMONSTRATION")
        logger.info("=" * 50)
        load_results = await integration.demonstrate_load_testing()
        logger.info(f"Load test results: {load_results}")

    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)
    finally:
        # Always cleanup
        await integration.cleanup()

    logger.info("SkausWatch Performance Integration Demo completed!")


if __name__ == "__main__":
    # Run the demonstration
    asyncio.run(main())
