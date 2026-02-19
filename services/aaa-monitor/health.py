"""
SkausWatch AAA Monitor Service - Health Checker

Comprehensive health monitoring for all service components including
collectors, processors, threat intelligence, and AI providers.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

import structlog
import psutil
import redis.asyncio as redis

logger = structlog.get_logger(__name__)


class HealthChecker:
    """Comprehensive health checker for AAA Monitor service"""

    def __init__(
        self,
        config: Dict[str, Any],
        redis_client: Optional[redis.Redis],
        components: Dict[str, Any],
    ):
        """Initialize health checker

        Args:
            config: Health check configuration
            redis_client: Optional Redis client
            components: Dictionary of components to monitor
        """
        self.config = config
        self.redis_client = redis_client
        self.components = components

        # Health check state
        self.last_check = None
        self.check_history = []
        self.max_history = config.get("max_history", 100)

        # Component health status
        self.component_status = {}

        # System metrics
        self.system_metrics = {}

        # Monitoring task
        self.monitoring_task = None
        self.running = False

    async def check_all(self) -> Dict[str, Any]:
        """Perform comprehensive health check of all components

        Returns:
            Health status dictionary
        """
        try:
            start_time = time.time()
            checks = {}
            overall_status = "healthy"

            # System health checks
            checks["system"] = await self._check_system_health()
            if checks["system"]["status"] != "healthy":
                overall_status = "degraded"

            # Redis health check
            if self.redis_client:
                checks["redis"] = await self._check_redis_health()
                if checks["redis"]["status"] != "healthy":
                    overall_status = "degraded"

            # Component health checks
            for component_name in self.config.get("checks", []):
                if component_name in self.components:
                    checks[component_name] = await self._check_component_health(
                        component_name, self.components[component_name]
                    )
                    if checks[component_name]["status"] != "healthy":
                        overall_status = "degraded"

            # Calculate overall status
            critical_failures = sum(
                1 for check in checks.values() if check["status"] == "unhealthy"
            )

            if critical_failures > 0:
                overall_status = "unhealthy"

            check_time = time.time() - start_time
            timestamp = datetime.utcnow()

            health_status = {
                "status": overall_status,
                "timestamp": timestamp.isoformat(),
                "check_duration": check_time,
                "checks": checks,
                "metrics": self.system_metrics,
                "uptime": self._get_uptime(),
                "version": self._get_version(),
            }

            # Update check history
            self.last_check = timestamp
            self.check_history.append(
                {
                    "timestamp": timestamp.isoformat(),
                    "status": overall_status,
                    "duration": check_time,
                    "component_count": len(checks),
                }
            )

            # Limit history size
            if len(self.check_history) > self.max_history:
                self.check_history = self.check_history[-self.max_history :]

            logger.debug(
                "Health check completed",
                status=overall_status,
                duration=check_time,
                components_checked=len(checks),
            )

            return health_status

        except Exception as e:
            logger.error("Error during health check", error=str(e))
            return {
                "status": "unhealthy",
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e),
                "checks": {},
                "uptime": self._get_uptime(),
                "version": self._get_version(),
            }

    async def _check_system_health(self) -> Dict[str, Any]:
        """Check system-level health metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)

            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available = memory.available

            # Disk usage
            disk = psutil.disk_usage("/")
            disk_percent = (disk.used / disk.total) * 100
            disk_free = disk.free

            # Load average (Unix systems)
            try:
                load_avg = psutil.getloadavg()
            except (AttributeError, OSError):
                load_avg = [0, 0, 0]  # Windows doesn't have load average

            # Network I/O
            network = psutil.net_io_counters()

            # Process information
            process = psutil.Process()
            process_memory = process.memory_info().rss
            process_cpu = process.cpu_percent()

            # Update system metrics
            self.system_metrics = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "memory_available_bytes": memory_available,
                "disk_percent": disk_percent,
                "disk_free_bytes": disk_free,
                "load_average": load_avg,
                "network_bytes_sent": network.bytes_sent,
                "network_bytes_recv": network.bytes_recv,
                "process_memory_bytes": process_memory,
                "process_cpu_percent": process_cpu,
                "timestamp": datetime.utcnow().isoformat(),
            }

            # Determine system health status
            status = "healthy"
            issues = []

            # CPU threshold check
            if cpu_percent > 90:
                status = "unhealthy"
                issues.append(f"High CPU usage: {cpu_percent:.1f}%")
            elif cpu_percent > 75:
                status = "degraded"
                issues.append(f"Elevated CPU usage: {cpu_percent:.1f}%")

            # Memory threshold check
            if memory_percent > 95:
                status = "unhealthy"
                issues.append(f"Critical memory usage: {memory_percent:.1f}%")
            elif memory_percent > 85:
                if status == "healthy":
                    status = "degraded"
                issues.append(f"High memory usage: {memory_percent:.1f}%")

            # Disk space check
            if disk_percent > 95:
                status = "unhealthy"
                issues.append(f"Critical disk usage: {disk_percent:.1f}%")
            elif disk_percent > 85:
                if status == "healthy":
                    status = "degraded"
                issues.append(f"High disk usage: {disk_percent:.1f}%")

            # Load average check (for Unix systems)
            cpu_count = psutil.cpu_count()
            if load_avg[0] > cpu_count * 2:
                status = "unhealthy"
                issues.append(f"High load average: {load_avg[0]:.2f}")
            elif load_avg[0] > cpu_count * 1.5:
                if status == "healthy":
                    status = "degraded"
                issues.append(f"Elevated load average: {load_avg[0]:.2f}")

            return {
                "status": status,
                "issues": issues,
                "metrics": self.system_metrics,
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error("Error checking system health", error=str(e))
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def _check_redis_health(self) -> Dict[str, Any]:
        """Check Redis connection health"""
        try:
            start_time = time.time()

            # Ping Redis
            await self.redis_client.ping()

            # Get Redis info
            info = await self.redis_client.info()

            ping_time = (time.time() - start_time) * 1000  # ms

            # Check Redis metrics
            used_memory = info.get("used_memory", 0)
            used_memory_peak = info.get("used_memory_peak", 0)
            connected_clients = info.get("connected_clients", 0)
            total_commands_processed = info.get("total_commands_processed", 0)

            status = "healthy"
            issues = []

            # High latency check
            if ping_time > 100:  # 100ms
                status = "degraded"
                issues.append(f"High Redis latency: {ping_time:.1f}ms")

            # Memory usage check
            max_memory = info.get("maxmemory", 0)
            if max_memory > 0:
                memory_percent = (used_memory / max_memory) * 100
                if memory_percent > 95:
                    status = "unhealthy"
                    issues.append(f"Redis memory usage critical: {memory_percent:.1f}%")
                elif memory_percent > 85:
                    if status == "healthy":
                        status = "degraded"
                    issues.append(f"Redis memory usage high: {memory_percent:.1f}%")

            return {
                "status": status,
                "issues": issues,
                "latency_ms": ping_time,
                "metrics": {
                    "used_memory": used_memory,
                    "used_memory_peak": used_memory_peak,
                    "connected_clients": connected_clients,
                    "total_commands_processed": total_commands_processed,
                },
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error("Error checking Redis health", error=str(e))
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def _check_component_health(
        self, name: str, component: Any
    ) -> Dict[str, Any]:
        """Check health of a specific component"""
        try:
            # Check if component has a health check method
            if hasattr(component, "get_health_status"):
                return await component.get_health_status()
            elif hasattr(component, "health_check"):
                return await component.health_check()
            elif hasattr(component, "get_statistics"):
                # Use statistics as health indicator
                stats = component.get_statistics()
                return self._analyze_component_stats(name, stats)
            else:
                # Basic health check - component exists and has expected attributes
                return await self._basic_component_check(name, component)

        except Exception as e:
            logger.error(
                "Error checking component health", component=name, error=str(e)
            )
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    def _analyze_component_stats(
        self, name: str, stats: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze component statistics to determine health"""
        try:
            status = "healthy"
            issues = []

            # Common statistics analysis patterns
            if "errors" in stats and stats["errors"] > 0:
                if stats["errors"] > 100:  # High error count
                    status = "unhealthy"
                    issues.append(f"High error count: {stats['errors']}")
                else:
                    status = "degraded"
                    issues.append(f"Errors detected: {stats['errors']}")

            if "processing_errors" in stats and stats["processing_errors"] > 0:
                if stats["processing_errors"] > 50:
                    status = "unhealthy"
                    issues.append(
                        f"High processing errors: {stats['processing_errors']}"
                    )
                else:
                    if status == "healthy":
                        status = "degraded"
                    issues.append(f"Processing errors: {stats['processing_errors']}")

            # Queue size checks
            if "queue_size" in stats:
                if stats["queue_size"] > 10000:
                    status = "unhealthy"
                    issues.append(f"Queue overloaded: {stats['queue_size']}")
                elif stats["queue_size"] > 5000:
                    if status == "healthy":
                        status = "degraded"
                    issues.append(f"High queue size: {stats['queue_size']}")

            # Connection failures
            if "connection_failures" in stats and stats["connection_failures"] > 10:
                status = "unhealthy"
                issues.append(f"Connection failures: {stats['connection_failures']}")

            # Last activity check
            if "last_activity" in stats:
                try:
                    last_activity = datetime.fromisoformat(stats["last_activity"])
                    time_since = datetime.utcnow() - last_activity

                    if time_since > timedelta(hours=1):
                        status = "unhealthy"
                        issues.append(f"No activity for {time_since}")
                    elif time_since > timedelta(minutes=30):
                        if status == "healthy":
                            status = "degraded"
                        issues.append(f"Low activity: {time_since}")
                except:
                    pass

            return {
                "status": status,
                "issues": issues,
                "statistics": stats,
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            return {
                "status": "unhealthy",
                "error": f"Stats analysis failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def _basic_component_check(self, name: str, component: Any) -> Dict[str, Any]:
        """Basic component health check"""
        try:
            status = "healthy"
            issues = []

            # Check if component is running (if applicable)
            if hasattr(component, "running"):
                if not component.running:
                    status = "unhealthy"
                    issues.append("Component not running")

            # Check if component is initialized
            if hasattr(component, "initialized"):
                if not component.initialized:
                    status = "unhealthy"
                    issues.append("Component not initialized")

            # Check for error states
            if hasattr(component, "error_state"):
                if component.error_state:
                    status = "unhealthy"
                    issues.append("Component in error state")

            return {
                "status": status,
                "issues": issues,
                "component_type": type(component).__name__,
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            return {
                "status": "unhealthy",
                "error": f"Basic check failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat(),
            }

    def _get_uptime(self) -> float:
        """Get service uptime in seconds"""
        try:
            boot_time = psutil.boot_time()
            process = psutil.Process()
            start_time = process.create_time()
            return time.time() - start_time
        except:
            return 0.0

    def _get_version(self) -> str:
        """Get service version"""
        try:
            from .utils import get_version

            return get_version()
        except:
            return "unknown"

    async def start_monitoring(self):
        """Start background health monitoring"""
        if self.running:
            return

        self.running = True

        async def monitoring_loop():
            while self.running:
                try:
                    # Perform health check
                    await self.check_all()

                    # Wait for next check
                    await asyncio.sleep(self.config.get("check_interval", 30))

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error("Error in health monitoring loop", error=str(e))
                    await asyncio.sleep(60)  # Wait longer on error

        self.monitoring_task = asyncio.create_task(monitoring_loop())
        logger.info("Health monitoring started")

    async def stop_monitoring(self):
        """Stop background health monitoring"""
        self.running = False

        if self.monitoring_task and not self.monitoring_task.done():
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass

        logger.info("Health monitoring stopped")

    def get_check_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get health check history

        Args:
            limit: Optional limit on number of entries

        Returns:
            List of historical health check results
        """
        history = self.check_history.copy()

        if limit:
            history = history[-limit:]

        return history

    def get_component_status(self) -> Dict[str, Any]:
        """Get status of individual components"""
        return self.component_status.copy()

    async def check_dependencies(self) -> Dict[str, Any]:
        """Check external dependencies"""
        dependencies = {}

        # Check if we can reach common ports/services
        external_checks = [
            ("DNS", "8.8.8.8", 53),
            ("HTTPS", "google.com", 443),
        ]

        for name, host, port in external_checks:
            try:
                from .utils import wait_for_port

                available = await wait_for_port(host, port, timeout=5)
                dependencies[name] = {
                    "status": "available" if available else "unavailable",
                    "host": host,
                    "port": port,
                }
            except Exception as e:
                dependencies[name] = {
                    "status": "error",
                    "error": str(e),
                    "host": host,
                    "port": port,
                }

        return dependencies

    async def close(self):
        """Close health checker and cleanup"""
        await self.stop_monitoring()
        logger.info("Health checker closed")
