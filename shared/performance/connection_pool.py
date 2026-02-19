"""
Connection Pool Management for SkausWatch Services

Provides comprehensive connection pooling for databases, Redis, HTTP clients,
and other network resources with health monitoring, auto-scaling, and metrics.
"""

import asyncio
import logging
import time
import urllib.parse
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    AsyncContextManager,
    AsyncIterator,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    TypeVar,
    Union,
    Tuple,
    Set,
)
from uuid import uuid4
import weakref
import ssl

# Third-party imports (conditional)
try:
    import asyncpg

    HAS_ASYNCPG = True
except ImportError:
    HAS_ASYNCPG = False
    asyncpg = None

try:
    import aiosqlite

    HAS_AIOSQLITE = True
except ImportError:
    HAS_AIOSQLITE = False
    aiosqlite = None

try:
    import redis.asyncio as aioredis

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    aioredis = None

try:
    import aiohttp

    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    aiohttp = None

logger = logging.getLogger(__name__)

T = TypeVar("T")
Connection = TypeVar("Connection")


class PoolStatus(Enum):
    """Connection pool status"""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    SHUTTING_DOWN = "shutting_down"
    SHUTDOWN = "shutdown"


class ConnectionState(Enum):
    """Individual connection state"""

    IDLE = "idle"
    ACTIVE = "active"
    TESTING = "testing"
    FAILED = "failed"
    CLOSED = "closed"


@dataclass
class PoolConfig:
    """Base configuration for connection pools"""

    min_size: int = 5
    max_size: int = 20
    max_idle_time: float = 300.0  # 5 minutes
    max_lifetime: float = 3600.0  # 1 hour
    health_check_interval: float = 30.0
    connection_timeout: float = 10.0
    query_timeout: float = 30.0
    retry_attempts: int = 3
    retry_delay: float = 1.0
    auto_scale: bool = True
    scale_threshold_high: float = 0.8  # Scale up when 80% connections in use
    scale_threshold_low: float = 0.3  # Scale down when 30% connections in use
    metrics_enabled: bool = True


@dataclass
class HealthCheckConfig:
    """Health check configuration"""

    enabled: bool = True
    interval: float = 30.0
    timeout: float = 5.0
    failure_threshold: int = 3
    success_threshold: int = 2
    query: str = "SELECT 1"  # Default health check query


@dataclass
class ConnectionInfo:
    """Information about a connection"""

    connection_id: str
    created_at: float
    last_used: float
    use_count: int
    state: ConnectionState
    error_count: int
    last_error: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PoolMetrics:
    """Connection pool metrics"""

    pool_name: str
    status: PoolStatus
    total_connections: int
    active_connections: int
    idle_connections: int
    failed_connections: int
    total_acquired: int
    total_released: int
    total_created: int
    total_closed: int
    total_errors: int
    average_acquire_time: float
    average_connection_lifetime: float
    uptime_seconds: float
    last_health_check: float
    health_check_failures: int


class BaseConnectionPool(Generic[Connection], ABC):
    """Base class for connection pools"""

    def __init__(
        self,
        name: str,
        config: PoolConfig,
        health_config: Optional[HealthCheckConfig] = None,
    ):
        self.name = name
        self.config = config
        self.health_config = health_config or HealthCheckConfig()

        # Pool state
        self.status = PoolStatus.HEALTHY
        self.created_at = time.time()
        self.connections: Dict[str, Connection] = {}
        self.connection_info: Dict[str, ConnectionInfo] = {}
        self.available_connections: asyncio.Queue = asyncio.Queue()
        self.pending_connections: Set[str] = set()

        # Synchronization
        self._lock = asyncio.Lock()
        self._condition = asyncio.Condition(self._lock)

        # Health monitoring
        self.health_check_task: Optional[asyncio.Task] = None
        self.last_health_check = 0.0
        self.consecutive_health_failures = 0

        # Metrics
        self.metrics = PoolMetrics(
            pool_name=name,
            status=self.status,
            total_connections=0,
            active_connections=0,
            idle_connections=0,
            failed_connections=0,
            total_acquired=0,
            total_released=0,
            total_created=0,
            total_closed=0,
            total_errors=0,
            average_acquire_time=0.0,
            average_connection_lifetime=0.0,
            uptime_seconds=0.0,
            last_health_check=0.0,
            health_check_failures=0,
        )

        # Cleanup task
        self.cleanup_task: Optional[asyncio.Task] = None

    @abstractmethod
    async def _create_connection(self) -> Connection:
        """Create a new connection"""
        pass

    @abstractmethod
    async def _close_connection(self, connection: Connection) -> None:
        """Close a connection"""
        pass

    @abstractmethod
    async def _test_connection(self, connection: Connection) -> bool:
        """Test if connection is healthy"""
        pass

    async def start(self) -> None:
        """Start the connection pool"""
        logger.info(f"Starting connection pool '{self.name}'")

        # Create initial connections
        await self._create_initial_connections()

        # Start health monitoring
        if self.health_config.enabled:
            self.health_check_task = asyncio.create_task(self._health_check_loop())

        # Start cleanup task
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())

        logger.info(
            f"Connection pool '{self.name}' started with {len(self.connections)} connections"
        )

    async def stop(self) -> None:
        """Stop the connection pool"""
        logger.info(f"Stopping connection pool '{self.name}'")
        self.status = PoolStatus.SHUTTING_DOWN

        # Cancel background tasks
        if self.health_check_task:
            self.health_check_task.cancel()
        if self.cleanup_task:
            self.cleanup_task.cancel()

        # Close all connections
        async with self._lock:
            for connection_id in list(self.connections.keys()):
                await self._close_connection_internal(connection_id)

        self.status = PoolStatus.SHUTDOWN
        logger.info(f"Connection pool '{self.name}' stopped")

    @asynccontextmanager
    async def acquire(
        self, timeout: Optional[float] = None
    ) -> AsyncIterator[Connection]:
        """Acquire a connection from the pool"""
        if self.status in [PoolStatus.SHUTTING_DOWN, PoolStatus.SHUTDOWN]:
            raise RuntimeError(f"Pool {self.name} is not available")

        acquire_start = time.time()
        connection = None
        connection_id = None

        try:
            timeout = timeout or self.config.connection_timeout
            connection_id, connection = await asyncio.wait_for(
                self._get_connection(), timeout
            )

            # Update metrics
            acquire_time = time.time() - acquire_start
            self._update_acquire_metrics(acquire_time)

            # Update connection info
            if connection_id in self.connection_info:
                info = self.connection_info[connection_id]
                info.last_used = time.time()
                info.use_count += 1
                info.state = ConnectionState.ACTIVE

            self.metrics.active_connections += 1
            self.metrics.idle_connections -= 1
            self.metrics.total_acquired += 1

            yield connection

        except asyncio.TimeoutError:
            logger.error(f"Timeout acquiring connection from pool {self.name}")
            self.metrics.total_errors += 1
            raise
        except Exception as e:
            logger.error(f"Error acquiring connection from pool {self.name}: {e}")
            self.metrics.total_errors += 1
            raise
        finally:
            if connection and connection_id:
                await self._return_connection(connection_id, connection)

    async def _get_connection(self) -> Tuple[str, Connection]:
        """Get an available connection"""
        async with self._condition:
            # Try to get existing connection
            while True:
                if not self.available_connections.empty():
                    try:
                        connection_id = await asyncio.wait_for(
                            self.available_connections.get(), timeout=0.1
                        )
                        connection = self.connections.get(connection_id)

                        if connection and await self._validate_connection(
                            connection_id
                        ):
                            return connection_id, connection
                        else:
                            # Connection invalid, remove it
                            if connection_id in self.connections:
                                await self._close_connection_internal(connection_id)
                            continue

                    except asyncio.TimeoutError:
                        break

                # Create new connection if under limit
                if len(self.connections) < self.config.max_size:
                    return await self._create_new_connection()

                # Wait for available connection
                await self._condition.wait()

        raise Exception("No connections available and pool is at maximum size")

    async def _create_new_connection(self) -> Tuple[str, Connection]:
        """Create a new connection"""
        connection_id = str(uuid4())

        try:
            connection = await self._create_connection()
            current_time = time.time()

            self.connections[connection_id] = connection
            self.connection_info[connection_id] = ConnectionInfo(
                connection_id=connection_id,
                created_at=current_time,
                last_used=current_time,
                use_count=0,
                state=ConnectionState.IDLE,
                error_count=0,
                last_error=None,
            )

            self.metrics.total_connections += 1
            self.metrics.idle_connections += 1
            self.metrics.total_created += 1

            logger.debug(f"Created new connection {connection_id} for pool {self.name}")
            return connection_id, connection

        except Exception as e:
            logger.error(f"Failed to create connection for pool {self.name}: {e}")
            self.metrics.total_errors += 1
            raise

    async def _return_connection(
        self, connection_id: str, connection: Connection
    ) -> None:
        """Return connection to the pool"""
        async with self._condition:
            if connection_id in self.connection_info:
                info = self.connection_info[connection_id]
                info.state = ConnectionState.IDLE

                # Check if connection should be kept
                if await self._should_keep_connection(connection_id):
                    self.available_connections.put_nowait(connection_id)
                    self.metrics.active_connections -= 1
                    self.metrics.idle_connections += 1
                    self.metrics.total_released += 1
                else:
                    await self._close_connection_internal(connection_id)

                self._condition.notify()

    async def _validate_connection(self, connection_id: str) -> bool:
        """Validate that a connection is still usable"""
        if connection_id not in self.connections:
            return False

        connection = self.connections[connection_id]
        info = self.connection_info[connection_id]

        try:
            # Test connection
            info.state = ConnectionState.TESTING
            is_healthy = await self._test_connection(connection)

            if is_healthy:
                info.state = ConnectionState.IDLE
                info.error_count = 0
                return True
            else:
                info.state = ConnectionState.FAILED
                info.error_count += 1
                return False

        except Exception as e:
            logger.warning(f"Connection validation failed for {connection_id}: {e}")
            info.state = ConnectionState.FAILED
            info.error_count += 1
            info.last_error = str(e)
            return False

    async def _should_keep_connection(self, connection_id: str) -> bool:
        """Check if connection should be kept in pool"""
        if connection_id not in self.connection_info:
            return False

        info = self.connection_info[connection_id]
        current_time = time.time()

        # Check age limits
        if (current_time - info.created_at) > self.config.max_lifetime:
            logger.debug(f"Connection {connection_id} exceeded max lifetime")
            return False

        if (current_time - info.last_used) > self.config.max_idle_time:
            logger.debug(f"Connection {connection_id} exceeded max idle time")
            return False

        # Check error rate
        if info.error_count >= 3:
            logger.debug(f"Connection {connection_id} has too many errors")
            return False

        return True

    async def _close_connection_internal(self, connection_id: str) -> None:
        """Close connection and clean up"""
        if connection_id in self.connections:
            connection = self.connections[connection_id]

            try:
                await self._close_connection(connection)
            except Exception as e:
                logger.error(f"Error closing connection {connection_id}: {e}")

            del self.connections[connection_id]

            if connection_id in self.connection_info:
                info = self.connection_info[connection_id]
                info.state = ConnectionState.CLOSED

                # Update lifetime metrics
                lifetime = time.time() - info.created_at
                self._update_lifetime_metrics(lifetime)

                del self.connection_info[connection_id]

            self.metrics.total_connections -= 1
            self.metrics.total_closed += 1

            if (
                self.connection_info.get(
                    connection_id,
                    ConnectionInfo("", 0, 0, 0, ConnectionState.IDLE, 0, None),
                ).state
                == ConnectionState.ACTIVE
            ):
                self.metrics.active_connections -= 1
            else:
                self.metrics.idle_connections -= 1

            logger.debug(f"Closed connection {connection_id} for pool {self.name}")

    async def _create_initial_connections(self) -> None:
        """Create initial pool connections"""
        tasks = []
        for _ in range(self.config.min_size):
            task = asyncio.create_task(self._create_new_connection())
            tasks.append(task)

        # Wait for all connections to be created
        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful = 0
        for result in results:
            if isinstance(result, tuple):
                connection_id, connection = result
                self.available_connections.put_nowait(connection_id)
                successful += 1
            else:
                logger.error(f"Failed to create initial connection: {result}")

        logger.info(
            f"Created {successful}/{self.config.min_size} initial connections for pool {self.name}"
        )

    async def _health_check_loop(self) -> None:
        """Health check loop"""
        while self.status != PoolStatus.SHUTTING_DOWN:
            try:
                await asyncio.sleep(self.health_config.interval)
                await self._perform_health_check()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error for pool {self.name}: {e}")

    async def _perform_health_check(self) -> None:
        """Perform health check on pool"""
        current_time = time.time()
        self.last_health_check = current_time
        self.metrics.last_health_check = current_time

        healthy_connections = 0
        failed_connections = 0

        # Test a sample of idle connections
        sample_size = min(3, len(self.connection_info))
        sample_connections = list(self.connection_info.keys())[:sample_size]

        for connection_id in sample_connections:
            if connection_id in self.connections:
                if await self._validate_connection(connection_id):
                    healthy_connections += 1
                else:
                    failed_connections += 1
                    await self._close_connection_internal(connection_id)

        # Update pool status
        if failed_connections > healthy_connections:
            self.consecutive_health_failures += 1
        else:
            self.consecutive_health_failures = 0

        if self.consecutive_health_failures >= self.health_config.failure_threshold:
            self.status = PoolStatus.UNHEALTHY
            self.metrics.health_check_failures += 1
        elif failed_connections > 0:
            self.status = PoolStatus.DEGRADED
        else:
            self.status = PoolStatus.HEALTHY

        # Auto-scaling
        if self.config.auto_scale:
            await self._check_auto_scaling()

        logger.debug(
            f"Health check for pool {self.name}: {healthy_connections} healthy, {failed_connections} failed"
        )

    async def _check_auto_scaling(self) -> None:
        """Check if auto-scaling is needed"""
        current_size = len(self.connections)
        utilization = self.metrics.active_connections / max(1, current_size)

        # Scale up
        if (
            utilization >= self.config.scale_threshold_high
            and current_size < self.config.max_size
        ):
            try:
                connection_id, connection = await self._create_new_connection()
                self.available_connections.put_nowait(connection_id)
                logger.info(
                    f"Scaled up pool {self.name} to {len(self.connections)} connections"
                )
            except Exception as e:
                logger.error(f"Failed to scale up pool {self.name}: {e}")

        # Scale down
        elif (
            utilization <= self.config.scale_threshold_low
            and current_size > self.config.min_size
        ):
            # Find oldest idle connection to remove
            oldest_connection = None
            oldest_time = float("inf")

            for connection_id, info in self.connection_info.items():
                if info.state == ConnectionState.IDLE and info.last_used < oldest_time:
                    oldest_time = info.last_used
                    oldest_connection = connection_id

            if oldest_connection:
                await self._close_connection_internal(oldest_connection)
                logger.info(
                    f"Scaled down pool {self.name} to {len(self.connections)} connections"
                )

    async def _cleanup_loop(self) -> None:
        """Cleanup loop for expired connections"""
        while self.status != PoolStatus.SHUTTING_DOWN:
            try:
                await asyncio.sleep(60.0)  # Run cleanup every minute
                await self._cleanup_expired_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup error for pool {self.name}: {e}")

    async def _cleanup_expired_connections(self) -> None:
        """Clean up expired connections"""
        current_time = time.time()
        expired_connections = []

        for connection_id, info in self.connection_info.items():
            if (
                info.state == ConnectionState.IDLE
                and (current_time - info.last_used) > self.config.max_idle_time
            ):
                expired_connections.append(connection_id)

        for connection_id in expired_connections:
            if len(self.connections) > self.config.min_size:
                await self._close_connection_internal(connection_id)
                logger.debug(f"Cleaned up expired connection {connection_id}")

    def _update_acquire_metrics(self, acquire_time: float) -> None:
        """Update connection acquire metrics"""
        # Simple moving average
        if self.metrics.average_acquire_time == 0.0:
            self.metrics.average_acquire_time = acquire_time
        else:
            self.metrics.average_acquire_time = (
                self.metrics.average_acquire_time * 0.9 + acquire_time * 0.1
            )

    def _update_lifetime_metrics(self, lifetime: float) -> None:
        """Update connection lifetime metrics"""
        # Simple moving average
        if self.metrics.average_connection_lifetime == 0.0:
            self.metrics.average_connection_lifetime = lifetime
        else:
            self.metrics.average_connection_lifetime = (
                self.metrics.average_connection_lifetime * 0.9 + lifetime * 0.1
            )

    def get_metrics(self) -> PoolMetrics:
        """Get current pool metrics"""
        self.metrics.status = self.status
        self.metrics.total_connections = len(self.connections)
        self.metrics.uptime_seconds = time.time() - self.created_at

        # Count connections by state
        active = idle = failed = 0
        for info in self.connection_info.values():
            if info.state == ConnectionState.ACTIVE:
                active += 1
            elif info.state == ConnectionState.IDLE:
                idle += 1
            elif info.state == ConnectionState.FAILED:
                failed += 1

        self.metrics.active_connections = active
        self.metrics.idle_connections = idle
        self.metrics.failed_connections = failed

        return self.metrics


# Specialized connection pools


class DatabaseConnectionPool(BaseConnectionPool[Any]):
    """Database connection pool supporting multiple database types"""

    def __init__(
        self,
        name: str,
        database_url: str,
        config: Optional[PoolConfig] = None,
        health_config: Optional[HealthCheckConfig] = None,
    ):
        super().__init__(name, config or PoolConfig(), health_config)
        self.database_url = database_url
        self._parse_database_url()

    def _parse_database_url(self) -> None:
        """Parse database URL to determine type and connection parameters"""
        parsed = urllib.parse.urlparse(self.database_url)
        self.db_type = parsed.scheme.lower()
        self.host = parsed.hostname
        self.port = parsed.port
        self.database = parsed.path.lstrip("/")
        self.username = parsed.username
        self.password = parsed.password

        # Set default health check queries
        if self.db_type in ["postgresql", "postgres"]:
            self.health_config.query = "SELECT 1"
        elif self.db_type in ["mysql", "mariadb"]:
            self.health_config.query = "SELECT 1"
        elif self.db_type == "sqlite":
            self.health_config.query = "SELECT 1"
        else:
            self.health_config.query = "SELECT 1"

    async def _create_connection(self) -> Any:
        """Create database connection based on type"""
        if self.db_type in ["postgresql", "postgres"]:
            if not HAS_ASYNCPG:
                raise RuntimeError("asyncpg is required for PostgreSQL connections")
            return await asyncpg.connect(self.database_url)

        elif self.db_type == "sqlite":
            if not HAS_AIOSQLITE:
                raise RuntimeError("aiosqlite is required for SQLite connections")
            return await aiosqlite.connect(self.database)

        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")

    async def _close_connection(self, connection: Any) -> None:
        """Close database connection"""
        try:
            if hasattr(connection, "close"):
                await connection.close()
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")

    async def _test_connection(self, connection: Any) -> bool:
        """Test database connection health"""
        try:
            if self.db_type in ["postgresql", "postgres"]:
                await connection.fetchval(self.health_config.query)
            elif self.db_type == "sqlite":
                async with connection.execute(self.health_config.query) as cursor:
                    await cursor.fetchone()
            return True
        except Exception as e:
            logger.debug(f"Database health check failed: {e}")
            return False


class RedisConnectionPool(BaseConnectionPool[Any]):
    """Redis connection pool"""

    def __init__(
        self,
        name: str,
        redis_url: str,
        config: Optional[PoolConfig] = None,
        health_config: Optional[HealthCheckConfig] = None,
    ):
        super().__init__(name, config or PoolConfig(), health_config)
        self.redis_url = redis_url
        self.health_config.query = "PING"

    async def _create_connection(self) -> Any:
        """Create Redis connection"""
        if not HAS_REDIS:
            raise RuntimeError("redis is required for Redis connections")
        return aioredis.from_url(self.redis_url)

    async def _close_connection(self, connection: Any) -> None:
        """Close Redis connection"""
        try:
            await connection.close()
        except Exception as e:
            logger.error(f"Error closing Redis connection: {e}")

    async def _test_connection(self, connection: Any) -> bool:
        """Test Redis connection health"""
        try:
            response = await connection.ping()
            return response is True
        except Exception as e:
            logger.debug(f"Redis health check failed: {e}")
            return False


class HTTPConnectionPool(BaseConnectionPool[Any]):
    """HTTP client connection pool using aiohttp"""

    def __init__(
        self,
        name: str,
        base_url: Optional[str] = None,
        config: Optional[PoolConfig] = None,
        health_config: Optional[HealthCheckConfig] = None,
        session_config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(name, config or PoolConfig(), health_config)
        self.base_url = base_url
        self.session_config = session_config or {}

    async def _create_connection(self) -> Any:
        """Create HTTP client session"""
        if not HAS_AIOHTTP:
            raise RuntimeError("aiohttp is required for HTTP connections")

        connector = aiohttp.TCPConnector(
            limit=self.config.max_size,
            limit_per_host=self.config.max_size,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )

        return aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(
                total=self.config.query_timeout, connect=self.config.connection_timeout
            ),
            **self.session_config,
        )

    async def _close_connection(self, connection: Any) -> None:
        """Close HTTP client session"""
        try:
            await connection.close()
        except Exception as e:
            logger.error(f"Error closing HTTP connection: {e}")

    async def _test_connection(self, connection: Any) -> bool:
        """Test HTTP connection health"""
        try:
            if self.base_url:
                async with connection.get(f"{self.base_url}/health") as response:
                    return response.status < 500
            return not connection.closed
        except Exception as e:
            logger.debug(f"HTTP health check failed: {e}")
            return False


class ConnectionPoolManager:
    """Centralized connection pool management"""

    def __init__(self):
        self.pools: Dict[str, BaseConnectionPool] = {}
        self.default_configs = {
            "database": PoolConfig(min_size=2, max_size=10, max_idle_time=600.0),
            "redis": PoolConfig(min_size=5, max_size=20, max_idle_time=300.0),
            "http": PoolConfig(min_size=3, max_size=30, max_idle_time=120.0),
        }

    def create_database_pool(
        self,
        name: str,
        database_url: str,
        config: Optional[PoolConfig] = None,
        health_config: Optional[HealthCheckConfig] = None,
    ) -> DatabaseConnectionPool:
        """Create database connection pool"""
        if name in self.pools:
            raise ValueError(f"Pool '{name}' already exists")

        config = config or self.default_configs["database"]
        pool = DatabaseConnectionPool(name, database_url, config, health_config)
        self.pools[name] = pool

        return pool

    def create_redis_pool(
        self,
        name: str,
        redis_url: str,
        config: Optional[PoolConfig] = None,
        health_config: Optional[HealthCheckConfig] = None,
    ) -> RedisConnectionPool:
        """Create Redis connection pool"""
        if name in self.pools:
            raise ValueError(f"Pool '{name}' already exists")

        config = config or self.default_configs["redis"]
        pool = RedisConnectionPool(name, redis_url, config, health_config)
        self.pools[name] = pool

        return pool

    def create_http_pool(
        self,
        name: str,
        base_url: Optional[str] = None,
        config: Optional[PoolConfig] = None,
        health_config: Optional[HealthCheckConfig] = None,
        session_config: Optional[Dict[str, Any]] = None,
    ) -> HTTPConnectionPool:
        """Create HTTP connection pool"""
        if name in self.pools:
            raise ValueError(f"Pool '{name}' already exists")

        config = config or self.default_configs["http"]
        pool = HTTPConnectionPool(name, base_url, config, health_config, session_config)
        self.pools[name] = pool

        return pool

    def get_pool(self, name: str) -> Optional[BaseConnectionPool]:
        """Get existing pool by name"""
        return self.pools.get(name)

    async def start_all_pools(self) -> None:
        """Start all pools"""
        tasks = []
        for pool in self.pools.values():
            tasks.append(asyncio.create_task(pool.start()))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def stop_all_pools(self) -> None:
        """Stop all pools"""
        tasks = []
        for pool in self.pools.values():
            tasks.append(asyncio.create_task(pool.stop()))

        await asyncio.gather(*tasks, return_exceptions=True)
        self.pools.clear()

    def get_all_metrics(self) -> Dict[str, PoolMetrics]:
        """Get metrics for all pools"""
        return {name: pool.get_metrics() for name, pool in self.pools.items()}


# Global pool manager instance
_global_pool_manager: Optional[ConnectionPoolManager] = None


def get_global_pool_manager() -> ConnectionPoolManager:
    """Get global connection pool manager"""
    global _global_pool_manager
    if _global_pool_manager is None:
        _global_pool_manager = ConnectionPoolManager()
    return _global_pool_manager


async def cleanup_global_pools():
    """Cleanup global connection pools"""
    global _global_pool_manager
    if _global_pool_manager is not None:
        await _global_pool_manager.stop_all_pools()
        _global_pool_manager = None
