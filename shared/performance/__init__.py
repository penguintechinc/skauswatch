"""
SkausWatch Shared Performance Utilities

This package provides comprehensive performance optimization utilities
for async operations, connection pooling, caching, and thread management
across all SkausWatch services.
"""

from .async_utils import (
    AsyncContextManager,
    AsyncQueue,
    AsyncTaskManager,
    async_batch_processor,
    async_circuit_breaker,
    async_gather_with_concurrency,
    async_rate_limit,
    async_retry,
    async_semaphore_limit,
    async_timeout,
)
from .cache_manager import (
    CacheConfig,
    CacheManager,
    MemoryCache,
    RedisCache,
    TieredCache,
    cache_decorator,
    cache_key_generator,
    invalidate_cache,
)
from .connection_pool import (
    ConnectionPoolManager,
    DatabaseConnectionPool,
    HealthCheckConfig,
    HTTPConnectionPool,
    PoolConfig,
    RedisConnectionPool,
)
from .rate_limiter import (
    DistributedRateLimiter,
    RateLimitConfig,
    RateLimiter,
    RateLimitExceeded,
    SlidingWindowRateLimiter,
    TokenBucketRateLimiter,
    rate_limit_decorator,
)
from .thread_pool import (
    AsyncThreadPoolExecutor,
    CPUBoundTaskManager,
    IOBoundTaskManager,
    ThreadPoolManager,
    thread_pool_task,
)

__all__ = [
    # Async utilities
    "async_retry",
    "async_timeout",
    "async_circuit_breaker",
    "async_semaphore_limit",
    "async_batch_processor",
    "AsyncContextManager",
    "AsyncTaskManager",
    "AsyncQueue",
    "async_gather_with_concurrency",
    "async_rate_limit",
    # Thread pool management
    "ThreadPoolManager",
    "AsyncThreadPoolExecutor",
    "thread_pool_task",
    "CPUBoundTaskManager",
    "IOBoundTaskManager",
    # Connection pooling
    "ConnectionPoolManager",
    "DatabaseConnectionPool",
    "RedisConnectionPool",
    "HTTPConnectionPool",
    "PoolConfig",
    "HealthCheckConfig",
    # Cache management
    "CacheManager",
    "RedisCache",
    "MemoryCache",
    "TieredCache",
    "CacheConfig",
    "cache_decorator",
    "invalidate_cache",
    "cache_key_generator",
    # Rate limiting
    "RateLimiter",
    "DistributedRateLimiter",
    "TokenBucketRateLimiter",
    "SlidingWindowRateLimiter",
    "RateLimitConfig",
    "rate_limit_decorator",
    "RateLimitExceeded",
]

__version__ = "1.0.0"
