"""
SkausWatch Shared Performance Utilities

This package provides comprehensive performance optimization utilities
for async operations, connection pooling, caching, and thread management
across all SkausWatch services.
"""

from .async_utils import (
    async_retry,
    async_timeout,
    async_circuit_breaker,
    async_semaphore_limit,
    async_batch_processor,
    AsyncContextManager,
    AsyncTaskManager,
    AsyncQueue,
    async_gather_with_concurrency,
    async_rate_limit,
)

from .thread_pool import (
    ThreadPoolManager,
    AsyncThreadPoolExecutor,
    thread_pool_task,
    CPUBoundTaskManager,
    IOBoundTaskManager,
)

from .connection_pool import (
    ConnectionPoolManager,
    DatabaseConnectionPool,
    RedisConnectionPool,
    HTTPConnectionPool,
    PoolConfig,
    HealthCheckConfig,
)

from .cache_manager import (
    CacheManager,
    RedisCache,
    MemoryCache,
    TieredCache,
    CacheConfig,
    cache_decorator,
    invalidate_cache,
    cache_key_generator,
)

from .rate_limiter import (
    RateLimiter,
    DistributedRateLimiter,
    TokenBucketRateLimiter,
    SlidingWindowRateLimiter,
    RateLimitConfig,
    rate_limit_decorator,
    RateLimitExceeded,
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
