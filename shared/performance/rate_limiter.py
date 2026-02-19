"""
Rate Limiting for SkausWatch Services

Provides comprehensive rate limiting solutions including token bucket,
sliding window, fixed window, and distributed rate limiting with Redis backend.
"""

import asyncio
import logging
import math
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import (
    Any,
    AsyncContextManager,
    Callable,
    Dict,
    List,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    Union,
)
from uuid import uuid4

# Third-party imports (conditional)
try:
    import redis.asyncio as aioredis

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    aioredis = None

logger = logging.getLogger(__name__)


class RateLimitStrategy(Enum):
    """Rate limiting strategies"""

    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    LEAKY_BUCKET = "leaky_bucket"


class RateLimitScope(Enum):
    """Rate limit scope"""

    GLOBAL = "global"
    PER_USER = "per_user"
    PER_IP = "per_ip"
    PER_API_KEY = "per_api_key"
    CUSTOM = "custom"


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""

    strategy: RateLimitStrategy = RateLimitStrategy.TOKEN_BUCKET
    requests: int = 100
    window_seconds: float = 60.0
    burst_size: Optional[int] = None  # For token bucket
    scope: RateLimitScope = RateLimitScope.GLOBAL
    key_extractor: Optional[Callable] = None  # Extract key from request
    redis_url: Optional[str] = None
    redis_key_prefix: str = "rate_limit"
    cleanup_interval: float = 300.0  # 5 minutes
    metrics_enabled: bool = True


@dataclass
class RateLimitResult:
    """Result of rate limit check"""

    allowed: bool
    requests_remaining: int
    reset_time: float
    retry_after: Optional[float] = None
    rate_limit_key: str = ""
    current_usage: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RateLimitMetrics:
    """Rate limiting metrics"""

    total_requests: int = 0
    allowed_requests: int = 0
    denied_requests: int = 0
    unique_keys: int = 0
    average_usage: float = 0.0
    peak_usage: int = 0
    reset_count: int = 0
    cache_hits: int = 0
    cache_misses: int = 0


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded"""

    def __init__(self, result: RateLimitResult, message: str = "Rate limit exceeded"):
        self.result = result
        super().__init__(message)


class WindowEntry(NamedTuple):
    """Entry in sliding window"""

    timestamp: float
    count: int = 1


class BaseRateLimiter(ABC):
    """Base class for rate limiters"""

    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.metrics = RateLimitMetrics()
        self.metrics_lock = threading.Lock()

    @abstractmethod
    async def check_rate_limit(self, key: str) -> RateLimitResult:
        """Check if request is within rate limit"""
        pass

    @abstractmethod
    async def reset_rate_limit(self, key: str) -> bool:
        """Reset rate limit for key"""
        pass

    @abstractmethod
    async def get_current_usage(self, key: str) -> int:
        """Get current usage for key"""
        pass

    @abstractmethod
    async def cleanup(self) -> int:
        """Clean up expired entries"""
        pass

    def _update_metrics(self, allowed: bool, key: str, usage: int) -> None:
        """Update rate limiting metrics"""
        with self.metrics_lock:
            self.metrics.total_requests += 1
            if allowed:
                self.metrics.allowed_requests += 1
            else:
                self.metrics.denied_requests += 1

            self.metrics.peak_usage = max(self.metrics.peak_usage, usage)

            # Update average usage (simple moving average)
            if self.metrics.total_requests == 1:
                self.metrics.average_usage = usage
            else:
                self.metrics.average_usage = (
                    self.metrics.average_usage * 0.95 + usage * 0.05
                )

    def get_metrics(self) -> RateLimitMetrics:
        """Get current metrics"""
        with self.metrics_lock:
            return RateLimitMetrics(
                total_requests=self.metrics.total_requests,
                allowed_requests=self.metrics.allowed_requests,
                denied_requests=self.metrics.denied_requests,
                unique_keys=self.metrics.unique_keys,
                average_usage=self.metrics.average_usage,
                peak_usage=self.metrics.peak_usage,
                reset_count=self.metrics.reset_count,
                cache_hits=self.metrics.cache_hits,
                cache_misses=self.metrics.cache_misses,
            )

    def reset_metrics(self) -> None:
        """Reset all metrics"""
        with self.metrics_lock:
            self.metrics = RateLimitMetrics()


class TokenBucketRateLimiter(BaseRateLimiter):
    """Token bucket rate limiter implementation"""

    def __init__(self, config: RateLimitConfig):
        super().__init__(config)
        self.buckets: Dict[str, Dict[str, Any]] = {}
        self.lock = asyncio.Lock()

        # Calculate token generation rate
        self.tokens_per_second = config.requests / config.window_seconds
        self.bucket_size = config.burst_size or config.requests

        # Start cleanup task
        self.cleanup_task: Optional[asyncio.Task] = None
        self.start_cleanup()

    def start_cleanup(self) -> None:
        """Start cleanup task"""
        if self.cleanup_task is None:
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop_cleanup(self) -> None:
        """Stop cleanup task"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
            self.cleanup_task = None

    async def check_rate_limit(self, key: str) -> RateLimitResult:
        """Check rate limit using token bucket algorithm"""
        async with self.lock:
            current_time = time.time()

            # Get or create bucket
            if key not in self.buckets:
                self.buckets[key] = {
                    "tokens": self.bucket_size,
                    "last_refill": current_time,
                    "total_requests": 0,
                }
                with self.metrics_lock:
                    self.metrics.unique_keys += 1

            bucket = self.buckets[key]
            bucket["total_requests"] += 1

            # Refill tokens
            time_passed = current_time - bucket["last_refill"]
            tokens_to_add = time_passed * self.tokens_per_second
            bucket["tokens"] = min(self.bucket_size, bucket["tokens"] + tokens_to_add)
            bucket["last_refill"] = current_time

            # Check if token available
            if bucket["tokens"] >= 1:
                bucket["tokens"] -= 1
                allowed = True
                requests_remaining = int(bucket["tokens"])
                retry_after = None
            else:
                allowed = False
                requests_remaining = 0
                # Calculate when next token will be available
                retry_after = (1 - bucket["tokens"]) / self.tokens_per_second

            # Calculate reset time (when bucket will be full)
            tokens_needed = self.bucket_size - bucket["tokens"]
            reset_time = current_time + (tokens_needed / self.tokens_per_second)

            current_usage = self.bucket_size - int(bucket["tokens"])
            self._update_metrics(allowed, key, current_usage)

            return RateLimitResult(
                allowed=allowed,
                requests_remaining=requests_remaining,
                reset_time=reset_time,
                retry_after=retry_after,
                rate_limit_key=key,
                current_usage=current_usage,
                metadata={
                    "strategy": "token_bucket",
                    "bucket_size": self.bucket_size,
                    "tokens_per_second": self.tokens_per_second,
                },
            )

    async def reset_rate_limit(self, key: str) -> bool:
        """Reset rate limit for key"""
        async with self.lock:
            if key in self.buckets:
                self.buckets[key]["tokens"] = self.bucket_size
                self.buckets[key]["last_refill"] = time.time()
                with self.metrics_lock:
                    self.metrics.reset_count += 1
                return True
            return False

    async def get_current_usage(self, key: str) -> int:
        """Get current token usage"""
        async with self.lock:
            if key not in self.buckets:
                return 0
            bucket = self.buckets[key]
            return self.bucket_size - int(bucket["tokens"])

    async def cleanup(self) -> int:
        """Clean up inactive buckets"""
        current_time = time.time()
        cleanup_threshold = self.config.cleanup_interval

        async with self.lock:
            keys_to_remove = []
            for key, bucket in self.buckets.items():
                time_since_last_use = current_time - bucket["last_refill"]
                if time_since_last_use > cleanup_threshold:
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                del self.buckets[key]

            if keys_to_remove:
                with self.metrics_lock:
                    self.metrics.unique_keys = len(self.buckets)

            return len(keys_to_remove)

    async def _cleanup_loop(self) -> None:
        """Automatic cleanup loop"""
        while True:
            try:
                await asyncio.sleep(self.config.cleanup_interval)
                cleaned = await self.cleanup()
                if cleaned > 0:
                    logger.debug(f"Cleaned up {cleaned} inactive rate limit buckets")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Rate limiter cleanup error: {e}")


class SlidingWindowRateLimiter(BaseRateLimiter):
    """Sliding window rate limiter implementation"""

    def __init__(self, config: RateLimitConfig):
        super().__init__(config)
        self.windows: Dict[str, deque] = {}
        self.lock = asyncio.Lock()

        # Start cleanup task
        self.cleanup_task: Optional[asyncio.Task] = None
        self.start_cleanup()

    def start_cleanup(self) -> None:
        """Start cleanup task"""
        if self.cleanup_task is None:
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop_cleanup(self) -> None:
        """Stop cleanup task"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
            self.cleanup_task = None

    async def check_rate_limit(self, key: str) -> RateLimitResult:
        """Check rate limit using sliding window algorithm"""
        async with self.lock:
            current_time = time.time()
            window_start = current_time - self.config.window_seconds

            # Get or create window
            if key not in self.windows:
                self.windows[key] = deque()
                with self.metrics_lock:
                    self.metrics.unique_keys += 1

            window = self.windows[key]

            # Remove expired entries
            while window and window[0].timestamp < window_start:
                window.popleft()

            # Count current requests in window
            current_requests = sum(entry.count for entry in window)

            # Check if request is allowed
            if current_requests < self.config.requests:
                window.append(WindowEntry(current_time, 1))
                allowed = True
                requests_remaining = self.config.requests - current_requests - 1
            else:
                allowed = False
                requests_remaining = 0

            # Calculate reset time (when oldest entry expires)
            if window:
                reset_time = window[0].timestamp + self.config.window_seconds
            else:
                reset_time = current_time + self.config.window_seconds

            # Calculate retry after
            retry_after = None
            if not allowed and window:
                retry_after = (
                    window[0].timestamp + self.config.window_seconds - current_time
                )

            self._update_metrics(allowed, key, current_requests)

            return RateLimitResult(
                allowed=allowed,
                requests_remaining=requests_remaining,
                reset_time=reset_time,
                retry_after=retry_after,
                rate_limit_key=key,
                current_usage=current_requests,
                metadata={
                    "strategy": "sliding_window",
                    "window_size": self.config.window_seconds,
                    "window_entries": len(window),
                },
            )

    async def reset_rate_limit(self, key: str) -> bool:
        """Reset rate limit for key"""
        async with self.lock:
            if key in self.windows:
                self.windows[key].clear()
                with self.metrics_lock:
                    self.metrics.reset_count += 1
                return True
            return False

    async def get_current_usage(self, key: str) -> int:
        """Get current usage in window"""
        async with self.lock:
            if key not in self.windows:
                return 0

            current_time = time.time()
            window_start = current_time - self.config.window_seconds
            window = self.windows[key]

            # Remove expired entries
            while window and window[0].timestamp < window_start:
                window.popleft()

            return sum(entry.count for entry in window)

    async def cleanup(self) -> int:
        """Clean up empty windows"""
        async with self.lock:
            keys_to_remove = []
            current_time = time.time()
            window_start = current_time - self.config.window_seconds

            for key, window in self.windows.items():
                # Remove expired entries
                while window and window[0].timestamp < window_start:
                    window.popleft()

                # Remove empty windows that haven't been used recently
                if not window:
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                del self.windows[key]

            if keys_to_remove:
                with self.metrics_lock:
                    self.metrics.unique_keys = len(self.windows)

            return len(keys_to_remove)

    async def _cleanup_loop(self) -> None:
        """Automatic cleanup loop"""
        while True:
            try:
                await asyncio.sleep(self.config.cleanup_interval)
                cleaned = await self.cleanup()
                if cleaned > 0:
                    logger.debug(f"Cleaned up {cleaned} empty sliding windows")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Sliding window cleanup error: {e}")


class FixedWindowRateLimiter(BaseRateLimiter):
    """Fixed window rate limiter implementation"""

    def __init__(self, config: RateLimitConfig):
        super().__init__(config)
        self.windows: Dict[str, Dict[str, Any]] = {}
        self.lock = asyncio.Lock()

        # Start cleanup task
        self.cleanup_task: Optional[asyncio.Task] = None
        self.start_cleanup()

    def start_cleanup(self) -> None:
        """Start cleanup task"""
        if self.cleanup_task is None:
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop_cleanup(self) -> None:
        """Stop cleanup task"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
            self.cleanup_task = None

    async def check_rate_limit(self, key: str) -> RateLimitResult:
        """Check rate limit using fixed window algorithm"""
        async with self.lock:
            current_time = time.time()
            window_start = (
                int(current_time // self.config.window_seconds)
                * self.config.window_seconds
            )

            # Get or create window
            if key not in self.windows:
                self.windows[key] = {"count": 0, "window_start": window_start}
                with self.metrics_lock:
                    self.metrics.unique_keys += 1

            window = self.windows[key]

            # Reset window if expired
            if window["window_start"] < window_start:
                window["count"] = 0
                window["window_start"] = window_start

            # Check if request is allowed
            if window["count"] < self.config.requests:
                window["count"] += 1
                allowed = True
                requests_remaining = self.config.requests - window["count"]
            else:
                allowed = False
                requests_remaining = 0

            # Calculate reset time
            reset_time = window_start + self.config.window_seconds

            # Calculate retry after
            retry_after = None
            if not allowed:
                retry_after = reset_time - current_time

            self._update_metrics(allowed, key, window["count"])

            return RateLimitResult(
                allowed=allowed,
                requests_remaining=requests_remaining,
                reset_time=reset_time,
                retry_after=retry_after,
                rate_limit_key=key,
                current_usage=window["count"],
                metadata={
                    "strategy": "fixed_window",
                    "window_start": window_start,
                    "window_size": self.config.window_seconds,
                },
            )

    async def reset_rate_limit(self, key: str) -> bool:
        """Reset rate limit for key"""
        async with self.lock:
            if key in self.windows:
                self.windows[key]["count"] = 0
                with self.metrics_lock:
                    self.metrics.reset_count += 1
                return True
            return False

    async def get_current_usage(self, key: str) -> int:
        """Get current usage in window"""
        async with self.lock:
            if key not in self.windows:
                return 0

            current_time = time.time()
            window_start = (
                int(current_time // self.config.window_seconds)
                * self.config.window_seconds
            )
            window = self.windows[key]

            # Check if window is still valid
            if window["window_start"] < window_start:
                return 0

            return window["count"]

    async def cleanup(self) -> int:
        """Clean up expired windows"""
        async with self.lock:
            current_time = time.time()
            current_window_start = (
                int(current_time // self.config.window_seconds)
                * self.config.window_seconds
            )

            keys_to_remove = []
            for key, window in self.windows.items():
                # Remove windows that are more than one window period old
                if (
                    window["window_start"]
                    < current_window_start - self.config.window_seconds
                ):
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                del self.windows[key]

            if keys_to_remove:
                with self.metrics_lock:
                    self.metrics.unique_keys = len(self.windows)

            return len(keys_to_remove)

    async def _cleanup_loop(self) -> None:
        """Automatic cleanup loop"""
        while True:
            try:
                await asyncio.sleep(self.config.cleanup_interval)
                cleaned = await self.cleanup()
                if cleaned > 0:
                    logger.debug(f"Cleaned up {cleaned} expired fixed windows")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fixed window cleanup error: {e}")


class DistributedRateLimiter(BaseRateLimiter):
    """Redis-based distributed rate limiter"""

    def __init__(self, config: RateLimitConfig):
        if not HAS_REDIS:
            raise RuntimeError("redis package is required for DistributedRateLimiter")

        super().__init__(config)
        self.redis_client: Optional[aioredis.Redis] = None
        self.connection_pool: Optional[aioredis.ConnectionPool] = None

        # Lua scripts for atomic operations
        self.token_bucket_script = """
        local key = KEYS[1]
        local bucket_size = tonumber(ARGV[1])
        local tokens_per_second = tonumber(ARGV[2])
        local current_time = tonumber(ARGV[3])
        
        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1]) or bucket_size
        local last_refill = tonumber(bucket[2]) or current_time
        
        -- Refill tokens
        local time_passed = current_time - last_refill
        tokens = math.min(bucket_size, tokens + time_passed * tokens_per_second)
        
        local allowed = 0
        if tokens >= 1 then
            tokens = tokens - 1
            allowed = 1
        end
        
        -- Update bucket
        redis.call('HMSET', key, 'tokens', tokens, 'last_refill', current_time)
        redis.call('EXPIRE', key, 3600)  -- Expire after 1 hour of inactivity
        
        return {allowed, math.floor(tokens), current_time + (bucket_size - tokens) / tokens_per_second}
        """

        self.sliding_window_script = """
        local key = KEYS[1]
        local window_size = tonumber(ARGV[1])
        local limit = tonumber(ARGV[2])
        local current_time = tonumber(ARGV[3])
        local window_start = current_time - window_size
        
        -- Remove expired entries
        redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
        
        -- Count current requests
        local current_count = redis.call('ZCARD', key)
        
        local allowed = 0
        if current_count < limit then
            -- Add current request
            redis.call('ZADD', key, current_time, current_time .. ':' .. math.random())
            redis.call('EXPIRE', key, math.ceil(window_size))
            allowed = 1
            current_count = current_count + 1
        end
        
        -- Calculate reset time
        local oldest_score = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
        local reset_time = current_time + window_size
        if oldest_score[2] then
            reset_time = tonumber(oldest_score[2]) + window_size
        end
        
        return {allowed, limit - current_count, reset_time, current_count}
        """

    async def _ensure_connection(self) -> None:
        """Ensure Redis connection is established"""
        if self.redis_client is None:
            if self.config.redis_url:
                self.connection_pool = aioredis.ConnectionPool.from_url(
                    self.config.redis_url, decode_responses=True
                )
                self.redis_client = aioredis.Redis(connection_pool=self.connection_pool)
            else:
                raise ValueError(
                    "redis_url must be provided for DistributedRateLimiter"
                )

    def _make_key(self, key: str) -> str:
        """Create Redis key with prefix"""
        return f"{self.config.redis_key_prefix}:{key}"

    async def check_rate_limit(self, key: str) -> RateLimitResult:
        """Check rate limit using Redis-based algorithm"""
        await self._ensure_connection()
        redis_key = self._make_key(key)
        current_time = time.time()

        try:
            if self.config.strategy == RateLimitStrategy.TOKEN_BUCKET:
                result = await self._check_token_bucket(redis_key, current_time)
            elif self.config.strategy == RateLimitStrategy.SLIDING_WINDOW:
                result = await self._check_sliding_window(redis_key, current_time)
            else:
                # Fallback to sliding window
                result = await self._check_sliding_window(redis_key, current_time)

            self._update_metrics(result.allowed, key, result.current_usage)
            with self.metrics_lock:
                if result.allowed:
                    self.metrics.cache_hits += 1
                else:
                    self.metrics.cache_misses += 1

            return result

        except Exception as e:
            logger.error(f"Distributed rate limiter error for key {key}: {e}")
            # Fail open - allow request if Redis is unavailable
            return RateLimitResult(
                allowed=True,
                requests_remaining=self.config.requests,
                reset_time=current_time + self.config.window_seconds,
                rate_limit_key=key,
                current_usage=0,
                metadata={"error": str(e)},
            )

    async def _check_token_bucket(
        self, redis_key: str, current_time: float
    ) -> RateLimitResult:
        """Check rate limit using token bucket with Redis"""
        bucket_size = self.config.burst_size or self.config.requests
        tokens_per_second = self.config.requests / self.config.window_seconds

        result = await self.redis_client.eval(
            self.token_bucket_script,
            1,
            redis_key,
            bucket_size,
            tokens_per_second,
            current_time,
        )

        allowed = bool(result[0])
        requests_remaining = int(result[1])
        reset_time = float(result[2])

        retry_after = None
        if not allowed:
            retry_after = 1.0 / tokens_per_second

        current_usage = bucket_size - requests_remaining

        return RateLimitResult(
            allowed=allowed,
            requests_remaining=requests_remaining,
            reset_time=reset_time,
            retry_after=retry_after,
            rate_limit_key=redis_key,
            current_usage=current_usage,
            metadata={
                "strategy": "distributed_token_bucket",
                "bucket_size": bucket_size,
                "tokens_per_second": tokens_per_second,
            },
        )

    async def _check_sliding_window(
        self, redis_key: str, current_time: float
    ) -> RateLimitResult:
        """Check rate limit using sliding window with Redis"""
        result = await self.redis_client.eval(
            self.sliding_window_script,
            1,
            redis_key,
            self.config.window_seconds,
            self.config.requests,
            current_time,
        )

        allowed = bool(result[0])
        requests_remaining = int(result[1])
        reset_time = float(result[2])
        current_usage = int(result[3])

        retry_after = None
        if not allowed:
            retry_after = reset_time - current_time

        return RateLimitResult(
            allowed=allowed,
            requests_remaining=requests_remaining,
            reset_time=reset_time,
            retry_after=retry_after,
            rate_limit_key=redis_key,
            current_usage=current_usage,
            metadata={
                "strategy": "distributed_sliding_window",
                "window_size": self.config.window_seconds,
            },
        )

    async def reset_rate_limit(self, key: str) -> bool:
        """Reset rate limit for key"""
        await self._ensure_connection()
        redis_key = self._make_key(key)

        try:
            result = await self.redis_client.delete(redis_key)
            if result > 0:
                with self.metrics_lock:
                    self.metrics.reset_count += 1
                return True
            return False
        except Exception as e:
            logger.error(f"Error resetting rate limit for key {key}: {e}")
            return False

    async def get_current_usage(self, key: str) -> int:
        """Get current usage for key"""
        await self._ensure_connection()
        redis_key = self._make_key(key)

        try:
            if self.config.strategy == RateLimitStrategy.TOKEN_BUCKET:
                bucket = await self.redis_client.hmget(redis_key, "tokens")
                if bucket[0] is not None:
                    tokens = float(bucket[0])
                    bucket_size = self.config.burst_size or self.config.requests
                    return int(bucket_size - tokens)
                return 0
            else:  # Sliding window
                count = await self.redis_client.zcard(redis_key)
                return int(count)
        except Exception as e:
            logger.error(f"Error getting usage for key {key}: {e}")
            return 0

    async def cleanup(self) -> int:
        """Cleanup is handled by Redis TTL"""
        return 0

    async def close(self) -> None:
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()
        if self.connection_pool:
            await self.connection_pool.disconnect()


class RateLimiter:
    """Main rate limiter class that delegates to appropriate implementation"""

    def __init__(self, config: RateLimitConfig):
        self.config = config

        # Create appropriate limiter implementation
        if config.redis_url:
            self.limiter = DistributedRateLimiter(config)
        elif config.strategy == RateLimitStrategy.TOKEN_BUCKET:
            self.limiter = TokenBucketRateLimiter(config)
        elif config.strategy == RateLimitStrategy.SLIDING_WINDOW:
            self.limiter = SlidingWindowRateLimiter(config)
        elif config.strategy == RateLimitStrategy.FIXED_WINDOW:
            self.limiter = FixedWindowRateLimiter(config)
        else:
            # Default to token bucket
            self.limiter = TokenBucketRateLimiter(config)

    async def check_rate_limit(
        self, identifier: str, context: Optional[Dict[str, Any]] = None
    ) -> RateLimitResult:
        """Check rate limit for identifier"""
        # Generate rate limit key based on scope
        key = self._generate_key(identifier, context)
        return await self.limiter.check_rate_limit(key)

    async def is_allowed(
        self, identifier: str, context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Check if request is allowed (simple interface)"""
        result = await self.check_rate_limit(identifier, context)
        return result.allowed

    async def reset(
        self, identifier: str, context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Reset rate limit for identifier"""
        key = self._generate_key(identifier, context)
        return await self.limiter.reset_rate_limit(key)

    async def get_usage(
        self, identifier: str, context: Optional[Dict[str, Any]] = None
    ) -> int:
        """Get current usage for identifier"""
        key = self._generate_key(identifier, context)
        return await self.limiter.get_current_usage(key)

    def _generate_key(
        self, identifier: str, context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate rate limit key based on scope and identifier"""
        if self.config.key_extractor and context:
            try:
                return self.config.key_extractor(identifier, context)
            except Exception as e:
                logger.warning(f"Key extractor failed: {e}")

        # Default key generation based on scope
        if self.config.scope == RateLimitScope.GLOBAL:
            return "global"
        elif self.config.scope == RateLimitScope.PER_USER:
            return f"user:{identifier}"
        elif self.config.scope == RateLimitScope.PER_IP:
            return f"ip:{identifier}"
        elif self.config.scope == RateLimitScope.PER_API_KEY:
            return f"api_key:{identifier}"
        else:  # CUSTOM
            return identifier

    async def close(self) -> None:
        """Close rate limiter resources"""
        if hasattr(self.limiter, "close"):
            await self.limiter.close()
        if hasattr(self.limiter, "stop_cleanup"):
            await self.limiter.stop_cleanup()

    def get_metrics(self) -> RateLimitMetrics:
        """Get rate limiter metrics"""
        return self.limiter.get_metrics()


# Decorator and context manager


def rate_limit_decorator(
    config: RateLimitConfig,
    identifier_extractor: Optional[Callable] = None,
    raise_on_limit: bool = True,
):
    """Decorator to apply rate limiting to functions"""
    limiter = RateLimiter(config)

    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Extract identifier
            if identifier_extractor:
                identifier = identifier_extractor(*args, **kwargs)
            else:
                # Use first argument as identifier, fallback to "default"
                identifier = str(args[0]) if args else "default"

            # Check rate limit
            result = await limiter.check_rate_limit(identifier)

            if not result.allowed:
                if raise_on_limit:
                    raise RateLimitExceeded(result)
                else:
                    logger.warning(f"Rate limit exceeded for {identifier}")
                    return None

            return await func(*args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # For sync functions, we can't easily apply async rate limiting
            logger.warning("Rate limiting not supported for synchronous functions")
            return func(*args, **kwargs)

        # Return appropriate wrapper
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


@asynccontextmanager
async def rate_limit_context(
    limiter: RateLimiter,
    identifier: str,
    context: Optional[Dict[str, Any]] = None,
    raise_on_limit: bool = True,
) -> AsyncContextManager[RateLimitResult]:
    """Context manager for rate limiting"""
    result = await limiter.check_rate_limit(identifier, context)

    if not result.allowed and raise_on_limit:
        raise RateLimitExceeded(result)

    yield result


# Global rate limiter instances
_global_rate_limiters: Dict[str, RateLimiter] = {}


def get_global_rate_limiter(
    name: str, config: Optional[RateLimitConfig] = None
) -> RateLimiter:
    """Get or create global rate limiter"""
    if name not in _global_rate_limiters:
        if config is None:
            config = RateLimitConfig()
        _global_rate_limiters[name] = RateLimiter(config)

    return _global_rate_limiters[name]


async def cleanup_global_rate_limiters():
    """Cleanup global rate limiters"""
    for limiter in _global_rate_limiters.values():
        await limiter.close()
    _global_rate_limiters.clear()
